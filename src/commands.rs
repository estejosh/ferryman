//! Implementations of the subcommands. Every operation resolves its settings
//! as: defaults < `deadman.toml` < CLI flags. All output is plain text on
//! stdout; errors go through [`crate::Error`] so `main` can map exit codes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::archive::{self, ArchiveOptions};
use crate::artifact::{self, ArtifactHeader, write_atomic};
use crate::beacon::Beacon;
use crate::config::{self, ArchiveCmd, BeaconSetting, Config, HeartbeatSource, NotifyCfg};
use crate::duration::format_window;
use crate::error::{self, Error, Result};
use crate::fingerprint;
use crate::state::{self, Mode, State, SuccessorRecord};
use crate::tlock;

/// Default wait budget for test-trigger against the real network.
const DRAND_DEFAULT_WAIT: Duration = Duration::from_secs(300);
/// Slack added to sim windows when test-trigger waits.
const SIM_WAIT_SLACK_SECS: u64 = 30;
/// Default silence window when neither config nor flags say otherwise.
const DEFAULT_WINDOW: &str = "30d";

fn canonical_repo(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        return Err(Error::NotAGitRepo(path.to_path_buf()));
    }
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !crate::beacon::is_git_repo(&abs) {
        return Err(Error::NotAGitRepo(abs));
    }
    Ok(abs)
}

// ---------------------------------------------------------------------------
// effective-settings resolution (defaults < config < flags)
// ---------------------------------------------------------------------------

/// CLI overrides accepted by `arm`. Absent values defer to the config.
#[derive(Debug, Default)]
pub struct ArmArgs {
    pub repo: PathBuf,
    pub config: Option<PathBuf>,
    /// Repeatable `--successor [name=]key`.
    pub successors: Vec<(Option<String>, String)>,
    pub window: Option<String>,
    pub include_secrets: Option<bool>,
    pub includes: Vec<String>,
    pub beacon: Option<String>,
    pub simulate: bool,
    /// Shell line replacing the built-in archiver.
    pub archive_cmd: Option<String>,
}

/// Settings after defaults/config/flag resolution. Beacon identity (mode,
/// url, chain) always comes from this struct at arm time and from persisted
/// state afterwards — heartbeats never switch beacons mid-flight.
struct Effective {
    window_secs: u64,
    mode: Mode,
    beacon_url: Option<String>,
    chain_hash: Option<String>,
    beacon: Beacon,
    include_secrets: bool,
    include_globs: Vec<String>,
    successors: Vec<SuccessorRecord>,
    archive_command: Option<ArchiveCmd>,
}

/// Parse a CLI `--successor` value: `[name=]key`. The name may contain
/// letters, digits, spaces and `._-` (1..=64 chars); the key may be a file
/// path or inline hex.
pub fn parse_successor(raw: &str) -> Result<(Option<String>, String)> {
    let t = raw.trim();
    if let Some((name, key)) = t.split_once('=') {
        let name = name.trim();
        if name.is_empty() || key.trim().is_empty() {
            return Err(Error::BadInput(format!(
                "--successor {raw:?}: expected [name=]key with non-empty parts"
            )));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
            || name.len() > 64
        {
            return Err(Error::BadInput(format!(
                "--successor {raw:?}: name must be 1-64 chars of [a-zA-Z0-9._ -]"
            )));
        }
        Ok((Some(name.to_string()), key.trim().to_string()))
    } else {
        Ok((None, t.to_string()))
    }
}

fn print_unknown_keys(loaded: &config::Loaded) {
    for k in &loaded.unknown_keys {
        eprintln!(
            "warning: {} ignores unknown key {k:?} (known by a newer ferry-deadman?)",
            loaded.path.display()
        );
    }
}

fn resolve_successors(
    cfg: &Config,
    cli: &[(Option<String>, String)],
) -> Result<Vec<SuccessorRecord>> {
    let mut out: Vec<SuccessorRecord> = Vec::new();
    for (name, key) in cli {
        push_successor(&mut out, name.clone().unwrap_or_default(), key.clone())?;
    }
    if out.is_empty() {
        for s in &cfg.successors {
            push_successor(&mut out, s.name.clone(), s.key.clone())?;
        }
    }
    if out.is_empty() {
        return Err(Error::BadInput(
            "no successors configured: add [[successors]] to deadman.toml or pass \
             --successor name=key"
                .into(),
        ));
    }
    Ok(out)
}

fn push_successor(out: &mut Vec<SuccessorRecord>, name: String, key: String) -> Result<()> {
    let fp = if key.trim().is_empty() {
        fingerprint::fingerprint_name(&name)?
    } else {
        fingerprint::fingerprint_successor(&key)?
    };
    let rec = SuccessorRecord {
        name: name.trim().to_string(),
        fingerprint: fp,
    };
    if out.contains(&rec) {
        return Err(Error::BadInput(format!(
            "duplicate successor {:?}",
            rec.name
        )));
    }
    out.push(rec);
    Ok(())
}

fn build_effective_beacon(
    args_simulate: bool,
    args_url: Option<&str>,
    cfg_beacon: Option<BeaconSetting>,
) -> Result<(Mode, Beacon, Option<String>, Option<String>)> {
    if args_simulate || matches!(cfg_beacon, Some(BeaconSetting::Simulate)) {
        return Ok((Mode::Sim, Beacon::sim(error::unix_now()?), None, None));
    }
    let explicit_url = match (args_url, &cfg_beacon) {
        (Some(u), _) => (!u.trim().is_empty()).then(|| u.trim().to_string()),
        (None, Some(BeaconSetting::Url(u))) => (!u.trim().is_empty()).then(|| u.trim().to_string()),
        (None, Some(BeaconSetting::Simulate)) | (None, None) => None,
    };
    match explicit_url {
        Some(u) => {
            let b = Beacon::drand(&u, crate::beacon::QUICKNET_CHAIN_HASH)?;
            Ok((
                Mode::Drand,
                b,
                Some(u),
                Some(crate::beacon::QUICKNET_CHAIN_HASH.to_string()),
            ))
        }
        None => {
            // No endpoint pinned anywhere: try the public quicknet mirrors.
            let (base, info) = Beacon::fetch_default_drand()?;
            Ok((
                Mode::Drand,
                Beacon::Drand(crate::beacon::DrandParams {
                    base_url: base.clone(),
                    chain_hash: info.hash.to_ascii_lowercase(),
                    info,
                }),
                Some(base),
                Some(crate::beacon::QUICKNET_CHAIN_HASH.to_string()),
            ))
        }
    }
}

fn resolve_arm(repo: &Path, args: &ArmArgs) -> Result<Effective> {
    let loaded = config::load(args.config.as_deref(), repo)?;
    print_unknown_keys(&loaded);
    let cfg = loaded.config;

    let (mode, beacon, beacon_url, chain_hash) =
        build_effective_beacon(args.simulate, args.beacon.as_deref(), cfg.beacon.clone())?;

    let window_raw = args
        .window
        .clone()
        .or_else(|| cfg.window.clone())
        .unwrap_or_else(|| DEFAULT_WINDOW.to_string());
    let window_secs = crate::duration::parse_window(&window_raw)?.as_secs();

    Ok(Effective {
        window_secs,
        mode,
        beacon_url,
        chain_hash,
        beacon,
        include_secrets: args.include_secrets.unwrap_or(cfg.include_secrets),
        include_globs: if args.includes.is_empty() {
            cfg.include.clone()
        } else {
            args.includes.clone()
        },
        successors: resolve_successors(&cfg, &args.successors)?,
        archive_command: match &args.archive_cmd {
            Some(s) => Some(ArchiveCmd::Shell(s.clone())),
            None => cfg.archive.command.clone(),
        },
    })
}

// ---------------------------------------------------------------------------
// sealing
// ---------------------------------------------------------------------------

/// Build the payload once, then write one independently sealed copy per
/// successor. Replaces stale copies of successors that left the config.
fn seal_and_write_all(repo: &Path, state: &mut State, eff: &Effective) -> Result<Vec<String>> {
    let opts = ArchiveOptions {
        include_secrets: eff.include_secrets,
        include_globs: &eff.include_globs,
        archive_command: eff.archive_command.as_ref(),
    };
    let built = archive::build_archive(repo, &opts)?;
    for warning in &built.warnings {
        eprintln!("warning: {warning}");
    }

    let unlock_round = eff
        .beacon
        .unlock_round(error::unix_now()?, state.window_secs);

    let mut written: Vec<String> = Vec::new();
    for succ in &state.successors {
        // Each successor gets its own master key and its own sealed envelope.
        let (master, key_blob) = tlock::seal_master_key(&eff.beacon, unlock_round)?;
        let header = ArtifactHeader {
            format: artifact::FORMAT.into(),
            mode: state.mode,
            beacon_url: state.beacon_url.clone(),
            chain_hash: state.chain_hash.clone(),
            unlock_round,
            period_secs: eff.beacon.period_secs(),
            genesis_unix: eff.beacon.genesis_unix(),
            created_unix: error::unix_now()?,
            successor_fingerprint: succ.fingerprint.clone(),
            successor_name: (!succ.name.is_empty()).then(|| succ.name.clone()),
            bundle_sha256: built.bundle_sha256.clone(),
            archive_sha256: built.archive_sha256.clone(),
            head_sha256: built.head_sha256.clone(),
        };
        let bytes = artifact::build_artifact(header, &master, key_blob, &built.payload)?;
        let fname = State::artifact_name_for(succ);
        write_atomic(&state::artifact_path(repo, &fname), &bytes)?;
        written.push(fname);
    }

    state.genesis_unix = eff.beacon.genesis_unix();
    state.period_secs = eff.beacon.period_secs();
    state.unlock_round = unlock_round;
    state.archive_sha256 = built.archive_sha256;
    state.bundle_sha256 = built.bundle_sha256;
    state.head_sha256 = built.head_sha256;

    // Prune copies of successors that left the configuration.
    let pruned = state::prune_artifacts(repo, &written)?;
    for p in pruned {
        println!("  pruned stale copy {}", p.display());
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// notify hooks
// ---------------------------------------------------------------------------

/// Run the hook configured for `event`, if any. Failures are warnings —
/// a broken notification channel must not corrupt the succession flow.
fn run_notify(repo: &Path, notify: &NotifyCfg, event: &str, state: &State) {
    let hook = match event {
        "arm" => notify.arm.as_deref(),
        "rearm" => notify.rearm.as_deref(),
        "trigger" => notify.trigger.as_deref(),
        _ => None,
    };
    let Some(hook) = hook else { return };
    let unlock_at = error::from_unix(state.beacon().round_time(state.unlock_round));
    let outcome = std::process::Command::new("sh")
        .arg("-c")
        .arg(hook)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .env("FERRY_DEADMAN_EVENT", event)
        .env("FERRY_DEADMAN_REPO", repo)
        .env("FERRY_DEADMAN_ROUND", state.unlock_round.to_string())
        .env("FERRY_DEADMAN_UNLOCK_AT", error::format_time(unlock_at))
        .status();
    match outcome {
        Ok(st) if st.success() => println!("  notify[{event}]: hook ran"),
        Ok(st) => eprintln!("warning: notify[{event}] hook exited with {st}"),
        Err(e) => eprintln!("warning: notify[{event}] hook failed to run: {e}"),
    }
}

/// If silence already passed the window, run the trigger hook once per armed
/// cycle. Persisting the marker first guarantees at-most-once delivery even
/// across crashes.
fn maybe_fire_trigger_hook(repo: &Path, state: &mut State, notify: &NotifyCfg) -> Result<bool> {
    if state.notified_trigger_unix.is_some() {
        return Ok(false);
    }
    let due = state.beacon().round_time(state.unlock_round) <= error::unix_now()?;
    if !due {
        return Ok(false);
    }
    state.notified_trigger_unix = Some(error::unix_now()?);
    state::save(repo, state)?;
    run_notify(repo, notify, "trigger", state);
    Ok(true)
}

fn load_notify(repo: &Path) -> NotifyCfg {
    config::load(None, repo)
        .map(|l| l.config.notify)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// arm / heartbeat / status / disarm / test-trigger / init
// ---------------------------------------------------------------------------

/// Write the commented config template into `<repo>/deadman.toml`.
pub fn init(repo_path: &Path, force: bool) -> Result<()> {
    let repo = canonical_repo(repo_path)?;
    let path = config::config_path(&repo);
    if path.exists() && !force {
        return Err(Error::BadInput(format!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        )));
    }
    std::fs::write(&path, config::TEMPLATE)
        .map_err(|e| Error::Other(format!("cannot write {}: {e}", path.display())))?;
    println!("wrote {}", path.display());
    println!(
        "  edit it, then run: ferry-deadman arm --repo {}",
        repo.display()
    );
    Ok(())
}

pub fn arm(args: &ArmArgs) -> Result<()> {
    let repo = canonical_repo(&args.repo)?;
    let was_armed = state::state_path(&repo).exists();
    let eff = resolve_arm(&repo, args)?;
    let now = error::unix_now()?;

    let mut state = State {
        version: state::STATE_VERSION,
        mode: eff.mode,
        beacon_url: eff.beacon_url.clone(),
        chain_hash: eff.chain_hash.clone(),
        period_secs: eff.beacon.period_secs(),
        genesis_unix: eff.beacon.genesis_unix(),
        armed_unix: now,
        window_secs: eff.window_secs,
        unlock_round: 0,
        successors: Vec::new(),
        include_secrets: eff.include_secrets,
        include_globs: eff.include_globs.clone(),
        archive_argv: eff.archive_command.as_ref().map(|c| c.argv()),
        notified_trigger_unix: None,
        last_heartbeat_unix: now,
        archive_sha256: String::new(),
        bundle_sha256: None,
        head_sha256: None,
    };

    state.successors = eff.successors.clone();

    seal_and_write_all(&repo, &mut state, &eff)?;
    state.last_heartbeat_unix = error::unix_now()?;
    state::save(&repo, &state)?;
    state::exclude_from_git_index(&repo);
    run_notify(
        &repo,
        &load_notify(&repo),
        if was_armed { "rearm" } else { "arm" },
        &state,
    );

    print_arm_summary(&repo, &state);
    Ok(())
}

fn print_arm_summary(repo: &Path, state: &State) {
    let beacon = state.beacon();
    let unlock_at = error::from_unix(beacon.round_time(state.unlock_round));
    println!("armed {} (ferry-deadman/v2)", repo.display());
    println!("  mode:                 {}", mode_line(state.mode));
    println!(
        "  window:               {}",
        format_window(state.window_secs)
    );
    if state.mode == Mode::Drand {
        println!(
            "  chain:                {}",
            state.chain_hash.as_deref().unwrap_or("-")
        );
        println!(
            "  endpoint:             {}",
            state.beacon_url.as_deref().unwrap_or("-")
        );
    }
    println!("  successors:           {}", state.successors.len());
    for succ in &state.successors {
        println!(
            "    - {} ({})",
            display_name(succ),
            fingerprint::short(&succ.fingerprint)
        );
    }
    println!(
        "  extras:               {} glob(s), conventional secrets {}",
        state.include_globs.len(),
        yes_no(state.include_secrets)
    );
    if let Some(argv) = &state.archive_argv {
        println!("  archiver:             custom ({})", argv.join(" "));
    }
    println!(
        "  unlocks:              round {} at {}",
        state.unlock_round,
        error::format_time(unlock_at)
    );
    for succ in &state.successors {
        let fname = State::artifact_name_for(succ);
        println!(
            "  sealed copy:          {}",
            state::artifact_path(repo, &fname).display()
        );
    }
    if state.mode == Mode::Sim {
        println!();
        println!(
            "  !! SIMULATION MODE — the timelock is enforced by policy only, NOT cryptography."
        );
        println!("  !! Re-arm against a real drand beacon to seal for real.");
    } else {
        println!();
        println!("  Sync each sealed copy to its successor via any channel you trust.");
        println!("  Living? Run `ferry-deadman heartbeat` (or re-arm) to push the deadline out.");
    }
}

fn display_name(succ: &SuccessorRecord) -> String {
    if succ.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        succ.name.clone()
    }
}

fn mode_line(mode: Mode) -> &'static str {
    match mode {
        Mode::Sim => "simulate (offline fake beacon)",
        Mode::Drand => "drand quicknet (real timelock)",
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn rebuild_beacon(state: &State) -> Result<Beacon> {
    Ok(match state.mode {
        Mode::Sim => Beacon::sim(state.genesis_unix),
        Mode::Drand => {
            let url = state
                .beacon_url
                .clone()
                .ok_or_else(|| Error::Corrupt("drand state missing beacon url".into()))?;
            let chain = state
                .chain_hash
                .clone()
                .ok_or_else(|| Error::Corrupt("drand state missing chain hash".into()))?;
            Beacon::drand(&url, &chain)?
        }
    })
}

/// Prove life: re-seal every configured copy at a NEW future round and prune
/// replaced artifacts. Settings refresh from `deadman.toml` when one exists;
/// repos without one keep whatever state.json recorded.
///
/// This is also the engine behind `any-cli` heartbeats.
pub fn heartbeat(repo_path: &Path) -> Result<()> {
    let repo = canonical_repo(repo_path)?;
    let mut state = state::load(&repo)?;

    let loaded = config::load(None, &repo)?;
    print_unknown_keys(&loaded);
    let cfg_present = loaded.present;
    let cfg = loaded.config;

    // Beacon identity is frozen at arm time; only the seal moves forward.
    let beacon = rebuild_beacon(&state)?;

    let eff = Effective {
        window_secs: match cfg.window.as_deref() {
            Some(w) if cfg_present => crate::duration::parse_window(w)?.as_secs(),
            _ => state.window_secs,
        },
        mode: state.mode,
        beacon_url: state.beacon_url.clone(),
        chain_hash: state.chain_hash.clone(),
        beacon,
        include_secrets: if cfg_present {
            cfg.include_secrets
        } else {
            state.include_secrets
        },
        include_globs: if cfg_present {
            cfg.include.clone()
        } else {
            state.include_globs.clone()
        },
        successors: if cfg_present && !cfg.successors.is_empty() {
            resolve_successors(&cfg, &[])?
        } else {
            state.successors.clone()
        },
        archive_command: if cfg_present {
            cfg.archive.command.clone()
        } else {
            state.archive_argv.clone().map(ArchiveCmd::Argv)
        },
    };

    let previous_round = state.unlock_round;
    state.window_secs = eff.window_secs;
    state.include_secrets = eff.include_secrets;
    state.include_globs = eff.include_globs.clone();
    state.archive_argv = eff.archive_command.as_ref().map(|c| c.argv());
    state.successors = eff.successors.clone();
    state.notified_trigger_unix = None;

    seal_and_write_all(&repo, &mut state, &eff)?;
    state.last_heartbeat_unix = error::unix_now()?;
    state::save(&repo, &state)?;
    run_notify(&repo, &load_notify(&repo), "rearm", &state);

    let unlock_at = error::from_unix(eff.beacon.round_time(state.unlock_round));
    println!("heartbeat accepted");
    println!(
        "  unlock round:          {} -> {} at {}",
        previous_round,
        state.unlock_round,
        error::format_time(unlock_at)
    );
    println!("  old sealed artifacts pruned (atomically replaced)");
    Ok(())
}

/// Automatic heartbeat for repos whose config opted into `any-cli`. Never
/// fails the surrounding command: a nicety must not break `status` offline.
pub fn auto_heartbeat_if_configured(repo_path: &Path) {
    let outcome = try_auto_heartbeat(repo_path);
    match outcome {
        Ok(true) => println!("note: heartbeat recorded (heartbeat.sources includes \"any-cli\")"),
        Ok(false) => {}
        Err(_) => {}
    }
}

fn try_auto_heartbeat(repo_path: &Path) -> Result<bool> {
    let repo = canonical_repo(repo_path)?;
    // Only armed repos can heartbeat.
    state::load(&repo)?;
    let loaded = config::load(None, &repo)?;
    let opted_in = loaded
        .config
        .heartbeat
        .sources
        .contains(&HeartbeatSource::AnyCli);
    if !opted_in {
        return Ok(false);
    }
    heartbeat(&repo)?;
    Ok(true)
}

pub fn status(repo_path: &Path) -> Result<()> {
    let repo = canonical_repo(repo_path)?;
    // Repos opting into `any-cli` heartbeats re-arm on every invocation,
    // including this one.
    auto_heartbeat_if_configured(&repo);
    let mut state = state::load(&repo)?;
    let beacon = state.beacon();
    let now = error::unix_now()?;
    let current_round = beacon.round_at(now);
    let unlock_at = error::from_unix(beacon.round_time(state.unlock_round));
    let overdue = now >= beacon.round_time(state.unlock_round);

    println!("ferry-deadman status for {}", repo.display());
    println!(
        "  armed at:             {}",
        error::format_time(error::from_unix(state.armed_unix))
    );
    println!("  mode:                 {}", mode_line(state.mode));
    if state.mode == Mode::Drand {
        println!(
            "  chain:                {}",
            state.chain_hash.as_deref().unwrap_or("-")
        );
        println!(
            "  endpoint:             {}",
            state.beacon_url.as_deref().unwrap_or("-")
        );
    }
    println!("  window:               {}", state.window_display());
    println!(
        "  extras:               {} glob(s), conventional secrets {}",
        state.include_globs.len(),
        yes_no(state.include_secrets)
    );
    if let Some(argv) = &state.archive_argv {
        println!("  archiver:             custom ({})", argv.join(" "));
    }
    println!("  successors:           {}", state.successors.len());
    for succ in &state.successors {
        println!(
            "    - {} ({})",
            display_name(succ),
            fingerprint::short(&succ.fingerprint)
        );
    }
    println!(
        "  last heartbeat:       {} ({}) ago",
        error::format_time(error::from_unix(state.last_heartbeat_unix)),
        human_age(now - state.last_heartbeat_unix)
    );
    println!(
        "  next unlock:          round {} at {}",
        state.unlock_round,
        error::format_time(unlock_at)
    );
    if overdue {
        println!(
            "  state:                UNLOCKED — silence past window, archives are decryptable"
        );
    } else {
        let remaining = beacon.round_time(state.unlock_round) - now;
        println!(
            "  state:                ARMED — owner alive; re-arm within {}",
            human_age(remaining)
        );
    }
    println!("  current beacon round: {current_round}");
    for succ in &state.successors {
        let p = state::artifact_path(&repo, &State::artifact_name_for(succ));
        match std::fs::metadata(&p) {
            Ok(meta) => println!(
                "  copy for {}: {} ({} bytes)",
                display_name(succ),
                p.display(),
                meta.len()
            ),
            Err(_) => println!(
                "  copy for {}: MISSING (run arm or heartbeat)",
                display_name(succ)
            ),
        }
    }
    if overdue {
        let notify = load_notify(&repo);
        maybe_fire_trigger_hook(&repo, &mut state, &notify)?;
    }
    if state.mode == Mode::Sim {
        println!();
        println!("  !! SIMULATION MODE — not real protection. Re-arm against a real beacon.");
    }
    Ok(())
}

fn human_age(secs: i64) -> String {
    format_window(secs.unsigned_abs())
}

pub fn disarm(repo_path: &Path) -> Result<()> {
    let repo = canonical_repo(repo_path)?;
    // Load first so a disarmed repo reports NotArmed rather than deleting blindly.
    let _state = state::load(&repo)?;
    let dir = state::state_dir(&repo);
    let mut removed = Vec::new();
    collect_files(&dir, &mut removed);
    std::fs::remove_dir_all(&dir)
        .map_err(|e| Error::Other(format!("failed to remove {}: {e}", dir.display())))?;

    let cfg_file = config::config_path(&repo);
    if cfg_file.is_file() {
        std::fs::remove_file(&cfg_file)
            .map_err(|e| Error::Other(format!("failed to remove {}: {e}", cfg_file.display())))?;
        removed.push(cfg_file);
    }

    println!("disarmed {}", repo.display());
    println!("  removed:");
    for f in &removed {
        println!("    {}", f.display());
    }
    println!("  no sealed artifacts remain locally");
    println!("  note: copies already synced to successors still unlock at their recorded rounds");
    Ok(())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}

pub struct TestTriggerArgs {
    pub repo: PathBuf,
    /// Override the wait budget; `None` picks a sensible default per mode.
    pub max_wait: Option<Duration>,
    /// Keep the recovered tree instead of deleting it.
    pub keep: bool,
}

pub fn test_trigger(args: &TestTriggerArgs) -> Result<()> {
    let repo = canonical_repo(&args.repo)?;
    auto_heartbeat_if_configured(&repo);
    let mut state = state::load(&repo)?;

    // Parse every successor's copy up front and cross-check vs state.
    let mut copies: Vec<(SuccessorRecord, artifact::SealedArtifact)> = Vec::new();
    for succ in &state.successors {
        let fname = State::artifact_name_for(succ);
        let raw = artifact::read_file(&state::artifact_path(&repo, &fname))?;
        let parsed =
            artifact::parse_artifact(&raw).map_err(|e| Error::Corrupt(format!("{fname}: {e}")))?;
        if parsed.header.unlock_round != state.unlock_round {
            return Err(Error::Corrupt(format!(
                "{fname} unlock round {} does not match state {}",
                parsed.header.unlock_round, state.unlock_round
            )));
        }
        copies.push((succ.clone(), parsed));
    }

    let beacon = rebuild_beacon(&state)?;
    let max_wait = args.max_wait.unwrap_or(match state.mode {
        Mode::Sim => Duration::from_secs(state.window_secs.saturating_add(SIM_WAIT_SLACK_SECS)),
        Mode::Drand => DRAND_DEFAULT_WAIT,
    });

    println!(
        "test-trigger: waiting for beacon round {} (unlocks {})",
        state.unlock_round,
        error::format_time(error::from_unix(beacon.round_time(state.unlock_round)))
    );
    let signature = beacon.wait_for_signature(state.unlock_round, max_wait)?;
    println!("  signature obtained ({} bytes)", signature.len());

    // Open EVERY copy independently, then prove they decrypt to the same
    // bytes; recovery proceeds from the first copy.
    let mut first_payload: Option<Vec<u8>> = None;
    for (succ, s) in &copies {
        let who = display_name(succ);
        let key = tlock::open_master_key(&s.key_blob, &signature)?;
        let payload = artifact::decrypt_payload(&key, &s.encrypted_payload)?;
        let hash = crate::beacon::hex_digest(&payload);
        if hash != s.header.archive_sha256 || hash != state.archive_sha256 {
            return Err(Error::Corrupt(format!(
                "copy for {who}: decrypted payload hash mismatch"
            )));
        }
        match &first_payload {
            None => first_payload = Some(payload),
            Some(first) => {
                if first != &payload {
                    return Err(Error::Corrupt(format!(
                        "copy for {who} decrypts to different bytes than the first copy"
                    )));
                }
            }
        }
        println!("  copy for {who}: sha256 {hash} MATCH");
    }
    let payload = first_payload.expect("arm guarantees at least one successor");

    let dest = if args.keep {
        std::env::temp_dir().join(format!("ferry-deadman-recovery-{}", std::process::id()))
    } else {
        tempfile::Builder::new()
            .prefix("ferry-deadman-drill-")
            .tempdir_in(std::env::temp_dir())
            .map_err(|e| Error::Other(format!("cannot create recovery dir: {e}")))?
            .keep()
    };
    let report = archive::recover_payload(&payload, &dest)?;

    println!();
    println!("PROOF — decryption path verified end-to-end");
    println!(
        "  unlock round:         {} (signature authentic via beacon)",
        state.unlock_round
    );
    println!("  archive sha256:       {} MATCH", state.archive_sha256);
    match report.kind {
        archive::RecoveryKind::BundleTarGz => {
            let got_bundle = report
                .bundle_sha256
                .clone()
                .expect("bundle kind implies hash");
            if state.bundle_sha256.as_ref() != Some(&got_bundle) {
                return Err(Error::Corrupt(
                    "bundle hash differs from seal-time record".into(),
                ));
            }
            println!("  git bundle sha256:    {got_bundle} MATCH");
            println!("  git bundle verify:    OK");
            println!("  refs recovered:       {}", report.refs.len());
            for r in &report.refs {
                println!("    {r}");
            }
            match &report.clone_head {
                Some(head) => println!("  clone HEAD:           {head} OK"),
                None => println!(
                    "  clone HEAD:           (bundle has no branch to check out; verify passed)"
                ),
            }
        }
        archive::RecoveryKind::PlainTarGz => {
            println!("  tar.gz recovered (no git bundle inside — custom archiver)");
            println!("  files extracted to    {}", dest.display());
        }
        archive::RecoveryKind::Opaque => {
            println!("  opaque payload recovered (custom archiver)");
            println!("  file written to       {}", dest.display());
        }
    }
    if args.keep {
        println!("  recovered tree kept at {}", dest.display());
    } else {
        let _ = std::fs::remove_dir_all(&dest);
        println!("  recovered tree cleaned up (pass --keep to inspect)");
    }

    // A successful drill realizes the trigger event exactly once per cycle.
    let notify = load_notify(&repo);
    maybe_fire_trigger_hook(&repo, &mut state, &notify)?;
    println!("  SUCCESS: your successors will be able to do this after the unlock round.");
    Ok(())
}

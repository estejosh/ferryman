//! Implementations of the five subcommands. All output is plain text on
//! stdout; errors go through [`crate::Error`] so `main` can map exit codes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::archive;
use crate::artifact::{self, ArtifactHeader, write_atomic};
use crate::beacon::Beacon;
use crate::duration::format_window;
use crate::error::{self, Error, Result};
use crate::fingerprint;
use crate::state::{self, Mode, State};
use crate::tlock;

/// Default wait budget for test-trigger against the real network.
const DRAND_DEFAULT_WAIT: Duration = Duration::from_secs(300);
/// Slack added to sim windows when test-trigger waits.
const SIM_WAIT_SLACK_SECS: u64 = 30;

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

fn seal_and_write(
    repo: &Path,
    state: &mut State,
    beacon: &Beacon,
    successor_fp: String,
) -> Result<()> {
    let built = archive::build_archive(repo, state.include_secrets)?;
    let unlock_round = beacon.unlock_round(error::unix_now()?, state.window_secs);
    let (master, key_blob) = tlock::seal_master_key(beacon, unlock_round)?;

    let header = ArtifactHeader {
        format: crate::artifact::FORMAT.into(),
        mode: state.mode,
        beacon_url: state.beacon_url.clone(),
        chain_hash: state.chain_hash.clone(),
        unlock_round,
        period_secs: beacon.period_secs(),
        genesis_unix: beacon.genesis_unix(),
        created_unix: error::unix_now()?,
        successor_fingerprint: successor_fp,
        bundle_sha256: built.bundle_sha256.clone(),
        archive_sha256: built.archive_sha256.clone(),
        head_sha256: built.head_sha256.clone(),
    };
    let bytes = artifact::build_artifact(header, &master, key_blob, &built.tar_gz)?;
    write_atomic(&state::artifact_path(repo), &bytes)?;

    for warning in &built.warnings {
        eprintln!("warning: {warning}");
    }

    state.genesis_unix = beacon.genesis_unix();
    state.period_secs = beacon.period_secs();
    state.unlock_round = unlock_round;
    state.archive_sha256 = built.archive_sha256;
    state.bundle_sha256 = built.bundle_sha256;
    state.head_sha256 = built.head_sha256;
    Ok(())
}

pub struct ArmArgs {
    pub repo: PathBuf,
    pub successor_pub: String,
    pub window: String,
    pub include_secrets: bool,
    pub beacon: Option<String>,
    pub simulate: bool,
}

pub fn arm(args: &ArmArgs) -> Result<()> {
    let repo = canonical_repo(&args.repo)?;
    let window_secs = crate::duration::parse_window(&args.window)?.as_secs();
    let successor_fp = fingerprint::fingerprint_successor(&args.successor_pub)?;
    let now = error::unix_now()?;

    let (mode, beacon) = if args.simulate {
        (Mode::Sim, Beacon::sim(now))
    } else {
        match &args.beacon {
            Some(url) => (
                Mode::Drand,
                Beacon::drand(url, crate::beacon::QUICKNET_CHAIN_HASH)?,
            ),
            None => {
                let (base, info) = Beacon::fetch_default_drand()?;
                (
                    Mode::Drand,
                    Beacon::Drand(crate::beacon::DrandParams {
                        base_url: base,
                        chain_hash: info.hash.to_ascii_lowercase(),
                        info,
                    }),
                )
            }
        }
    };

    let mut state = State {
        version: state::STATE_VERSION,
        mode,
        beacon_url: match &beacon {
            Beacon::Drand(p) => Some(p.base_url.clone()),
            Beacon::Sim(_) => None,
        },
        chain_hash: match &beacon {
            Beacon::Drand(p) => Some(p.chain_hash.clone()),
            Beacon::Sim(_) => None,
        },
        period_secs: beacon.period_secs(),
        genesis_unix: beacon.genesis_unix(),
        armed_unix: now,
        window_secs,
        unlock_round: 0,
        successor_fingerprint: successor_fp.clone(),
        include_secrets: args.include_secrets,
        last_heartbeat_unix: now,
        archive_sha256: String::new(),
        bundle_sha256: String::new(),
        head_sha256: None,
    };

    seal_and_write(&repo, &mut state, &beacon, successor_fp.clone())?;
    state::save(&repo, &state)?;
    state::exclude_from_git_index(&repo);

    let unlock_at = error::from_unix(beacon.round_time(state.unlock_round));
    println!("armed {} (ferry-deadman/v1)", repo.display());
    println!("  mode:                 {}", mode_line(mode));
    println!("  window:               {}", format_window(window_secs));
    if let Mode::Drand = mode {
        println!(
            "  chain:                {}",
            state.chain_hash.as_deref().unwrap_or("-")
        );
        println!(
            "  endpoint:             {}",
            state.beacon_url.as_deref().unwrap_or("-")
        );
    }
    println!("  successor fingerprint {}", successor_fp);
    println!(
        "  unlocks:              round {} at {}",
        state.unlock_round,
        error::format_time(unlock_at)
    );
    println!(
        "  artifact:             {}",
        state::artifact_path(&repo).display()
    );
    if mode == Mode::Sim {
        println!();
        println!(
            "  !! SIMULATION MODE — the timelock is enforced by policy only, NOT cryptography."
        );
        println!("  !! Re-arm without --simulate to seal against the real drand quicknet chain.");
    } else {
        println!();
        println!("  Sync the artifact file to your successor via any channel you trust.");
        println!("  Living? Run `ferry-deadman heartbeat` (or re-arm) to push the deadline out.");
    }
    Ok(())
}

fn mode_line(mode: Mode) -> &'static str {
    match mode {
        Mode::Sim => "simulate (offline fake beacon)",
        Mode::Drand => "drand quicknet (real timelock)",
    }
}

pub fn heartbeat(repo_path: &Path) -> Result<()> {
    let repo = canonical_repo(repo_path)?;
    let mut state = state::load(&repo)?;
    let now = error::unix_now()?;
    let beacon = rebuild_beacon(&state)?;
    let successor_fp = state.successor_fingerprint.clone();
    seal_and_write(&repo, &mut state, &beacon, successor_fp)?;
    state.last_heartbeat_unix = now;
    state::save(&repo, &state)?;

    let unlock_at = error::from_unix(beacon.round_time(state.unlock_round));
    println!("heartbeat accepted");
    println!("  previous unlock round: see prior artifact (replaced)");
    println!(
        "  new unlock round:      {} at {}",
        state.unlock_round,
        error::format_time(unlock_at)
    );
    println!("  old sealed artifact pruned (atomically replaced)");
    Ok(())
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

pub fn status(repo_path: &Path) -> Result<()> {
    let repo = canonical_repo(repo_path)?;
    let state = state::load(&repo)?;
    let beacon = state.beacon();
    let now = error::unix_now()?;
    let current_round = beacon.round_at(now);
    let unlock_at = error::from_unix(beacon.round_time(state.unlock_round));
    let overdue = now >= beacon.round_time(state.unlock_round);
    let art = state::artifact_path(&repo);

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
    println!("  include secrets:      {}", yes_no(state.include_secrets));
    println!(
        "  successor:            {}",
        fingerprint::short(&state.successor_fingerprint)
    );
    println!(
        "  last heartbeat:       {} ({})",
        error::format_time(error::from_unix(state.last_heartbeat_unix)),
        human_age(now - state.last_heartbeat_unix)
    );
    println!(
        "  next unlock:          round {} at {}",
        state.unlock_round,
        error::format_time(unlock_at)
    );
    if overdue {
        println!("  state:                UNLOCKED — silence past window, archive is decryptable");
    } else {
        let remaining = beacon.round_time(state.unlock_round) - now;
        println!(
            "  state:                ARMED — owner alive; re-arm within {}",
            human_age(remaining)
        );
    }
    println!("  current beacon round: {current_round}");
    match std::fs::metadata(&art) {
        Ok(meta) => println!(
            "  artifact:             {} ({} bytes)",
            art.display(),
            meta.len()
        ),
        Err(_) => println!("  artifact:             MISSING (run arm or heartbeat)"),
    }
    if state.mode == Mode::Sim {
        println!();
        println!("  !! SIMULATION MODE — not real protection. Re-arm without --simulate.");
    }
    Ok(())
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
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
    println!("disarmed {}", repo.display());
    println!("  removed {}:", dir.display());
    for f in &removed {
        println!("    {}", f.display());
    }
    println!(
        "  no sealed artifacts remain locally; sync any copies held by channels/successor are unaffected"
    );
    println!("  note: previously synced artifacts still unlock at their recorded rounds");
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
    let state = state::load(&repo)?;
    let art_path = state::artifact_path(&repo);
    let raw = artifact::read_file(&art_path)?;
    let sealed = artifact::parse_artifact(&raw)?;

    // Cross-check header vs state.
    if sealed.header.unlock_round != state.unlock_round {
        return Err(Error::Corrupt(format!(
            "artifact unlock round {} does not match state {}",
            sealed.header.unlock_round, state.unlock_round
        )));
    }

    let beacon = rebuild_beacon(&state)?;
    let max_wait = args.max_wait.unwrap_or(match state.mode {
        Mode::Sim => Duration::from_secs(state.window_secs.saturating_add(SIM_WAIT_SLACK_SECS)),
        Mode::Drand => DRAND_DEFAULT_WAIT,
    });

    println!(
        "test-trigger: waiting for beacon round {} (unlocks {})",
        sealed.header.unlock_round,
        error::format_time(error::from_unix(
            beacon.round_time(sealed.header.unlock_round)
        ))
    );
    let signature = beacon.wait_for_signature(sealed.header.unlock_round, max_wait)?;

    println!("  signature obtained ({} bytes)", signature.len());
    let master = tlock::open_master_key(&sealed.key_blob, &signature)?;
    let tar_gz = artifact::decrypt_payload(&master, &sealed.encrypted_payload)?;

    let got_archive_hash = crate::beacon::hex_digest(&tar_gz);
    if got_archive_hash != sealed.header.archive_sha256 || got_archive_hash != state.archive_sha256
    {
        return Err(Error::Corrupt("decrypted archive hash mismatch".into()));
    }

    let dest = if args.keep {
        std::env::temp_dir().join(format!("ferry-deadman-recovery-{}", std::process::id()))
    } else {
        tempfile::Builder::new()
            .prefix("ferry-deadman-drill-")
            .tempdir_in(std::env::temp_dir())
            .map_err(|e| Error::Other(format!("cannot create recovery dir: {e}")))?
            .keep()
    };
    let report = archive::extract_and_verify(&tar_gz, &dest)?;

    println!();
    println!("PROOF — decryption path verified end-to-end");
    println!("  artifact:             {}", art_path.display());
    println!(
        "  unlock round:         {} (signature authentic via beacon)",
        sealed.header.unlock_round
    );
    println!("  archive sha256:       {} MATCH", got_archive_hash);
    println!("  bundle sha256:        {} MATCH", report.bundle_sha256);
    if report.bundle_sha256 != sealed.header.bundle_sha256 {
        return Err(Error::Corrupt(
            "bundle hash differs from seal-time record".into(),
        ));
    }
    println!("  git bundle verify:    OK");
    println!("  refs recovered:       {}", report.refs.len());
    for r in &report.refs {
        println!("    {r}");
    }
    match &report.clone_head {
        Some(head) => println!("  clone HEAD:           {head} OK"),
        None => {
            println!("  clone HEAD:           (bundle has no branch to check out; verify passed)")
        }
    }
    if !report.refs.iter().any(|r| r.contains("refs/heads/")) {
        // bare bundles with only tags etc. — fine, just note it
        println!("  note:                 no branch refs found in bundle");
    }
    if args.keep {
        println!("  recovered tree kept at {}", dest.display());
    } else {
        let _ = std::fs::remove_dir_all(&dest);
        println!("  recovered tree cleaned up (pass --keep to inspect)");
    }
    println!("  SUCCESS: your successor will be able to do this after the unlock round.");
    Ok(())
}

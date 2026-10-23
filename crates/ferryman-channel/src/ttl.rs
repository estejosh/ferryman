//! Opt-in expiry for small, short-lived files (ADR 0027, section d).
//!
//! A project's master may sign `ttl.json` into the channel. Only then, and only for files
//! under `handins/` and `outbox/`, does anything expire. Everything else in a channel
//! (tasks, messages, orders, results, grants, the roster) can never be matched, whatever
//! a signed file says.
//!
//! ```text
//! { "kind": "ttl", "project": "custodly-deposit", "seq": 1, "days": 14,
//!   "paths": ["handins/", "outbox/"], "at": "...", "signed_by": "beastly", "signature": "..." }
//! ```
//!
//! # How a file expires
//!
//! Nobody sends a deletion: the lane never deletes, and this does not change that. Every
//! machine decides alone, from its own clock. A file is moved into a machine-local
//! `expired/` quarantine (beside the project's other local state, never inside a folder
//! the lane or Syncthing carries) and kept there for [`QUARANTINE_DAYS`] before it is
//! really deleted, so a mistake is recoverable.
//!
//! # What "old" means
//!
//! The lane keeps modification times (a received file is given the sender's), so mtime
//! says how old a file is, but a phone with a wrong clock can claim any age, and a file
//! that arrives with an old mtime must not vanish the moment it lands. So a file expires
//! only when BOTH are at least `days` old: its mtime, and the time this machine first saw
//! it (kept in `ttl-state.json`). A future mtime never expires anything. The earliest a
//! file can go is therefore `days` after it reached this machine, and never sooner than
//! `days` after its mtime. `days` is at least [`MIN_DAYS`].
//!
//! A peer that has not expired a file yet may send it back after this machine did. The
//! state remembers what was expired (path and mtime), so the copy that comes back is
//! expired again on the next pass rather than kept for another `days`.
//!
//! # Syncthing
//!
//! Syncthing propagates a local delete to every peer at once, by the deleting machine's
//! clock, which is exactly what expiry must not do. So a folder Syncthing carries (it has
//! a `.stfolder` marker) is refused: `ttl set` will not write a rule for it and the
//! expiry pass removes nothing there, and `ferry doctor` says so. The quarantine lives
//! outside every carried folder, so no `.stignore` entry is needed for it.
//!
//! # Trust
//!
//! The rule is honoured only if it names this project, is signed by the project's master
//! (the roster key the declaration pins), is not older than the highest `seq` this
//! machine has accepted, and every path in it is `handins` or `outbox` or below. A file
//! that fails any of that is ignored whole, and nothing expires.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature};

/// The least a rule may say. A file is never removed sooner than this after it landed.
pub const MIN_DAYS: u32 = 14;
/// How long an expired file stays in the local quarantine before it is really deleted.
pub const QUARANTINE_DAYS: i64 = 7;
/// The only top-level folders a rule can reach.
pub const ALLOWED: [&str; 2] = ["handins", "outbox"];
/// Remembered expiries (for a copy that comes back) are dropped after this many days.
const TOMBSTONE_DAYS: i64 = 30;
const FILE: &str = "ttl.json";
const STATE_FILE: &str = "ttl-state.json";
const STAMP: &str = "%Y%m%dT%H%M%SZ";
const MAX_DEPTH: usize = 32;
const MAX_RULE_BYTES: u64 = 16 * 1024;

/// The signed rule file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ttl {
    pub kind: String,
    pub project: String,
    /// Rises with every change; a lower number than one already accepted is ignored.
    pub seq: u64,
    /// True for the signed "no expiry any more" a `clear` writes. A rule file is never
    /// deleted, because the lane never carries a delete.
    #[serde(default)]
    pub cleared: bool,
    pub days: u32,
    /// Each is `handins` or `outbox`, or a path below one, without a trailing slash.
    pub paths: Vec<String>,
    pub at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn payload(ttl: &Ttl) -> String {
    format!(
        "ferryman-ttl-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        ttl.project,
        ttl.seq,
        ttl.cleared,
        ttl.days,
        ttl.paths.join(","),
        ttl.at.to_rfc3339()
    )
}

/// What `ttl.json` amounts to on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// No file: nothing ever expires.
    None,
    /// A good rule from the master.
    Active(Ttl),
    /// The master switched expiry off.
    Cleared,
    /// A file is there and is not honoured (the reason). Nothing expires.
    Ignored(String),
}

/// Check one path of a rule and return it in the form it is stored: no trailing slash,
/// first component `handins` or `outbox`, and no way out of that folder.
pub fn normalise_path(raw: &str) -> Result<String> {
    let text = raw.trim();
    if text.is_empty() {
        bail!("an empty path");
    }
    if text.starts_with('/')
        || text.contains('\\')
        || text.contains(':')
        || text.chars().any(char::is_control)
    {
        bail!("'{raw}' is not a plain relative path");
    }
    let parts: Vec<&str> = text.trim_end_matches('/').split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        bail!("'{raw}' has an empty, '.' or '..' part");
    }
    if !ALLOWED.contains(&parts[0]) {
        bail!("'{raw}' is not under handins/ or outbox/; nothing else can expire");
    }
    Ok(parts.join("/"))
}

fn normalise_all(raw: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for path in raw {
        let path = normalise_path(path)?;
        if !out.contains(&path) {
            out.push(path);
        }
    }
    if out.is_empty() {
        bail!("no paths");
    }
    out.sort();
    Ok(out)
}

fn rule_path(route: &ProjectRoute) -> PathBuf {
    route.communications.join(FILE)
}

/// Where this machine keeps what it knows about expiry: beside the channel, never inside
/// it and never inside the hand-ins folder, so nothing that carries those carries this.
#[must_use]
pub fn state_dir(route: &ProjectRoute) -> PathBuf {
    route.attachment.join("ttl")
}

fn handins_root(route: &ProjectRoute) -> PathBuf {
    crate::ferry::handins_dir_for(&route.communications, &route.project_id)
}

fn outbox_root(route: &ProjectRoute) -> PathBuf {
    route.communications.join("outbox")
}

/// The folder a `handins/...` or `outbox/...` rule path is relative to.
fn share_root(route: &ProjectRoute, share: &str) -> PathBuf {
    if share == "handins" {
        handins_root(route)
    } else {
        outbox_root(route)
    }
}

/// A `.stfolder` marker means Syncthing carries the folder, and would carry a delete.
fn syncthing_marker(route: &ProjectRoute) -> Option<PathBuf> {
    [
        route.communications.clone(),
        handins_root(route),
        outbox_root(route),
    ]
    .into_iter()
    .map(|dir| dir.join(".stfolder"))
    .find(|marker| marker.exists())
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Seen {
    mtime_ms: i64,
    first_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gone {
    mtime_ms: i64,
    first_seen: DateTime<Utc>,
    at: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// The highest rule `seq` this machine has accepted.
    #[serde(default)]
    seen_seq: u64,
    /// Files under a rule: their mtime when last looked at, and when first seen.
    #[serde(default)]
    files: BTreeMap<String, Seen>,
    /// Files expired here lately, so a copy a slow peer sends back goes again at once.
    #[serde(default)]
    expired: BTreeMap<String, Gone>,
}

impl State {
    fn load(dir: &Path) -> Self {
        fs::read(dir.join(STATE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, dir: &Path) -> Result<()> {
        crate::atomic_json(&dir.join(STATE_FILE), self)
    }
}

fn mtime_ms(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Read `ttl.json` and decide whether it counts. Never writes.
#[must_use]
pub fn read(route: &ProjectRoute) -> Rule {
    let path = rule_path(route);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return Rule::None;
    };
    if !meta.is_file() || meta.len() > MAX_RULE_BYTES {
        return Rule::Ignored("ttl.json is not a plain small file".into());
    }
    let Some(ttl) = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Ttl>(&bytes).ok())
    else {
        return Rule::Ignored("ttl.json cannot be read".into());
    };
    if ttl.kind != "ttl" || ttl.project != route.project_id {
        return Rule::Ignored("ttl.json is for another project".into());
    }
    let master = match crate::master::master_agent(route) {
        Ok(Some(master)) => master,
        Ok(None) => return Rule::Ignored("the project has no master to have signed it".into()),
        Err(error) => return Rule::Ignored(format!("the master cannot be read: {error:#}")),
    };
    if !ttl.signed_by.eq_ignore_ascii_case(&master.name)
        || check_signature(
            Some(&ttl.signed_by),
            Some(&ttl.signature),
            &payload(&ttl),
            std::slice::from_ref(&master),
        ) != SignatureCheck::Valid
    {
        return Rule::Ignored(format!(
            "ttl.json is not signed by the project's master ({})",
            master.name
        ));
    }
    let seen = State::load(&state_dir(route)).seen_seq;
    if ttl.seq < seen {
        return Rule::Ignored(format!(
            "ttl.json is older (seq {}) than one already accepted (seq {seen})",
            ttl.seq
        ));
    }
    if ttl.cleared {
        return Rule::Cleared;
    }
    if ttl.days < MIN_DAYS {
        return Rule::Ignored(format!("ttl.json asks for under {MIN_DAYS} days"));
    }
    match normalise_all(&ttl.paths) {
        Ok(clean) if clean == ttl.paths => Rule::Active(ttl),
        Ok(_) => Rule::Ignored("ttl.json paths are not in their plain form".into()),
        Err(error) => Rule::Ignored(format!(
            "ttl.json has a path outside the allowed: {error:#}"
        )),
    }
}

fn master_identity_check(route: &ProjectRoute, who: &AgentIdentity) -> Result<()> {
    let Some(master) = crate::master::read_master(route)? else {
        bail!("this project has no master yet");
    };
    if !master.master.eq_ignore_ascii_case(who.name()) {
        bail!("only the master ({}) may change expiry", master.master);
    }
    Ok(())
}

fn next_seq(route: &ProjectRoute) -> u64 {
    let on_disk = fs::read(rule_path(route))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Ttl>(&bytes).ok())
        .map_or(0, |ttl| ttl.seq);
    on_disk.max(State::load(&state_dir(route)).seen_seq) + 1
}

fn write_signed(route: &ProjectRoute, who: &AgentIdentity, mut ttl: Ttl) -> Result<Ttl> {
    ttl.signature = who.sign_bytes(payload(&ttl).as_bytes());
    crate::atomic_json(&rule_path(route), &ttl)?;
    let dir = state_dir(route);
    let mut state = State::load(&dir);
    state.seen_seq = state.seen_seq.max(ttl.seq);
    fs::create_dir_all(&dir)?;
    state.save(&dir)?;
    Ok(ttl)
}

/// Master only: turn expiry on for `paths` after `days`.
pub fn set(
    route: &ProjectRoute,
    master: &AgentIdentity,
    days: u32,
    paths: &[String],
) -> Result<Ttl> {
    master_identity_check(route, master)?;
    if days < MIN_DAYS {
        bail!("expiry must be at least {MIN_DAYS} days");
    }
    let paths = normalise_all(paths)?;
    if let Some(marker) = syncthing_marker(route) {
        bail!(
            "Syncthing carries a folder of this project ({} exists): it would send every \
             expiry to all machines as a delete, by one machine's clock. Expiry is refused \
             until the project is on the iroh lane alone",
            marker.display()
        );
    }
    write_signed(
        route,
        master,
        Ttl {
            kind: "ttl".into(),
            project: route.project_id.clone(),
            seq: next_seq(route),
            cleared: false,
            days,
            paths,
            at: Utc::now(),
            signed_by: master.name().to_owned(),
            signature: String::new(),
        },
    )
}

/// Master only: switch expiry off. Writes a signed "cleared" rule, because a deletion of
/// `ttl.json` would not travel.
pub fn clear(route: &ProjectRoute, master: &AgentIdentity) -> Result<Ttl> {
    master_identity_check(route, master)?;
    write_signed(
        route,
        master,
        Ttl {
            kind: "ttl".into(),
            project: route.project_id.clone(),
            seq: next_seq(route),
            cleared: true,
            days: 0,
            paths: Vec::new(),
            at: Utc::now(),
            signed_by: master.name().to_owned(),
            signature: String::new(),
        },
    )
}

/// What `ferry channel ttl show` and `ferry doctor` say.
#[derive(Debug, Clone)]
pub struct Summary {
    pub rule: Rule,
    /// Set when Syncthing carries a folder, so nothing expires here.
    pub syncthing: Option<PathBuf>,
    /// Quarantine batches waiting out their [`QUARANTINE_DAYS`].
    pub quarantined: usize,
}

#[must_use]
pub fn summary(route: &ProjectRoute) -> Summary {
    let quarantined = fs::read_dir(state_dir(route).join("expired"))
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);
    Summary {
        rule: read(route),
        syncthing: syncthing_marker(route),
        quarantined,
    }
}

impl Summary {
    /// One line, and whether it is as the master would want.
    #[must_use]
    pub fn line(&self) -> (bool, String) {
        match &self.rule {
            Rule::None => (
                true,
                "no expiry: nothing in this project is ever removed".into(),
            ),
            Rule::Cleared => (true, "expiry was switched off by the master".into()),
            Rule::Ignored(why) => (false, format!("ttl.json ignored, nothing expires: {why}")),
            Rule::Active(ttl) => {
                if let Some(marker) = &self.syncthing {
                    return (
                        false,
                        format!(
                            "ttl.json asks for {} day expiry but Syncthing carries this \
                             project ({} exists), so nothing expires here",
                            ttl.days,
                            marker.display()
                        ),
                    );
                }
                (
                    true,
                    format!(
                        "files under {} expire {} days after they landed here (rule {}); \
                         {} batch(es) in the {QUARANTINE_DAYS}-day quarantine",
                        ttl.paths.join(", "),
                        ttl.days,
                        ttl.seq,
                        self.quarantined
                    ),
                )
            }
        }
    }
}

/// What an expiry pass did, or would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub dry_run: bool,
    /// Why nothing was done, when that is so.
    pub note: Option<String>,
    /// Files moved to quarantine (or that would be), as `handins/...` / `outbox/...`.
    pub expired: Vec<String>,
    /// Files under the rule that are not old enough yet.
    pub waiting: usize,
    /// Quarantine batches deleted for good (or that would be).
    pub purged: Vec<String>,
    /// Symlinks met and left alone.
    pub links_skipped: usize,
}

struct Found {
    rel: String,
    path: PathBuf,
    base: PathBuf,
    mtime_ms: i64,
}

fn real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn collect(
    base: &Path,
    share: &str,
    dir: &Path,
    depth: usize,
    out: &mut Vec<Found>,
    links: &mut usize,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            *links += 1;
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if meta.is_dir() {
            collect(base, share, &path, depth + 1, out, links);
        } else if meta.is_file() {
            // Half-written files from either carrier are not the file yet.
            if name.ends_with(".tmp")
                || name.starts_with(".syncthing.")
                || name.starts_with("~syncthing~")
            {
                continue;
            }
            let Ok(rest) = path.strip_prefix(base) else {
                continue;
            };
            let rel = std::iter::once(share.to_owned())
                .chain(
                    rest.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned()),
                )
                .collect::<Vec<_>>()
                .join("/");
            out.push(Found {
                rel,
                path,
                base: base.to_path_buf(),
                mtime_ms: mtime_ms(&meta),
            });
        }
    }
}

/// Every plain file a rule path reaches. A symlink is never followed, at any level, so a
/// link inside `handins/` cannot lead the pass out of it.
fn gather(route: &ProjectRoute, ttl: &Ttl) -> (Vec<Found>, usize) {
    let mut found = Vec::new();
    let mut links = 0;
    for rule_path in &ttl.paths {
        let mut parts = rule_path.split('/');
        let share = parts.next().unwrap_or_default();
        if !ALLOWED.contains(&share) {
            continue;
        }
        let base = share_root(route, share);
        if !real_dir(&base) {
            continue;
        }
        let mut start = base.clone();
        let mut ok = true;
        for part in parts {
            start.push(part);
            if !real_dir(&start) {
                ok = false;
                break;
            }
        }
        if ok {
            collect(&base, share, &start, 0, &mut found, &mut links);
        }
    }
    found.sort_by(|a, b| a.rel.cmp(&b.rel));
    found.dedup_by(|a, b| a.rel == b.rel);
    (found, links)
}

/// Whether a file is due, by this machine's clock.
#[must_use]
pub fn due(now: DateTime<Utc>, days: u32, mtime_ms: i64, first_seen: DateTime<Utc>) -> bool {
    let limit = Duration::days(i64::from(days));
    let by_mtime = now.timestamp_millis().saturating_sub(mtime_ms) >= limit.num_milliseconds();
    let by_arrival = now - first_seen >= limit;
    by_mtime && by_arrival
}

fn quarantine_move(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to.parent().context("no parent")?)?;
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    // Another volume: copy, then remove the original only once the copy is whole.
    fs::copy(from, to).with_context(|| format!("copy {} to quarantine", from.display()))?;
    fs::remove_file(from)?;
    Ok(())
}

fn purge(dir: &Path, now: DateTime<Utc>, dry_run: bool) -> Vec<String> {
    let root = dir.join("expired");
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut gone = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(stamp) = NaiveDateTime::parse_from_str(&name, STAMP) else {
            continue;
        };
        if now - stamp.and_utc() < Duration::days(QUARANTINE_DAYS) || !real_dir(&entry.path()) {
            continue;
        }
        if dry_run || fs::remove_dir_all(entry.path()).is_ok() {
            gone.push(name);
        }
    }
    gone.sort();
    gone
}

/// One expiry pass for a project: move what is due into quarantine, delete quarantine
/// batches past their seven days. Safe to call often; with no honoured rule it only tidies
/// the quarantine.
pub fn expire(route: &ProjectRoute, now: DateTime<Utc>, dry_run: bool) -> Result<Report> {
    let dir = state_dir(route);
    let mut report = Report {
        dry_run,
        ..Report::default()
    };
    let rule = read(route);
    let Rule::Active(ttl) = rule else {
        report.purged = purge(&dir, now, dry_run);
        report.note = match rule {
            Rule::Ignored(why) => Some(format!("ignored: {why}")),
            Rule::Cleared => Some("expiry is switched off".into()),
            _ => Some("no ttl.json: nothing expires".into()),
        };
        return Ok(report);
    };
    if let Some(marker) = syncthing_marker(route) {
        report.purged = purge(&dir, now, dry_run);
        report.note = Some(format!(
            "refused: Syncthing carries this project ({} exists) and would send the delete \
             to every machine",
            marker.display()
        ));
        return Ok(report);
    }
    for shared in [
        &route.communications,
        &handins_root(route),
        &outbox_root(route),
    ] {
        if dir.starts_with(shared) {
            bail!(
                "the expiry state folder {} is inside {}, which is carried; refusing",
                dir.display(),
                shared.display()
            );
        }
    }

    let mut state = State::load(&dir);
    let (found, links) = gather(route, &ttl);
    report.links_skipped = links;
    let stamp = now.format(STAMP).to_string();
    let mut present = std::collections::BTreeSet::new();

    for file in &found {
        present.insert(file.rel.clone());
        let first_seen = match (state.files.get(&file.rel), state.expired.get(&file.rel)) {
            (Some(seen), _) if seen.mtime_ms == file.mtime_ms => seen.first_seen,
            // The same bytes' mtime as one already expired: a copy sent back.
            (_, Some(gone)) if gone.mtime_ms == file.mtime_ms => gone.first_seen,
            _ => now,
        };
        state.files.insert(
            file.rel.clone(),
            Seen {
                mtime_ms: file.mtime_ms,
                first_seen,
            },
        );
        if !due(now, ttl.days, file.mtime_ms, first_seen) {
            report.waiting += 1;
            continue;
        }
        // The last guard: the file must really be inside the folder the rule named.
        let inside = match (fs::canonicalize(&file.path), fs::canonicalize(&file.base)) {
            (Ok(path), Ok(base)) => path.starts_with(base),
            _ => false,
        };
        if !inside {
            report.waiting += 1;
            continue;
        }
        if !dry_run {
            let target = dir.join("expired").join(&stamp).join(&file.rel);
            quarantine_move(&file.path, &target)?;
            state.expired.insert(
                file.rel.clone(),
                Gone {
                    mtime_ms: file.mtime_ms,
                    first_seen,
                    at: now,
                },
            );
            state.files.remove(&file.rel);
        }
        report.expired.push(file.rel.clone());
    }

    if !dry_run {
        // Forget files that left (consumed, or moved) and old tombstones.
        let in_scope = |rel: &str| {
            ttl.paths
                .iter()
                .any(|p| rel == p || rel.starts_with(&format!("{p}/")))
        };
        state
            .files
            .retain(|rel, _| present.contains(rel) || !in_scope(rel));
        state
            .expired
            .retain(|_, gone| now - gone.at < Duration::days(TOMBSTONE_DAYS));
        state.seen_seq = state.seen_seq.max(ttl.seq);
        fs::create_dir_all(&dir)?;
        state.save(&dir)?;
    }
    report.purged = purge(&dir, now, dry_run);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    struct Fixture {
        _dir: tempfile::TempDir,
        route: ProjectRoute,
        master: AgentIdentity,
        handins: PathBuf,
    }

    fn set_mtime(path: &Path, age_days: i64) {
        let span = std::time::Duration::from_secs(86_400 * age_days.unsigned_abs());
        let when = if age_days >= 0 {
            SystemTime::now() - span
        } else {
            SystemTime::now() + span
        };
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    fn put(path: &Path, age_days: i64) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
        set_mtime(path, age_days);
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let project = dir.path().join("projects").join("demo");
        let channel = project.join("comms");
        fs::create_dir_all(&channel).unwrap();
        let handins = project.join("handins");
        fs::create_dir_all(&handins).unwrap();
        let master = AgentIdentity::from_seed("beastly", [5u8; 32]);
        let comms_root = dir.path().join("elsewhere");
        fs::create_dir_all(&comms_root).unwrap();
        crate::master::claim_if_masterless(&channel, "demo", &comms_root, &master).unwrap();
        let agents = crate::read_agent_roster(&channel).unwrap();
        let attachment = project.join("attachment");
        let route = ProjectRoute {
            project_id: "demo".into(),
            workspace: project.clone(),
            attachment,
            communications: channel,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents,
        };
        Fixture {
            _dir: dir,
            route,
            master,
            handins,
        }
    }

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn a_project_without_ttl_json_expires_nothing() {
        let f = fixture();
        put(&f.handins.join("phone/a.bin"), 400);
        let report = expire(&f.route, Utc::now(), false).unwrap();
        assert!(report.expired.is_empty());
        assert!(f.handins.join("phone/a.bin").exists());
        assert_eq!(read(&f.route), Rule::None);
    }

    #[test]
    fn only_the_master_sets_a_rule_and_it_needs_fourteen_days_and_allowed_paths() {
        let f = fixture();
        let other = AgentIdentity::from_seed("mallory", [9u8; 32]);
        assert!(set(&f.route, &other, 14, &paths(&["handins"])).is_err());
        assert!(set(&f.route, &f.master, 13, &paths(&["handins"])).is_err());
        for bad in [
            "tasks",
            "messages/",
            "../handins",
            "handins/../tasks",
            "handins/..",
            "/etc",
            "handins\\..\\x",
            "C:handins",
            "",
            "handinsx",
            "grants",
            "outbox/./a",
        ] {
            assert!(
                set(&f.route, &f.master, 14, &paths(&[bad])).is_err(),
                "{bad} must be refused"
            );
        }
        let ttl = set(&f.route, &f.master, 14, &paths(&["handins/", "outbox/"])).unwrap();
        assert_eq!(ttl.paths, ["handins", "outbox"]);
        assert_eq!(read(&f.route), Rule::Active(ttl));
    }

    #[test]
    fn old_files_go_to_quarantine_young_ones_and_other_folders_stay() {
        let f = fixture();
        set(&f.route, &f.master, 14, &paths(&["handins", "outbox"])).unwrap();
        put(&f.handins.join("phone/old.bin"), 40);
        put(&f.route.communications.join("outbox/phone/r.json"), 40);
        for outside in [
            "tasks/t-1/order.json",
            "messages/m.json",
            "grants/g.json",
            "agents/a.json",
        ] {
            put(&f.route.communications.join(outside), 400);
        }
        let first_run = Utc::now();
        // The machine has not seen the files for 14 days yet: nothing goes on first sight.
        let none = expire(&f.route, first_run, false).unwrap();
        assert!(none.expired.is_empty(), "{none:?}");
        assert_eq!(none.waiting, 2);
        // A file that lands later is first seen later, whatever its mtime says.
        put(&f.handins.join("phone/new.bin"), 40);
        let later = first_run + Duration::days(15);
        let dry = expire(&f.route, later, true).unwrap();
        assert_eq!(
            dry.expired,
            ["handins/phone/old.bin", "outbox/phone/r.json"]
        );
        assert!(
            f.handins.join("phone/old.bin").exists(),
            "a dry run changes nothing"
        );
        let done = expire(&f.route, later, false).unwrap();
        assert!(done.expired.contains(&"handins/phone/old.bin".to_owned()));
        assert!(done.expired.contains(&"outbox/phone/r.json".to_owned()));
        assert!(!f.handins.join("phone/old.bin").exists());
        assert!(!f.route.communications.join("outbox/phone/r.json").exists());
        for outside in [
            "tasks/t-1/order.json",
            "messages/m.json",
            "grants/g.json",
            "agents/a.json",
        ] {
            assert!(f.route.communications.join(outside).exists(), "{outside}");
        }
        let stamp = later.format(STAMP).to_string();
        assert!(
            state_dir(&f.route)
                .join("expired")
                .join(stamp)
                .join("handins/phone/old.bin")
                .is_file()
        );
    }

    #[test]
    fn a_file_with_an_old_mtime_does_not_vanish_on_arrival_and_a_future_mtime_never_expires() {
        let f = fixture();
        set(&f.route, &f.master, 14, &paths(&["handins"])).unwrap();
        put(&f.handins.join("ancient.bin"), 3000);
        put(&f.handins.join("future.bin"), -400);
        let now = Utc::now();
        assert!(expire(&f.route, now, false).unwrap().expired.is_empty());
        assert!(
            expire(&f.route, now + Duration::days(13), false)
                .unwrap()
                .expired
                .is_empty()
        );
        let report = expire(&f.route, now + Duration::days(15), false).unwrap();
        assert_eq!(report.expired, ["handins/ancient.bin"]);
        assert!(f.handins.join("future.bin").exists());
    }

    #[test]
    fn quarantine_is_kept_seven_days_then_deleted_and_a_returned_copy_goes_again() {
        let f = fixture();
        set(&f.route, &f.master, 14, &paths(&["handins"])).unwrap();
        let file = f.handins.join("a.bin");
        put(&file, 40);
        let t0 = Utc::now();
        expire(&f.route, t0, false).unwrap();
        let t1 = t0 + Duration::days(15);
        assert_eq!(expire(&f.route, t1, false).unwrap().expired.len(), 1);
        let batch = state_dir(&f.route)
            .join("expired")
            .join(t1.format(STAMP).to_string());
        assert!(batch.is_dir());
        // A slow peer sends it back with the same mtime: it goes at once, not in 14 more days.
        put(&file, 40);
        let meta_mtime = mtime_ms(&fs::metadata(&file).unwrap());
        let mut state = State::load(&state_dir(&f.route));
        state.expired.get_mut("handins/a.bin").unwrap().mtime_ms = meta_mtime;
        state.save(&state_dir(&f.route)).unwrap();
        let again = expire(&f.route, t1 + Duration::days(1), false).unwrap();
        assert_eq!(again.expired, ["handins/a.bin"]);
        assert!(batch.is_dir(), "still inside its seven days");
        let later = expire(&f.route, t1 + Duration::days(8), false).unwrap();
        assert!(later.purged.contains(&t1.format(STAMP).to_string()));
        assert!(!batch.exists());
    }

    #[test]
    fn a_forged_unsigned_or_non_master_rule_is_ignored() {
        let f = fixture();
        put(&f.handins.join("a.bin"), 400);
        let write =
            |ttl: &Ttl| fs::write(rule_path(&f.route), serde_json::to_vec(ttl).unwrap()).unwrap();
        let good = set(&f.route, &f.master, 14, &paths(&["handins"])).unwrap();

        // Unsigned.
        let mut unsigned = good.clone();
        unsigned.signature = String::new();
        write(&unsigned);
        assert!(matches!(read(&f.route), Rule::Ignored(_)));

        // Signed by a roster member who is not the master.
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);
        let mut forged = good.clone();
        forged.signed_by = "mallory".into();
        forged.signature = mallory.sign_bytes(payload(&forged).as_bytes());
        write(&forged);
        assert!(matches!(read(&f.route), Rule::Ignored(_)));

        // Claims to be the master but signed with another key.
        let mut impostor = good.clone();
        impostor.signature = mallory.sign_bytes(payload(&impostor).as_bytes());
        write(&impostor);
        assert!(matches!(read(&f.route), Rule::Ignored(_)));

        // Edited after signing (the paths widened, or the days shortened).
        let mut edited = good.clone();
        edited.days = 1;
        write(&edited);
        assert!(matches!(read(&f.route), Rule::Ignored(_)));
        let mut widened = good.clone();
        widened.paths = paths(&["handins", "tasks"]);
        write(&widened);
        assert!(matches!(read(&f.route), Rule::Ignored(_)));

        // Another project's rule copied in.
        let mut other = good.clone();
        other.project = "elsewhere".into();
        write(&other);
        assert!(matches!(read(&f.route), Rule::Ignored(_)));

        for _ in 0..2 {
            let report = expire(&f.route, Utc::now() + Duration::days(60), false).unwrap();
            assert!(report.expired.is_empty());
        }
        assert!(f.handins.join("a.bin").exists());

        // The master's genuine file works, and an older genuine copy cannot replace a newer.
        write(&good);
        assert!(matches!(read(&f.route), Rule::Active(_)));
        let newer = set(&f.route, &f.master, 30, &paths(&["handins"])).unwrap();
        assert!(newer.seq > good.seq);
        write(&good);
        assert!(
            matches!(read(&f.route), Rule::Ignored(_)),
            "a replayed older rule"
        );
    }

    #[test]
    fn a_signed_rule_that_reaches_outside_the_allowed_folders_is_ignored_whole() {
        let f = fixture();
        put(&f.route.communications.join("tasks/old.json"), 400);
        put(&f.handins.join("a.bin"), 400);
        for bad in [
            paths(&["tasks"]),
            paths(&["handins", "../comms"]),
            paths(&["handins/../tasks"]),
            paths(&[]),
        ] {
            let mut ttl = Ttl {
                kind: "ttl".into(),
                project: "demo".into(),
                seq: 50,
                cleared: false,
                days: 14,
                paths: bad,
                at: Utc::now(),
                signed_by: "beastly".into(),
                signature: String::new(),
            };
            ttl.signature = f.master.sign_bytes(payload(&ttl).as_bytes());
            fs::write(rule_path(&f.route), serde_json::to_vec(&ttl).unwrap()).unwrap();
            assert!(matches!(read(&f.route), Rule::Ignored(_)));
            let report = expire(&f.route, Utc::now() + Duration::days(60), false).unwrap();
            assert!(report.expired.is_empty());
        }
        assert!(f.route.communications.join("tasks/old.json").exists());
        assert!(f.handins.join("a.bin").exists());
    }

    #[test]
    fn clearing_switches_expiry_off_with_a_signed_file() {
        let f = fixture();
        put(&f.handins.join("a.bin"), 400);
        set(&f.route, &f.master, 14, &paths(&["handins"])).unwrap();
        clear(&f.route, &f.master).unwrap();
        assert_eq!(read(&f.route), Rule::Cleared);
        let report = expire(&f.route, Utc::now() + Duration::days(60), false).unwrap();
        assert!(report.expired.is_empty());
        assert!(f.handins.join("a.bin").exists());
    }

    #[test]
    fn a_syncthing_carried_project_is_refused() {
        let f = fixture();
        put(&f.handins.join("a.bin"), 400);
        set(&f.route, &f.master, 14, &paths(&["handins"])).unwrap();
        fs::create_dir_all(f.route.communications.join(".stfolder")).unwrap();
        let (ok, line) = summary(&f.route).line();
        assert!(!ok, "{line}");
        let report = expire(&f.route, Utc::now() + Duration::days(60), false).unwrap();
        assert!(report.expired.is_empty());
        assert!(report.note.unwrap().contains("Syncthing"));
        assert!(set(&f.route, &f.master, 14, &paths(&["handins"])).is_err());
        assert!(f.handins.join("a.bin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed_out_of_the_folder() {
        use std::os::unix::fs::symlink;
        let f = fixture();
        set(&f.route, &f.master, 14, &paths(&["handins", "outbox"])).unwrap();
        let secret = f.route.communications.join("tasks");
        put(&secret.join("keep.json"), 400);
        let outside = f._dir.path().join("outside");
        put(&outside.join("keep.txt"), 400);
        // A folder link, a file link, and a link as the whole outbox.
        symlink(&secret, f.handins.join("to-tasks")).unwrap();
        symlink(&outside, f.handins.join("to-outside")).unwrap();
        symlink(outside.join("keep.txt"), f.handins.join("file-link")).unwrap();
        symlink(&outside, f.route.communications.join("outbox")).unwrap();
        let now = Utc::now();
        expire(&f.route, now, false).unwrap();
        let report = expire(&f.route, now + Duration::days(30), false).unwrap();
        assert!(report.expired.is_empty(), "{report:?}");
        assert!(secret.join("keep.json").exists());
        assert!(outside.join("keep.txt").exists());
        assert!(fs::symlink_metadata(f.handins.join("file-link")).is_ok());
        assert!(report.links_skipped >= 3);
    }

    #[test]
    fn traversal_in_a_path_name_cannot_reach_beyond_the_folder() {
        // `..` cannot be written into a rule or survive reading one (tested above); here
        // the walk itself stays inside the folder it was given, whatever the names are.
        let f = fixture();
        set(&f.route, &f.master, 14, &paths(&["handins/phone"])).unwrap();
        put(&f.handins.join("phone/a.bin"), 40);
        put(&f.handins.join("other/b.bin"), 40);
        put(&f.handins.join("a.bin"), 40);
        let now = Utc::now();
        expire(&f.route, now, false).unwrap();
        let report = expire(&f.route, now + Duration::days(20), false).unwrap();
        assert_eq!(report.expired, ["handins/phone/a.bin"]);
        assert!(f.handins.join("other/b.bin").exists());
        assert!(f.handins.join("a.bin").exists());
    }

    #[test]
    fn due_needs_both_the_mtime_and_the_arrival_to_be_old_enough() {
        let now = Utc::now();
        let old = (now - Duration::days(20)).timestamp_millis();
        assert!(due(now, 14, old, now - Duration::days(20)));
        assert!(!due(now, 14, old, now - Duration::days(1)));
        assert!(!due(
            now,
            14,
            (now - Duration::days(1)).timestamp_millis(),
            now - Duration::days(20)
        ));
        assert!(!due(
            now,
            14,
            (now + Duration::days(5)).timestamp_millis(),
            now - Duration::days(20)
        ));
    }
}

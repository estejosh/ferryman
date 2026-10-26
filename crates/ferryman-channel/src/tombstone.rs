//! Signed tombstones: how a channel deletes a file and every peer honours it.
//!
//! A tombstone is an ordinary channel file under `tombstones/<blake3 hex of the path>.json`.
//! It travels over the lane and over Syncthing like any other file, under the same
//! receive-side access rules, so deleting or compacting on one machine removes the file on
//! every peer and a stale peer can never bring it back.
//!
//! Only the author of the deleted file, the project's master, or the head may sign one;
//! anything else is ignored. The manifest never offers, wants or accepts content a
//! honoured tombstone covers, and each round, after files arrive, a covered file is removed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, canonical_agent_name};

/// The folder a channel keeps its tombstones in.
pub const DIR: &str = "tombstones";

/// Days a honoured tombstone is kept before compaction drops it, when `ferry.toml` sets
/// no `[iroh] tombstone_days`.
pub const DEFAULT_TOMBSTONE_DAYS: u32 = 90;

/// The retention marker compaction writes when it drops tombstones: the oldest deletion it
/// no longer keeps a tombstone for, so a long-offline peer cannot resurrect anything.
const RETENTION_FILE: &str = "archive/retention.json";

/// The largest a tombstone may be: it is one JSON document naming one path.
const MAX_BYTES: u64 = 4096;

/// A signed statement that one path was deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub v: u32,
    pub project: String,
    /// Channel-relative, `/`-separated.
    pub path: String,
    /// BLAKE3 of the version being deleted, or `None`: any version with an mtime no later
    /// than [`Tombstone::deleted_at`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub deleted_at: i64,
    pub signed_by: String,
    pub signature: String,
}

/// Exactly what a tombstone signature covers.
fn payload(tombstone: &Tombstone) -> String {
    format!(
        "ferryman-tombstone-v1\n{}\n{}\n{}\n{}",
        tombstone.project,
        tombstone.path,
        tombstone.content.as_deref().unwrap_or("-"),
        tombstone.deleted_at,
    )
}

/// The channel-relative path a tombstone for `path` lives at.
#[must_use]
pub fn path_for(path: &str) -> String {
    format!("{DIR}/{}.json", blake3::hash(path.as_bytes()).to_hex())
}

fn mtime_ms(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

/// Windows device names, which name a device rather than a file in any directory.
const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// The components of a channel path a tombstone may name, or a refusal.
///
/// The same rules the lane applies to a received file: a plain relative path of ordinary
/// names, no `..`, no root, no drive, no backslash, no Windows device name, so a tombstone
/// can never reach outside the channel.
fn safe_relative(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() || path.len() > 1024 {
        bail!("an empty or overlong path");
    }
    if path.starts_with('/') || path.contains('\\') || path.contains(':') || path.contains('\0') {
        bail!("'{path}' is not a relative channel path");
    }
    let components: Vec<&str> = path.split('/').collect();
    for name in &components {
        let stem = name
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.is_empty()
            || *name == "."
            || *name == ".."
            || name.ends_with('.')
            || name.ends_with(' ')
            || name.chars().any(char::is_control)
            || RESERVED.contains(&stem.as_str())
        {
            bail!("'{path}' has a component that is not an ordinary name");
        }
    }
    Ok(components)
}

/// Where a tombstone may never point: the channel's own bookkeeping and trust files, and
/// anything under the fleet folder. Also refused is a path that is not a plain relative
/// path of ordinary names (see [`safe_relative`]).
#[must_use]
pub fn refused(path: &str, project: &str) -> bool {
    if safe_relative(path).is_err() {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    let first = lower.split('/').next().unwrap_or_default();
    if matches!(
        first,
        "tombstones" | "transports" | "agents" | "grants" | "invites" | "keys" | "local" | "fleet"
    ) || lower == "master.json"
    {
        return true;
    }
    project.eq_ignore_ascii_case(crate::fleethome::PROJECT)
}

/// Resolve a tombstone's path against the channel without following a symlink: every parent
/// must be an ordinary directory and the final component, when present, must not be a link.
fn resolve_path(channel: &Path, path: &str) -> Result<PathBuf> {
    let components = safe_relative(path)?;
    let mut dir = channel.to_path_buf();
    for (index, name) in components.iter().enumerate() {
        dir.push(name);
        let meta = fs::symlink_metadata(&dir);
        if index + 1 == components.len() {
            if let Ok(meta) = meta
                && !meta.is_file()
            {
                bail!("'{path}' is here and is not a plain file");
            }
        } else {
            match meta {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => bail!("'{path}' goes through something that is not a folder"),
                Err(_) => bail!("'{path}' does not exist in this channel"),
            }
        }
    }
    Ok(dir)
}

/// Whether a tombstone covers the version of a file described by `hash` (BLAKE3) and `mtime`
/// (milliseconds): the exact contents it names, or, with no contents, any version at or
/// before `deleted_at`.
#[must_use]
pub fn covered(tombstone: &Tombstone, hash: &str, mtime: i64) -> bool {
    match &tombstone.content {
        Some(content) => content == hash,
        None => mtime <= tombstone.deleted_at,
    }
}

/// Write a tombstone for `path`, signed by `identity`. `content` is the BLAKE3 of the version
/// being deleted, or `None` for any version at or before `deleted_at`.
///
/// # Errors
/// The path is refused, or the tombstone cannot be written.
pub fn write(
    route: &ProjectRoute,
    path: &str,
    content: Option<&str>,
    deleted_at: i64,
    identity: &AgentIdentity,
) -> Result<Tombstone> {
    if refused(path, &route.project_id) {
        bail!(
            "refusing to tombstone '{}': a channel never deletes its own bookkeeping",
            path
        );
    }
    let mut tombstone = Tombstone {
        v: 1,
        project: route.project_id.clone(),
        path: path.to_owned(),
        content: content.map(str::to_owned),
        deleted_at,
        signed_by: identity.name().to_owned(),
        signature: String::new(),
    };
    tombstone.signature = identity.sign_bytes(payload(&tombstone).as_bytes());
    let full = route.communications.join(path_for(path));
    let parent = full.parent().context("a tombstone path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(&tombstone)?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("a tombstone is over {MAX_BYTES} bytes");
    }
    fs::write(&temporary, &bytes)?;
    fs::rename(&temporary, &full)?;
    Ok(tombstone)
}

/// Whether `agent` is the project's master or head, by the same checks the channel readers
/// already apply. The master is read against the roster the caller already holds, so this
/// works for a caller holding only a channel directory and not a fully-formed route.
fn is_master_or_head(route: &ProjectRoute, roster: &[crate::AgentRoute], agent: &str) -> bool {
    if crate::master::read_master_at(&route.communications, roster)
        .ok()
        .flatten()
        .is_some_and(|master| master.master.eq_ignore_ascii_case(agent))
    {
        return true;
    }
    crate::head::current(&route.communications, &route.project_id)
        .ok()
        .flatten()
        .is_some_and(|head| head.agent.eq_ignore_ascii_case(agent))
}

/// The agent that owns a channel-relative `handins/<agent>/...` path, if the path is one.
fn handins_owner(path: &str) -> Option<String> {
    let mut parts = path.split('/');
    if parts.next()?.eq_ignore_ascii_case("handins") {
        parts.next().map(canonical_agent_name)
    } else {
        None
    }
}

/// Every author a tombstone's target names: the `handins/<agent>/` owner (if any) and the
/// file's own author keys and file name, as the receive-side access rules read them.
fn authors_of(route: &ProjectRoute, path: &str) -> Vec<String> {
    let mut authors = Vec::new();
    if let Some(owner) = handins_owner(path) {
        authors.push(owner);
    }
    let bytes = resolve_path(&route.communications, path)
        .ok()
        .and_then(|full| fs::read(full).ok())
        .unwrap_or_default();
    for who in crate::access::file_authors(path, &bytes) {
        let who = canonical_agent_name(&who);
        if !authors.iter().any(|have| have == &who) {
            authors.push(who);
        }
    }
    authors
}

/// Whether a tombstone counts on this channel: signed by the target's author, the master or
/// the head, with a signature that verifies against the roster. A tombstone that would
/// never be honoured (bad path, or a path the channel never deletes) is refused.
fn honoured_one(route: &ProjectRoute, tombstone: &Tombstone) -> bool {
    if tombstone.v != 1
        || !tombstone.project.eq_ignore_ascii_case(&route.project_id)
        || refused(&tombstone.path, &route.project_id)
    {
        return false;
    }
    let Ok(roster) = crate::read_agent_roster(&route.communications) else {
        return false;
    };
    if crate::check_signature(
        Some(&tombstone.signed_by),
        Some(&tombstone.signature),
        &payload(tombstone),
        &roster,
    ) != SignatureCheck::Valid
    {
        return false;
    }
    if is_master_or_head(route, &roster, &tombstone.signed_by) {
        return true;
    }
    authors_of(route, &tombstone.path)
        .iter()
        .any(|who| who.eq_ignore_ascii_case(&tombstone.signed_by))
}

/// Every honoured tombstone in a channel, by path. A tombstone whose signature does not
/// verify, whose signer has no authority, or whose target a channel never deletes is ignored.
#[must_use]
pub fn honoured(route: &ProjectRoute) -> Vec<Tombstone> {
    let mut found: Vec<Tombstone> = Vec::new();
    let Ok(entries) = fs::read_dir(route.communications.join(DIR)) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.len() as u64 > MAX_BYTES {
            continue;
        }
        let Ok(tombstone) = serde_json::from_slice::<Tombstone>(&bytes) else {
            continue;
        };
        if honoured_one(route, &tombstone) {
            found.push(tombstone);
        }
    }
    found.sort_by(|a, b| (a.path.as_str(), a.deleted_at).cmp(&(b.path.as_str(), b.deleted_at)));
    found
}

/// The honoured tombstones of a channel, ready for the lane's decisions.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    by_path: BTreeMap<String, Tombstone>,
}

impl Resolved {
    /// Resolve from a channel, honouring only the tombstones that count.
    #[must_use]
    pub fn read(route: &ProjectRoute) -> Self {
        let mut by_path = BTreeMap::new();
        for tombstone in honoured(route) {
            by_path.insert(tombstone.path.clone(), tombstone);
        }
        Self { by_path }
    }

    /// Whether the version of `path` described by `hash` and `mtime` is covered by a
    /// honoured tombstone, and so must neither be offered, wanted nor accepted.
    #[must_use]
    pub fn is_covered(&self, path: &str, hash: &str, mtime: i64) -> bool {
        self.by_path
            .get(path)
            .is_some_and(|tombstone| covered(tombstone, hash, mtime))
    }

    /// Whether the channel holds any honoured tombstone at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

/// Apply the honoured tombstones of a channel: remove, atomically, every file a tombstone
/// covers. A file that has since been rewritten with different contents (or a later mtime
/// under a contents-less tombstone) is a new file and stays.
///
/// Returns the paths removed.
///
/// # Errors
/// A covered file cannot be removed.
pub fn apply(route: &ProjectRoute) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    for tombstone in honoured(route) {
        let full = match resolve_path(&route.communications, &tombstone.path) {
            Ok(full) => full,
            Err(_) => continue,
        };
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let bytes = fs::read(&full).unwrap_or_default();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        if covered(&tombstone, &hash, mtime_ms(&meta)) {
            fs::remove_file(&full)?;
            removed.push(tombstone.path.clone());
        }
    }
    Ok(removed)
}

/// What compaction writes to say how far back the channel's deletions reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    /// The oldest deletion no tombstone is kept for any more, milliseconds since the epoch.
    pub oldest_deleted_at: i64,
    /// When this mark was written, milliseconds since the epoch.
    pub at: i64,
}

/// The channel's retention mark, if compaction has dropped a tombstone.
#[must_use]
pub fn retention_mark(route: &ProjectRoute) -> Option<Retention> {
    let bytes = fs::read(route.communications.join(RETENTION_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Drop the honoured tombstones older than `tombstone_days`, recording the oldest dropped
/// `deleted_at` in the channel so a long-offline peer cannot resurrect what they covered.
/// Returns the mark written, or `None` when nothing was dropped.
///
/// # Errors
/// The retention mark cannot be written.
pub fn drop_expired(route: &ProjectRoute, tombstone_days: u32) -> Result<Option<Retention>> {
    let cutoff = now_ms() - i64::from(tombstone_days) * 86_400_000;
    let mut dropped_at: Option<i64> = None;
    for tombstone in honoured(route) {
        if tombstone.deleted_at < cutoff {
            dropped_at =
                Some(dropped_at.map_or(tombstone.deleted_at, |old| old.min(tombstone.deleted_at)));
            let full = route.communications.join(path_for(&tombstone.path));
            let _ = fs::remove_file(&full);
        }
    }
    let Some(oldest_deleted_at) = dropped_at else {
        return Ok(None);
    };
    let retention = Retention {
        oldest_deleted_at,
        at: now_ms(),
    };
    let full = route.communications.join(RETENTION_FILE);
    let parent = full.parent().context("the retention file has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&temporary, serde_json::to_vec_pretty(&retention)?)?;
    fs::rename(&temporary, &full)?;
    Ok(Some(retention))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    fn fixture() -> (tempfile::TempDir, ProjectRoute) {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("demo");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&communications).unwrap();
        let route = ProjectRoute {
            project_id: "demo".into(),
            workspace,
            attachment,
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: "private".into(),
            agents: Vec::new(),
        };
        (dir, route)
    }

    fn enrol(route: &ProjectRoute, identity: &AgentIdentity) {
        crate::register_agent(
            route,
            &AgentRoute {
                name: identity.name().into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
    }

    #[test]
    fn a_tombstone_round_trips_and_verifies() {
        let (_dir, route) = fixture();
        let fang = AgentIdentity::load_or_create("fang", &route.attachment).unwrap();
        enrol(&route, &fang);
        let file = route.communications.join("claim.fang.json");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"{\"signed_by\":\"fang\"}").unwrap();
        let tombstone = write(&route, "claim.fang.json", None, now_ms(), &fang).unwrap();
        assert_eq!(tombstone.v, 1);
        let honoured = honoured(&route);
        assert_eq!(honoured.len(), 1);
        assert_eq!(honoured[0].path, "claim.fang.json");
    }

    #[test]
    fn the_bookkeeping_paths_are_refused() {
        for path in [
            "agents/fang.json",
            "transports/fang.json",
            "master.json",
            "invites/x.json",
            "grants/x.json",
            "keys/fang.key",
            "tombstones/x.json",
            "fleet/x.json",
            "../outside.json",
        ] {
            assert!(refused(path, "demo"), "{path}");
        }
        assert!(!refused("messages/m-1.json", "demo"));
        assert!(
            refused("messages/m-1.json", "fleet"),
            "fleet channel deletes nothing"
        );
    }

    #[test]
    fn a_tombstone_covers_exactly_what_it_names() {
        let tombstone = Tombstone {
            v: 1,
            project: "demo".into(),
            path: "a.json".into(),
            content: Some("hash1".into()),
            deleted_at: 100,
            signed_by: "fang".into(),
            signature: String::new(),
        };
        assert!(covered(&tombstone, "hash1", 100));
        assert!(!covered(&tombstone, "hash2", 100));
        let tombstone = Tombstone {
            content: None,
            ..tombstone
        };
        assert!(covered(&tombstone, "hash2", 100), "before deleted_at");
        assert!(!covered(&tombstone, "hash2", 101), "a later write wins");
    }

    #[test]
    fn a_non_author_non_master_tombstone_is_ignored_and_the_masters_is_honoured() {
        let (_dir, route) = fixture();
        let fang = AgentIdentity::load_or_create("fang", &route.attachment).unwrap();
        let wisp = AgentIdentity::load_or_create("wisp", &route.attachment).unwrap();
        let master = AgentIdentity::load_or_create("josh", &route.attachment).unwrap();
        for identity in [&fang, &wisp, &master] {
            enrol(&route, identity);
        }
        crate::master::initialize_master(&route, &master, "josh").unwrap();
        let file = route.communications.join("claim.fang.json");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"{\"signed_by\":\"fang\"}").unwrap();

        // wisp is neither the author, the master nor the head: ignored.
        write(&route, "claim.fang.json", None, now_ms(), &wisp).unwrap();
        assert!(honoured(&route).is_empty());

        // The master's word counts.
        write(&route, "claim.fang.json", None, now_ms(), &master).unwrap();
        let honoured = honoured(&route);
        assert_eq!(honoured.len(), 1);
        assert_eq!(honoured[0].signed_by, "josh");
    }

    #[test]
    fn apply_removes_a_covered_file_and_leaves_a_newer_write() {
        let (_dir, route) = fixture();
        let fang = AgentIdentity::load_or_create("fang", &route.attachment).unwrap();
        enrol(&route, &fang);
        let file = route.communications.join("claim.fang.json");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"{\"signed_by\":\"fang\"}").unwrap();
        let hash = blake3::hash(b"{\"signed_by\":\"fang\"}")
            .to_hex()
            .to_string();

        write(&route, "claim.fang.json", Some(&hash), now_ms(), &fang).unwrap();
        assert_eq!(apply(&route).unwrap(), ["claim.fang.json"]);
        assert!(!file.exists());

        // A newer write with different contents is a new file and stays.
        fs::write(&file, b"{\"signed_by\":\"fang\",\"new\":true}").unwrap();
        write(&route, "claim.fang.json", Some(&hash), now_ms(), &fang).unwrap();
        assert!(apply(&route).unwrap().is_empty());
        assert!(file.exists());
    }
}

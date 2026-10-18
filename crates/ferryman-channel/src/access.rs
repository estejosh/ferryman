//! Access levels: Worker, Member, Orchestrator (ADR 0024).
//!
//! A level is a statement the project's master signs about one agent, kept in the channel as
//! `access/<agent>.json`. It is not a setting a machine can flip for itself: a machine that
//! writes a grant for itself, or edits one, produces a file nobody honours, because the
//! signature has to verify against the key the channel knows the master by.
//!
//! ```text
//! Worker        reads the channel, never writes it. Everything it produces goes to its own
//!               subfolder of the project's handins/ folder, which the head reads.
//! Member        reads and writes the channel, works in its own clone, holds only the
//!               project's own .env.
//! Orchestrator  a Member who may also load write credentials from the root's secrets/.
//! ```
//!
//! Default: Member, for every agent that has no grant. The master, and whoever the master has
//! named head, are Orchestrators.
//!
//! # Enforced where it is received
//!
//! A worker that behaves is the easy case. The rule is held by the machines that read, not by
//! the one that writes: [`comms_author_refused`] is what the iroh lane applies to every file
//! that arrives in a channel, and what the channel readers apply to every file they open.
//! A file in a channel that was authored by a worker-level agent is ignored, wherever it
//! came from. A worker's writes count only when they arrive from `handins/<agent>/`, and
//! [`overlay_dirs`] is where the readers look for them.
//!
//! The worker's own machine adds two more locks (its lane does not publish the channel, and
//! under Syncthing its channel folder is receive-only), but those are defence in depth. If
//! the worker lies about them, the receivers still refuse.
//!
//! # Only when there is somewhere else to write
//!
//! A project whose hand-ins folder is inside its channel (layout 1) gives a worker nowhere
//! but the channel to write, so for such a project levels are recorded and shown and nothing
//! is refused. See [`enforced`].
//!
//! # Replay
//!
//! Each grant carries a `seq` the signature covers, and each machine remembers the highest it
//! has accepted for each agent. An older signed grant put back over a newer one (a Worker
//! restored to Member) does not change what that machine does.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ferry::{Entry, Root, same_place};
use crate::{AgentIdentity, ProjectRoute, SignatureCheck, canonical_agent_name, is_safe_component};

/// The folder inside a channel that holds the master's signed grants.
pub const DIR: &str = "access";

/// What an agent may do in a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Worker,
    Member,
    Orchestrator,
}

impl Level {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Member => "member",
            Self::Orchestrator => "orchestrator",
        }
    }

    /// # Errors
    /// Anything but `worker`, `member` or `orchestrator`.
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "worker" => Ok(Self::Worker),
            "member" => Ok(Self::Member),
            "orchestrator" => Ok(Self::Orchestrator),
            other => bail!("'{other}' is not an access level: worker, member or orchestrator"),
        }
    }

    /// Whether this level may write the channel.
    #[must_use]
    pub fn writes_channel(self) -> bool {
        self != Self::Worker
    }

    /// Whether this level may load write credentials from the root's `secrets/`.
    #[must_use]
    pub fn reads_secrets(self) -> bool {
        self == Self::Orchestrator
    }
}

/// The master's signed statement of one agent's level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessGrant {
    pub project_id: String,
    pub agent: String,
    pub level: Level,
    /// One more than the highest the master could see when signing; covered by the signature.
    #[serde(default)]
    pub seq: u64,
    pub granted_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn payload(grant: &AccessGrant) -> String {
    format!(
        "ferryman-access-v1\n{}\n{}\n{}\n{}\n{}",
        grant.project_id,
        grant.agent,
        grant.level.as_str(),
        grant.seq,
        grant.granted_at.to_rfc3339(),
    )
}

fn grant_file(channel: &Path, agent: &str) -> PathBuf {
    channel
        .join(DIR)
        .join(format!("{}.json", canonical_agent_name(agent)))
}

/// What this machine last accepted, per agent, for one channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Memory {
    #[serde(default)]
    agents: BTreeMap<String, AccessGrant>,
}

fn memory_path(channel: &Path, project_id: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let dir = crate::licensing::machine_state_dir()?.join("access");
    let place = fs::canonicalize(channel).unwrap_or_else(|_| channel.to_path_buf());
    let digest = Sha256::digest(place.display().to_string().to_lowercase().as_bytes());
    Some(dir.join(format!(
        "{}-{}.json",
        project_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>(),
        &hex::encode(digest)[..16]
    )))
}

fn read_memory(channel: &Path, project_id: &str) -> Memory {
    memory_path(channel, project_id)
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_memory(channel: &Path, project_id: &str, memory: &Memory) {
    let Some(path) = memory_path(channel, project_id) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = crate::atomic_json(&path, memory);
}

/// The grant in `access/<agent>.json` when it verifies as the project master's. No memory.
fn verified_file(
    project_id: &str,
    file: &Path,
    roster: &[crate::AgentRoute],
    master: &str,
) -> Option<AccessGrant> {
    let grant: AccessGrant = serde_json::from_slice(&fs::read(file).ok()?).ok()?;
    let stem = file.file_stem()?.to_str()?;
    (grant.project_id == project_id
        && canonical_agent_name(&grant.agent) == stem
        && is_safe_component(&grant.agent)
        && grant.signed_by.eq_ignore_ascii_case(master)
        && crate::check_signature(
            Some(&grant.signed_by),
            Some(&grant.signature),
            &payload(&grant),
            roster,
        ) == SignatureCheck::Valid)
        .then_some(grant)
}

/// Every explicit level in the channel that verifies as the master's, by agent (canonical
/// name), after the machine's memory: a file older than one already accepted does not count,
/// and a file that has gone does not take a restriction away.
#[must_use]
pub fn grants(channel: &Path, project_id: &str) -> BTreeMap<String, AccessGrant> {
    let mut memory = read_memory(channel, project_id);
    let before = memory.agents.clone();
    // The common case - no grant was ever signed here - costs one failed directory read, not
    // a roster read and a signature check per file the channel reader looks at.
    if let Ok(entries) = fs::read_dir(channel.join(DIR))
        && let Ok(roster) = crate::read_agent_roster(channel)
        && let Ok(Some(master)) = crate::master::read_master_at(channel, &roster)
        && master.project_id == project_id
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let Some(grant) = verified_file(project_id, &path, &roster, &master.master) else {
                continue;
            };
            let key = canonical_agent_name(&grant.agent);
            let accept = match memory.agents.get(&key) {
                None => true,
                // A different master's hand is a handover, not a rollback.
                Some(held) if !held.signed_by.eq_ignore_ascii_case(&grant.signed_by) => true,
                Some(held) => grant.seq > held.seq,
            };
            if accept {
                memory.agents.insert(key, grant);
            }
        }
    }
    if memory.agents != before {
        write_memory(channel, project_id, &memory);
    }
    memory.agents
}

/// An agent's level in this project.
///
/// The master's explicit grant if there is one; otherwise Orchestrator for the master and
/// for the current head; otherwise Member.
#[must_use]
pub fn level_of(channel: &Path, project_id: &str, agent: &str) -> Level {
    let name = canonical_agent_name(agent);
    if let Ok(roster) = crate::read_agent_roster(channel)
        && let Ok(Some(master)) = crate::master::read_master_at(channel, &roster)
        && canonical_agent_name(&master.master) == name
    {
        return Level::Orchestrator;
    }
    if let Some(grant) = grants(channel, project_id).get(&name) {
        return grant.level;
    }
    if crate::head::current(channel, project_id)
        .ok()
        .flatten()
        .is_some_and(|head| canonical_agent_name(&head.agent) == name)
    {
        return Level::Orchestrator;
    }
    Level::Member
}

/// Every level in the project, for the agents on the roster: explicit, or the default.
#[must_use]
pub fn levels(channel: &Path, project_id: &str) -> BTreeMap<String, Level> {
    let mut out = BTreeMap::new();
    for agent in crate::read_agent_roster(channel).unwrap_or_default() {
        let name = canonical_agent_name(&agent.name);
        let level = level_of(channel, project_id, &name);
        out.insert(name, level);
    }
    out
}

/// The canonical names of the agents that are Worker-level here.
#[must_use]
pub fn worker_agents(channel: &Path, project_id: &str) -> BTreeSet<String> {
    grants(channel, project_id)
        .into_iter()
        .filter(|(_, grant)| grant.level == Level::Worker)
        .map(|(name, _)| name)
        // An explicit Worker grant never outranks the master, who signs it.
        .filter(|name| level_of(channel, project_id, name) == Level::Worker)
        .collect()
}

/// Sign `agent`'s level into the channel. Only the project's master can; the signing key
/// has to be the one the channel knows the master by.
///
/// # Errors
/// The signer is not the master, the agent is not on the roster, the agent is the master
/// (who is not demoted), or the file cannot be written.
pub fn set_level(
    route: &ProjectRoute,
    master: &AgentIdentity,
    agent: &str,
    level: Level,
) -> Result<AccessGrant> {
    let channel = &route.communications;
    if !is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier");
    }
    crate::ferry::require_master(channel, &route.project_id, master, "set access levels")?;
    let name = canonical_agent_name(agent);
    let roster = crate::read_agent_roster(channel)?;
    if !roster
        .iter()
        .any(|member| canonical_agent_name(&member.name) == name)
    {
        bail!(
            "{agent} is not on {}'s roster, so there is nobody to set a level for",
            route.project_id
        );
    }
    if canonical_agent_name(master.name()) == name && level != Level::Orchestrator {
        bail!("the master is always an orchestrator; hand the role over first");
    }
    // Widening is held back with the rest of what a master with a failing anchor may do.
    if level != Level::Worker {
        crate::anchor::refuse_if_paused(route, master.name(), "widen access")?;
    }
    let held = read_memory(channel, &route.project_id)
        .agents
        .get(&name)
        .map_or(0, |grant| grant.seq);
    let on_file = fs::read(grant_file(channel, &name))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AccessGrant>(&bytes).ok())
        .map_or(0, |grant| grant.seq);
    let mut grant = AccessGrant {
        project_id: route.project_id.clone(),
        agent: name.clone(),
        level,
        seq: held.max(on_file) + 1,
        granted_at: Utc::now(),
        signed_by: master.name().to_owned(),
        signature: String::new(),
    };
    grant.signature = master.sign_bytes(payload(&grant).as_bytes());
    fs::create_dir_all(channel.join(DIR))?;
    crate::atomic_json(&grant_file(channel, &name), &grant)?;
    let mut memory = read_memory(channel, &route.project_id);
    memory.agents.insert(name, grant.clone());
    write_memory(channel, &route.project_id, &memory);
    Ok(grant)
}

// ---------------------------------------------------------------------------------------
// Where a worker's writes go, and how a channel is read around them.

/// Whether the project keeps a worker out of its channel: true when its hand-ins folder is
/// somewhere other than inside the channel, because only then does a worker have another
/// place to write.
#[must_use]
pub fn enforced(channel: &Path, project_id: &str) -> bool {
    let handins = crate::ferry::handins_dir_for(channel, project_id);
    !handins.starts_with(channel)
}

/// The Worker-level agents whose files a channel reader refuses to take from the channel.
/// Empty for every project that has no Worker and for a project that does not separate
/// hand-ins (a Worker there has nowhere else to write). Cheap in the common case.
#[must_use]
pub fn refused_authors(channel: &Path, project_id: &str) -> BTreeSet<String> {
    let workers = worker_agents(channel, project_id);
    if workers.is_empty() || !enforced(channel, project_id) {
        return BTreeSet::new();
    }
    workers
}

/// The folder a Worker-level agent's own writes go in (`<handins>/<agent>`), or `None` when
/// the agent writes the channel like everyone else: it is not a Worker, or the project has
/// nowhere else to put what it writes.
#[must_use]
pub fn worker_out_dir(route: &ProjectRoute, agent: &str) -> Option<PathBuf> {
    let channel = &route.communications;
    if !enforced(channel, &route.project_id) {
        return None;
    }
    if level_of(channel, &route.project_id, agent) != Level::Worker {
        return None;
    }
    Some(
        crate::ferry::handins_dir_for(channel, &route.project_id).join(canonical_agent_name(agent)),
    )
}

/// Where `agent` writes the file whose channel-relative path is `relative`: the channel for
/// everyone, `handins/<agent>/` for a Worker.
#[must_use]
pub fn out_path(route: &ProjectRoute, agent: &str, relative: &Path) -> PathBuf {
    match worker_out_dir(route, agent) {
        Some(dir) => dir.join(relative),
        None => route.communications.join(relative),
    }
}

/// The folders where Worker-level agents' signed files are looked for, as if they were in the
/// channel: one `(agent, handins/<agent>)` per Worker that has one. Empty when the project
/// does not separate hand-ins.
#[must_use]
pub fn overlay_dirs(channel: &Path, project_id: &str) -> Vec<(String, PathBuf)> {
    if !enforced(channel, project_id) {
        return Vec::new();
    }
    let handins = crate::ferry::handins_dir_for(channel, project_id);
    worker_agents(channel, project_id)
        .into_iter()
        .map(|agent| {
            let dir = handins.join(&agent);
            (agent, dir)
        })
        .filter(|(_, dir)| dir.is_dir())
        .collect()
}

/// A file name's dot-separated words, lower case, without the extension.
fn words(name: &str) -> Vec<String> {
    let stem = name
        .strip_suffix(".jsonl")
        .or_else(|| name.strip_suffix(".json"))
        .unwrap_or(name);
    stem.split('.').map(str::to_ascii_lowercase).collect()
}

/// Whether the file at `relative` (channel-relative, `/`-separated) is authored by one of the
/// `workers`, and so is not to be accepted from a channel. Returns the worker it names.
///
/// By name: a file called `claim.<w>.json`, `result.<w>.001.json`, `<w>.json`,
/// `ledger.<w>.jsonl` (any word of the file name, outside the folders that are *about* an
/// agent and not by it). And by content when `bytes` are given: a JSON file whose `signed_by`
/// or `sender` is a worker.
#[must_use]
pub fn comms_author_refused(
    relative: &str,
    bytes: Option<&[u8]>,
    workers: &BTreeSet<String>,
) -> Option<String> {
    if workers.is_empty() {
        return None;
    }
    let lower = relative.to_ascii_lowercase();
    let mut parts = lower.split('/');
    let first = parts.next().unwrap_or_default();
    // About an agent, written by someone else: the roster entry, the master's grants and
    // levels, device records.
    let about = matches!(first, "agents" | "grants" | "access" | "devices");
    if !about
        && let Some(name) = lower.rsplit('/').next()
        && let Some(worker) = words(name).iter().find(|word| workers.contains(*word))
    {
        return Some(worker.clone());
    }
    if let Some(bytes) = bytes
        && bytes.len() <= 2 * 1024 * 1024
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
    {
        for key in ["signed_by", "sender", "from"] {
            if let Some(who) = value.get(key).and_then(serde_json::Value::as_str) {
                let who = canonical_agent_name(who);
                if workers.contains(&who) && !about {
                    return Some(who);
                }
            }
        }
    }
    None
}

/// Whether a channel-relative path in a worker's overlay folder is the worker's own: the
/// folder holds only what that worker wrote, so a file named for another agent (a claim in
/// someone else's name) is not accepted from it.
#[must_use]
pub fn overlay_file_is_theirs(agent: &str, file_name: &str) -> bool {
    let agent = canonical_agent_name(agent);
    words(&file_name.to_ascii_lowercase()).contains(&agent)
}

/// Move the files a Worker-level agent wrote into the channel, out of it, into
/// `handins/<agent>/` at the same relative path: the sweep for a worker's machine that
/// predates the grant, or a tool that wrote the channel directly. Nothing is deleted; a file
/// that is already in the overlay is left, and the stray is set aside beside it.
///
/// Returns the paths moved (channel-relative). Does nothing for a project that does not
/// separate hand-ins.
pub fn sweep_worker_writes(route: &ProjectRoute, agent: &str) -> Vec<String> {
    let Some(out) = worker_out_dir(route, agent) else {
        return Vec::new();
    };
    let workers: BTreeSet<String> = std::iter::once(canonical_agent_name(agent)).collect();
    let mut moved = Vec::new();
    let mut pending = vec![(route.communications.clone(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                if name != ".stfolder" && name != ".stversions" && name != "keys" {
                    pending.push((entry.path(), relative));
                }
                continue;
            }
            if !meta.is_file() || comms_author_refused(&relative, None, &workers).is_none() {
                continue;
            }
            let target = out.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = target.parent()
                && fs::create_dir_all(parent).is_err()
            {
                continue;
            }
            if target.exists() {
                continue;
            }
            if fs::rename(entry.path(), &target).is_ok() {
                moved.push(relative);
            }
        }
    }
    moved
}

// ---------------------------------------------------------------------------------------
// Credentials: by path, so it holds for custom placements too.

/// What an agent at a given level may load from disk, judged by the path it asks for.
///
/// Worker and Member: the project's own `.env` and nothing under the root's `secrets/`.
/// Orchestrator: the same, and `secrets/`. No level reads another project's `.env`. The
/// comparison is on resolved paths (symlinks followed, `..` applied), so a link or a custom
/// placement cannot lead a lower level into `secrets/`.
#[derive(Debug, Clone)]
pub struct CredentialScope {
    secrets: PathBuf,
    project_env: PathBuf,
    project_id: String,
    level: Level,
}

/// A path as it really is: symlinks resolved as far as the path exists, the rest applied
/// lexically with `.` and `..` folded.
fn resolve(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = fs::canonicalize(&existing) {
            let mut full = crate::real_path(&real);
            for part in tail.iter().rev() {
                match Path::new(part).components().next() {
                    Some(Component::ParentDir) => {
                        full.pop();
                    }
                    Some(Component::CurDir) | None => {}
                    _ => full.push(part),
                }
            }
            return full;
        }
        match (
            existing.file_name().map(std::ffi::OsString::from),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                existing = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn inside(child: &Path, parent: &Path) -> bool {
    let fold = |p: &Path| {
        let text = p.display().to_string().replace('\\', "/");
        let text = text.trim_end_matches('/').to_owned();
        if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
        }
    };
    let (child, parent) = (fold(child), fold(parent));
    child == parent || child.starts_with(&format!("{parent}/"))
}

fn is_env_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            lower == ".env" || lower.starts_with(".env.") || lower.ends_with(".env")
        })
}

impl CredentialScope {
    #[must_use]
    pub fn new(root: &Root, entry: &Entry, level: Level) -> Self {
        Self {
            secrets: root.secrets(),
            project_env: entry.env_path(root),
            project_id: entry.project_id.clone(),
            level,
        }
    }

    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }

    /// Whether this scope may open `path`, and why not when it may not.
    ///
    /// # Errors
    /// The path is under `secrets/` and the level is below Orchestrator, or it is some other
    /// `.env` than this project's.
    pub fn check(&self, path: &Path) -> Result<()> {
        let real = resolve(path);
        if inside(&real, &resolve(&self.secrets)) && !self.level.reads_secrets() {
            bail!(
                "{} is under secrets/, which holds write credentials; a {} may not read it",
                path.display(),
                self.level.as_str()
            );
        }
        if is_env_file(&real)
            && !inside(&real, &resolve(&self.secrets))
            && !same_place(&real, &resolve(&self.project_env))
        {
            bail!(
                "{} is not {}'s .env ({}); an agent sees only its project's own keys",
                path.display(),
                self.project_id,
                self.project_env.display()
            );
        }
        Ok(())
    }

    /// `KEY=value` lines of an env file, after [`CredentialScope::check`].
    ///
    /// # Errors
    /// The path is out of scope, or unreadable (a missing file is an empty map, not an error).
    pub fn read_env(&self, path: &Path) -> Result<HashMap<String, String>> {
        self.check(path)?;
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HashMap::new());
            }
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        Ok(parse_env(&text))
    }

    /// The project's own `.env`.
    #[must_use]
    pub fn project_env(&self) -> HashMap<String, String> {
        self.read_env(&self.project_env).unwrap_or_default()
    }

    /// Write credentials from the root's `secrets/`: `fleet.env`, then `<project>.env`.
    ///
    /// # Errors
    /// The level is below Orchestrator.
    pub fn write_credentials(&self) -> Result<HashMap<String, String>> {
        if !self.level.reads_secrets() {
            bail!(
                "write credentials are loaded by an orchestrator; this agent is a {}",
                self.level.as_str()
            );
        }
        let mut out = HashMap::new();
        for name in ["fleet.env".to_owned(), format!("{}.env", self.project_id)] {
            let path = self.secrets.join(name);
            // A name that is not a plain file name never reaches here: both are built from
            // a path-safe project id.
            out.extend(self.read_env(&path)?);
        }
        Ok(out)
    }
}

/// The access level of `agent` in the project in `route`, and the credential scope that
/// follows from it, when this machine's ferry root files the project.
#[must_use]
pub fn credential_scope(route: &ProjectRoute, agent: &str) -> Option<CredentialScope> {
    let root =
        crate::ferry::find_root_from(&route.communications).or_else(crate::ferry::find_root)?;
    let entry = root.read().projects.into_iter().find(|entry| {
        entry.project_id == route.project_id && same_place(&entry.channel, &route.communications)
    })?;
    let level = level_of(&route.communications, &route.project_id, agent);
    Some(CredentialScope::new(&root, &entry, level))
}

/// A dotenv file's `KEY=value` lines: comments, blank lines and `export ` ignored, one pair
/// of quotes stripped, the last of a repeated key wins.
#[must_use]
pub fn parse_env(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.contains(char::is_whitespace) {
            continue;
        }
        let mut value = value.trim();
        for quote in ['"', '\''] {
            if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
                value = &value[1..value.len() - 1];
            }
        }
        out.insert(key.to_owned(), value.to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    struct Fixture {
        _dir: tempfile::TempDir,
        root: Root,
        route: ProjectRoute,
        master: AgentIdentity,
        worker: AgentIdentity,
        member: AgentIdentity,
    }

    fn enrol(route: &ProjectRoute, identity: &AgentIdentity, role: &str) {
        crate::register_agent(
            route,
            &AgentRoute {
                name: identity.name().into(),
                role: role.into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = Root::create(&dir.path().join("ferry")).unwrap();
        let channel = root.comms_home("demo");
        fs::create_dir_all(&channel).unwrap();
        fs::create_dir_all(root.path.join("projects/demo/repo/.ferryman")).unwrap();
        let attachment = root.path.join("projects/demo/repo/.ferryman");
        let route = ProjectRoute {
            project_id: "demo".into(),
            workspace: root.path.join("projects/demo/repo"),
            attachment: attachment.clone(),
            communications: channel.clone(),
            shared_remote: "demo-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        root.adopt("demo", &channel, Some(&route.workspace))
            .unwrap();
        let master = AgentIdentity::from_seed("josh", [7u8; 32]);
        let worker = AgentIdentity::from_seed("wisp", [8u8; 32]);
        let member = AgentIdentity::from_seed("fang", [9u8; 32]);
        enrol(&route, &master, "operator");
        enrol(&route, &worker, "worker");
        enrol(&route, &member, "worker");
        let mut route = route;
        route.agents = crate::read_agent_roster(&channel).unwrap();
        crate::master::initialize_master(&route, &master, "josh").unwrap();
        Fixture {
            _dir: dir,
            root,
            route,
            master,
            worker,
            member,
        }
    }

    #[test]
    fn everyone_is_a_member_until_the_master_says_otherwise() {
        let f = fixture();
        let channel = &f.route.communications;
        assert_eq!(level_of(channel, "demo", "fang"), Level::Member);
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Member);
        assert_eq!(level_of(channel, "demo", "josh"), Level::Orchestrator);
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Worker);
        assert_eq!(level_of(channel, "demo", "fang"), Level::Member);
        assert_eq!(
            worker_agents(channel, "demo"),
            BTreeSet::from(["wisp".to_owned()])
        );
        set_level(&f.route, &f.master, "fang", Level::Orchestrator).unwrap();
        assert_eq!(level_of(channel, "demo", "fang"), Level::Orchestrator);
    }

    #[test]
    fn a_grant_must_be_signed_by_the_master() {
        let f = fixture();
        let channel = &f.route.communications;
        // A member cannot set a level, for anyone.
        assert!(set_level(&f.route, &f.member, "wisp", Level::Worker).is_err());
        assert!(set_level(&f.route, &f.worker, "wisp", Level::Orchestrator).is_err());

        // A forged file: a member writes Orchestrator for itself, signed with its own key.
        let mut forged = AccessGrant {
            project_id: "demo".into(),
            agent: "fang".into(),
            level: Level::Orchestrator,
            seq: 1,
            granted_at: Utc::now(),
            signed_by: "fang".into(),
            signature: String::new(),
        };
        forged.signature = f.member.sign_bytes(payload(&forged).as_bytes());
        fs::create_dir_all(channel.join(DIR)).unwrap();
        crate::atomic_json(&grant_file(channel, "fang"), &forged).unwrap();
        assert_eq!(level_of(channel, "demo", "fang"), Level::Member);

        // The same file claiming to be the master's but not signed by the master's key.
        forged.signed_by = "josh".into();
        crate::atomic_json(&grant_file(channel, "fang"), &forged).unwrap();
        assert_eq!(level_of(channel, "demo", "fang"), Level::Member);

        // A genuine grant edited afterwards no longer verifies.
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        let file = grant_file(channel, "wisp");
        let mut edited: AccessGrant = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        edited.level = Level::Orchestrator;
        crate::atomic_json(&file, &edited).unwrap();
        assert_eq!(
            level_of(channel, "demo", "wisp"),
            Level::Worker,
            "the remembered, verified grant stands over an edited file"
        );

        // A grant lifted from another project is not this project's.
        let mut lifted = AccessGrant {
            project_id: "elsewhere".into(),
            agent: "fang".into(),
            level: Level::Worker,
            seq: 9,
            granted_at: Utc::now(),
            signed_by: "josh".into(),
            signature: String::new(),
        };
        lifted.signature = f.master.sign_bytes(payload(&lifted).as_bytes());
        crate::atomic_json(&grant_file(channel, "fang"), &lifted).unwrap();
        assert_eq!(level_of(channel, "demo", "fang"), Level::Member);
    }

    #[test]
    fn an_older_signed_grant_put_back_does_not_restore_access() {
        let f = fixture();
        let channel = &f.route.communications;
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        let old = fs::read(grant_file(channel, "wisp")).unwrap();
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Worker);
        set_level(&f.route, &f.master, "wisp", Level::Member).unwrap();
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Member);
        // Somebody restores the Worker file, or the other way round.
        fs::write(grant_file(channel, "wisp"), &old).unwrap();
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Member);
        // And deleting a restriction does not lift it.
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Worker);
        fs::remove_file(grant_file(channel, "wisp")).unwrap();
        assert_eq!(level_of(channel, "demo", "wisp"), Level::Worker);
    }

    #[test]
    fn the_master_is_not_demoted_and_unknown_agents_get_no_grant() {
        let f = fixture();
        assert!(set_level(&f.route, &f.master, "josh", Level::Worker).is_err());
        assert!(set_level(&f.route, &f.master, "nobody", Level::Worker).is_err());
        assert!(set_level(&f.route, &f.master, "../escape", Level::Worker).is_err());
    }

    #[test]
    fn files_authored_by_a_worker_are_refused_by_name_and_by_content() {
        let workers = BTreeSet::from(["wisp".to_owned()]);
        for refused in [
            "tasks/t-1/claim.wisp.json",
            "tasks/t-1/result.wisp.001.json",
            "tasks/t-1/heartbeat.wisp.json",
            "presence/wisp.json",
            "ledger.wisp.jsonl",
            "transports/wisp.json",
            "trajectories/t-1/wisp.001.json",
        ] {
            assert_eq!(
                comms_author_refused(refused, None, &workers).as_deref(),
                Some("wisp"),
                "{refused}"
            );
        }
        for fine in [
            "tasks/t-1/order.json",
            "tasks/t-1/claim.fang.json",
            "agents/wisp.json",
            "grants/wisp.json",
            "access/wisp.json",
            "messages/wisp/abc.json",
            "presence/fang.json",
        ] {
            assert!(
                comms_author_refused(fine, None, &workers).is_none(),
                "{fine}"
            );
        }
        // By content: a message whose sender is the worker, wherever it was put.
        let message = br#"{"sender":"Wisp","recipient":"fang"}"#;
        assert_eq!(
            comms_author_refused("messages/fang/m1.json", Some(message), &workers).as_deref(),
            Some("wisp")
        );
        let signed = br#"{"signed_by":"wisp"}"#;
        assert!(comms_author_refused("anything/at/all.json", Some(signed), &workers).is_some());
        let about = br#"{"agent":"wisp","signed_by":"josh"}"#;
        assert!(comms_author_refused("tasks/t-1/review.001.json", Some(about), &workers).is_none());
        assert!(
            comms_author_refused("tasks/t-1/claim.wisp.json", None, &BTreeSet::new()).is_none()
        );
    }

    #[test]
    fn a_worker_writes_to_handins_and_a_member_to_the_channel() {
        let f = fixture();
        let channel = f.route.communications.clone();
        let relative = Path::new("tasks/t-1/claim.wisp.json");
        // Before any grant, the default is Member and the channel.
        assert_eq!(out_path(&f.route, "wisp", relative), channel.join(relative));
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        let handins = f.root.path.join("projects/demo/handins");
        assert_eq!(
            out_path(&f.route, "wisp", relative),
            handins.join("wisp").join(relative)
        );
        assert_eq!(
            out_path(&f.route, "fang", Path::new("tasks/t-1/claim.fang.json")),
            channel.join("tasks/t-1/claim.fang.json")
        );
        // Its files are found as if they were in the channel, once there are any.
        assert!(overlay_dirs(&channel, "demo").is_empty());
        fs::create_dir_all(handins.join("wisp")).unwrap();
        let overlay = overlay_dirs(&channel, "demo");
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay[0].0, "wisp");
    }

    fn order(id: &str, issuer: &AgentIdentity) -> crate::Order {
        let mut order = crate::Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: issuer.name().into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: serde_json::json!({"task": "write the report"}),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        issuer.sign_order(&mut order);
        order
    }

    fn result(id: &str, who: &AgentIdentity) -> crate::TaskResult {
        let mut result = crate::TaskResult {
            order_id: id.into(),
            agent: who.name().into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: serde_json::json!({"done": true}),
            signed_by: None,
            signature: None,
        };
        who.sign_result(&mut result);
        result
    }

    #[test]
    fn a_workers_claim_and_result_go_to_its_handins_and_are_read_as_if_in_the_channel() {
        let f = fixture();
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        crate::issue_order(&f.route, &order("t-1", &f.master)).unwrap();
        crate::claim_order(&f.route, "t-1", "wisp").unwrap();
        crate::submit_result(&f.route, &result("t-1", &f.worker)).unwrap();

        let channel = &f.route.communications;
        let mine = f.root.path.join("projects/demo/handins/wisp/tasks/t-1");
        assert!(mine.join("claim.wisp.json").is_file());
        assert!(mine.join("result.wisp.001.json").is_file());
        assert!(
            !channel.join("tasks/t-1/claim.wisp.json").exists()
                && !channel.join("tasks/t-1/result.wisp.001.json").exists(),
            "a Worker never writes the channel"
        );

        let task = crate::read_task(&f.route, "t-1").unwrap();
        assert_eq!(task.claims.len(), 1, "its claim is read from its folder");
        assert_eq!(task.results.len(), 1, "and its signed result");

        // A Member's claim still goes to the channel.
        crate::claim_order(&f.route, "t-1", "fang").unwrap();
        assert!(channel.join("tasks/t-1/claim.fang.json").is_file());
        assert_eq!(crate::read_task(&f.route, "t-1").unwrap().claims.len(), 2);
    }

    #[test]
    fn a_reader_refuses_comms_files_a_worker_authored_even_when_validly_signed() {
        let f = fixture();
        crate::issue_order(&f.route, &order("t-1", &f.master)).unwrap();
        // While wisp is still a Member, its channel files count.
        crate::claim_order(&f.route, "t-1", "wisp").unwrap();
        crate::submit_result(&f.route, &result("t-1", &f.worker)).unwrap();
        let before = crate::read_task(&f.route, "t-1").unwrap();
        assert_eq!((before.claims.len(), before.results.len()), (1, 1));

        // The master makes wisp a Worker. The same files, still in the channel (a synced
        // copy, a hand copy, a tool that ignored the rule), are no longer taken.
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        let after = crate::read_task(&f.route, "t-1").unwrap();
        assert!(
            after.claims.is_empty(),
            "a Worker's claim in comms is refused"
        );
        assert!(
            after.results.is_empty(),
            "so is its result, though the signature is genuine"
        );

        // Sweeping them into its folder is how a machine that predates the grant catches up;
        // from there they are read again, as the Worker's own.
        assert_eq!(sweep_worker_writes(&f.route, "wisp").len(), 2);
        let swept = crate::read_task(&f.route, "t-1").unwrap();
        assert_eq!((swept.claims.len(), swept.results.len()), (1, 1));

        // Its folder holds only its own: a claim in someone else's name is not accepted.
        let folder = f.root.path.join("projects/demo/handins/wisp/tasks/t-1");
        fs::write(
            folder.join("claim.fang.json"),
            serde_json::to_vec(&crate::Claim {
                order_id: "t-1".into(),
                agent: "fang".into(),
                claimed_at: Utc::now(),
            })
            .unwrap(),
        )
        .unwrap();
        let task = crate::read_task(&f.route, "t-1").unwrap();
        assert!(
            task.claims.iter().all(|claim| claim.agent == "wisp"),
            "{:?}",
            task.claims
        );
    }

    #[test]
    fn a_workers_transport_record_is_honoured_from_its_folder_only() {
        let f = fixture();
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        let endpoint = "ab".repeat(32);
        assert!(crate::transports::publish(&f.route, &f.worker, &endpoint, None).unwrap());
        assert!(
            f.root
                .path
                .join("projects/demo/handins/wisp/transports/wisp.json")
                .is_file()
        );
        assert!(!f.route.communications.join("transports/wisp.json").exists());
        let records = crate::transports::honoured_records(&f.route);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].agent, "wisp");

        // Put the same record in the channel instead and take the folder copy away: refused.
        let copy = f.route.communications.join("transports");
        fs::create_dir_all(&copy).unwrap();
        fs::copy(
            f.root
                .path
                .join("projects/demo/handins/wisp/transports/wisp.json"),
            copy.join("wisp.json"),
        )
        .unwrap();
        fs::remove_dir_all(f.root.path.join("projects/demo/handins/wisp")).unwrap();
        assert!(crate::transports::honoured_records(&f.route).is_empty());
    }

    #[test]
    fn a_layout_one_project_records_levels_and_refuses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let channel = dir.path().join("comms").join("old-ferryman");
        fs::create_dir_all(&channel).unwrap();
        assert!(!enforced(&channel, "old"));
        assert!(overlay_dirs(&channel, "old").is_empty());
    }

    #[test]
    fn sweeping_moves_a_workers_channel_files_beside_its_handins() {
        let f = fixture();
        set_level(&f.route, &f.master, "wisp", Level::Worker).unwrap();
        let channel = f.route.communications.clone();
        fs::create_dir_all(channel.join("tasks/t-1")).unwrap();
        fs::write(channel.join("tasks/t-1/claim.wisp.json"), "{}").unwrap();
        fs::write(channel.join("tasks/t-1/order.json"), "{}").unwrap();
        let moved = sweep_worker_writes(&f.route, "wisp");
        assert_eq!(moved, ["tasks/t-1/claim.wisp.json"]);
        assert!(!channel.join("tasks/t-1/claim.wisp.json").exists());
        assert!(channel.join("tasks/t-1/order.json").is_file());
        assert!(
            f.root
                .path
                .join("projects/demo/handins/wisp/tasks/t-1/claim.wisp.json")
                .is_file()
        );
        // A Member's files stay where they are.
        fs::write(channel.join("tasks/t-1/claim.fang.json"), "{}").unwrap();
        assert!(sweep_worker_writes(&f.route, "fang").is_empty());
    }

    #[test]
    fn a_worker_or_member_cannot_reach_secrets_by_any_path() {
        let f = fixture();
        let entry = f.root.read().projects.remove(0);
        fs::write(f.root.secrets().join("fleet.env"), "GH_RW_X=write\n").unwrap();
        fs::write(f.root.secrets().join("demo.env"), "GH_RW_DEMO=write2\n").unwrap();
        fs::write(f.root.project_env("demo"), "GH_RO=read\n").unwrap();
        for level in [Level::Worker, Level::Member] {
            let scope = CredentialScope::new(&f.root, &entry, level);
            assert_eq!(
                scope.project_env().get("GH_RO").map(String::as_str),
                Some("read")
            );
            assert!(scope.write_credentials().is_err());
            for sneaky in [
                f.root.secrets().join("fleet.env"),
                f.root.secrets().join("demo.env"),
                f.root.secrets().join("nothing-yet"),
                f.root.path.join("projects/demo/../../secrets/fleet.env"),
                f.root.path.join("secrets/./fleet.env"),
                f.root
                    .path
                    .join("projects/demo/comms/../../../secrets/demo.env"),
            ] {
                assert!(
                    scope.read_env(&sneaky).is_err(),
                    "{level:?} read {}",
                    sneaky.display()
                );
            }
        }
        let boss = CredentialScope::new(&f.root, &entry, Level::Orchestrator);
        let loaded = boss.write_credentials().unwrap();
        assert_eq!(loaded.get("GH_RW_X").map(String::as_str), Some("write"));
        assert_eq!(loaded.get("GH_RW_DEMO").map(String::as_str), Some("write2"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_secrets_does_not_get_a_member_in() {
        let f = fixture();
        let entry = f.root.read().projects.remove(0);
        fs::write(f.root.secrets().join("fleet.env"), "K=v\n").unwrap();
        let link = f.root.path.join("projects/demo/innocent");
        std::os::unix::fs::symlink(f.root.secrets(), &link).unwrap();
        let scope = CredentialScope::new(&f.root, &entry, Level::Member);
        assert!(scope.read_env(&link.join("fleet.env")).is_err());
    }

    #[test]
    fn a_custom_env_is_the_projects_and_another_projects_env_is_not() {
        let f = fixture();
        let elsewhere = f._dir.path().join("my-keys").join("demo.env");
        fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        fs::write(&elsewhere, "ONLY=mine\n").unwrap();
        f.root
            .update_entry("demo", |entry| entry.env = Some(elsewhere.clone()))
            .unwrap();
        let entry = f.root.read().projects.remove(0);
        let scope = CredentialScope::new(&f.root, &entry, Level::Member);
        assert_eq!(
            scope.project_env().get("ONLY").map(String::as_str),
            Some("mine")
        );
        let other = f.root.project_dir("other").join(".env");
        fs::create_dir_all(other.parent().unwrap()).unwrap();
        fs::write(&other, "X=1\n").unwrap();
        assert!(scope.read_env(&other).is_err());
        // A custom env that is put inside secrets/ is still secrets/.
        let inside_secrets = f.root.secrets().join("sneaky.env");
        fs::write(&inside_secrets, "S=1\n").unwrap();
        f.root
            .update_entry("demo", |entry| entry.env = Some(inside_secrets.clone()))
            .unwrap();
        let entry = f.root.read().projects.remove(0);
        let scope = CredentialScope::new(&f.root, &entry, Level::Worker);
        assert!(scope.project_env().is_empty());
        assert!(scope.read_env(&inside_secrets).is_err());
    }

    #[test]
    fn env_files_parse_like_dotenv() {
        let parsed = parse_env("# c\nA=1\nexport B=\"two\"\n\nC='3'\nA=4\nnot a pair\n");
        assert_eq!(parsed.get("A").map(String::as_str), Some("4"));
        assert_eq!(parsed.get("B").map(String::as_str), Some("two"));
        assert_eq!(parsed.get("C").map(String::as_str), Some("3"));
        assert_eq!(parsed.len(), 3);
    }
}

//! New projects reach every machine of the fleet, without anyone typing anything (ADR 0030).
//!
//! # What was missing
//!
//! A project enabled on one machine existed on that machine. Nothing filed it on another, the
//! iroh lane only exchanges projects both sides already serve, and first contact needs the
//! peer's worker on the channel's roster on BOTH sides. So every new project was a hand-made
//! channel, a hand-made clone and a hand-made roster entry per machine.
//!
//! # The chain of trust
//!
//! Everything here is read from the fleet folder (`ferryman_channel::fleethome`), where a
//! file counts only if it is signed by the fleet's master or by a machine the master admitted
//! (`ferry fleet admit`). The chain is: the master admitted a machine; the machine signs its
//! own directory entries and its own record; the record names the machine's all-projects
//! worker (a name and a PUBLIC key); so a peer may put that worker on a roster. A machine the
//! master has not admitted is ignored, and so is a project whose master is not the fleet's.
//!
//! # The four halves
//!
//! - [`adverts`]: what a machine adds to its directory entries so others can take a project
//!   up (where the clone came from, who masters it). A remote with a credential in it is
//!   never published ([`publishable_remote`]).
//! - [`make_room`]: for each project this machine serves, the roster gets the OTHER machines'
//!   workers, so the lane will talk to them. First key wins; a different key is a finding,
//!   never an overwrite.
//! - [`receive`]: a project another machine advertised, that this one does not file, is
//!   filed here as a channel with this worker (and the advertiser's) on its roster.
//! - [`sync_arrivals`]: a filed project with no checkout is cloned and attached (`repos
//!   sync`), at most a few per pass, each git command on a clock.
//!
//! # What never happens
//!
//! A key is never copied between machines (only public keys travel, in signed records), never
//! put in a channel, and never made for a name the roster already knows. A roster entry that
//! holds a different key is left as it is.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ferryman_channel::ferry::{self, Entry, Placement, Root};
use ferryman_channel::fleethome::{self as home, Advert, Trust, WorkerId};
use ferryman_channel::{AgentIdentity, AgentRoute, canonical_agent_name, is_safe_component};
use serde::{Deserialize, Serialize};

use crate::repos;
use crate::rootconfig::{self, RootConfig};

/// Something a pass did or refused, for the worker's log. `key` is what makes it the same
/// event next pass, so a caller says each once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub key: String,
    pub warn: bool,
    pub line: String,
}

impl Event {
    fn info(key: impl Into<String>, line: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            warn: false,
            line: line.into(),
        }
    }

    fn warn(key: impl Into<String>, line: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            warn: true,
            line: line.into(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// This machine's own part of the fleet folder (never synced)

const WORKER_FILE: &str = "worker.json";
const ARRIVED_FILE: &str = "arrived.json";

fn write_json(path: &std::path::Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("write {}", path.display()))
}

/// Remember which worker this machine runs, so every publish of the machine record names it,
/// not only the worker's own. Public half only; nothing private is written. A root with no
/// fleet folder remembers nothing (the worker tells the next pass).
pub fn remember_worker(root: &Root, worker: &AgentIdentity) {
    if !home::exists(root) {
        return;
    }
    let id = WorkerId {
        name: worker.name().to_owned(),
        public_key: worker.public_key_hex(),
    };
    if own_worker(root).as_ref() != Some(&id) {
        let _ = write_json(&root.fleet_local().join(WORKER_FILE), &id);
    }
}

/// The worker this machine runs, as last remembered.
#[must_use]
pub fn own_worker(root: &Root) -> Option<WorkerId> {
    let text = fs::read_to_string(root.fleet_local().join(WORKER_FILE)).ok()?;
    serde_json::from_str::<WorkerId>(&text)
        .ok()
        .filter(WorkerId::is_well_formed)
}

/// A project that arrived from another machine: who advertised it and where it can be cloned
/// from. Kept in the fleet folder's machine-local part, so it is never synced and never in
/// the person's `ferry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Arrived {
    from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    git_remote: Option<String>,
    at: DateTime<Utc>,
}

fn read_arrivals(root: &Root) -> BTreeMap<String, Arrived> {
    fs::read_to_string(root.fleet_local().join(ARRIVED_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// The remote another machine advertised for `project` when it arrived here, if it passes the
/// same checks a remote in `ferry.toml` does. A candidate for `repos sync`, after the
/// machine's own way of forming a remote.
#[must_use]
pub fn arrival_remote(root: &Root, project: &str) -> Option<String> {
    read_arrivals(root)
        .remove(project)?
        .git_remote
        .filter(|remote| usable_remote(remote))
}

fn usable_remote(remote: &str) -> bool {
    rootconfig::check_remote(remote).is_ok() && home::remote_is_clean(remote)
}

// ---------------------------------------------------------------------------------------
// A. Advertise

/// `origin`, as it may be written into a signed file other machines read: any credential
/// taken out, checked by the rules every remote must pass ([`rootconfig::check_remote`]), and
/// nothing with a user name or password left in a `scheme://` address. A remote only this
/// machine can reach (a path, `file://`) is not one to advertise. `None` means do not.
#[must_use]
pub fn publishable_remote(origin: &str) -> Option<String> {
    let stripped = rootconfig::without_credentials(origin.trim());
    if !usable_remote(&stripped) {
        return None;
    }
    let lower = stripped.to_ascii_lowercase();
    let bytes = stripped.as_bytes();
    let local = lower.starts_with("file:")
        || stripped.starts_with(['/', '.', '~', '\\'])
        || (bytes.len() > 1 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && {
            // `C:\repo` and `C:/repo` are drives; `host:path` (scp-like) has more than one letter.
            bytes.len() == 2 || matches!(bytes[2], b'\\' | b'/')
        });
    (!local).then_some(stripped)
}

/// What this machine adds to each directory entry it publishes: the `origin` of the project's
/// managed clone (else of its filed checkout) and the project's verified master. A project
/// its master took out of the swarm (`swarm = off`) adds nothing, so no other machine takes
/// it up. Keyed by project id.
#[must_use]
pub fn adverts(root: &Root) -> BTreeMap<String, Advert> {
    let mut out = BTreeMap::new();
    for entry in root.read().projects {
        if !is_safe_component(&entry.project_id) {
            continue;
        }
        let here = entry.channel.is_dir();
        if here && entry.swarm_off() {
            continue;
        }
        let master = if here {
            ferry::master_of(&entry.channel)
                .ok()
                .flatten()
                .map(|master| canonical_agent_name(&master))
        } else {
            None
        };
        let clone = entry.managed_clone_path(root);
        let git_remote = repos::origin_of(&clone)
            .or_else(|| entry.repo.as_deref().and_then(repos::origin_of))
            .and_then(|origin| publishable_remote(&origin));
        out.insert(entry.project_id, Advert { git_remote, master });
    }
    out
}

// ---------------------------------------------------------------------------------------
// B. Make room for peers' workers

/// Put every OTHER admitted machine's worker on the roster of each project this machine
/// serves (live, in the swarm, mastered by the fleet's master), unless that machine keeps the
/// project out of its swarm. Worker role: a worker needs no grant, and every access level
/// reads as before. First key wins; a name that already holds a different key is a finding.
///
/// Returns what it wrote or refused.
#[must_use]
pub fn make_room(root: &Root, machine: &str) -> Vec<Event> {
    let mut events = Vec::new();
    if !home::exists(root) {
        return events;
    }
    let trust = Trust::load(&root.fleet_dir());
    let Some(fleet_master) = trust.master().map(str::to_owned) else {
        return events;
    };
    // A machine record counts only if the master or the machine's own admitted identity
    // signed it; `read_machines` has already dropped the rest.
    let (machines, _) = home::read_machines(root);
    let peers: Vec<_> = machines
        .iter()
        .filter(|row| !row.body.machine.eq_ignore_ascii_case(machine))
        .filter_map(|row| row.body.worker.as_ref().map(|worker| (row, worker)))
        .collect();
    if peers.is_empty() {
        return events;
    }
    let config = RootConfig::load(root);
    for entry in root.projects() {
        let id = entry.project_id.clone();
        if !is_safe_component(&id) || config.excluded(&id) || entry.swarm_off() {
            continue;
        }
        match ferry::master_of(&entry.channel) {
            Ok(Some(master)) if canonical_agent_name(&master) == fleet_master => {}
            _ => continue,
        }
        let Ok((route, _)) = Entry {
            repo: None,
            ..entry.clone()
        }
        .route(root) else {
            continue;
        };
        for (row, worker) in &peers {
            if row
                .body
                .excludes
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(&id))
            {
                continue;
            }
            let agent = AgentRoute {
                name: worker.name.clone(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: None,
            };
            match ferryman_channel::register_peer_key(&route, &agent, &worker.public_key) {
                Ok(true) => events.push(Event::info(
                    format!("room:{id}:{}", worker.name),
                    format!(
                        "{id}: made room for '{}', the worker of {} (public key only)",
                        worker.name, row.body.machine
                    ),
                )),
                Ok(false) => {}
                Err(error) => events.push(Event::warn(
                    format!("room:{id}:{}", worker.name),
                    format!(
                        "{id}: not putting '{}' ({}'s worker) on the roster: {error:#}",
                        worker.name, row.body.machine
                    ),
                )),
            }
        }
    }
    events
}

// ---------------------------------------------------------------------------------------
// C. Receive

/// File every project another admitted machine advertised that this one does not have:
/// live, mastered by the fleet's master, not excluded here, with a safe id. Each gets a
/// channel folder in the root's layout, this machine's worker (and the advertiser's) on its
/// roster, and an entry in the manifest with no checkout yet. The advertised remote is kept
/// for `repos sync`, outside `ferry.toml`.
///
/// `worker` is the identity this machine's all-projects worker already holds; nothing is made.
#[must_use]
pub fn receive(root: &Root, machine: &str, worker: &AgentIdentity) -> Vec<Event> {
    let mut events = Vec::new();
    if !home::exists(root) {
        return events;
    }
    let trust = Trust::load(&root.fleet_dir());
    let Some(fleet_master) = trust.master().map(str::to_owned) else {
        return events;
    };
    let directory = home::read_directory(root);
    let (machines, _) = home::read_machines(root);
    let config = RootConfig::load(root);
    let filed: BTreeSet<String> = root
        .read()
        .projects
        .into_iter()
        .map(|entry| entry.project_id)
        .collect();
    for (project, by_machine) in &directory.projects {
        if project == home::PROJECT
            || filed.contains(project)
            || config.excluded(project)
            || !is_safe_component(project)
        {
            continue;
        }
        // The newest entry from another machine that says it is live and masters the project
        // as the fleet's master does. An entry from a machine the master has not admitted
        // never gets here: the reader drops it.
        let Some((from, entry)) = by_machine
            .iter()
            .filter(|(from, _)| !from.eq_ignore_ascii_case(machine))
            .filter(|(_, entry)| {
                entry.body.lifecycle == "live"
                    && entry
                        .body
                        .master
                        .as_deref()
                        .is_some_and(|master| canonical_agent_name(master) == fleet_master)
            })
            .max_by_key(|(_, entry)| entry.written_at)
        else {
            continue;
        };
        let comms = root.comms_home(project);
        if let Err(error) = fs::create_dir_all(&comms) {
            events.push(Event::warn(
                format!("arrive:{project}"),
                format!("{project}: could not make {}: {error}", comms.display()),
            ));
            continue;
        }
        let stand_in = Entry {
            project_id: project.clone(),
            channel: comms.clone(),
            ..Entry::default()
        };
        let Ok((route, _)) = stand_in.route(root) else {
            continue;
        };
        // This worker on the roster first: the lane trusts a peer only for a channel in
        // which BOTH sides' workers are listed. Its own key, held here, never a made one.
        let own = AgentRoute {
            name: worker.name().to_owned(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        };
        if let Err(error) = ferryman_channel::register_agent_key(&route, &own, worker) {
            events.push(Event::warn(
                format!("arrive:{project}"),
                format!(
                    "{project}: advertised by {from}, but '{}' cannot go on its roster: {error:#}",
                    worker.name()
                ),
            ));
            continue;
        }
        // The advertiser's worker too, by its public key from its signed machine record, so
        // this side will answer it. A different key already there is a finding, not a change.
        if let Some(peer) = machines
            .iter()
            .find(|row| row.body.machine.eq_ignore_ascii_case(from))
            .and_then(|row| row.body.worker.as_ref())
        {
            let agent = AgentRoute {
                name: peer.name.clone(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: None,
            };
            if let Err(error) =
                ferryman_channel::register_peer_key(&route, &agent, &peer.public_key)
            {
                events.push(Event::warn(
                    format!("arrive:{project}:{}", peer.name),
                    format!(
                        "{project}: not putting '{}' ({from}'s worker) on the roster: {error:#}",
                        peer.name
                    ),
                ));
            }
        }
        match root.adopt(project, &comms, None) {
            Ok(true) => {}
            Ok(false) => {
                events.push(Event::warn(
                    format!("arrive:{project}"),
                    format!("{project}: not filed, {} is scratch space", comms.display()),
                ));
                continue;
            }
            Err(error) => {
                events.push(Event::warn(
                    format!("arrive:{project}"),
                    format!("{project}: could not file it: {error:#}"),
                ));
                continue;
            }
        }
        let remote = entry
            .body
            .git_remote
            .clone()
            .filter(|remote| usable_remote(remote));
        let mut arrivals = read_arrivals(root);
        arrivals.insert(
            project.clone(),
            Arrived {
                from: from.clone(),
                git_remote: remote,
                at: Utc::now(),
            },
        );
        let _ = write_json(&root.fleet_local().join(ARRIVED_FILE), &arrivals);
        events.push(Event::info(
            format!("arrived:{project}"),
            format!("{project} arrived from {from}: filed, cloning"),
        ));
    }
    events
}

// ---------------------------------------------------------------------------------------
// D. Clone what arrived

/// The projects that are filed, have a channel here and no checkout attached: what `repos
/// sync` would clone and attach. Not archived, not excluded, not out of the swarm, not
/// placed by hand. A project whose checkout is a person's working copy is attached, so it is
/// not in this list and is never taken over from here.
#[must_use]
pub fn unattached(root: &Root) -> Vec<String> {
    let config = RootConfig::load(root);
    root.read()
        .projects
        .into_iter()
        .filter(|entry| {
            entry.channel.is_dir()
                && entry.attachment().is_none()
                && !entry.is_archived()
                && !config.excluded(&entry.project_id)
                && !entry.swarm_off()
                && entry.placement_in(root) != Placement::Custom
        })
        .map(|entry| entry.project_id)
        .collect()
}

/// What a worker remembers between passes about the clones it tried, so a project that
/// cannot be cloned (no remote, no access) is retried now and then and does not use up every
/// pass.
#[derive(Debug, Default)]
pub struct SyncState {
    failed: BTreeMap<String, Instant>,
}

/// How long a project that could not be cloned is left alone before the next try.
pub const RETRY_AFTER: Duration = Duration::from_secs(5 * 60);
/// The longest one git command may take in a worker's pass.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(120);

impl SyncState {
    fn due(&self, project: &str, now: Instant) -> bool {
        self.failed
            .get(project)
            .is_none_or(|at| now.duration_since(*at) >= RETRY_AFTER)
    }
}

/// Clone and attach up to `max` of the projects [`unattached`] lists, each git command on
/// the clock of `timeout`. One that fails is left for [`RETRY_AFTER`], so a project nobody
/// can clone does not hold up the ones behind it.
#[must_use]
pub fn sync_arrivals(
    root: &Root,
    state: &mut SyncState,
    max: usize,
    timeout: Duration,
    now: Instant,
) -> Vec<Event> {
    let mut events = Vec::new();
    let due: Vec<String> = unattached(root)
        .into_iter()
        .filter(|project| state.due(project, now))
        .take(max)
        .collect();
    for project in due {
        let options = repos::Options {
            only: Some(project.clone()),
            git_timeout: Some(timeout),
            ..repos::Options::default()
        };
        let rows = match repos::sync(root, &options) {
            Ok(rows) => rows,
            Err(error) => {
                state.failed.insert(project.clone(), now);
                events.push(Event::warn(
                    format!("clone:{project}:{error}"),
                    format!("{project}: could not sync: {error:#}"),
                ));
                continue;
            }
        };
        for row in rows {
            match &row.status {
                repos::Status::Done(steps) => {
                    state.failed.remove(&project);
                    events.push(Event::info(
                        format!("cloned:{project}"),
                        format!("{project}: {}", steps.join(", ")),
                    ));
                }
                repos::Status::AlreadyOk => {
                    state.failed.remove(&project);
                }
                repos::Status::Skipped(why) => {
                    state.failed.insert(project.clone(), now);
                    let reason = why.reason();
                    events.push(Event::warn(
                        format!("clone:{project}:{reason}"),
                        format!(
                            "{project}: not cloned yet ({reason}); trying again in {} minutes",
                            RETRY_AFTER.as_secs() / 60
                        ),
                    ));
                }
            }
        }
    }
    events
}

#[cfg(test)]
mod tests;

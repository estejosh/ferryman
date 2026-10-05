//! One worker, every project it belongs to.
//!
//! # What was missing
//!
//! A worker is one identity with one set of engines, and the work it can do is the work
//! of every project whose roster it is on. Both halves were per project in practice:
//! `ferry agent run` served the one project its `agent.toml` sat in, and `--comms`
//! served a folder of *checkouts* (directories that each hold a `.ferryman`), each under
//! whatever `agent.toml` it happened to carry. A ferry root keeps its channels, not
//! checkouts, under `comms/`, so `--comms <root>/comms` found next to nothing, and what it
//! found ran as a different identity with a different engine.
//!
//! So a project the master owned was served only if somebody had set a worker up in that
//! project by hand, and there was no one command that put a worker on all of them.
//!
//! This module is the two halves of that:
//!
//! - [`plan_worker`] and [`serve`]: from the ferry root's manifest, the projects this
//!   worker identity can serve here, under the one config it was started with, and one
//!   line saying why for every project it cannot.
//! - [`enrol`]: put one existing identity on the roster of every project a master owns,
//!   with the master's signed grant, so the first half has something to find.
//!
//! Neither widens anyone's authority. The worker still needs to be on the roster under
//! the key it signs with and still passes `may_work`; enrolling is signed by the project's
//! own master or it does not happen, and a name a master has revoked is left revoked.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use ferryman_channel::{
    AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, canonical_agent_name,
    ferry::{Entry, Root},
};

use crate::agent::{AgentConfig, Fleet};

/// What this worker does about one project.
pub enum Standing {
    /// It serves it. `seat` says the project's checkout does not hold this identity's key
    /// yet, and the machine's own copy is to be put there before the first pass.
    Serves {
        route: Box<ProjectRoute>,
        seat: bool,
    },
    /// It does not, and why - in words that say what to do about it.
    Skips(String),
}

/// One project in the ferry root, and where this worker stands in it.
pub struct Row {
    pub project: String,
    pub channel: PathBuf,
    pub standing: Standing,
}

impl Row {
    /// The line `--dry-run` prints for this project.
    #[must_use]
    pub fn describe(&self, config: &AgentConfig) -> String {
        match &self.standing {
            Standing::Serves { .. } => format!(
                "would serve as {} with engines {}",
                config.agent,
                engines_line(config)
            ),
            Standing::Skips(why) => format!("not serving: {why}"),
        }
    }
}

/// Every project in the ferry root, in order, and what this worker does about each.
pub struct WorkerPlan {
    pub rows: Vec<Row>,
}

impl WorkerPlan {
    /// How many projects it would serve.
    #[must_use]
    pub fn serving(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| matches!(row.standing, Standing::Serves { .. }))
            .count()
    }
}

/// The engines a config runs, as the worker announces them: `claude-sonnet (build) > ...`,
/// or the one command when no list is configured.
#[must_use]
pub fn engines_line(config: &AgentConfig) -> String {
    if config.engines.is_empty() {
        return format!("'{}'", config.command);
    }
    config
        .engines
        .iter()
        .map(|engine| format!("{} ({})", engine.name, engine.tier.as_str()))
        .collect::<Vec<_>>()
        .join(" > ")
}

/// The roster file for `agent` in this channel itself - not the machine-wide copy that
/// [`ferryman_channel::read_agent_roster`] folds in, which would make a name look
/// enrolled in every channel as soon as it was enrolled in one.
fn listed(channel: &Path, agent: &str) -> Option<AgentRoute> {
    let path = channel
        .join("agents")
        .join(format!("{}.json", canonical_agent_name(agent)));
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn key_of_listing(listing: Option<&AgentRoute>) -> Option<&str> {
    listing
        .and_then(|agent| agent.public_key.as_deref())
        .filter(|key| !key.is_empty())
}

fn skip(why: impl Into<String>) -> Standing {
    Standing::Skips(why.into())
}

/// Work out, for every project in `root`, whether the identity `config` names serves it.
///
/// `home` is the attachment holding that identity's key and `agent.toml`. Nothing is
/// written; [`serve`] does the one thing that is, and only for the projects that pass.
///
/// # Errors
/// This machine holds no key for the configured name in `home`: a key is never made here,
/// because a second key under a name the rosters know reads as an impostor everywhere.
pub fn plan_worker(
    root: &Root,
    home: &Path,
    config: &AgentConfig,
) -> Result<(WorkerPlan, AgentIdentity)> {
    let Some(identity) = AgentIdentity::load_existing(&config.agent, home)? else {
        bail!(
            "this machine holds no key for '{}' in {}, so nothing it did could be signed. \
             Run this where the worker's own agent.toml and keys are (--workspace <dir>), \
             or name this machine's own agent in that agent.toml.",
            config.agent,
            home.display()
        );
    };
    let key = identity.public_key_hex();
    let rows = root
        .read()
        .projects
        .into_iter()
        .map(|entry| {
            let standing = judge(root, &entry, config, &key)
                .unwrap_or_else(|error| skip(format!("{error:#}")));
            Row {
                project: entry.project_id,
                channel: entry.channel,
                standing,
            }
        })
        .collect();
    Ok((WorkerPlan { rows }, identity))
}

fn judge(root: &Root, entry: &Entry, config: &AgentConfig, key: &str) -> Result<Standing> {
    let agent = config.agent.as_str();
    if !entry.channel.is_dir() {
        return Ok(skip("its channel folder is not on this machine"));
    }
    if entry.is_archived() {
        return Ok(skip("archived, so nothing new is worked there"));
    }
    if entry.attachment().is_none() {
        return Ok(skip(format!(
            "no checkout of {} on this machine, so there is nowhere to do its work. Clone it \
             here and run 'ferry enable' in it",
            entry.project_id
        )));
    }
    let (route, _) = entry.route(root)?;
    let enrol = format!("its master enrols it with: ferry team approve {agent} --all");
    let listing = listed(&route.communications, agent);
    if listing.is_none() {
        return Ok(skip(format!("'{agent}' is not on its roster ({enrol})")));
    }
    match key_of_listing(listing.as_ref()) {
        None => {
            return Ok(skip(format!(
                "'{agent}' is on its roster without a key ({enrol})"
            )));
        }
        Some(listed_key) if listed_key != key => {
            return Ok(skip(format!(
                "its roster lists a different key for '{agent}'. First key wins, so this \
                 machine cannot sign as '{agent}' there"
            )));
        }
        Some(_) => {}
    }
    // The key every check on this machine will actually use is the one it pinned the first
    // time it saw the name, which is not always the one in the file now.
    let pinned = route
        .agents
        .iter()
        .find(|known| canonical_agent_name(&known.name) == canonical_agent_name(agent))
        .and_then(|known| known.public_key.as_deref());
    if pinned.is_some_and(|pinned| pinned != key) {
        return Ok(skip(format!(
            "this machine pinned a different key for '{agent}' there, so its signatures would \
             not verify"
        )));
    }
    if !ferryman_channel::master::may_work(&route, agent, &config.role)? {
        return Ok(skip(format!(
            "its master has not let '{agent}' work there as {} (revoked, or that role needs \
             the master's grant)",
            config.role
        )));
    }
    let seat = match AgentIdentity::load_existing(agent, &route.attachment)? {
        Some(held) if held.public_key_hex() == key => false,
        Some(_) => {
            return Ok(skip(format!(
                "its checkout holds a different key for '{agent}'. Refusing to replace it: \
                 everything it signed would read as an impostor"
            )));
        }
        None => true,
    };
    Ok(Standing::Serves {
        route: Box::new(route),
        seat,
    })
}

/// The projects to watch: each served project under the one `config`, and the rest named.
///
/// Where the project's checkout does not hold the identity's key yet, this machine's own
/// copy is put there - the same move `ferry channel seat` makes, and only for a project
/// whose roster already lists exactly this key. It copies a key between two directories of
/// one machine; it mints nothing and replaces nothing.
///
/// One config for all of them, so one `max_parallel` is the whole worker's budget: a pass
/// works one channel at a time, and each claims at most that many orders.
#[must_use]
pub fn serve(plan: WorkerPlan, identity: &AgentIdentity, config: &AgentConfig) -> Fleet {
    let mut served = Vec::new();
    let mut skipped = Vec::new();
    for row in plan.rows {
        match row.standing {
            Standing::Serves { route, seat } => {
                if seat && let Err(error) = identity.seat_in(&route.attachment) {
                    skipped.push((
                        row.channel,
                        format!("{}: could not put the key there: {error:#}", row.project),
                    ));
                    continue;
                }
                served.push((*route, config.clone()));
            }
            Standing::Skips(why) => skipped.push((row.channel, format!("{}: {why}", row.project))),
        }
    }
    Fleet { served, skipped }
}

/// What enrolling an identity did in one project.
#[derive(Debug, PartialEq, Eq)]
pub enum Enrolment {
    /// Written now: the roster entry, the master's grant, or both.
    Added { roster: bool, grant: bool },
    /// Both were already there. Nothing was written and nobody was asked to sign.
    AlreadyThere,
    /// Another person masters it. Nothing was written.
    NotMaster { master: String },
    /// It has no master yet, so there is nobody who could sign. Nothing was written.
    NoMaster,
    /// Left alone, and why.
    Skipped(String),
}

/// The public key `name` carries on the rosters under this root, when every roster that
/// lists it with a key agrees.
///
/// # Errors
/// No roster lists it with a key, or two disagree - in which case nothing is chosen for
/// the master: which key a name has is the thing the rosters exist to pin.
pub fn key_on_rosters(root: &Root, name: &str) -> Result<String> {
    let mut found: Vec<(String, String)> = Vec::new();
    for entry in root.read().projects {
        if let Some(listing) = listed(&entry.channel, name)
            && let Some(key) = key_of_listing(Some(&listing))
        {
            found.push((entry.project_id.clone(), key.to_owned()));
        }
    }
    let Some((_, first)) = found.first().cloned() else {
        bail!(
            "no project under {} lists '{name}' with a key, and this machine does not hold \
             its key either. It has to have joined one project first",
            root.path.display()
        );
    };
    if let Some((project, other)) = found.iter().find(|(_, key)| *key != first) {
        bail!(
            "the rosters disagree about '{name}': {first} in {} and {other} in {project}. \
             Resolve which key is real before enrolling it anywhere",
            found[0].0
        );
    }
    Ok(first)
}

/// The person who is master of the most projects here, to sign as when nobody said.
#[must_use]
pub fn dominant_master(root: &Root) -> Option<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for entry in root.read().projects {
        let Ok((route, _)) = entry.route(root) else {
            continue;
        };
        let Ok(Some(declared)) = ferryman_channel::master::read_master(&route) else {
            continue;
        };
        match counts
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(&declared.master))
        {
            Some((_, count)) => *count += 1,
            None => counts.push((declared.master, 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts.into_iter().next().map(|(name, _)| name)
}

/// How many folders directly under `dir` are channels with no checkout beside them: a
/// roster or a master declaration, and no `.ferryman`.
///
/// What `--comms` cannot watch and `--all-projects` can, counted so the first can say so
/// instead of quietly finding nothing.
#[must_use]
pub fn bare_channels(dir: &Path) -> usize {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            !path.join(".ferryman").is_dir()
                && (path.join("master.json").is_file() || path.join("agents").is_dir())
        })
        .count()
}
/// Hands over the master's identity for one project. Called only when something is about
/// to be written, and it is where a password is asked for.
pub type Signer<'a> = dyn FnMut(&Entry, &str) -> Result<AgentIdentity> + 'a;

/// Put `name` (with public key `key`) on the roster of every project here that
/// `as_master` is master of, with that master's signed grant for `role`.
///
/// `signer` is called only when something is about to be written - never for a project
/// that is already enrolled, and never for one somebody else masters. A grant that cannot
/// be signed is an error for that project and writes nothing there.
///
/// Idempotent. A name the master has revoked in a project stays revoked: a grant would
/// lift the revocation, which is a decision for `ferry team approve` in that project, not
/// a side effect of a bulk command. A roster that already knows the name under another key
/// is left alone, since first key wins.
pub fn enrol(
    root: &Root,
    name: &str,
    role: &str,
    key: &str,
    as_master: &str,
    signer: &mut Signer<'_>,
) -> Vec<(String, Enrolment)> {
    root.read()
        .projects
        .into_iter()
        .map(|entry| {
            let outcome = if !entry.channel.is_dir() {
                Enrolment::Skipped("its channel folder is not on this machine".into())
            } else if entry.is_archived() {
                Enrolment::Skipped("archived".into())
            } else {
                enrol_one(root, &entry, name, role, key, as_master, signer)
                    .unwrap_or_else(|error| Enrolment::Skipped(format!("{error:#}")))
            };
            (entry.project_id, outcome)
        })
        .collect()
}

fn enrol_one(
    root: &Root,
    entry: &Entry,
    name: &str,
    role: &str,
    key: &str,
    as_master: &str,
    signer: &mut Signer<'_>,
) -> Result<Enrolment> {
    let (route, _) = entry.route(root)?;
    let Some(declared) = ferryman_channel::master::read_master(&route)? else {
        return Ok(Enrolment::NoMaster);
    };
    if !declared.master.eq_ignore_ascii_case(as_master) {
        return Ok(Enrolment::NotMaster {
            master: declared.master,
        });
    }
    let name = canonical_agent_name(name);
    let listing = listed(&route.communications, &name);
    if key_of_listing(listing.as_ref()).is_some_and(|listed_key| listed_key != key) {
        return Ok(Enrolment::Skipped(format!(
            "its roster already knows '{name}' under a different key. First key wins, so \
             nothing was changed"
        )));
    }
    if ferryman_channel::master::is_revoked(&route, &name)?
        || ferryman_channel::owner::is_revoked(&route, &name)?
    {
        return Ok(Enrolment::Skipped(format!(
            "'{name}' was revoked there. Enrolling would lift that; if it is meant, run \
             'ferry team approve {name}' in that project"
        )));
    }
    let on_roster = key_of_listing(listing.as_ref()).is_some();
    let granted = ferryman_channel::master::member_grants(&route)?
        .iter()
        .any(|(grant, check)| {
            grant.grantee == name
                && *check == SignatureCheck::Valid
                && grant.public_key == key
                && (grant.roles.is_empty()
                    || grant
                        .roles
                        .iter()
                        .any(|held| held.eq_ignore_ascii_case(role)))
        });
    if on_roster && granted {
        return Ok(Enrolment::AlreadyThere);
    }
    // Only now, with something to write, is the master asked for.
    let master = signer(entry, &declared.master)?;
    if !granted {
        ferryman_channel::master::grant_member(
            &route,
            &master,
            &name,
            key,
            vec![route.project_id.clone()],
            vec![role.to_owned()],
            Vec::new(),
        )?;
    }
    if !on_roster {
        let reserved = listing;
        ferryman_channel::register_agent(
            &route,
            &AgentRoute {
                name: name.clone(),
                role: reserved
                    .as_ref()
                    .map_or_else(|| role.to_owned(), |agent| agent.role.clone()),
                capabilities: reserved
                    .as_ref()
                    .map(|agent| agent.capabilities.clone())
                    .unwrap_or_default(),
                public_key: Some(key.to_owned()),
                encryption_key: reserved.and_then(|agent| agent.encryption_key),
            },
        )?;
    }
    Ok(Enrolment::Added {
        roster: !on_roster,
        grant: !granted,
    })
}

#[cfg(test)]
mod tests;

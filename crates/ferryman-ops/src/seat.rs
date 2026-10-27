//! Connector identities, seated in every project this machine serves (ADR 0030).
//!
//! # What was missing
//!
//! An identity that spans projects (an MCP connector such as `claude-ai-josh`, the Telegram
//! bridge's operator) has one key per machine and is "seated" in a project only where
//! `<attachment>/keys/<name>.key` exists. Nothing put it there for a project that arrived
//! later, so the connector could not use any project created after it was set up.
//!
//! # What this does, and what it never does
//!
//! For each name in the root's `[seat] agents`, and for each project this machine serves, it
//! copies the key THIS machine already holds into that project's attachment (the same move
//! `ferry channel seat` makes) and lists the name on the project's roster. The key is looked
//! for in the other projects' attachments and in the machine's own key store, and nowhere
//! else.
//!
//! - It never makes a key. A name this machine holds no key for is left alone: a second key
//!   under a name the rosters know reads as an impostor everywhere.
//! - It never copies a key to another machine. Each machine seats only keys it already has.
//! - It never puts a key in a channel. The key goes under the checkout's `.ferryman/keys/`,
//!   and only where git is told to ignore it ([`crate::fleet::keeps_keys_out_of_git`]).
//! - It refuses when the machine holds two different keys under one name (the rule `team
//!   approve --all` already has), and never replaces a different key already seated or
//!   listed.
//! - It grants nothing. Seating gives a key file and a roster line; what the identity may do
//!   still comes from the project's master (`ferry team approve <name> --all`).

use std::path::PathBuf;

use anyhow::{Result, bail};
use ferryman_channel::ferry::{Entry, Root};
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute, canonical_agent_name};

use crate::rootconfig::RootConfig;

/// What seating one name in one project came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The key was put in the attachment, or the name put on the roster, or both.
    Seated,
    /// Both were already in place. Nothing was written.
    Already,
    /// This machine holds no key under the name, so there is nothing to seat. Not an error,
    /// and nothing is made.
    NoKey,
    /// Left alone, and why.
    Refused(String),
}

/// One name in one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    pub project: String,
    pub name: String,
    pub outcome: Outcome,
}

impl Seat {
    /// A sentence for a log or a listing, or `None` when there is nothing worth saying
    /// (already in place, or no key here).
    #[must_use]
    pub fn line(&self) -> Option<String> {
        match &self.outcome {
            Outcome::Seated => Some(format!("seated '{}' in {}", self.name, self.project)),
            Outcome::Refused(why) => Some(format!(
                "did not seat '{}' in {}: {why}",
                self.name, self.project
            )),
            Outcome::Already | Outcome::NoKey => None,
        }
    }
}

/// The key this machine holds for `name`: in any project's attachment here, or in the
/// machine's own key store. `None` when it holds none; never makes one.
///
/// # Errors
/// The machine holds two different keys under the name, or a key file cannot be read.
pub fn held(root: &Root, name: &str) -> Result<Option<AgentIdentity>> {
    let mut places: Vec<PathBuf> = root
        .read()
        .projects
        .iter()
        .filter_map(Entry::attachment)
        .collect();
    if let Some(store) = ferryman_channel::licensing::machine_state_dir() {
        places.push(store);
    }
    let mut found: Vec<AgentIdentity> = Vec::new();
    for place in places {
        if let Some(identity) = AgentIdentity::load_existing(name, &place)?
            && !found
                .iter()
                .any(|known| known.public_key_hex() == identity.public_key_hex())
        {
            found.push(identity);
        }
    }
    if found.len() > 1 {
        bail!(
            "this machine holds {} different keys for '{name}' (across its checkouts and its \
             key store). Which is real has to be decided, and the other removed, before it is \
             seated anywhere",
            found.len()
        );
    }
    Ok(found.pop())
}

/// Seat every name in `names` in each of `routes`. A route is a served project: one whose
/// attachment holds the worker's own key. Names this machine holds no key for are reported
/// as [`Outcome::NoKey`], once per project.
#[must_use]
pub fn seat_all(root: &Root, names: &[String], routes: &[&ProjectRoute]) -> Vec<Seat> {
    let mut out = Vec::new();
    for name in names {
        let name = canonical_agent_name(name);
        let identity = match held(root, &name) {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                out.extend(routes.iter().map(|route| Seat {
                    project: route.project_id.clone(),
                    name: name.clone(),
                    outcome: Outcome::NoKey,
                }));
                continue;
            }
            Err(error) => {
                out.extend(routes.iter().map(|route| Seat {
                    project: route.project_id.clone(),
                    name: name.clone(),
                    outcome: Outcome::Refused(format!("{error:#}")),
                }));
                continue;
            }
        };
        for route in routes {
            let outcome = seat_one(root, &identity, route)
                .unwrap_or_else(|error| Outcome::Refused(format!("{error:#}")));
            out.push(Seat {
                project: route.project_id.clone(),
                name: name.clone(),
                outcome,
            });
        }
    }
    out
}

/// The roster file for `name` in this channel itself, not the machine-wide copy.
fn listed_here(route: &ProjectRoute, name: &str) -> Option<AgentRoute> {
    crate::fleet::listed(&route.communications, name)
}

/// The role `name` already has on another project's roster here, if any.
fn role_elsewhere(root: &Root, name: &str, besides: &str) -> Option<String> {
    root.read()
        .projects
        .iter()
        .filter(|entry| entry.project_id != besides)
        .find_map(|entry| crate::fleet::listed(&entry.channel, name))
        .map(|agent| agent.role)
        .filter(|role| ferryman_channel::is_safe_component(role))
}

fn seat_one(root: &Root, identity: &AgentIdentity, route: &ProjectRoute) -> Result<Outcome> {
    let name = identity.name();
    let key = identity.public_key_hex();
    let listing = listed_here(route, name);
    if let Some(listed_key) = listing
        .as_ref()
        .and_then(|agent| agent.public_key.as_deref())
        .filter(|listed| !listed.is_empty())
        && listed_key != key
    {
        return Ok(Outcome::Refused(format!(
            "its roster lists a different key for '{name}'. First key wins, so nothing was \
             changed"
        )));
    }
    let held_here = match AgentIdentity::load_existing(name, &route.attachment)? {
        Some(held) if held.public_key_hex() == key => true,
        Some(_) => {
            return Ok(Outcome::Refused(format!(
                "its checkout holds a different key for '{name}'. Refusing to replace it: \
                 everything it signed would read as an impostor"
            )));
        }
        None => false,
    };
    // A key under a checkout that git would take into a commit is published with the
    // repository. Not put there.
    if !held_here && !crate::fleet::keeps_keys_out_of_git(&route.attachment, name) {
        return Ok(Outcome::Refused(format!(
            "its checkout does not git-ignore .ferryman, so the key is not put there. Run \
             'ferry enable' in {} (it adds /.ferryman/ to .gitignore)",
            route.workspace.display()
        )));
    }
    let on_roster = listing
        .as_ref()
        .and_then(|agent| agent.public_key.as_deref())
        .is_some_and(|listed| listed == key);
    if held_here && on_roster {
        return Ok(Outcome::Already);
    }
    if !held_here {
        identity.seat_in(&route.attachment)?;
    }
    if !on_roster {
        let role = listing
            .as_ref()
            .map(|agent| agent.role.clone())
            .or_else(|| role_elsewhere(root, name, &route.project_id))
            .unwrap_or_else(|| "member".to_owned());
        ferryman_channel::register_agent_key(
            route,
            &AgentRoute {
                name: name.to_owned(),
                role,
                capabilities: listing
                    .as_ref()
                    .map(|agent| agent.capabilities.clone())
                    .unwrap_or_default(),
                public_key: None,
                encryption_key: listing.and_then(|agent| agent.encryption_key),
            },
            identity,
        )?;
    }
    Ok(Outcome::Seated)
}

/// Seat `names` in every project here that a worker would serve: it has a checkout, a
/// channel, is not archived, and is not kept out of the swarm. What `ferry root seat` does
/// the moment a name is added.
#[must_use]
pub fn seat_everywhere(root: &Root, names: &[String]) -> Vec<Seat> {
    let machine = RootConfig::load(root);
    let routes: Vec<ProjectRoute> = root
        .read()
        .projects
        .iter()
        .filter(|entry| {
            entry.channel.is_dir()
                && !entry.is_archived()
                && crate::fleet::out_of_the_swarm(entry, &machine).is_none()
        })
        .filter(|entry| entry.attachment().is_some())
        .filter_map(|entry| entry.route(root).ok())
        .filter_map(|(route, attached)| attached.then_some(route))
        .collect();
    seat_all(root, names, &routes.iter().collect::<Vec<_>>())
}

/// Seat the root's `[seat] agents` in `routes`. What the worker does as it starts serving
/// them, and `repos sync` does for a clone it has just attached.
#[must_use]
pub fn seat_configured(root: &Root, routes: &[&ProjectRoute]) -> Vec<Seat> {
    let names = RootConfig::load(root).seat_agents;
    if names.is_empty() || routes.is_empty() {
        return Vec::new();
    }
    seat_all(root, &names, routes)
}

#[cfg(test)]
mod tests;

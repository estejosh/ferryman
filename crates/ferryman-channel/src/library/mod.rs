//! The librarian: the fleet's memory and front desk.
//!
//! One person runs many projects and agents on several machines. The library is the one
//! place that keeps what they all need to know, and the one place any of them can ask. It
//! gives advice and never authority: anything that changes code or settings still goes
//! through signed orders and the master's approval.
//!
//! # Where it lives, and why
//!
//! In the channel of the *home* project, the same one the swarm's focus lives in (`ferryman`
//! unless `FERRYMAN_FOCUS_HOME` names another), under `library/`. That channel is already
//! carried to every machine in the fleet by Syncthing, already has the master the fleet
//! trusts, and every machine that runs a worker has it: a second fleet-wide channel would be
//! a second place to roll back and a second master to keep in step. A machine without the
//! home channel simply has no library, and says so.
//!
//! * [`store`]: the signed, append-only entries (facts, the master's confirm and retract,
//!   the mail tag map), their authority and rollback rules, and the contradictions between
//!   them;
//! * [`guard`]: the refusal of anything that looks like a secret, which is kept as a pointer
//!   ("NVIDIA key: Custodly, name nvidiaapi") and never as a value;
//! * [`views`]: read-only pages the librarian generates from live state (machines, engines,
//!   projects and their focus, inboxes, where each secret lives);
//! * [`index`]: a full-text index (SQLite FTS5) rebuilt from the signed entries;
//! * [`ask`]: retrieval, the prompt a model with no tools is given, and the checks on what
//!   it says (it must cite what it was shown; with nothing relevant the answer is "I don't
//!   know");
//! * [`mail`]: the shared agent inbox, handled without trusting a word of it.

pub mod ask;
pub mod guard;
pub mod index;
pub mod mail;
pub mod store;
pub mod views;

pub use ask::{Answer, Found, Query};
pub use store::{
    Conflict, Fact, Library, NewFact, Status, TagMap, Written, confirm, remember, retract,
    set_tag_map,
};

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Where the home project's channel and keys are on this machine.
#[derive(Debug, Clone)]
pub struct Home {
    pub project: String,
    pub channel: PathBuf,
    /// The directory the machine's keys are in: the home checkout's `.ferryman`, else the
    /// ferry root.
    pub attachment: PathBuf,
}

impl Home {
    /// The home project as a route made from the channel and keys alone, with the roster as
    /// the channel holds it now. Enough to read and write the library, ask the master and
    /// keep the ledger.
    #[must_use]
    pub fn route(&self) -> crate::ProjectRoute {
        crate::ProjectRoute {
            project_id: self.project.clone(),
            workspace: self
                .attachment
                .parent()
                .map_or_else(|| self.attachment.clone(), std::path::Path::to_path_buf),
            attachment: self.attachment.clone(),
            communications: self.channel.clone(),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: crate::read_agent_roster(&self.channel).unwrap_or_default(),
        }
    }
}

/// The home project on this machine, found through the ferry root.
///
/// # Errors
/// No ferry root, or the home project's channel is not on this machine.
pub fn home() -> Result<Home> {
    let project = crate::focus::home_project();
    let root =
        crate::ferry::find_root().context("no ferry root yet - make one with `ferry root init`")?;
    let entry = root
        .read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == project && entry.channel.is_dir())
        .with_context(|| {
            format!(
                "the library lives in {project}'s channel, which is not on this machine \
                 (set FERRYMAN_FOCUS_HOME to name another home project)"
            )
        })?;
    let attachment = entry
        .repo
        .as_ref()
        .map(|repo| repo.join(".ferryman"))
        .filter(|attachment| attachment.is_dir())
        .unwrap_or_else(|| root.path.clone());
    Ok(Home {
        project,
        channel: entry.channel,
        attachment,
    })
}

/// The home project's route, with its roster as the channel holds it now.
///
/// # Errors
/// As [`home`], or the project's route cannot be built.
pub fn home_route() -> Result<crate::ProjectRoute> {
    let home = home()?;
    let root = crate::ferry::find_root().context("no ferry root")?;
    let entry = root
        .read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == home.project)
        .context("the home project is not in the ferry root")?;
    let (mut route, _) = entry.route(&root)?;
    route.agents = crate::read_agent_roster(&route.communications).unwrap_or_default();
    Ok(route)
}

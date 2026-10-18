//! Moving orders off an identity that is gone: `ferry order reoffer` and
//! `ferry order release --held-by`.
//!
//! When a machine moves to one worker identity, the old identities are revoked. That leaves
//! two kinds of order stuck behind a name that will never work again:
//!
//! - an order **addressed** to the old identity (`assigned_to`), which sits `Offered` to it.
//!   The signed order cannot be edited, and should not be: its signature is the record of
//!   what the issuer asked for. [`reoffer`] writes a new signed record beside it, naming who
//!   it is offered to now (an identity, or the queue). Only the order's issuer or the
//!   project's master may.
//! - an order the old identity has **claimed** and never finished. [`release_held`] writes
//!   the master's signed release of that claim, which returns the order to the queue (or to
//!   its address). The claim, the order and everything else stay where they are; the ledger
//!   records who let it go and why. It refuses to release a name whose worker is still
//!   alive on this machine.
//!
//! Neither deletes or rewrites anything, and neither is done by a worker on its own: both
//! need the master's (or the issuer's) key, asked for only when something is about to be
//! written.

use anyhow::{Context, Result, bail};
use ferryman_channel::ferry::{Entry, Root};
use ferryman_channel::offer::Offer;

use crate::fleet::Signer;

fn entry_of(root: &Root, project: &str) -> Result<Entry> {
    root.read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == project)
        .with_context(|| {
            format!(
                "no project '{project}' in {}",
                root.manifest_path().display()
            )
        })
}

/// Offer `order` in `project` to `to` (`None`: whoever picks it up first), signed.
///
/// `signer_name` is who signs: the order's issuer or the project's master. Without it, the
/// master. `signer` is asked for that identity's key only now, when it is about to be used.
///
/// # Errors
/// The project or order is not there, the signer is neither issuer nor master (the check
/// is the channel's own, [`ferryman_channel::offer::may_offer`]), or the order is finished
/// or killed.
pub fn reoffer(
    root: &Root,
    project: &str,
    order: &str,
    to: Option<&str>,
    reason: &str,
    signer_name: Option<&str>,
    signer: &mut Signer<'_>,
) -> Result<Offer> {
    let entry = entry_of(root, project)?;
    if !entry.channel.is_dir() {
        bail!("{project}'s channel is not on this machine");
    }
    // The channel and nothing else: what is signed is a file in the channel.
    let (route, _) = Entry {
        repo: None,
        ..entry.clone()
    }
    .route(root)?;
    let name = match signer_name {
        Some(name) => name.to_owned(),
        None => ferryman_channel::master::read_master(&route)?
            .map(|declared| declared.master)
            .with_context(|| {
                format!("{project} has no master yet; say who signs with --as, or claim it with 'ferry root master'")
            })?,
    };
    let identity = signer(&entry, &name)?;
    ferryman_channel::offer::reoffer(&route, order, to, reason, &identity)
}

/// What releasing did for one claim.
#[derive(Debug, PartialEq, Eq)]
pub enum Released {
    /// A signed release was written (or, in a dry run, would be).
    Done,
    /// Left alone, and why.
    Skipped(String),
}

/// Release every unfinished claim `retired` holds, in every project `as_master` masters.
///
/// Returns `(project, order, outcome)`. In a dry run nothing is signed and nobody is asked
/// for a key.
pub fn release_held(
    root: &Root,
    retired: &str,
    as_master: &str,
    reason: &str,
    dry_run: bool,
    signer: &mut Signer<'_>,
) -> Vec<(String, String, Released)> {
    let mut out = Vec::new();
    for entry in root.read().projects {
        if !entry.channel.is_dir() {
            continue;
        }
        let project = entry.project_id.clone();
        match release_in(root, &entry, retired, as_master, reason, dry_run, signer) {
            Ok(rows) => out.extend(
                rows.into_iter()
                    .map(|(order, what)| (project.clone(), order, what)),
            ),
            Err(error) => out.push((
                project,
                String::new(),
                Released::Skipped(format!("{error:#}")),
            )),
        }
    }
    out
}

fn release_in(
    root: &Root,
    entry: &Entry,
    retired: &str,
    as_master: &str,
    reason: &str,
    dry_run: bool,
    signer: &mut Signer<'_>,
) -> Result<Vec<(String, Released)>> {
    let retired = ferryman_channel::canonical_agent_name(retired);
    let (route, _) = Entry {
        repo: None,
        ..entry.clone()
    }
    .route(root)?;
    let Some(declared) = ferryman_channel::master::read_master(&route)? else {
        return Ok(vec![(
            String::new(),
            Released::Skipped("no master yet".into()),
        )]);
    };
    if !declared.master.eq_ignore_ascii_case(as_master) {
        return Ok(vec![(
            String::new(),
            Released::Skipped(format!(
                "its master is {}, not {as_master}",
                declared.master
            )),
        )]);
    }
    let mut places = vec![entry.managed_clone_path(root)];
    places.extend(entry.repo.iter().cloned());
    places.extend(entry.human_checkouts.iter().cloned());
    if places
        .iter()
        .any(|place| crate::agent::worker_alive(&place.join(".ferryman"), &retired))
    {
        return Ok(vec![(
            String::new(),
            Released::Skipped(format!(
                "a worker as '{retired}' is alive on this machine; stop it first"
            )),
        )]);
    }
    let mut out = Vec::new();
    let mut identity = None;
    for task in ferryman_channel::list_tasks(&route)? {
        let holds = task
            .claims
            .iter()
            .any(|claim| claim.agent.eq_ignore_ascii_case(&retired))
            && !task.released(&retired);
        if !holds
            || task.latest_revision().is_some()
            || matches!(task.state(), ferryman_channel::TaskState::Killed { .. })
        {
            continue;
        }
        let order = task.order.id.clone();
        if dry_run {
            out.push((order, Released::Done));
            continue;
        }
        if identity.is_none() {
            let master = signer(entry, &declared.master)?;
            ferryman_channel::ferry::require_master(
                &route.communications,
                &route.project_id,
                &master,
                "release a retired identity's claim",
            )?;
            identity = Some(master);
        }
        let Some(master) = identity.as_ref() else {
            continue;
        };
        match ferryman_channel::release_claim(
            &route,
            &order,
            &retired,
            master.name(),
            reason,
            master,
        ) {
            Ok(_) => out.push((order, Released::Done)),
            Err(error) => out.push((order, Released::Skipped(format!("{error:#}")))),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;

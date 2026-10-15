//! One place called `ferry`, and a manifest that says where everything is.
//!
//! ADR 0019.
//!
//! ```text
//! ferry/
//!   comms/     every channel:  <project>-ferryman/
//!   repos/     repositories Ferryman cloned, and links to ones it adopted
//!   work/      task worktrees, which are transient
//!   .ferry     this manifest
//! ```
//!
//! # Why a manifest rather than a scan
//!
//! Finding projects by reading the directory beside wherever a command happened to be
//! launched is guesswork dressed as discovery: it finds a fleet kept as siblings, finds
//! nothing from a checkout on another drive, cannot see two locations at once, and fails
//! *silently* - showing one project as though one were all there is.
//!
//! # What is never done
//!
//! **A repository the user made is never moved.** It is adopted where it stands and the
//! manifest records where that is. `create_worktree` puts worktrees beside the
//! repository, so moving one breaks every existing worktree - a worktree's `.git` is a
//! file holding an absolute path back to its repo, and [`crate::worktree`] already
//! documents that failure because it happened. `repos/` may hold a *link* to an adopted
//! repository, which costs nothing to break.
//!
//! The rule underneath: the files are the truth, and this carries the channel rather than
//! the work. Coordinating work does not entitle it to somebody's filesystem.
//!
//! # Machine-local, always
//!
//! Every path here is machine-specific - which is exactly why one machine can see
//! nineteen projects and another two. The manifest never travels in a channel: a path
//! from another machine is worse than no path at all.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, SignatureCheck};

/// The file that marks a ferry root and describes what is in it.
pub const MANIFEST: &str = ".ferry";

/// The marker, inside a channel, that says its project is finished.
///
/// It lives in the channel and not in the manifest because the manifest is machine-local
/// and archiving is not: a project finished on one machine is finished on all of them,
/// and the channel is the one thing they all share. Syncthing carries the marker out and
/// carries its removal back, so `--restore` travels the same way.
///
/// Only the project's master can put it there. The marker is signed, and a machine
/// honours it only when the signature is the master's, by the key the channel knows the
/// master by - so a peer that can write the channel can write the file, but cannot make
/// anyone believe it. Removing the file is the one thing a peer can do unsigned, and all
/// that does is bring a project back into view: it hides nothing.
pub const ARCHIVED: &str = "ARCHIVED";

/// What the [`ARCHIVED`] marker holds: the master saying the project is finished.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ArchiveMark {
    project_id: String,
    archived_at: DateTime<Utc>,
    signed_by: String,
    signature: String,
}

/// Exactly what an archive mark's signature covers. The project id is in it so a mark
/// cannot be lifted from one channel into another.
fn mark_payload(project_id: &str, archived_at: &DateTime<Utc>) -> String {
    format!(
        "ferryman-archive-v1\n{project_id}\n{}",
        archived_at.to_rfc3339()
    )
}

fn sign_mark(project_id: &str, signer: &AgentIdentity) -> ArchiveMark {
    let archived_at = Utc::now();
    let signature = signer
        .signing
        .sign(mark_payload(project_id, &archived_at).as_bytes());
    ArchiveMark {
        project_id: project_id.to_owned(),
        archived_at,
        signed_by: signer.name().to_owned(),
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Who the master of the project in this channel is, verified - `None` if it has none.
///
/// # Errors
/// A declaration that is there but does not verify is an error, not a `None`: a forged
/// master is not the same thing as no master.
pub fn master_of(channel: &Path) -> Result<Option<String>> {
    let roster = crate::read_agent_roster(channel)?;
    Ok(crate::master::read_master_at(channel, &roster)?.map(|declaration| declaration.master))
}

/// One project, and where its two halves live on this machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub project_id: String,
    /// The channel directory - the thing Syncthing carries.
    pub channel: PathBuf,
    /// The repository the work happens in, wherever it actually is. `None` for a project
    /// that is only a channel here, which is the normal state on a machine that syncs a
    /// channel but does not run the work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<PathBuf>,
    /// Whether this repository was adopted where it stood rather than created here.
    /// Recorded so nothing ever assumes it may be moved or removed.
    #[serde(default)]
    pub adopted: bool,
    /// Working copies a person keeps of this project on this machine (`X:\ferryman`,
    /// `~/code/fructly`) when `repo` is Ferryman's own managed clone under `repos/`.
    /// Information only: Ferryman never moves, cleans or writes into them, and nothing
    /// reads them to decide where work happens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub human_checkouts: Vec<PathBuf>,
}

impl Entry {
    /// Finished. Still here, still synced, still readable - but not offered as somewhere
    /// work happens.
    ///
    /// The third state the index was missing. `forget` is for an entry whose channel has
    /// gone; a project that is simply *over* has neither a reason to be removed (its
    /// signed history is the record of what happened) nor a reason to keep appearing
    /// beside the live ones. Read from the channel's [`ARCHIVED`] marker, so every
    /// machine that syncs the channel gives the same answer - and honoured only when the
    /// project's master signed it.
    #[must_use]
    pub fn is_archived(&self) -> bool {
        self.mark_holds().unwrap_or(false)
    }

    /// The `.ferryman` directory of this project's checkout on this machine, if it has
    /// one: the place its keys, `agent.toml` and `bridge.toml` live.
    ///
    /// `None` for a project that is only a channel here, which is the normal state for a
    /// machine that syncs a channel but does not run the work.
    #[must_use]
    pub fn attachment(&self) -> Option<PathBuf> {
        self.repo
            .as_ref()
            .map(|repo| repo.join(".ferryman"))
            .filter(|attachment| attachment.join("bridge.toml").is_file())
    }

    /// The route to this project on this machine, and whether a checkout is here.
    ///
    /// With a checkout it is the route its `bridge.toml` describes. Without one it is the
    /// channel and nothing else: the same stand-in `claim_masters` signs through, whose
    /// "attachment" is only the directory the channel sits in. Such a route can read and
    /// sign the channel's own records; there is no workspace behind it to run work in.
    ///
    /// # Errors
    /// The attachment names a different project than the manifest does, or its
    /// `bridge.toml` or the channel's roster cannot be read.
    pub fn route(&self, root: &Root) -> Result<(crate::ProjectRoute, bool)> {
        if let Some(attachment) = self.attachment() {
            let route = crate::load_route(&attachment)?;
            if route.project_id != self.project_id {
                bail!(
                    "the checkout at {} belongs to '{}', not '{}'",
                    attachment.display(),
                    route.project_id,
                    self.project_id
                );
            }
            // The manifest's channel is the folder the archive mark, the roster and the
            // master are judged in elsewhere; the checkout's `bridge.toml` is a file
            // somebody can edit. If they name different folders, a project would be
            // judged in one and written to in the other.
            if let (Ok(manifest), Ok(described)) = (
                std::fs::canonicalize(&self.channel),
                std::fs::canonicalize(&route.communications),
            ) && manifest != described
            {
                bail!(
                    "the checkout at {} reads its channel from {}, but this machine files \
                     '{}' under {}",
                    attachment.display(),
                    route.communications.display(),
                    self.project_id,
                    self.channel.display()
                );
            }
            return Ok((route, true));
        }
        let attachment = self
            .channel
            .parent()
            .map_or_else(|| root.path.clone(), Path::to_path_buf);
        Ok((
            crate::ProjectRoute {
                project_id: self.project_id.clone(),
                workspace: attachment.parent().unwrap_or(&attachment).to_path_buf(),
                attachment,
                communications: self.channel.clone(),
                shared_remote: format!("{}-ferryman", self.project_id),
                git_remote: String::new(),
                git_visibility: String::new(),
                agents: crate::read_agent_roster(&self.channel)?,
            },
            false,
        ))
    }
    fn mark_holds(&self) -> Result<bool> {
        let path = self.channel.join(ARCHIVED);
        if !path.is_file() {
            return Ok(false);
        }
        let mark: ArchiveMark = serde_json::from_slice(&std::fs::read(&path)?)?;
        let roster = crate::read_agent_roster(&self.channel)?;
        let Some(master) = crate::master::read_master_at(&self.channel, &roster)? else {
            return Ok(false);
        };
        Ok(mark.project_id == self.project_id
            && master.project_id == self.project_id
            && mark.signed_by.eq_ignore_ascii_case(&master.master)
            && crate::check_signature(
                Some(&mark.signed_by),
                Some(&mark.signature),
                &mark_payload(&mark.project_id, &mark.archived_at),
                &roster,
            ) == SignatureCheck::Valid)
    }
}

/// Whether the project in `channel` carries a valid master-signed [`ARCHIVED`] mark.
///
/// For callers that hold a channel rather than a ferry-root entry: the same check as
/// [`Entry::is_archived`], so an unsigned, forged or non-master file reads as not
/// archived.
#[must_use]
pub fn is_archived(channel: &Path, project_id: &str) -> bool {
    Entry {
        project_id: project_id.to_owned(),
        channel: channel.to_path_buf(),
        repo: None,
        adopted: false,
        human_checkouts: Vec::new(),
    }
    .is_archived()
}

/// Archive the project in `channel`, or bring it back, signed by its master. What
/// [`Root::archive`] does once it has found the channel. Returns whether anything
/// changed.
pub fn set_archived(
    channel: &Path,
    project_id: &str,
    archived: bool,
    signer: &AgentIdentity,
) -> Result<bool> {
    // Without the channel there is nowhere to say it that the fleet would hear.
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({}) - archive it from one that has it",
            channel.display()
        );
    }
    require_master(channel, project_id, signer, "archive it or bring it back")?;
    let was = is_archived(channel, project_id);
    let marker = channel.join(ARCHIVED);
    if archived {
        if was {
            return Ok(false);
        }
        crate::atomic_json(&marker, &sign_mark(project_id, signer))
            .with_context(|| format!("writing {}", marker.display()))?;
    } else {
        // Removed whether or not it verified: a mark nobody honours is litter.
        if marker.exists() {
            std::fs::remove_file(&marker)
                .with_context(|| format!("removing {}", marker.display()))?;
        }
        if !was {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Refuse unless `signer` is the master of the project in `channel`, by the key the
/// channel knows the master by. `what` finishes "only the master can ...".
pub fn require_master(
    channel: &Path,
    project_id: &str,
    signer: &AgentIdentity,
    what: &str,
) -> Result<()> {
    let roster = crate::read_agent_roster(channel)?;
    let Some(master) = crate::master::read_master_at(channel, &roster)? else {
        bail!("{project_id} has no master, and only a project's master can {what}");
    };
    if !signer.name().eq_ignore_ascii_case(&master.master) {
        bail!(
            "only {}, {project_id}'s master, can {what} - not {}",
            master.master,
            signer.name()
        );
    }
    // The name is not the proof; the key is. A key minted under the master's name
    // would sign a mark no machine honours, so refuse here rather than write one.
    let known = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(&master.master))
        .and_then(|agent| agent.public_key.clone());
    if known.as_deref() != Some(signer.public_key_hex().as_str()) {
        bail!(
            "this is not the key {} is known by in {project_id}'s channel, so nothing it signs would be honoured",
            master.master
        );
    }
    Ok(())
}

/// The setting, inside a channel, that says whether its project takes part in the weekly
/// self-improvement loop (`ferry improve`).
///
/// Off unless this file says on, signed by the project's master: the same trust as
/// [`ARCHIVED`], and in the channel for the same reason - it applies on every machine
/// that syncs the project. A missing, unreadable, edited, forged or non-master file reads
/// as off, so a peer that can write the channel can at most switch it off, never on.
pub const SELF_IMPROVE: &str = "SELF_IMPROVE";

/// What the [`SELF_IMPROVE`] file holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImproveSetting {
    pub project_id: String,
    pub enabled: bool,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
    /// Whose switch this is, when a delegate signed it for them. `None` is the signer's
    /// own. Honoured only under a valid `improve` delegation from the master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
}

impl ImproveSetting {
    /// Who set it, as a person reads it: `josh`, or `josh via telegram-grouchly`.
    #[must_use]
    pub fn set_by(&self) -> String {
        match &self.on_behalf_of {
            Some(principal) => crate::delegation::label(principal, &self.signed_by),
            None => self.signed_by.clone(),
        }
    }
}

/// Exactly what a self-improve setting's signature covers. The project id is in it so a
/// setting cannot be lifted from one channel into another; a delegated setting binds the
/// principal too.
fn improve_payload(project_id: &str, enabled: bool, set_at: &DateTime<Utc>) -> String {
    format!(
        "ferryman-self-improve-v1\n{project_id}\n{}\n{}",
        if enabled { "on" } else { "off" },
        set_at.to_rfc3339()
    )
}

fn setting_payload(setting: &ImproveSetting) -> String {
    let mut payload = improve_payload(&setting.project_id, setting.enabled, &setting.set_at);
    if let Some(principal) = &setting.on_behalf_of {
        payload.push_str(&format!("\nfor:{principal}"));
    }
    payload
}

/// The master's self-improve setting for the project in `channel`, when there is one
/// and it verifies as the master's. Anything else is `None`, which means off.
#[must_use]
pub fn self_improve_setting(channel: &Path, project_id: &str) -> Option<ImproveSetting> {
    let setting: ImproveSetting =
        serde_json::from_slice(&std::fs::read(channel.join(SELF_IMPROVE)).ok()?).ok()?;
    let roster = crate::read_agent_roster(channel).ok()?;
    let master = crate::master::read_master_at(channel, &roster).ok()??;
    let principal = setting
        .on_behalf_of
        .clone()
        .unwrap_or_else(|| setting.signed_by.clone());
    (setting.project_id == project_id
        && master.project_id == project_id
        && principal.eq_ignore_ascii_case(&master.master)
        && crate::delegation::authority(
            channel,
            project_id,
            &principal,
            &setting.signed_by,
            crate::delegation::IMPROVE,
            Utc::now(),
        )
        .allowed()
        && crate::check_signature(
            Some(&setting.signed_by),
            Some(&setting.signature),
            &setting_payload(&setting),
            &roster,
        ) == SignatureCheck::Valid)
        .then_some(setting)
}

/// Whether the project in `channel` is switched on for self-improvement. Off by default,
/// and always off for an archived project: the loop leaves finished work alone, whatever
/// the setting said before it was archived.
#[must_use]
pub fn self_improve_enabled(channel: &Path, project_id: &str) -> bool {
    self_improve_setting(channel, project_id).is_some_and(|setting| setting.enabled)
        && !is_archived(channel, project_id)
}

/// Switch self-improvement on or off for the project in `channel`, signed by `signer`,
/// who must be the project's master. Returns whether the setting changed.
pub fn set_self_improve(
    channel: &Path,
    project_id: &str,
    enabled: bool,
    signer: &AgentIdentity,
) -> Result<bool> {
    set_self_improve_as(channel, project_id, enabled, signer, None)
}

/// [`set_self_improve`], signed by a delegate for `on_behalf_of`, who must be the master
/// and must have delegated `improve` to the signer. `None` is the signer's own switch.
pub fn set_self_improve_as(
    channel: &Path,
    project_id: &str,
    enabled: bool,
    signer: &AgentIdentity,
    on_behalf_of: Option<&str>,
) -> Result<bool> {
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({})",
            channel.display()
        );
    }
    let on_behalf_of =
        on_behalf_of.filter(|principal| !principal.eq_ignore_ascii_case(signer.name()));
    match on_behalf_of {
        None => require_master(channel, project_id, signer, "switch self-improve on or off")?,
        Some(principal) => {
            let Some(master) = master_of(channel)? else {
                bail!(
                    "{project_id} has no master, and only a project's master can switch self-improve"
                );
            };
            if !principal.eq_ignore_ascii_case(&master) {
                bail!(
                    "only {master}, {project_id}'s master, can switch self-improve - not {principal}"
                );
            }
            if let crate::delegation::Authority::Refused(why) = crate::delegation::authority(
                channel,
                project_id,
                principal,
                signer.name(),
                crate::delegation::IMPROVE,
                Utc::now(),
            ) {
                bail!(
                    "{} cannot switch self-improve for {principal}: {why}",
                    signer.name()
                );
            }
        }
    }
    if enabled && is_archived(channel, project_id) {
        bail!(
            "{project_id} is archived, and an archived project cannot have self-improve switched \
             on; bring it back first with 'ferry root archive {project_id} --restore'"
        );
    }
    // Compared with the signed setting itself, not with the effective answer: an
    // archived project reads as off whatever its setting, and switching it off must
    // still write, or it would come back on when it is brought back.
    if self_improve_setting(channel, project_id).is_some_and(|setting| setting.enabled) == enabled {
        return Ok(false);
    }
    let mut setting = ImproveSetting {
        project_id: project_id.to_owned(),
        enabled,
        set_at: Utc::now(),
        signed_by: signer.name().to_owned(),
        signature: String::new(),
        on_behalf_of: on_behalf_of.map(str::to_owned),
    };
    setting.signature = hex::encode(
        signer
            .signing
            .sign(setting_payload(&setting).as_bytes())
            .to_bytes(),
    );
    let path = channel.join(SELF_IMPROVE);
    crate::atomic_json(&path, &setting).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// The setting, inside a channel, that keeps a project out of the swarm: `swarm = off`.
///
/// Some projects must not be worked by the fleet at all - a secrets repository, a third
/// party's. The master says so once and every machine that syncs the channel hears it:
/// `repos sync` does not clone it, `--all-projects` does not serve it, `team approve --all`
/// does not enrol anyone in it. Signed by the project's master, in the channel, for the
/// same reasons as [`ARCHIVED`] and [`SELF_IMPROVE`].
///
/// Absent means on: a project is in the swarm unless its master said otherwise. A machine
/// that has never seen the master's `off` (a new one, or one that was offline when it was
/// written and when it was deleted) cannot know, so deleting the file is the one unsigned
/// thing a peer can do to such a machine; a machine that has seen it keeps the newest
/// setting it accepted, so neither deleting the file nor putting an older signed one back
/// changes what it does (see [`SwarmSetting`]). A machine can also keep a project out on its
/// own, in its root config (`[swarm] exclude`), which no peer can reach. Versions before
/// this one do not read the file at all.
pub const SWARM: &str = "SWARM";

/// What the [`SWARM`] file holds.
///
/// `seq` is one more than the highest the master could see when signing, and it is covered
/// by the signature. Each machine remembers the highest it has accepted (see
/// [`swarm_setting`]), so an older signed file put back over a newer one, or the file
/// deleted, does not change what that machine does. Without it, deleting the file or
/// restoring an old `on` would put a project the master took out (a secrets repository) back
/// in the swarm. Nothing that is not the newest the machine has seen is obeyed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwarmSetting {
    pub project_id: String,
    /// `true` is `swarm = on`; `false` is `swarm = off`.
    pub on: bool,
    #[serde(default)]
    pub seq: u64,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn swarm_payload(project_id: &str, on: bool, seq: u64, set_at: &DateTime<Utc>) -> String {
    format!(
        "ferryman-swarm-v2\n{project_id}\n{}\n{seq}\n{}",
        if on { "on" } else { "off" },
        set_at.to_rfc3339()
    )
}

/// What this machine last accepted of a project's swarm setting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SwarmMemory {
    high: u64,
    good: Option<SwarmSetting>,
}

/// Where this machine remembers a channel's swarm setting: per channel, so two channels of
/// one project name (or a test's temporary one) never share it.
fn swarm_memory_path(channel: &Path, project_id: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let dir = crate::licensing::machine_state_dir()?.join("swarm");
    let place = std::fs::canonicalize(channel).unwrap_or_else(|_| channel.to_path_buf());
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

fn read_swarm_memory(channel: &Path, project_id: &str) -> SwarmMemory {
    swarm_memory_path(channel, project_id)
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Best effort: a machine that cannot write its memory still obeys the file it can read.
fn remember_swarm(channel: &Path, project_id: &str, setting: &SwarmSetting) {
    let Some(path) = swarm_memory_path(channel, project_id) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = crate::atomic_json(
        &path,
        &SwarmMemory {
            high: setting.seq,
            good: Some(setting.clone()),
        },
    );
}

/// The swarm file in `channel` when it verifies as the project master's. No memory.
fn swarm_file(channel: &Path, project_id: &str) -> Option<SwarmSetting> {
    let setting: SwarmSetting =
        serde_json::from_slice(&std::fs::read(channel.join(SWARM)).ok()?).ok()?;
    let roster = crate::read_agent_roster(channel).ok()?;
    let master = crate::master::read_master_at(channel, &roster).ok()??;
    (setting.project_id == project_id
        && master.project_id == project_id
        && setting.signed_by.eq_ignore_ascii_case(&master.master)
        && crate::check_signature(
            Some(&setting.signed_by),
            Some(&setting.signature),
            &swarm_payload(
                &setting.project_id,
                setting.on,
                setting.seq,
                &setting.set_at,
            ),
            &roster,
        ) == SignatureCheck::Valid)
        .then_some(setting)
}

/// The master's swarm setting for the project in `channel`: the newest this machine has
/// seen that verifies as the master's. Anything else is `None`, which means on.
///
/// The channel's file counts when it verifies and its `seq` is at least the highest this
/// machine has accepted, and it is then remembered. A file that is missing, does not
/// verify, or is older than one already accepted does not count: the remembered setting
/// stands. Only the master can move it forward, with a higher `seq`. A machine that has
/// never seen a setting has nothing to remember and reads the file as it is.
#[must_use]
pub fn swarm_setting(channel: &Path, project_id: &str) -> Option<SwarmSetting> {
    let file = swarm_file(channel, project_id);
    let memory = read_swarm_memory(channel, project_id);
    match (file, memory.good) {
        (Some(file), good) => {
            // A file that verifies was signed by the project's current master. One from a
            // different master than the one remembered is a handover, not a rollback: the
            // old master cannot have signed it, and it carries its own numbering.
            let new_hand = good
                .as_ref()
                .is_none_or(|good| !good.signed_by.eq_ignore_ascii_case(&file.signed_by));
            if file.seq > memory.high || new_hand {
                remember_swarm(channel, project_id, &file);
                Some(file)
            } else if file.seq == memory.high {
                // The same sequence number: what was accepted first stands.
                good.or(Some(file))
            } else {
                good
            }
        }
        (None, good) => good,
    }
}

/// Whether the swarm may work the project in `channel`: on unless its master signed `off`.
#[must_use]
pub fn swarm_enabled(channel: &Path, project_id: &str) -> bool {
    swarm_setting(channel, project_id).is_none_or(|setting| setting.on)
}

/// Switch the swarm on or off for the project in `channel`, signed by its master.
/// Returns whether the setting changed.
pub fn set_swarm(
    channel: &Path,
    project_id: &str,
    on: bool,
    signer: &AgentIdentity,
) -> Result<bool> {
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({})",
            channel.display()
        );
    }
    require_master(channel, project_id, signer, "put it in or out of the swarm")?;
    // What the channel itself says, and what this machine has seen: the new setting numbers
    // above both, so every machine that has seen the old one takes it as newer.
    let effective = swarm_setting(channel, project_id);
    let on_file = swarm_file(channel, project_id);
    if let (Some(file), Some(effective)) = (&on_file, &effective)
        && file.on == on
        && file.seq == effective.seq
    {
        return Ok(false);
    }
    if on_file.is_none() && effective.is_none() && on {
        // Nothing was ever said and on is the default: there is nothing to sign.
        return Ok(false);
    }
    let high = read_swarm_memory(channel, project_id)
        .high
        .max(on_file.as_ref().map_or(0, |file| file.seq))
        .max(effective.as_ref().map_or(0, |setting| setting.seq));
    let (set_at, seq) = (Utc::now(), high + 1);
    let setting = SwarmSetting {
        project_id: project_id.to_owned(),
        on,
        seq,
        set_at,
        signed_by: signer.name().to_owned(),
        signature: hex::encode(
            signer
                .signing
                .sign(swarm_payload(project_id, on, seq, &set_at).as_bytes())
                .to_bytes(),
        ),
    };
    let path = channel.join(SWARM);
    crate::atomic_json(&path, &setting).with_context(|| format!("writing {}", path.display()))?;
    remember_swarm(channel, project_id, &setting);
    Ok(true)
}

/// Whether two paths are the same place. Compared after resolving where they can be, folded
/// on Windows (where `X:\Ferry` and `x:\ferry` are one directory, and a temporary folder has
/// a short and a long spelling).
fn same_place(a: &Path, b: &Path) -> bool {
    let norm = |path: &Path| {
        let resolved = std::fs::canonicalize(path).map_or_else(
            |_| path.to_path_buf(),
            |resolved| crate::real_path(&resolved),
        );
        let text = resolved.display().to_string().replace('\\', "/");
        let text = text.trim_end_matches('/').to_owned();
        if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
        }
    };
    norm(a) == norm(b)
}

impl Entry {
    /// Whether the project's master has taken it out of the swarm.
    #[must_use]
    pub fn swarm_off(&self) -> bool {
        !swarm_enabled(&self.channel, &self.project_id)
    }
}

/// The latest week the self-improvement loop wrote anything for in `channel`, and which
/// of its steps that week holds: `evidence`, `plan`, `review`, `report`. `None` when it
/// has never run there. Read from `improve/<ISO week>/` in the channel.
#[must_use]
pub fn improve_last_run(channel: &Path) -> Option<(String, Vec<&'static str>)> {
    let week = std::fs::read_dir(channel.join("improve"))
        .ok()?
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name.len() == 8 && name.as_bytes()[4] == b'-')
        .max()?;
    let dir = channel.join("improve").join(&week);
    let steps = [
        ("evidence.md", "evidence"),
        ("plan.json", "plan"),
        ("plan-review.md", "review"),
        ("report.md", "report"),
    ]
    .into_iter()
    .filter(|(file, _)| dir.join(file).is_file())
    .map(|(_, step)| step)
    .collect();
    Some((week, steps))
}

/// What a ferry root holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Manifest {
    /// Format tag, so a future layout can be told from this one.
    #[serde(default = "manifest_version")]
    pub version: u32,
    #[serde(default)]
    pub projects: Vec<Entry>,
}

fn manifest_version() -> u32 {
    1
}

/// A ferry root on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub path: PathBuf,
}

impl Root {
    #[must_use]
    pub fn comms(&self) -> PathBuf {
        self.path.join("comms")
    }
    #[must_use]
    pub fn repos(&self) -> PathBuf {
        self.path.join("repos")
    }
    /// Where task worktrees go.
    ///
    /// Not beside the repository, which is where they went before. They are transient and
    /// belong to Ferryman, and putting them in a directory the user made both litters it
    /// and makes a scan of it find things that are not projects.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.path.join("work")
    }
    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        self.path.join(MANIFEST)
    }

    /// Create the layout and an empty manifest. Safe to run again.
    pub fn create(path: &Path) -> Result<Self> {
        let root = Self {
            path: path.to_path_buf(),
        };
        for dir in [root.comms(), root.repos(), root.work()] {
            std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }
        if !root.manifest_path().is_file() {
            root.write(&Manifest {
                version: manifest_version(),
                projects: Vec::new(),
            })?;
        }
        remember_root(&root.path);
        Ok(root)
    }

    /// Read the manifest. A missing or unreadable one is an empty manifest, never an
    /// error: this is an index, and a broken index must cost only its convenience.
    #[must_use]
    pub fn read(&self) -> Manifest {
        std::fs::read_to_string(self.manifest_path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn write(&self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec_pretty(manifest)?;
        let temporary = self.path.join(".ferry.tmp");
        std::fs::write(&temporary, json)
            .with_context(|| format!("write {}", temporary.display()))?;
        std::fs::rename(&temporary, self.manifest_path())
            .with_context(|| format!("write {}", self.manifest_path().display()))
    }

    /// Record a project, and where its repository is. Nothing on disk is moved.
    ///
    /// `repo` is taken as given. If it sits outside this root it is marked adopted, which
    /// is the flag everything else reads before deciding whether it may touch it.
    ///
    /// Returns whether it was filed. A scratch project is not, and that is not an error:
    /// see `would_outlive_the_project` for the one case this refuses and why.
    pub fn adopt(&self, project_id: &str, channel: &Path, repo: Option<&Path>) -> Result<bool> {
        if self.would_outlive_the_project(channel) {
            return Ok(false);
        }
        let mut manifest = self.read();
        let adopted = repo.is_some_and(|repo| !repo.starts_with(&self.path));
        let entry = Entry {
            project_id: project_id.to_string(),
            channel: channel.to_path_buf(),
            repo: repo.map(Path::to_path_buf),
            adopted,
            human_checkouts: Vec::new(),
        };
        match manifest
            .projects
            .iter_mut()
            .find(|existing| existing.project_id == project_id)
        {
            // Merge rather than replace. One project can be adopted from two places on
            // one machine - a checkout that has the work, and a synced channel directory
            // that does not - and letting the second overwrite the first threw away the
            // repository path it had already learned. Losing what you knew is worse than
            // not learning anything, and it is silent, which is worse again.
            Some(existing) => {
                existing.channel = entry.channel;
                if let Some(new_repo) = entry.repo {
                    let managed_now = existing
                        .repo
                        .as_deref()
                        .is_some_and(|repo| self.is_managed(repo));
                    let managed_new = self.is_managed(&new_repo);
                    if managed_now && !managed_new && existing.repo.as_ref() != Some(&new_repo) {
                        // Ferryman's own clone stays the one its workers use. A person's
                        // working copy that gets filed afterwards (an `enable`, an
                        // `attach`) is remembered beside it and nothing more.
                        if !existing
                            .human_checkouts
                            .iter()
                            .any(|known| same_place(known, &new_repo))
                        {
                            existing.human_checkouts.push(new_repo);
                        }
                    } else {
                        if managed_new
                            && let Some(old) = existing.repo.take()
                            && !same_place(&old, &new_repo)
                            && !existing
                                .human_checkouts
                                .iter()
                                .any(|known| same_place(known, &old))
                        {
                            existing.human_checkouts.push(old);
                        }
                        existing
                            .human_checkouts
                            .retain(|human| !same_place(human, &new_repo));
                        existing.repo = Some(new_repo);
                        existing.adopted = entry.adopted;
                    }
                }
                // The archive marker is deliberately not touched. Filing a project again
                // is something `enable` does on its own, and a project quietly coming back
                // from the archive because a command was re-run is the kind of silent
                // state change this index has been bitten by before. Coming back is
                // `archive --restore`, which is a thing someone chose to type.
            }
            None => manifest.projects.push(entry),
        }
        manifest
            .projects
            .sort_by(|a, b| a.project_id.cmp(&b.project_id));
        self.write(&manifest)?;
        Ok(true)
    }

    /// Whether filing this channel would leave the index pointing at a directory that
    /// disappears while the index does not.
    ///
    /// A channel under the machine's temporary directory is scratch: a test fixture, or
    /// a one-off run. Filing one into a durable root writes a path that will not exist
    /// in a minute, and because `adopt` merges by project id, a scratch project sharing
    /// a name with a real one OVERWRITES the real one's path. That is not hypothetical -
    /// it is how four live projects on this machine came to point at deleted
    /// `AppData\Local\Temp\.tmp*` directories: the test suite ran `enable` in temp
    /// workspaces, and each one filed itself into the operator's real ferry root.
    ///
    /// A temporary root filing a temporary channel is fine and is what the tests here
    /// do - both vanish together. The damage is only ever scratch into durable.
    fn would_outlive_the_project(&self, channel: &Path) -> bool {
        under_temp_dir(channel) && !under_temp_dir(&self.path)
    }

    /// The projects work can happen in: on disk, and not archived.
    ///
    /// An entry whose channel has gone is dropped rather than returned: offering a
    /// project that cannot be opened looks, to the person who picks it, exactly like the
    /// software ignoring them. An archived one is dropped for the opposite reason - it
    /// can be opened perfectly well, and is simply finished.
    ///
    /// Callers asking "where does work happen here" want this. Callers asking "what does
    /// this machine hold" want `read().projects`, and the two are not the same question.
    #[must_use]
    pub fn projects(&self) -> Vec<Entry> {
        self.read()
            .projects
            .into_iter()
            .filter(|entry| entry.channel.is_dir() && !entry.is_archived())
            .collect()
    }

    /// The finished ones, still on disk.
    #[must_use]
    pub fn archived(&self) -> Vec<Entry> {
        self.read()
            .projects
            .into_iter()
            .filter(Entry::is_archived)
            .collect()
    }

    /// Mark a project finished, or bring it back - on every machine that syncs it.
    ///
    /// Only the project's master may do either, and `signer` must be the master by the
    /// key the channel knows them by: a name alone proves nothing.
    ///
    /// Nothing moves and nothing is unshared. That is the whole point: the channel keeps
    /// its signed history, Syncthing keeps carrying it, and the project simply stops
    /// being offered as somewhere work happens. The one thing written is the signed
    /// [`ARCHIVED`] marker in the channel, which is how the other machines hear about it.
    ///
    /// Returns whether anything changed. Archiving an already-archived project is not an
    /// error - the desired state is that it is archived, and it is.
    pub fn archive(
        &self,
        project_id: &str,
        archived: bool,
        signer: &AgentIdentity,
    ) -> Result<bool> {
        let manifest = self.read();
        let entry = manifest
            .projects
            .iter()
            .find(|entry| entry.project_id == project_id)
            .with_context(|| {
                format!(
                    "no project '{project_id}' in {}",
                    self.manifest_path().display()
                )
            })?;
        set_archived(&entry.channel, project_id, archived, signer)
    }

    /// Declare `person` master of every project here whose channel has none.
    ///
    /// One unlocked identity, every channel: the CLI's `ferry root master` and the
    /// dashboard both come through here. A project with a master is left alone - a
    /// master is handed over, never taken - and so is one whose channel knows the
    /// person's name by a different key. See [`crate::master::claim_if_masterless`].
    pub fn claim_masters(
        &self,
        person: &AgentIdentity,
    ) -> Vec<(String, Result<crate::master::Claim>)> {
        self.read()
            .projects
            .into_iter()
            .filter(|entry| entry.channel.is_dir())
            .map(|entry| {
                // Machine-local state lives beside the repository; a channel-only
                // project uses the directory its channel sits in, as the roster's pins
                // already do.
                let attachment = entry
                    .repo
                    .as_ref()
                    .map(|repo| repo.join(".ferryman"))
                    .filter(|attachment| attachment.is_dir())
                    .or_else(|| entry.channel.parent().map(Path::to_path_buf))
                    .unwrap_or_else(|| self.path.clone());
                let outcome = crate::master::claim_if_masterless(
                    &entry.channel,
                    &entry.project_id,
                    &attachment,
                    person,
                );
                (entry.project_id, outcome)
            })
            .collect()
    }

    /// Where this project's channel belongs once it lives in the root.
    #[must_use]
    pub fn comms_home(&self, project_id: &str) -> PathBuf {
        self.comms().join(format!("{project_id}-ferryman"))
    }

    /// Move one project's channel into `comms/`, so every channel lives in one place.
    ///
    /// `adopt` deliberately moves nothing, which is right when you are recording what
    /// already exists. It is wrong as the only option: channels then accumulate wherever
    /// each `ferry enable` happened to run, and answering "where is everything" means
    /// reading a manifest of scattered paths and hoping it is current.
    ///
    /// Only the channel directory moves. Keys, `agent.toml` and `bridge.toml` stay in the
    /// project's `.ferryman/` where they were: the keys are the reason - they are never
    /// synced, and moving them into the directory Syncthing carries is precisely the
    /// mistake this software exists to make impossible.
    ///
    /// Safe across machines, which is the part that looks alarming and is not: a Syncthing
    /// folder's path is local to each device and the folder id is what peers match on. A
    /// channel gathered here keeps its id, so every other machine goes on syncing it at
    /// its own path, and nothing re-pairs.
    pub fn gather(&self, project_id: &str, dry_run: bool) -> Result<Gathered> {
        let manifest = self.read();
        let entry = manifest
            .projects
            .iter()
            .find(|entry| entry.project_id == project_id)
            .with_context(|| {
                format!(
                    "no project '{project_id}' in {}",
                    self.manifest_path().display()
                )
            })?
            .clone();
        let from = entry.channel.clone();
        let to = self.comms_home(project_id);

        let mut gathered = Gathered {
            project_id: project_id.to_string(),
            from: from.clone(),
            to: to.clone(),
            moved: false,
            note: String::new(),
        };
        if from == to {
            gathered.note = "already in the root".to_string();
            return Ok(gathered);
        }
        if !from.is_dir() {
            gathered.note = format!("channel {} is not on this machine", from.display());
            return Ok(gathered);
        }
        if to.exists() && std::fs::read_dir(&to).is_ok_and(|mut d| d.next().is_some()) {
            bail!(
                "{} already holds something; move it aside before gathering '{project_id}'",
                to.display()
            );
        }
        if dry_run {
            gathered.note = "would move".to_string();
            return Ok(gathered);
        }

        std::fs::create_dir_all(self.comms())?;
        move_directory(&from, &to)
            .with_context(|| format!("move {} to {}", from.display(), to.display()))?;
        // The manifest and bridge.toml must agree, and bridge.toml is what the running
        // agent reads. Rewriting the index alone would leave the worker writing into a
        // directory that is no longer the channel.
        repoint_bridge(&from, &to)?;
        // Other checkouts read the same channel through their own bridge.toml: the person's
        // checkout the root files, and Ferryman's own clone in `repos/`. Left alone they keep
        // naming the old path, and `repos sync` then refuses the clone as a second channel.
        for checkout in [entry.repo.clone(), Some(self.repos().join(project_id))]
            .into_iter()
            .flatten()
        {
            repoint_bridge_if_reads(&checkout.join(".ferryman").join("bridge.toml"), &from, &to)?;
        }
        self.adopt(project_id, &to, entry.repo.as_deref())?;
        gathered.moved = true;
        gathered.note = "moved".to_string();
        Ok(gathered)
    }

    /// Remove one project from the manifest. Nothing on disk is touched.
    ///
    /// The index could be added to and never subtracted from, and the omission was not
    /// visible: `projects` drops an entry whose channel has gone, so a dead one vanishes
    /// from every listing while staying in the file forever. That reads exactly like a
    /// project that was never adopted, which is the one thing it must not be confused
    /// with - the whole point of the index is to tell "nobody recorded this" apart from
    /// "this was recorded and is now unreachable".
    ///
    /// Returns whether an entry was removed. Forgetting an unknown project is not an
    /// error: the desired state is that it is absent, and it is.
    pub fn forget(&self, project_id: &str) -> Result<bool> {
        let mut manifest = self.read();
        let before = manifest.projects.len();
        manifest
            .projects
            .retain(|entry| entry.project_id != project_id);
        if manifest.projects.len() == before {
            return Ok(false);
        }
        self.write(&manifest)?;
        Ok(true)
    }

    /// Every manifest entry whose channel is not on this machine.
    ///
    /// Read this rather than `projects` when the question is what the index claims, not
    /// what it can open: these are the entries `projects` hides.
    #[must_use]
    pub fn unreachable(&self) -> Vec<Entry> {
        self.read()
            .projects
            .into_iter()
            .filter(|entry| !entry.channel.is_dir())
            .collect()
    }

    /// Where Ferryman's own clone of a project lives: `repos/<project>`.
    ///
    /// The fixed place. Workers use it and nothing else of the project's, and a person's
    /// working copy is never it. See `docs/LAYOUT.md`.
    #[must_use]
    pub fn managed_clone(&self, project_id: &str) -> PathBuf {
        self.repos().join(project_id)
    }

    /// Whether `repo` is a managed clone: a folder directly under this root's `repos/`.
    #[must_use]
    pub fn is_managed(&self, repo: &Path) -> bool {
        let fold = |path: &Path| {
            let text = path.display().to_string().replace('\\', "/");
            let text = text.trim_end_matches('/').to_string();
            if cfg!(windows) {
                text.to_lowercase()
            } else {
                text
            }
        };
        repo.parent()
            .is_some_and(|parent| fold(parent) == fold(&self.repos()))
    }

    /// Make `managed` the repository this project's workers use, and remember the one it
    /// replaces as a human checkout. Nothing on disk moves. Returns whether the manifest
    /// changed.
    pub fn set_managed_repo(&self, project_id: &str, managed: &Path) -> Result<bool> {
        let mut manifest = self.read();
        let Some(entry) = manifest
            .projects
            .iter_mut()
            .find(|entry| entry.project_id == project_id)
        else {
            bail!(
                "no project '{project_id}' in {}",
                self.manifest_path().display()
            );
        };
        let before = entry.clone();
        if let Some(old) = entry.repo.take()
            && !same_place(&old, managed)
            && !entry
                .human_checkouts
                .iter()
                .any(|known| same_place(known, &old))
        {
            entry.human_checkouts.push(old);
        }
        entry
            .human_checkouts
            .retain(|human| !same_place(human, managed));
        entry.repo = Some(managed.to_path_buf());
        entry.adopted = false;
        if *entry == before {
            return Ok(false);
        }
        self.write(&manifest)?;
        Ok(true)
    }

    /// Remember a person's working copy of a project, for information. Returns whether the
    /// manifest changed. Does nothing for the repository the workers use.
    pub fn note_human_checkout(&self, project_id: &str, checkout: &Path) -> Result<bool> {
        let mut manifest = self.read();
        let Some(entry) = manifest
            .projects
            .iter_mut()
            .find(|entry| entry.project_id == project_id)
        else {
            return Ok(false);
        };
        if entry
            .repo
            .as_deref()
            .is_some_and(|repo| same_place(repo, checkout))
            || entry
                .human_checkouts
                .iter()
                .any(|known| same_place(known, checkout))
        {
            return Ok(false);
        }
        entry.human_checkouts.push(checkout.to_path_buf());
        self.write(&manifest)?;
        Ok(true)
    }

    /// Put a link to an adopted repository in `repos/`, so the tidy view exists without
    /// anything having been moved.
    ///
    /// Best-effort by design: a link is a convenience, and a platform or filesystem that
    /// will not make one loses nothing that matters. The manifest is what discovery
    /// reads.
    pub fn link_repo(&self, project_id: &str, repo: &Path) -> Result<Option<PathBuf>> {
        if repo.starts_with(&self.path) {
            return Ok(None);
        }
        std::fs::create_dir_all(self.repos())?;
        let link = self.repos().join(project_id);
        if link.exists() {
            return Ok(Some(link));
        }
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(repo, &link).is_ok();
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(repo, &link).is_ok();
        #[cfg(not(any(unix, windows)))]
        let made = false;
        Ok(made.then_some(link))
    }
}

/// What gathering one project did, or would do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gathered {
    pub project_id: String,
    pub from: PathBuf,
    pub to: PathBuf,
    /// False when nothing needed doing, or when this was a dry run.
    pub moved: bool,
    pub note: String,
}

/// Move a directory, falling back to copy-then-remove across filesystems.
///
/// `rename` is the whole operation on one volume and cannot half-happen, which is what
/// you want for something an agent may be writing into. Across volumes there is no such
/// primitive, so the copy is done first and the original removed only once every file
/// arrived - a crash in the middle leaves both, which is recoverable, rather than
/// neither, which is not.
fn move_directory(from: &Path, to: &Path) -> Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    copy_tree(from, to)?;
    std::fs::remove_dir_all(from).with_context(|| format!("remove {}", from.display()))
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to).with_context(|| format!("create {}", to.display()))?;
    for entry in std::fs::read_dir(from).with_context(|| format!("read {}", from.display()))? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)
                .with_context(|| format!("copy {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Point `bridge.toml` at the channel's new home.
///
/// Rewritten a line at a time rather than through a TOML round trip. These files carry
/// Windows paths written literally - `X:\project` - which a strict TOML writer would
/// re-escape, changing every path in the file to fix one. Touch the one line that moved.
fn repoint_bridge(old_channel: &Path, new_channel: &Path) -> Result<()> {
    let Some(attachment) = old_channel.parent() else {
        return Ok(());
    };
    let bridge = attachment.join("bridge.toml");
    if !bridge.is_file() {
        return Ok(());
    }
    let text =
        std::fs::read_to_string(&bridge).with_context(|| format!("read {}", bridge.display()))?;
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("communications") && line.contains('=') {
                format!("communications = \"{}\"", new_channel.display())
            } else {
                line.to_string()
            }
        })
        .collect();
    let mut out = rewritten.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(&bridge, out).with_context(|| format!("write {}", bridge.display()))
}

/// Point `bridge` at `new_channel` if, and only if, it reads `old_channel` now.
///
/// A checkout attached to some other channel is not this move's business, so it is left
/// exactly as it is.
fn repoint_bridge_if_reads(bridge: &Path, old_channel: &Path, new_channel: &Path) -> Result<()> {
    let Ok(text) = std::fs::read_to_string(bridge) else {
        return Ok(());
    };
    let fold = |path: &str| {
        let text = path.replace('\\', "/").trim_end_matches('/').to_string();
        if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
        }
    };
    let old = fold(&old_channel.display().to_string());
    let reads_old = text.lines().any(|line| {
        line.trim_start().starts_with("communications")
            && line
                .split_once('=')
                .is_some_and(|(_, value)| fold(value.trim().trim_matches('"')) == old)
    });
    if !reads_old {
        return Ok(());
    }
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("communications") && line.contains('=') {
                format!("communications = \"{}\"", new_channel.display())
            } else {
                line.to_string()
            }
        })
        .collect();
    let mut out = rewritten.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(bridge, out).with_context(|| format!("write {}", bridge.display()))
}

/// Whether a path sits inside this machine's temporary directory.
///
/// Compared as folded text rather than by `canonicalize`, which would fail on a path
/// that has already been cleaned up - and a path that no longer exists is exactly the
/// case this is here to catch.
fn under_temp_dir(path: &Path) -> bool {
    let fold = |path: &Path| {
        let text = path.display().to_string().replace('\\', "/");
        let text = text.trim_end_matches('/').to_string();
        if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
        }
    };
    let temp = fold(&std::env::temp_dir());
    if temp.is_empty() {
        return false;
    }
    let candidate = fold(path);
    candidate == temp || candidate.starts_with(&format!("{temp}/"))
}

fn root_pointer() -> Option<PathBuf> {
    crate::licensing::machine_state_dir().map(|dir| dir.join("ferry-root"))
}

fn remember_root(path: &Path) {
    if let Some(pointer) = root_pointer() {
        if let Some(parent) = pointer.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(pointer, path.display().to_string());
    }
}

/// The ferry root for this machine, if there is one.
///
/// Looked for in the order that respects what the person actually did: an explicit
/// override, then a root they are standing inside, then the one they made.
#[must_use]
pub fn find_root() -> Option<Root> {
    if let Ok(explicit) = std::env::var("FERRYMAN_ROOT")
        && !explicit.is_empty()
    {
        let path = PathBuf::from(explicit);
        if looks_like_root(&path) {
            return Some(Root { path });
        }
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Some(root) = find_root_from(&cwd)
    {
        return Some(root);
    }
    let pointer = root_pointer()?;
    let recorded = std::fs::read_to_string(pointer).ok()?;
    let path = PathBuf::from(recorded.trim());
    looks_like_root(&path).then_some(Root { path })
}

/// Whether a directory is a ferry root.
///
/// The manifest marks one, but the LAYOUT is enough on its own. Deleting `.ferry` was
/// meant to cost only the index; it orphaned the whole root instead, so `ferry root show`
/// answered "no ferry root yet" while comms, repos and work sat there full of things. An
/// index whose loss destroys the thing it indexes is not an index.
fn looks_like_root(dir: &Path) -> bool {
    dir.join(MANIFEST).is_file() || (dir.join("comms").is_dir() && dir.join("work").is_dir())
}

/// Walk up from a directory looking for a root, so being anywhere inside one is enough.
#[must_use]
pub fn find_root_from(start: &Path) -> Option<Root> {
    let mut here = Some(start);
    while let Some(dir) = here {
        if looks_like_root(dir) {
            return Some(Root {
                path: dir.to_path_buf(),
            });
        }
        here = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(dir: &Path) -> Root {
        Root::create(&dir.join("ferry")).unwrap()
    }

    fn channel(dir: &Path, id: &str) -> PathBuf {
        let path = dir.join("comms").join(format!("{id}-ferryman"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn josh() -> crate::AgentIdentity {
        crate::AgentIdentity::from_seed("josh", [7u8; 32])
    }

    /// A channel with a master, and every one of `members` on its roster.
    fn mastered(
        dir: &Path,
        id: &str,
        master: &crate::AgentIdentity,
        members: &[&crate::AgentIdentity],
    ) -> PathBuf {
        let communications = channel(dir, id);
        let mut route = crate::ProjectRoute {
            project_id: id.into(),
            workspace: dir.join(id),
            attachment: dir.join(format!("{id}-attachment")),
            communications: communications.clone(),
            shared_remote: format!("{id}-ferryman"),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in std::iter::once(master).chain(members.iter().copied()) {
            let agent = crate::AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, master, master.name()).unwrap();
        communications
    }

    #[test]
    fn a_root_is_a_layout_and_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        assert!(root.comms().is_dir());
        assert!(root.repos().is_dir());
        assert!(root.work().is_dir());
        assert!(root.manifest_path().is_file());
        assert!(root.projects().is_empty());
    }

    /// Archiving keeps everything and only stops the project being offered.
    #[test]
    fn an_archived_project_leaves_the_working_set_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let live = channel(dir.path(), "live");
        let done = mastered(dir.path(), "done", &josh(), &[]);
        root.adopt("live", &live, None).unwrap();
        root.adopt("done", &done, None).unwrap();
        // Something signed, to prove archiving is not a quiet delete.
        std::fs::write(done.join("ledger.josh.jsonl"), "{\"what\":\"happened\"}\n").unwrap();

        assert!(root.archive("done", true, &josh()).unwrap());

        let working: Vec<String> = root
            .projects()
            .into_iter()
            .map(|entry| entry.project_id)
            .collect();
        assert_eq!(working, vec!["live".to_string()]);
        // Still in the file, still on disk, history intact.
        assert_eq!(root.read().projects.len(), 2);
        assert!(done.is_dir());
        assert_eq!(
            std::fs::read_to_string(done.join("ledger.josh.jsonl")).unwrap(),
            "{\"what\":\"happened\"}\n"
        );
        let archived = root.archived();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].project_id, "done");
    }

    /// And it can be taken back.
    #[test]
    fn an_archived_project_can_be_restored() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let done = mastered(dir.path(), "done", &josh(), &[]);
        root.adopt("done", &done, None).unwrap();

        assert!(root.archive("done", true, &josh()).unwrap());
        assert!(root.projects().is_empty());
        // Saying it twice is not an error; the desired state already holds.
        assert!(!root.archive("done", true, &josh()).unwrap());

        assert!(root.archive("done", false, &josh()).unwrap());
        assert_eq!(root.projects().len(), 1);
        assert!(root.archived().is_empty());
    }

    /// Filing a project again must not quietly un-archive it.
    ///
    /// `enable` files on its own, so a project coming back because a command was re-run
    /// would be a state change nobody asked for and nobody would see.
    #[test]
    fn adopting_an_archived_project_does_not_revive_it() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let done = mastered(dir.path(), "done", &josh(), &[]);
        let repo = dir.path().join("done-repo");
        std::fs::create_dir_all(&repo).unwrap();
        root.adopt("done", &done, None).unwrap();
        root.archive("done", true, &josh()).unwrap();

        root.adopt("done", &done, Some(&repo)).unwrap();

        assert!(root.projects().is_empty(), "still archived");
        let archived = root.archived();
        assert_eq!(archived.len(), 1);
        // The re-adoption's new information was still recorded.
        assert_eq!(archived[0].repo.as_deref(), Some(repo.as_path()));
    }

    /// Archiving is fleet-wide: it travels in the channel, not in the machine-local index.
    ///
    /// Two roots sharing one channel directory is what two machines syncing it look like
    /// from here - Syncthing is what makes the directory the same one.
    #[test]
    fn an_archive_made_on_one_machine_is_seen_on_every_other() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let beastly = root(&dir.path().join("beastly"));
        let grouchly = root(&dir.path().join("grouchly"));
        let shared = mastered(dir.path(), "done", &josh(), &[]);
        beastly.adopt("done", &shared, None).unwrap();
        grouchly.adopt("done", &shared, None).unwrap();

        assert!(beastly.archive("done", true, &josh()).unwrap());
        assert!(
            grouchly.projects().is_empty(),
            "archived there, so archived here"
        );
        assert_eq!(grouchly.archived().len(), 1);
        // And no machine's index was what carried it.
        let index = std::fs::read_to_string(grouchly.manifest_path()).unwrap();
        assert!(!index.contains("archived"), "{index}");

        assert!(grouchly.archive("done", false, &josh()).unwrap());
        assert_eq!(
            beastly.projects().len(),
            1,
            "restored there, so restored here"
        );
    }

    /// A machine without the channel cannot tell the fleet anything, and says so.
    #[test]
    fn archiving_a_channel_that_is_not_here_says_so() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let gone = mastered(dir.path(), "gone", &josh(), &[]);
        root.adopt("gone", &gone, None).unwrap();
        std::fs::remove_dir_all(&gone).unwrap();
        let error = root
            .archive("gone", true, &josh())
            .expect_err("nowhere to write the marker")
            .to_string();
        assert!(error.contains("not on this machine"), "{error}");
    }

    /// Only the master archives, and only the master brings it back.
    #[test]
    fn only_the_master_can_archive_or_restore() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let done = mastered(dir.path(), "done", &josh(), &[&grouchly]);
        root.adopt("done", &done, None).unwrap();

        let error = root
            .archive("done", true, &grouchly)
            .expect_err("a member is not the master")
            .to_string();
        assert!(error.contains("only josh"), "{error}");
        assert_eq!(root.projects().len(), 1);

        // Wearing the master's name with some other key gets nowhere either.
        let impostor = crate::AgentIdentity::from_seed("josh", [9u8; 32]);
        let error = root
            .archive("done", true, &impostor)
            .expect_err("the name is not the key")
            .to_string();
        assert!(error.contains("not the key"), "{error}");
        assert!(!done.join(ARCHIVED).exists(), "nothing was written");

        root.archive("done", true, &josh()).unwrap();
        let error = root
            .archive("done", false, &grouchly)
            .expect_err("a member cannot restore either")
            .to_string();
        assert!(error.contains("only josh"), "{error}");
        assert!(root.projects().is_empty());
    }

    /// A mark anyone but the master wrote is not honoured, on any machine.
    ///
    /// A peer can write any file into the channel. What it cannot do is sign as the
    /// master, and a mark that is not the master's is read as no mark at all.
    #[test]
    fn a_mark_the_master_did_not_sign_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let done = mastered(dir.path(), "done", &josh(), &[&grouchly]);
        root.adopt("done", &done, None).unwrap();

        // Signed, validly, by a member who is not the master.
        crate::atomic_json(&done.join(ARCHIVED), &sign_mark("done", &grouchly)).unwrap();
        assert_eq!(root.projects().len(), 1, "a member's mark is not honoured");

        // The master's own mark, lifted from another project, does not carry across.
        crate::atomic_json(&done.join(ARCHIVED), &sign_mark("elsewhere", &josh())).unwrap();
        assert_eq!(
            root.projects().len(),
            1,
            "another project's mark is not honoured"
        );

        // Nor does a file that is merely called ARCHIVED.
        std::fs::write(done.join(ARCHIVED), "archived, trust me\n").unwrap();
        assert_eq!(root.projects().len(), 1, "an unsigned mark is not honoured");

        // The master's restore clears the litter.
        assert!(!root.archive("done", false, &josh()).unwrap());
        assert!(!done.join(ARCHIVED).exists());
    }

    /// With no master there is nobody who may archive, and it says so.
    #[test]
    fn a_project_with_no_master_cannot_be_archived() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let orphan = channel(dir.path(), "orphan");
        root.adopt("orphan", &orphan, None).unwrap();
        let error = root
            .archive("orphan", true, &josh())
            .expect_err("no master, no archive")
            .to_string();
        assert!(error.contains("no master"), "{error}");
    }

    /// One identity claims every unclaimed project, and nothing that is someone else's.
    #[test]
    fn claiming_masters_takes_the_unclaimed_and_leaves_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let ada = crate::AgentIdentity::from_seed("ada", [3u8; 32]);
        let open = channel(dir.path(), "open");
        let hers = mastered(dir.path(), "hers", &ada, &[]);
        root.adopt("open", &open, None).unwrap();
        root.adopt("hers", &hers, None).unwrap();

        let mut outcomes = root.claim_masters(&josh());
        outcomes.sort_by(|a, b| a.0.cmp(&b.0));
        let outcomes: Vec<(String, crate::master::Claim)> = outcomes
            .into_iter()
            .map(|(id, outcome)| (id, outcome.unwrap()))
            .collect();
        assert_eq!(
            outcomes,
            vec![
                (
                    "hers".to_string(),
                    crate::master::Claim::Other("ada".into())
                ),
                ("open".to_string(), crate::master::Claim::Declared),
            ]
        );
        assert_eq!(master_of(&open).unwrap().as_deref(), Some("josh"));
        assert_eq!(master_of(&hers).unwrap().as_deref(), Some("ada"));
    }

    /// Archiving something that was never filed is an error naming it, not a silent no-op.
    #[test]
    fn archiving_an_unknown_project_says_which_one() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let error = root
            .archive("never-filed", true, &josh())
            .expect_err("an unknown project is not archivable")
            .to_string();
        assert!(error.contains("never-filed"), "{error}");
    }

    /// The asymmetry that let the index rot: everything filed, nothing ever removed.
    #[test]
    fn a_project_can_be_forgotten_and_the_rest_are_untouched() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let keep = channel(dir.path(), "keep");
        let drop = channel(dir.path(), "drop");
        root.adopt("keep", &keep, None).unwrap();
        root.adopt("drop", &drop, None).unwrap();

        assert!(root.forget("drop").unwrap());

        let left = root.read().projects;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].project_id, "keep");
        // The index is what changed. The channel is not the index's to delete.
        assert!(drop.is_dir());
    }

    /// Forgetting what is not there is the desired state, not a failure.
    #[test]
    fn forgetting_an_unknown_project_changes_nothing_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let kept = channel(dir.path(), "kept");
        root.adopt("kept", &kept, None).unwrap();

        assert!(!root.forget("never-existed").unwrap());
        assert_eq!(root.read().projects.len(), 1);
    }

    /// The entries `projects` hides, which is how a dead one stayed invisible.
    #[test]
    fn an_entry_whose_channel_is_gone_is_unreachable_rather_than_absent() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let here = channel(dir.path(), "here");
        let gone = channel(dir.path(), "gone");
        root.adopt("here", &here, None).unwrap();
        root.adopt("gone", &gone, None).unwrap();
        std::fs::remove_dir_all(&gone).unwrap();

        // What every listing shows.
        let listed = root.projects();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].project_id, "here");
        // What the file actually claims.
        assert_eq!(root.read().projects.len(), 2);
        // And the difference, named.
        let stale = root.unreachable();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].project_id, "gone");

        assert!(root.forget("gone").unwrap());
        assert!(root.unreachable().is_empty());
        assert_eq!(root.read().projects.len(), 1);
    }

    /// The exact damage this rule exists to stop, reproduced.
    ///
    /// A scratch run in a temp workspace filed itself into the operator's durable root
    /// and, because filing merges by project id, overwrote a live project's channel path
    /// with a directory that was deleted seconds later. Four real projects on one machine
    /// went that way in an afternoon.
    #[test]
    fn a_scratch_project_cannot_overwrite_a_real_one_in_a_durable_root() {
        let scratch = std::env::temp_dir().join("ferryman-scratch/alpha-ferryman");
        // Not created on disk: the rule is about where a path IS, and every other test
        // here builds its root inside a temp directory, so this one has to name
        // somewhere that is not.
        let durable_root = Root {
            path: if cfg!(windows) {
                PathBuf::from(r"X:\ferry")
            } else {
                PathBuf::from("/home/josh/ferry")
            },
        };
        let durable_channel = durable_root.comms().join("alpha-ferryman");
        let temporary_root = Root {
            path: std::env::temp_dir().join("ferryman-root"),
        };

        // The case that did the damage: scratch filed into a durable root.
        assert!(durable_root.would_outlive_the_project(&scratch));
        // And the three that are fine.
        assert!(!durable_root.would_outlive_the_project(&durable_channel));
        assert!(!temporary_root.would_outlive_the_project(&scratch));
        assert!(!temporary_root.would_outlive_the_project(&durable_channel));
    }

    /// The rule must not fire on the ordinary case of a root that is itself temporary,
    /// which is what every test here builds. Both vanish together, so nothing is stranded.
    #[test]
    fn a_temporary_root_still_files_its_own_temporary_projects() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let channel = channel(&root.path, "alpha");
        assert!(root.adopt("alpha", &channel, None).unwrap());
        assert_eq!(root.projects().len(), 1);
    }

    /// Gathering brings the channel home, leaves the keys where they were, and tells the
    /// truth in both places that record where the channel is. Getting either half wrong
    /// leaves a worker writing into a directory that is no longer the channel.
    #[test]
    fn gathering_moves_the_channel_and_never_the_keys() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = dir.path().join("scattered/my-repo");
        let attachment = repo.join(".ferryman");
        let scattered = attachment.join("ferryman");
        std::fs::create_dir_all(scattered.join("tasks")).unwrap();
        std::fs::write(scattered.join("tasks/one.json"), "{}").unwrap();
        std::fs::create_dir_all(attachment.join("keys")).unwrap();
        std::fs::write(attachment.join("keys/secret"), "never synced").unwrap();
        std::fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"alpha\"\ncommunications = \"{}\"\ngrants = \"open\"\n",
                scattered.display()
            ),
        )
        .unwrap();
        root.adopt("alpha", &scattered, Some(&repo)).unwrap();

        let gathered = root.gather("alpha", false).unwrap();
        assert!(gathered.moved);
        assert_eq!(gathered.to, root.comms_home("alpha"));

        // The channel and its contents came across.
        assert!(root.comms_home("alpha").join("tasks/one.json").is_file());
        assert!(!scattered.exists());

        // The keys did NOT. They are never synced, and the directory we just moved is
        // the one Syncthing carries.
        assert!(attachment.join("keys/secret").is_file());

        // Both records agree with each other and with the disk.
        assert_eq!(root.projects()[0].channel, root.comms_home("alpha"));
        let bridge = std::fs::read_to_string(attachment.join("bridge.toml")).unwrap();
        assert!(bridge.contains(&format!(
            "communications = \"{}\"",
            root.comms_home("alpha").display()
        )));
        assert!(
            bridge.contains("grants = \"open\""),
            "the rest is untouched"
        );
    }

    /// `ferry enable` also makes Ferryman's own clone in `repos/`, with a bridge.toml naming
    /// the channel where it was then. Gathering must move that clone's pointer too, or
    /// `repos sync` refuses the clone as a second channel.
    #[test]
    fn gathering_repoints_the_managed_clone_and_leaves_other_channels_alone() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let bridge = |at: &Path, channel: &Path| {
            std::fs::create_dir_all(at.join(".ferryman")).unwrap();
            std::fs::write(
                at.join(".ferryman/bridge.toml"),
                format!(
                    "project = \"alpha\"\ncommunications = \"{}\"\n",
                    channel.display()
                ),
            )
            .unwrap();
        };
        let repo = dir.path().join("scattered/my-repo");
        let scattered = repo.join(".ferryman/ferryman");
        std::fs::create_dir_all(&scattered).unwrap();
        bridge(&repo, &scattered);
        let clone = root.repos().join("alpha");
        bridge(&clone, &scattered);
        let other = dir.path().join("elsewhere");
        let unrelated = dir.path().join("some/other/channel");
        bridge(&other, &unrelated);
        root.adopt("alpha", &scattered, Some(&repo)).unwrap();

        root.gather("alpha", false).unwrap();
        let home = format!(
            "communications = \"{}\"",
            root.comms_home("alpha").display()
        );
        let read = |at: &Path| std::fs::read_to_string(at.join(".ferryman/bridge.toml")).unwrap();
        assert!(read(&repo).contains(&home));
        assert!(
            read(&clone).contains(&home),
            "the managed clone moved with it"
        );
        assert!(
            read(&other).contains(&unrelated.display().to_string()),
            "a checkout of another channel is not touched"
        );
    }

    /// Setup runs more than once and people re-run commands. Gathering something already
    /// gathered must be a no-op, not a move onto itself.
    #[test]
    fn gathering_twice_moves_nothing_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let scattered = dir.path().join("elsewhere/beta-ferryman");
        std::fs::create_dir_all(&scattered).unwrap();
        std::fs::write(scattered.join("keep"), "me").unwrap();
        root.adopt("beta", &scattered, None).unwrap();

        assert!(root.gather("beta", false).unwrap().moved);
        let second = root.gather("beta", false).unwrap();
        assert!(!second.moved);
        assert_eq!(second.note, "already in the root");
        assert!(root.comms_home("beta").join("keep").is_file());
    }

    /// A dry run must be readable and must not touch the disk, because the whole point
    /// of offering one is to be believed before seventeen channels move at once.
    #[test]
    fn a_dry_run_says_what_would_happen_and_does_none_of_it() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let scattered = dir.path().join("elsewhere/gamma-ferryman");
        std::fs::create_dir_all(&scattered).unwrap();
        root.adopt("gamma", &scattered, None).unwrap();

        let planned = root.gather("gamma", true).unwrap();
        assert!(!planned.moved);
        assert_eq!(planned.note, "would move");
        assert_eq!(planned.to, root.comms_home("gamma"));
        assert!(scattered.is_dir(), "still where it was");
        assert!(!root.comms_home("gamma").exists());
        assert_eq!(root.projects()[0].channel, scattered);
    }

    /// Refusing beats merging. Two channels landing in one directory is not something a
    /// person can unpick afterwards.
    #[test]
    fn gathering_onto_an_occupied_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let scattered = dir.path().join("elsewhere/delta-ferryman");
        std::fs::create_dir_all(&scattered).unwrap();
        root.adopt("delta", &scattered, None).unwrap();

        let occupied = root.comms_home("delta");
        std::fs::create_dir_all(&occupied).unwrap();
        std::fs::write(occupied.join("someone-elses"), "data").unwrap();

        assert!(root.gather("delta", false).is_err());
        assert!(scattered.is_dir(), "nothing was moved out");
        assert!(occupied.join("someone-elses").is_file(), "nor overwritten");
    }

    /// The rule this whole module exists to keep: adoption records, it does not move.
    #[test]
    fn adopting_a_repository_leaves_it_exactly_where_it_was() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = dir.path().join("somewhere/else/my-repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("marker"), "mine").unwrap();
        let channel = channel(&root.path, "alpha");

        root.adopt("alpha", &channel, Some(&repo)).unwrap();

        assert!(
            repo.join("marker").is_file(),
            "the repository must not have moved"
        );
        let entry = &root.projects()[0];
        assert_eq!(entry.repo.as_deref(), Some(repo.as_path()));
        assert!(
            entry.adopted,
            "a repo outside the root is adopted, never owned"
        );
    }

    #[test]
    fn a_repository_created_inside_the_root_is_not_marked_adopted() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = root.repos().join("ours");
        std::fs::create_dir_all(&repo).unwrap();
        root.adopt("ours", &channel(&root.path, "ours"), Some(&repo))
            .unwrap();

        assert!(!root.projects()[0].adopted);
    }

    #[test]
    fn a_project_whose_channel_has_gone_is_dropped_rather_than_offered() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let gone = channel(&root.path, "gone");
        root.adopt("gone", &gone, None).unwrap();
        root.adopt("here", &channel(&root.path, "here"), None)
            .unwrap();
        std::fs::remove_dir_all(&gone).unwrap();

        let ids: Vec<String> = root.projects().into_iter().map(|p| p.project_id).collect();
        assert_eq!(ids, vec!["here"]);
    }

    #[test]
    fn adopting_the_same_project_twice_updates_it_rather_than_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let channel = channel(&root.path, "alpha");

        let first = dir.path().join("a");
        let second = dir.path().join("b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();

        root.adopt("alpha", &channel, Some(&first)).unwrap();
        root.adopt("alpha", &channel, Some(&second)).unwrap();

        let projects = root.projects();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].repo.as_deref(), Some(second.as_path()));
    }

    /// Found by running it: one project can be adopted twice on one machine - once from
    /// the checkout that has the work, once from a synced channel directory that does
    /// not - and the second must not erase what the first knew.
    #[test]
    fn adopting_a_channel_only_copy_does_not_forget_where_the_repository_is() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = dir.path().join("checkout");
        std::fs::create_dir_all(&repo).unwrap();
        let from_checkout = channel(&root.path, "alpha");
        root.adopt("alpha", &from_checkout, Some(&repo)).unwrap();

        // The same project, reached through a synced channel with no repo beside it.
        let synced = dir.path().join("synced/alpha-ferryman");
        std::fs::create_dir_all(&synced).unwrap();
        root.adopt("alpha", &synced, None).unwrap();

        let entry = &root.projects()[0];
        assert_eq!(entry.channel, synced, "the newer channel path wins");
        assert_eq!(
            entry.repo.as_deref(),
            Some(repo.as_path()),
            "but the repository it already knew is not forgotten"
        );
        assert!(entry.adopted);
    }

    /// The manifest is an index, never authority. Losing it costs its convenience and
    /// nothing else.
    #[test]
    fn a_broken_manifest_reads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        root.adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();

        std::fs::write(root.manifest_path(), "{ not json at all").unwrap();
        assert!(
            root.projects().is_empty(),
            "a broken index must not be fatal"
        );

        // And it heals by being used again.
        root.adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();
        assert_eq!(root.projects().len(), 1);
    }

    /// The promise the index makes: losing it costs the index, not the root.
    #[test]
    fn deleting_the_manifest_does_not_lose_the_root() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        root.adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();

        std::fs::remove_file(root.manifest_path()).unwrap();

        let found = find_root_from(&root.path).expect("the layout is still a root");
        assert_eq!(found.path, root.path);
        assert!(found.projects().is_empty());

        // And it refills by being used.
        found
            .adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();
        assert_eq!(found.projects().len(), 1);
    }

    #[test]
    fn standing_anywhere_inside_a_root_finds_it() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let deep = root.work().join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(find_root_from(&deep).unwrap().path, root.path);

        // And outside one, nothing is invented.
        assert!(find_root_from(dir.path()).is_none());
    }

    /// Off until the master says on; the master's word travels with the channel; nobody
    /// else's counts, however it got there.
    #[test]
    fn self_improve_is_off_by_default_and_only_the_master_switches_it() {
        let dir = tempfile::tempdir().unwrap();
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let channel = mastered(dir.path(), "demo", &josh(), &[&grouchly]);

        assert!(!self_improve_enabled(&channel, "demo"), "off by default");

        let error = set_self_improve(&channel, "demo", true, &grouchly)
            .expect_err("a member is not the master")
            .to_string();
        assert!(error.contains("only josh"), "{error}");
        let impostor = crate::AgentIdentity::from_seed("josh", [9u8; 32]);
        let error = set_self_improve(&channel, "demo", true, &impostor)
            .expect_err("the name is not the key")
            .to_string();
        assert!(error.contains("not the key"), "{error}");
        assert!(!channel.join(SELF_IMPROVE).exists(), "nothing was written");

        assert!(set_self_improve(&channel, "demo", true, &josh()).unwrap());
        assert!(self_improve_enabled(&channel, "demo"));
        assert!(
            !set_self_improve(&channel, "demo", true, &josh()).unwrap(),
            "already on"
        );
        assert!(set_self_improve(&channel, "demo", false, &josh()).unwrap());
        assert!(!self_improve_enabled(&channel, "demo"));
    }

    /// A delegate with `improve` switches it for the master, the record says so, and
    /// nothing short of that delegation is honoured.
    #[test]
    fn a_delegate_switches_self_improve_only_under_an_improve_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let bridge = crate::AgentIdentity::from_seed("telegram-grouchly", [8u8; 32]);
        let channel = mastered(dir.path(), "demo", &josh(), &[&bridge]);

        // No delegation: refused, whoever it claims to act for.
        assert!(set_self_improve_as(&channel, "demo", true, &bridge, Some("josh")).is_err());
        // A delegation without the scope: refused.
        crate::delegation::grant(
            &channel,
            "demo",
            &josh(),
            "telegram-grouchly",
            &["orders".to_string()],
            None,
        )
        .unwrap();
        let error = set_self_improve_as(&channel, "demo", true, &bridge, Some("josh"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not delegated 'improve'"), "{error}");
        // Acting for someone who is not the master: refused.
        assert!(set_self_improve_as(&channel, "demo", true, &bridge, Some("ada")).is_err());

        crate::delegation::grant(
            &channel,
            "demo",
            &josh(),
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        assert!(set_self_improve_as(&channel, "demo", true, &bridge, Some("josh")).unwrap());
        let setting = self_improve_setting(&channel, "demo").unwrap();
        assert!(setting.enabled);
        assert_eq!(setting.set_by(), "josh via telegram-grouchly");

        // Revoked: the setting it signed stops counting, and so does any new one.
        crate::delegation::revoke(&channel, "demo", &josh(), "telegram-grouchly", "done").unwrap();
        assert!(!self_improve_enabled(&channel, "demo"));
        assert!(set_self_improve_as(&channel, "demo", true, &bridge, Some("josh")).is_err());
    }

    #[test]
    fn a_self_improve_setting_the_master_did_not_sign_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let channel = mastered(dir.path(), "demo", &josh(), &[&grouchly]);
        let forge = |signer: &crate::AgentIdentity, project: &str, enabled: bool| {
            let set_at = Utc::now();
            let signature = signer
                .signing
                .sign(improve_payload(project, enabled, &set_at).as_bytes());
            ImproveSetting {
                project_id: project.into(),
                enabled,
                set_at,
                signed_by: signer.name().into(),
                signature: hex::encode(signature.to_bytes()),
                on_behalf_of: None,
            }
        };
        let path = channel.join(SELF_IMPROVE);

        // Validly signed, by a member who is not the master.
        crate::atomic_json(&path, &forge(&grouchly, "demo", true)).unwrap();
        assert!(!self_improve_enabled(&channel, "demo"));
        // The master's own setting, lifted from another project.
        crate::atomic_json(&path, &forge(&josh(), "elsewhere", true)).unwrap();
        assert!(!self_improve_enabled(&channel, "demo"));
        // The master's "off", edited to "on".
        let mut edited = forge(&josh(), "demo", false);
        edited.enabled = true;
        crate::atomic_json(&path, &edited).unwrap();
        assert!(!self_improve_enabled(&channel, "demo"));
        // Garbage.
        std::fs::write(&path, "on").unwrap();
        assert!(!self_improve_enabled(&channel, "demo"));
        // And the real thing.
        crate::atomic_json(&path, &forge(&josh(), "demo", true)).unwrap();
        assert!(self_improve_enabled(&channel, "demo"));
    }

    /// In the swarm until the master says otherwise; the master's word travels with the
    /// channel; nobody else's counts, however it got there. Absent is on, so deleting the
    /// file can only put a project back, never take one out.
    #[test]
    fn the_swarm_is_on_by_default_and_only_the_master_takes_a_project_out() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let channel = mastered(dir.path(), "demo", &josh(), &[&grouchly]);

        assert!(swarm_enabled(&channel, "demo"), "in by default");
        let error = set_swarm(&channel, "demo", false, &grouchly)
            .expect_err("a member is not the master")
            .to_string();
        assert!(error.contains("only josh"), "{error}");
        let impostor = crate::AgentIdentity::from_seed("josh", [9u8; 32]);
        assert!(
            set_swarm(&channel, "demo", false, &impostor).is_err(),
            "the name is not the key"
        );
        assert!(!channel.join(SWARM).exists(), "nothing was written");

        assert!(set_swarm(&channel, "demo", false, &josh()).unwrap());
        assert!(!swarm_enabled(&channel, "demo"));
        assert_eq!(swarm_setting(&channel, "demo").unwrap().signed_by, "josh");
        assert!(
            !set_swarm(&channel, "demo", false, &josh()).unwrap(),
            "already out"
        );

        // Deleting the file does not put it back on a machine that has seen the master say
        // off: the remembered setting stands. (A machine that never saw it has nothing to
        // remember and does read "on"; that is why a machine can also exclude on its own.)
        let kept = std::fs::read(channel.join(SWARM)).unwrap();
        std::fs::remove_file(channel.join(SWARM)).unwrap();
        assert!(
            !swarm_enabled(&channel, "demo"),
            "off survives a deleted file"
        );
        // Re-signing the same word republishes it under a higher number.
        assert!(set_swarm(&channel, "demo", false, &josh()).unwrap());
        assert_eq!(swarm_setting(&channel, "demo").unwrap().seq, 2);
        assert_ne!(std::fs::read(channel.join(SWARM)).unwrap(), kept);

        // Only the master moves it forward again.
        assert!(set_swarm(&channel, "demo", true, &josh()).unwrap());
        assert!(swarm_enabled(&channel, "demo"));
        assert_eq!(swarm_setting(&channel, "demo").unwrap().seq, 3);
    }

    /// An old validly signed file put back over a newer one is a rollback, and a machine
    /// that has seen the newer one does not take it. A machine that has not (a new one, or
    /// one that was offline) has nothing to compare with and reads what is there.
    #[test]
    fn an_older_signed_swarm_file_put_back_is_not_obeyed() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let channel = mastered(dir.path(), "demo", &josh(), &[&grouchly]);
        let path = channel.join(SWARM);

        assert!(set_swarm(&channel, "demo", false, &josh()).unwrap());
        let off = std::fs::read(&path).unwrap();
        assert!(set_swarm(&channel, "demo", true, &josh()).unwrap());
        let on = std::fs::read(&path).unwrap();
        assert!(set_swarm(&channel, "demo", false, &josh()).unwrap());
        let off_again = std::fs::read(&path).unwrap();
        assert!(!swarm_enabled(&channel, "demo"));

        // Somebody restores the master's old "on". It verifies, and it is older.
        std::fs::write(&path, &on).unwrap();
        assert!(
            !swarm_enabled(&channel, "demo"),
            "this machine already saw a newer off"
        );
        // And the older off over the newer on does not take a project out either.
        std::fs::write(&path, &off_again).unwrap();
        assert!(set_swarm(&channel, "demo", true, &josh()).unwrap());
        std::fs::write(&path, &off).unwrap();
        assert!(
            swarm_enabled(&channel, "demo"),
            "the master's newer on stands against an old off"
        );

        // A machine that never saw any of it simply reads the file that is there.
        // (The state directory is chosen once per process, so "another machine" is this one
        // with its memory of the channel gone.)
        let state = crate::licensing::machine_state_dir().expect("a state directory");
        let _ = std::fs::remove_dir_all(state.join("swarm"));
        std::fs::write(&path, &off).unwrap();
        assert!(!swarm_enabled(&channel, "demo"));
    }

    /// A file the master really signed, with a number lower than one this machine has already
    /// accepted, is not taken, however it got into the channel; and a new number from the
    /// same master is.
    #[test]
    fn the_masters_own_older_number_is_not_taken_and_a_higher_one_is() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let channel = mastered(dir.path(), "demo", &josh(), &[]);
        assert!(set_swarm(&channel, "demo", false, &josh()).unwrap());
        assert!(set_swarm(&channel, "demo", true, &josh()).unwrap());
        assert!(set_swarm(&channel, "demo", false, &josh()).unwrap());
        assert_eq!(swarm_setting(&channel, "demo").unwrap().seq, 3);
        let signed = |on: bool, seq: u64| {
            let set_at = Utc::now();
            SwarmSetting {
                project_id: "demo".into(),
                on,
                seq,
                set_at,
                signed_by: "josh".into(),
                signature: hex::encode(
                    josh()
                        .signing
                        .sign(swarm_payload("demo", on, seq, &set_at).as_bytes())
                        .to_bytes(),
                ),
            }
        };
        crate::atomic_json(&channel.join(SWARM), &signed(true, 1)).unwrap();
        assert!(!swarm_enabled(&channel, "demo"), "number 1 is behind 3");
        // The number is part of what is signed: renumbering a real "on" does not work.
        let mut renumbered = signed(true, 1);
        renumbered.seq = 9;
        crate::atomic_json(&channel.join(SWARM), &renumbered).unwrap();
        assert!(
            !swarm_enabled(&channel, "demo"),
            "the signature no longer fits"
        );
        crate::atomic_json(&channel.join(SWARM), &signed(true, 4)).unwrap();
        assert!(
            swarm_enabled(&channel, "demo"),
            "number 4 is the master's newest"
        );
    }

    #[test]
    fn a_swarm_flag_the_master_did_not_sign_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let grouchly = crate::AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let channel = mastered(dir.path(), "demo", &josh(), &[&grouchly]);
        let forge = |signer: &crate::AgentIdentity, project: &str, on: bool| {
            let set_at = Utc::now();
            let signature = signer
                .signing
                .sign(swarm_payload(project, on, 1, &set_at).as_bytes());
            SwarmSetting {
                project_id: project.into(),
                on,
                seq: 1,
                set_at,
                signed_by: signer.name().into(),
                signature: hex::encode(signature.to_bytes()),
            }
        };
        let path = channel.join(SWARM);

        // Validly signed "off", by a member who is not the master: the project stays in.
        crate::atomic_json(&path, &forge(&grouchly, "demo", false)).unwrap();
        assert!(swarm_enabled(&channel, "demo"));
        // The master's "off" for another project, lifted into this one.
        crate::atomic_json(&path, &forge(&josh(), "elsewhere", false)).unwrap();
        assert!(swarm_enabled(&channel, "demo"));
        // The master's "on", edited to "off".
        let mut edited = forge(&josh(), "demo", true);
        edited.on = false;
        crate::atomic_json(&path, &edited).unwrap();
        assert!(swarm_enabled(&channel, "demo"));
        // Garbage.
        std::fs::write(&path, "off").unwrap();
        assert!(swarm_enabled(&channel, "demo"));
        // And the real thing.
        crate::atomic_json(&path, &forge(&josh(), "demo", false)).unwrap();
        assert!(!swarm_enabled(&channel, "demo"));
    }

    #[test]
    fn a_managed_clone_replaces_a_working_copy_and_the_working_copy_is_remembered() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let comms = channel(dir.path(), "demo");
        let human = dir.path().join("X-ferryman");
        root.adopt("demo", &comms, Some(&human)).unwrap();

        let clone = root.managed_clone("demo");
        assert_eq!(clone, root.repos().join("demo"));
        assert!(root.is_managed(&clone));
        assert!(!root.is_managed(&human));

        assert!(root.set_managed_repo("demo", &clone).unwrap());
        let entry = &root.projects()[0];
        assert_eq!(entry.repo.as_deref(), Some(clone.as_path()));
        assert_eq!(entry.human_checkouts, vec![human.clone()]);
        assert!(
            !root.set_managed_repo("demo", &clone).unwrap(),
            "idempotent"
        );

        // Noting the human copy again, or the clone as one, changes nothing.
        assert!(!root.note_human_checkout("demo", &human).unwrap());
        assert!(!root.note_human_checkout("demo", &clone).unwrap());
        let other = dir.path().join("another-copy");
        assert!(root.note_human_checkout("demo", &other).unwrap());
        assert_eq!(root.projects()[0].human_checkouts.len(), 2);
        assert!(
            !human.exists() && !clone.exists(),
            "recording paths creates nothing"
        );
    }
}

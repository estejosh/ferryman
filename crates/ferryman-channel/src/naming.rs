//! A project's name: a signed label over an id that never changes (ADR 0024).
//!
//! The project id is everywhere a signature or a peer looks: the Syncthing folder id
//! (`<id>-ferryman`), the `project_id` inside every signed record (grants, offers,
//! `SWARM`, `ARCHIVED`, iroh transports), the roster. Changing it would invalidate every
//! signature ever made and make every device share the folder again. So it does not change.
//!
//! What a person sees and types is the project's *name*. By default it is the id. The
//! master renames a project by signing a [`NAME`] record into its channel: the new name,
//! the names it had before (kept as aliases, so old commands and habits keep working) and
//! a sequence number that only goes up. Every machine that syncs the channel reads it and
//! moves its own folders to match ([`Root::follow_names`]): `comms/<name>-ferryman` and
//! `repos/<name>`. The Syncthing folder keeps its id, so no device re-pairs; peers match
//! on the id and each one's path is its own business.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::ferry::{Entry, Root, memory_path, move_directory, require_master, same_place};
use crate::{AgentIdentity, SignatureCheck};

/// The file in a channel that names its project.
pub const NAME: &str = "NAME";

/// The longest name accepted. Folder names and prompts stay readable.
pub const MAX_NAME: usize = 64;

/// What the [`NAME`] file holds.
///
/// `seq` is one more than the highest the master could see when signing and is covered by
/// the signature. Each machine remembers the highest it accepted, so an older signed file
/// put back over a newer one, or the file deleted, does not rename anything back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectName {
    pub project_id: String,
    pub name: String,
    /// Every name the project had before this one, newest first. Never the id (that is
    /// always accepted) and never the current name.
    #[serde(default)]
    pub aliases: Vec<String>,
    pub seq: u64,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn payload(
    project_id: &str,
    name: &str,
    aliases: &[String],
    seq: u64,
    at: &DateTime<Utc>,
) -> String {
    format!(
        "ferryman-name-v1\n{project_id}\n{name}\n{}\n{seq}\n{}",
        aliases.join(","),
        at.to_rfc3339()
    )
}

/// Whether `name` can be a project name: 1 to 64 of `a-z`, `0-9` and `-`, starting and
/// ending with a letter or digit. The same shape as a project id, because it becomes a
/// folder name on every machine.
///
/// # Errors
/// Says what is wrong with it.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME {
        bail!(
            "a project name is 1 to {MAX_NAME} characters, not {}",
            name.len()
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("'{name}' can only use lowercase letters, digits and '-'");
    }
    if name.starts_with('-') || name.ends_with('-') {
        bail!("'{name}' cannot start or end with '-'");
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Memory {
    high: u64,
    good: Option<ProjectName>,
}

fn read_memory(channel: &Path, project_id: &str) -> Memory {
    memory_path("name", channel, project_id)
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Best effort: a machine that cannot write its memory still obeys the file it reads.
fn remember(channel: &Path, project_id: &str, name: &ProjectName) {
    let Some(path) = memory_path("name", channel, project_id) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = crate::atomic_json(
        &path,
        &Memory {
            high: name.seq,
            good: Some(name.clone()),
        },
    );
}

/// The channel's name file when it verifies as signed by the project's master.
fn name_file(channel: &Path, project_id: &str) -> Option<ProjectName> {
    let record: ProjectName =
        serde_json::from_slice(&std::fs::read(channel.join(NAME)).ok()?).ok()?;
    let roster = crate::read_agent_roster(channel).ok()?;
    let master = crate::master::read_master_at(channel, &roster).ok()??;
    (record.project_id == project_id
        && master.project_id == project_id
        && check_name(&record.name).is_ok()
        && record.signed_by.eq_ignore_ascii_case(&master.master)
        && crate::check_signature(
            Some(&record.signed_by),
            Some(&record.signature),
            &payload(
                &record.project_id,
                &record.name,
                &record.aliases,
                record.seq,
                &record.set_at,
            ),
            &roster,
        ) == SignatureCheck::Valid)
        .then_some(record)
}

/// The master's name for the project in `channel`: the newest this machine has accepted
/// that verifies. `None` when the project was never renamed, which means its name is its id.
#[must_use]
pub fn project_name(channel: &Path, project_id: &str) -> Option<ProjectName> {
    let file = name_file(channel, project_id);
    let memory = read_memory(channel, project_id);
    match (file, memory.good) {
        (Some(file), good) => {
            // A different master's file is a handover with its own numbering, not a rollback.
            let new_hand = good
                .as_ref()
                .is_none_or(|good| !good.signed_by.eq_ignore_ascii_case(&file.signed_by));
            if file.seq > memory.high || new_hand {
                remember(channel, project_id, &file);
                Some(file)
            } else if file.seq == memory.high {
                good.or(Some(file))
            } else {
                good
            }
        }
        (None, good) => good,
    }
}

/// What to call the project in `channel`: its signed name, or its id.
#[must_use]
pub fn display_name(channel: &Path, project_id: &str) -> String {
    project_name(channel, project_id).map_or_else(|| project_id.to_owned(), |n| n.name)
}

/// Every name the project answers to: its name, its id, then its old names.
#[must_use]
pub fn names(channel: &Path, project_id: &str) -> Vec<String> {
    let mut all = Vec::new();
    let mut add = |name: String| {
        if !all.contains(&name) {
            all.push(name);
        }
    };
    match project_name(channel, project_id) {
        Some(record) => {
            add(record.name);
            add(project_id.to_owned());
            record.aliases.into_iter().for_each(&mut add);
        }
        None => add(project_id.to_owned()),
    }
    all
}

/// Rename the project in `channel` to `name`, signed by its master. `taken` holds every
/// name, id and alias of the *other* projects this machine knows, so two projects never
/// answer to one name. Renaming to the id itself undoes a rename. Returns whether
/// anything changed.
///
/// # Errors
/// The name is not a valid name or is taken, the signer is not the master by the key the
/// channel knows, or the file cannot be written.
pub fn set_name(
    channel: &Path,
    project_id: &str,
    name: &str,
    taken: &[String],
    signer: &AgentIdentity,
) -> Result<bool> {
    check_name(name)?;
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({})",
            channel.display()
        );
    }
    if taken.iter().any(|other| other.eq_ignore_ascii_case(name)) {
        bail!("another project here already answers to '{name}'");
    }
    require_master(channel, project_id, signer, "rename it")?;
    let current = project_name(channel, project_id);
    let now_called = current
        .as_ref()
        .map_or_else(|| project_id.to_owned(), |record| record.name.clone());
    if now_called == name {
        return Ok(false);
    }
    // Old names stay answerable: the one it is leaving first, then the ones before it.
    let mut aliases = vec![now_called];
    if let Some(record) = &current {
        aliases.extend(record.aliases.iter().cloned());
    }
    let mut seen = Vec::new();
    aliases.retain(|alias| {
        let keep = alias != name && alias != project_id && !seen.contains(alias);
        seen.push(alias.clone());
        keep
    });
    let high = read_memory(channel, project_id)
        .high
        .max(name_file(channel, project_id).map_or(0, |file| file.seq))
        .max(current.as_ref().map_or(0, |record| record.seq));
    let (set_at, seq) = (Utc::now(), high + 1);
    let record = ProjectName {
        project_id: project_id.to_owned(),
        name: name.to_owned(),
        signature: hex::encode(
            signer
                .signing
                .sign(payload(project_id, name, &aliases, seq, &set_at).as_bytes())
                .to_bytes(),
        ),
        aliases,
        seq,
        set_at,
        signed_by: signer.name().to_owned(),
    };
    let path = channel.join(NAME);
    crate::atomic_json(&path, &record).with_context(|| format!("writing {}", path.display()))?;
    remember(channel, project_id, &record);
    Ok(true)
}

/// What following a project's name did on this machine, or would do.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Followed {
    pub project_id: String,
    pub name: String,
    /// The channel moved from, to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<(PathBuf, PathBuf)>,
    /// Ferryman's own clone moved from, to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<(PathBuf, PathBuf)>,
    /// Why something that should move did not (yet). Tried again next time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Followed {
    /// Whether anything moved (or, in a dry run, would).
    #[must_use]
    pub fn moved(&self) -> bool {
        self.channel.is_some() || self.repo.is_some()
    }
}

impl Entry {
    /// What to call this project: its signed name, or its id.
    #[must_use]
    pub fn name(&self) -> String {
        if self.channel.is_dir() {
            display_name(&self.channel, &self.project_id)
        } else {
            self.project_id.clone()
        }
    }

    /// Every name this project answers to.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        if self.channel.is_dir() {
            names(&self.channel, &self.project_id)
        } else {
            vec![self.project_id.clone()]
        }
    }
}

impl Root {
    /// The folder name a project's channel and clone use on this machine: its name.
    #[must_use]
    pub fn folder_name(&self, project_id: &str) -> String {
        self.read()
            .projects
            .into_iter()
            .find(|entry| entry.project_id == project_id)
            .map_or_else(|| project_id.to_owned(), |entry| entry.name())
    }

    /// The project `wanted` names: its id, its name, or one of its old names. An id wins
    /// over a name, and a name over an old name, so nothing typed today means two projects.
    ///
    /// # Errors
    /// No project answers to it, or more than one does at the same level.
    pub fn resolve(&self, wanted: &str) -> Result<Entry> {
        let projects = self.read().projects;
        if let Some(entry) = projects.iter().find(|entry| entry.project_id == wanted) {
            return Ok(entry.clone());
        }
        for level in 0..2 {
            let hits: Vec<&Entry> = projects
                .iter()
                .filter(|entry| {
                    let names = entry.names();
                    if level == 0 {
                        names
                            .first()
                            .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
                    } else {
                        names
                            .iter()
                            .skip(1)
                            .any(|name| name.eq_ignore_ascii_case(wanted))
                    }
                })
                .collect();
            match hits.as_slice() {
                [one] => return Ok((*one).clone()),
                [] => {}
                many => bail!(
                    "'{wanted}' names more than one project here: {}",
                    many.iter()
                        .map(|entry| entry.project_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        bail!(
            "no project '{wanted}' in {}",
            self.manifest_path().display()
        )
    }

    /// Every name, id and old name of every project here except `project_id`: what a
    /// rename of `project_id` must not take.
    #[must_use]
    pub fn names_taken_by_others(&self, project_id: &str) -> Vec<String> {
        self.read()
            .projects
            .into_iter()
            .filter(|entry| entry.project_id != project_id)
            .flat_map(|entry| entry.names())
            .collect()
    }

    /// Rename a project here, signed by its master, then move this machine's folders.
    /// Other machines follow when they next read the channel.
    ///
    /// # Errors
    /// See [`set_name`].
    pub fn rename(
        &self,
        wanted: &str,
        name: &str,
        signer: &AgentIdentity,
    ) -> Result<(bool, Followed)> {
        let entry = self.resolve(wanted)?;
        let taken = self.names_taken_by_others(&entry.project_id);
        let changed = set_name(&entry.channel, &entry.project_id, name, &taken, signer)?;
        let followed = self.follow(&entry.project_id, false)?;
        Ok((changed, followed))
    }

    /// Move every project's folders to its current name. Safe to run any time: a project
    /// already in place is untouched, a folder in use or a target that is taken is left
    /// as it is with a note, and nothing is ever deleted.
    #[must_use]
    pub fn follow_names(&self, dry_run: bool) -> Vec<Followed> {
        self.read()
            .projects
            .into_iter()
            .filter(|entry| entry.channel.is_dir())
            .filter_map(|entry| match self.follow(&entry.project_id, dry_run) {
                Ok(followed) if followed.moved() || !followed.notes.is_empty() => Some(followed),
                Ok(_) => None,
                Err(error) => Some(Followed {
                    project_id: entry.project_id.clone(),
                    name: entry.project_id,
                    notes: vec![format!("{error:#}")],
                    ..Followed::default()
                }),
            })
            .collect()
    }

    /// Move one project's channel (if it lives in `comms/`) and Ferryman's own clone (if
    /// it lives in `repos/`) to its name. Folders anywhere else belong to a person, or to
    /// an older layout, and are never moved.
    ///
    /// # Errors
    /// The project is not filed here, or the manifest cannot be written.
    pub fn follow(&self, project_id: &str, dry_run: bool) -> Result<Followed> {
        let mut entry = self
            .read()
            .projects
            .into_iter()
            .find(|entry| entry.project_id == project_id)
            .with_context(|| {
                format!(
                    "no project '{project_id}' in {}",
                    self.manifest_path().display()
                )
            })?;
        let name = entry.name();
        let mut followed = Followed {
            project_id: project_id.to_owned(),
            name: name.clone(),
            ..Followed::default()
        };

        let in_comms = entry
            .channel
            .parent()
            .is_some_and(|parent| same_place(parent, &self.comms()));
        let channel_home = self.comms().join(format!("{name}-ferryman"));
        if in_comms && entry.channel.is_dir() && !same_place(&entry.channel, &channel_home) {
            match vacancy(&channel_home) {
                Some(why) => followed.notes.push(why),
                None => {
                    if !dry_run {
                        if let Err(error) = move_directory(&entry.channel, &channel_home) {
                            followed.notes.push(format!(
                                "channel not moved yet ({error:#}); it is tried again next time"
                            ));
                        } else {
                            if let Some(attachment) = entry.attachment() {
                                rewrite_bridge(
                                    &attachment.join("bridge.toml"),
                                    &[("communications", &channel_home)],
                                )?;
                            }
                            followed.channel = Some((entry.channel.clone(), channel_home.clone()));
                            entry.channel = channel_home.clone();
                        }
                    } else {
                        followed.channel = Some((entry.channel.clone(), channel_home.clone()));
                    }
                }
            }
        }

        let clone_home = self.repos().join(&name);
        if let Some(repo) = entry.repo.clone()
            && self.is_managed(&repo)
            && repo.is_dir()
            && !same_place(&repo, &clone_home)
        {
            // A worker's home (its agent.toml is there) is named in its service unit or
            // scheduled task; moving it under a running or installed worker would strand
            // it. It moves when the service is set up again.
            let home = repo.join(".ferryman").join("agent.toml").is_file();
            match vacancy(&clone_home) {
                _ if home => followed.notes.push(format!(
                    "{} is this machine's worker home, so it keeps its folder name until \
                     `ferry fleet setup --service` runs again",
                    repo.display()
                )),
                Some(why) => followed.notes.push(why),
                None if dry_run => followed.repo = Some((repo, clone_home)),
                None => match move_directory_no_copy(&repo, &clone_home) {
                    Err(error) => followed.notes.push(format!(
                        "clone not moved yet ({error:#}); a worker may be using it, so it is \
                         tried again when the worker next starts"
                    )),
                    Ok(()) => {
                        let attachment = clone_home.join(".ferryman");
                        rewrite_bridge(
                            &attachment.join("bridge.toml"),
                            &[
                                ("workspace", &clone_home),
                                ("attachment", &attachment),
                                ("communications", &entry.channel),
                            ],
                        )?;
                        repair_worktrees(&clone_home);
                        followed.repo = Some((repo, clone_home.clone()));
                        entry.repo = Some(clone_home);
                    }
                },
            }
        }

        if !dry_run && followed.moved() {
            self.adopt(project_id, &entry.channel, entry.repo.as_deref())?;
        }
        Ok(followed)
    }
}

/// After a channel moved: point this machine's Syncthing at the new folder, keeping the
/// folder id and every device it is shared with, so no peer notices anything. Returns
/// what Syncthing said, for the record.
#[must_use]
pub fn reregister_moved_channel(root: &Root, followed: &Followed) -> Option<String> {
    followed.channel.as_ref()?;
    let entry = root
        .read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == followed.project_id)?;
    let note = entry
        .route(root)
        .and_then(|(route, _)| crate::syncthing_share_folder(&route, &[]))
        .map_or_else(
            |error| format!("Syncthing not updated ({error:#}); run `ferry channel syncthing on` in the project"),
            |setup| setup.note,
        );
    Some(note)
}

/// `None` when `target` can be moved onto; otherwise why not.
fn vacancy(target: &Path) -> Option<String> {
    let occupied = target.exists()
        && std::fs::read_dir(target).map_or(true, |mut entries| entries.next().is_some());
    occupied.then(|| {
        format!(
            "{} already holds something, so nothing was moved there; move it aside to finish",
            target.display()
        )
    })
}

/// A clone is a git repository with worktrees and locks: a copy across volumes is not a
/// move worth risking. Same volume, one rename, or not at all.
fn move_directory_no_copy(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if to.is_dir() {
        // Empty (checked by `vacancy`); rename onto an existing directory fails on Windows.
        std::fs::remove_dir(to).with_context(|| format!("clear {}", to.display()))?;
    }
    std::fs::rename(from, to)
        .with_context(|| format!("rename {} to {}", from.display(), to.display()))
}

/// Point a moved clone's task worktrees back at it. Best effort: a worktree left behind
/// is pruned by the loop, and git tells the next run what it could not fix.
fn repair_worktrees(clone: &Path) {
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(["worktree", "repair"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Rewrite the given keys of a `bridge.toml`, a line at a time, so the other lines (and
/// their literal Windows paths) stay exactly as they were. A missing file is fine.
fn rewrite_bridge(bridge: &Path, keys: &[(&str, &Path)]) -> Result<()> {
    if !bridge.is_file() {
        return Ok(());
    }
    let text =
        std::fs::read_to_string(bridge).with_context(|| format!("read {}", bridge.display()))?;
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            let key = line.split('=').next().unwrap_or("").trim();
            keys.iter()
                .find(|(wanted, _)| line.contains('=') && key == *wanted)
                .map_or_else(
                    || line.to_owned(),
                    |(wanted, path)| format!("{wanted} = \"{}\"", path.display()),
                )
        })
        .collect();
    let mut out = rewritten.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(bridge, out).with_context(|| format!("write {}", bridge.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn josh() -> AgentIdentity {
        AgentIdentity::from_seed("josh", [7u8; 32])
    }

    fn mallory() -> AgentIdentity {
        AgentIdentity::from_seed("mallory", [9u8; 32])
    }

    /// A root with one project in the fleet layout: its channel in `comms/`, Ferryman's
    /// clone in `repos/` with a `bridge.toml`, josh as master and mallory on the roster.
    fn project(root: &Root, id: &str) -> (PathBuf, PathBuf) {
        let channel = root.comms().join(format!("{id}-ferryman"));
        std::fs::create_dir_all(channel.join("tasks")).unwrap();
        std::fs::write(channel.join("tasks/one.json"), "{}").unwrap();
        let repo = root.repos().join(id);
        let attachment = repo.join(".ferryman");
        std::fs::create_dir_all(attachment.join("keys")).unwrap();
        std::fs::write(attachment.join("keys/secret"), "never synced").unwrap();
        std::fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"{id}\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\nshared_remote = \"{id}-ferryman\"\ngrants = \"open\"\n",
                repo.display(),
                attachment.display(),
                channel.display()
            ),
        )
        .unwrap();
        let mut route = crate::ProjectRoute {
            project_id: id.into(),
            workspace: repo.clone(),
            attachment: attachment.clone(),
            communications: channel.clone(),
            shared_remote: format!("{id}-ferryman"),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in [josh(), mallory()] {
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
        crate::master::initialize_master(&route, &josh(), "josh").unwrap();
        root.adopt(id, &channel, Some(&repo)).unwrap();
        (channel, repo)
    }

    fn setup() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = Root::create(&dir.path().join("ferry")).unwrap();
        (dir, root)
    }

    #[test]
    fn names_are_folder_shaped() {
        for good in ["a", "ferryman-comms", "idle-ish", "v2"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "Fructly",
            "has space",
            "-lead",
            "trail-",
            "a/b",
            "..",
            &"x".repeat(65),
        ] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    /// The whole point: the id, the Syncthing folder id and every signature stay; the
    /// folders follow the name; the keys never move; both names keep working.
    #[test]
    fn a_rename_moves_the_folders_and_keeps_the_id() {
        let (_dir, root) = setup();
        let (channel, repo) = project(&root, "fructly");
        let roster_before = std::fs::read_dir(channel.join("agents")).unwrap().count();

        let (changed, followed) = root.rename("fructly", "ferryman-comms", &josh()).unwrap();
        assert!(changed);
        assert!(followed.notes.is_empty(), "{:?}", followed.notes);

        let new_channel = root.comms().join("ferryman-comms-ferryman");
        let new_repo = root.repos().join("ferryman-comms");
        assert_eq!(
            followed.channel,
            Some((channel.clone(), new_channel.clone()))
        );
        assert_eq!(followed.repo, Some((repo.clone(), new_repo.clone())));
        assert!(new_channel.join("tasks/one.json").is_file());
        assert!(
            new_repo.join(".ferryman/keys/secret").is_file(),
            "keys move with the clone, never into the channel"
        );
        assert!(!new_channel.join("keys").exists());
        assert!(!channel.exists() && !repo.exists());

        // The id is untouched everywhere it matters.
        let entry = root.resolve("ferryman-comms").unwrap();
        assert_eq!(entry.project_id, "fructly");
        assert_eq!(entry.channel, new_channel);
        assert_eq!(entry.repo.as_deref(), Some(new_repo.as_path()));
        assert_eq!(
            std::fs::read_dir(new_channel.join("agents"))
                .unwrap()
                .count(),
            roster_before
        );
        let bridge = std::fs::read_to_string(new_repo.join(".ferryman/bridge.toml")).unwrap();
        assert!(bridge.contains("project = \"fructly\""));
        assert!(
            bridge.contains("shared_remote = \"fructly-ferryman\""),
            "the Syncthing folder id stays"
        );
        assert!(bridge.contains(&format!("communications = \"{}\"", new_channel.display())));
        assert!(bridge.contains(&format!("workspace = \"{}\"", new_repo.display())));
        assert!(
            bridge.contains("grants = \"open\""),
            "other lines untouched"
        );
        let route = crate::load_route(&new_repo.join(".ferryman")).unwrap();
        assert_eq!(route.project_id, "fructly");
        assert_eq!(route.communications, new_channel);

        // Old and new names, and the id, all reach it.
        for wanted in ["fructly", "ferryman-comms", "FERRYMAN-COMMS"] {
            assert_eq!(
                root.resolve(wanted).unwrap().project_id,
                "fructly",
                "{wanted}"
            );
        }
        assert_eq!(root.comms_home("fructly"), new_channel);
        assert_eq!(root.managed_clone("fructly"), new_repo);

        // Following again moves nothing.
        assert!(root.follow_names(false).is_empty());
    }

    /// A second rename keeps every old name; renaming to the id undoes it.
    #[test]
    fn old_names_stay_answerable_and_the_id_undoes_a_rename() {
        let (_dir, root) = setup();
        project(&root, "fructly");
        root.rename("fructly", "comms", &josh()).unwrap();
        root.rename("comms", "talk", &josh()).unwrap();
        let entry = root.resolve("comms").unwrap();
        assert_eq!(entry.names(), vec!["talk", "fructly", "comms"]);
        assert!(root.comms().join("talk-ferryman").is_dir());

        root.rename("talk", "fructly", &josh()).unwrap();
        let entry = root.resolve("talk").unwrap();
        assert_eq!(entry.name(), "fructly");
        assert!(root.comms().join("fructly-ferryman").is_dir());
        assert!(root.repos().join("fructly").is_dir());
    }

    /// Only the master renames; a forged or copied file renames nothing; an older signed
    /// file put back does not roll a machine back.
    #[test]
    fn only_the_newest_master_signed_name_counts() {
        let (_dir, root) = setup();
        let (channel, _) = project(&root, "fructly");
        let error = root.rename("fructly", "evil", &mallory()).unwrap_err();
        assert!(format!("{error:#}").contains("only josh"), "{error:#}");
        assert!(!channel.join(NAME).exists());

        // Mallory writes the file herself.
        let at = Utc::now();
        let forged = ProjectName {
            project_id: "fructly".into(),
            name: "evil".into(),
            aliases: Vec::new(),
            seq: 99,
            set_at: at,
            signature: hex::encode(
                mallory()
                    .signing
                    .sign(payload("fructly", "evil", &[], 99, &at).as_bytes())
                    .to_bytes(),
            ),
            signed_by: "mallory".into(),
        };
        crate::atomic_json(&channel.join(NAME), &forged).unwrap();
        assert_eq!(display_name(&channel, "fructly"), "fructly");
        std::fs::remove_file(channel.join(NAME)).unwrap();

        root.rename("fructly", "one", &josh()).unwrap();
        let channel = root.resolve("one").unwrap().channel;
        let first = std::fs::read(channel.join(NAME)).unwrap();
        root.rename("one", "two", &josh()).unwrap();
        let channel = root.resolve("two").unwrap().channel;
        std::fs::write(channel.join(NAME), &first).unwrap();
        assert_eq!(
            display_name(&channel, "fructly"),
            "two",
            "an old file does not roll back"
        );
        std::fs::remove_file(channel.join(NAME)).unwrap();
        assert_eq!(
            display_name(&channel, "fructly"),
            "two",
            "nor does deleting it"
        );
    }

    /// A worker's home is named in its service; it is never moved out from under it.
    #[test]
    fn a_workers_home_keeps_its_folder() {
        let (_dir, root) = setup();
        let (channel, repo) = project(&root, "ferryman");
        std::fs::write(repo.join(".ferryman/agent.toml"), "agent = \"w\"\n").unwrap();
        set_name(&channel, "ferryman", "fm", &[], &josh()).unwrap();
        let followed = root.follow("ferryman", false).unwrap();
        assert!(followed.channel.is_some(), "the channel still follows");
        assert!(followed.repo.is_none());
        assert!(repo.is_dir());
        assert_eq!(followed.notes.len(), 1, "{:?}", followed.notes);
    }

    #[test]
    fn two_projects_never_share_a_name() {
        let (_dir, root) = setup();
        project(&root, "alpha");
        project(&root, "beta");
        assert!(root.rename("beta", "alpha", &josh()).is_err());
        root.rename("alpha", "first", &josh()).unwrap();
        // "alpha" is now an old name of alpha: still taken.
        assert!(root.rename("beta", "alpha", &josh()).is_err());
        assert!(root.rename("beta", "first", &josh()).is_err());
        assert!(root.rename("beta", "second", &josh()).unwrap().0);
    }

    /// Another machine: the NAME file arrives with the channel and the next follow moves
    /// that machine's folders. Nothing is signed there.
    #[test]
    fn a_machine_that_receives_a_rename_follows_it() {
        let (_dir, root) = setup();
        let (channel, repo) = project(&root, "fructly");
        // Signed elsewhere: only the file changes here.
        set_name(&channel, "fructly", "comms", &[], &josh()).unwrap();
        let planned = root.follow_names(true);
        assert_eq!(planned.len(), 1);
        assert!(channel.is_dir() && repo.is_dir(), "a dry run moves nothing");

        let done = root.follow_names(false);
        assert_eq!(done[0].name, "comms");
        assert!(root.comms().join("comms-ferryman").is_dir());
        assert!(root.repos().join("comms").is_dir());
    }

    /// A folder already at the new place, or a channel outside `comms/` (a person's own
    /// layout), is never moved over or moved at all.
    #[test]
    fn nothing_is_moved_onto_something_or_out_of_a_persons_folder() {
        let (dir, root) = setup();
        let (channel, _) = project(&root, "fructly");
        std::fs::create_dir_all(root.comms().join("comms-ferryman/someone")).unwrap();
        set_name(&channel, "fructly", "comms", &[], &josh()).unwrap();
        let followed = root.follow("fructly", false).unwrap();
        assert!(followed.channel.is_none());
        assert_eq!(followed.notes.len(), 1, "{:?}", followed.notes);
        assert!(channel.is_dir(), "left where it was");
        assert!(followed.repo.is_some(), "the clone still follows");

        // A project whose channel and repo live outside the root.
        let outside = dir.path().join("elsewhere/beta/.ferryman/ferryman");
        std::fs::create_dir_all(&outside).unwrap();
        crate::atomic_json(&outside.join("x.json"), &serde_json::json!({})).unwrap();
        root.adopt("beta", &outside, Some(&dir.path().join("elsewhere/beta")))
            .unwrap();
        let followed = root.follow("beta", false).unwrap();
        assert!(!followed.moved());
        assert!(outside.is_dir());
    }
}

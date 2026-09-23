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
                if entry.repo.is_some() {
                    existing.repo = entry.repo;
                    existing.adopted = entry.adopted;
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
        // Without the channel there is nowhere to say it that the fleet would hear.
        if !entry.channel.is_dir() {
            bail!(
                "{project_id}'s channel is not on this machine ({}) - archive it from one that has it",
                entry.channel.display()
            );
        }
        let roster = crate::read_agent_roster(&entry.channel)?;
        let Some(master) = crate::master::read_master_at(&entry.channel, &roster)? else {
            bail!(
                "{project_id} has no master, and only a project's master can archive it or bring it back"
            );
        };
        if !signer.name().eq_ignore_ascii_case(&master.master) {
            bail!(
                "only {}, {project_id}'s master, can archive it or bring it back - not {}",
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
        let was = entry.is_archived();
        let marker = entry.channel.join(ARCHIVED);
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
}

//! `ferry root attach` - hang an existing checkout on the channel the ferry root already
//! files for its project.
//!
//! # What was missing
//!
//! A project can be a channel on this machine (filed in the root, with a master, a roster
//! and a history) and a clone beside it that nothing connects. `ferry enable` in the clone
//! is the obvious command and the wrong one: with no `bridge.toml` there it makes a second,
//! empty channel inside the repository, re-registers the project's Syncthing folder at that
//! new path (which deletes and recreates the folder) and enrols its identity on the way.
//! The only repair was a script: write `.ferryman/bridge.toml` naming the channel that
//! already exists, keep `/.ferryman/` out of git, then `ferry root adopt`.
//!
//! This is that script, with the three properties the script did not have: it is the same
//! on every machine, it can say what it would do first, and it cannot touch anything it
//! should not.
//!
//! # What it writes, and what it never does
//!
//! Three things, in this order: a line in the clone's own `.git/info/exclude` (never a
//! tracked file), `.ferryman/bridge.toml` naming the channel the root files, and the root's
//! record of where the checkout is. It touches no roster, no key, no device record and no
//! Syncthing folder, and it signs nothing. A checkout that already has a `bridge.toml`
//! naming a different channel is left exactly as it is: that is the damage `enable` does,
//! and merging two channels is a decision for a person.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use ferryman_channel::ferry::{Entry, Root};

/// Why a checkout was not attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Not a git repository, so there is no `.git/info/exclude` to keep the key out of git.
    NotGit,
    /// The master archived the project. Nothing new is worked there.
    Archived,
    /// The root files the project, but its channel folder is not on this machine.
    NoChannel,
    /// The caller asked for it to be left out.
    ByName,
    /// The root files no project of that name.
    NotFiled(String),
    /// Another checkout is already the one the root files for the project.
    AttachedElsewhere(PathBuf),
    /// The checkout has a `bridge.toml` that reads some other channel.
    OtherChannel { reads: PathBuf, files: PathBuf },
    /// Something failed; nothing past the failure was done.
    Failed(String),
}

impl Skip {
    /// The two or three words a listing shows.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotGit => "not a git repo",
            Self::Archived => "archived",
            Self::NoChannel => "no channel",
            Self::ByName => "skipped by name",
            Self::NotFiled(_) => "not filed",
            Self::AttachedElsewhere(_) => "attached elsewhere",
            Self::OtherChannel { .. } => "own channel",
            Self::Failed(_) => "failed",
        }
    }

    /// The sentence that says what to do about it.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::NotGit => {
                "there is no .git here, so there is nowhere to keep .ferryman out of git".into()
            }
            Self::Archived => "the master archived it, so nothing new is worked there".into(),
            Self::NoChannel => {
                "the root files it but its channel folder is not on this machine".into()
            }
            Self::ByName => "left out on request".into(),
            Self::NotFiled(id) => format!(
                "the ferry root files no project '{id}' (pass --project <id>, or 'ferry root adopt' where its channel is)"
            ),
            Self::AttachedElsewhere(other) => format!(
                "the root already files {} as its checkout; not replacing it",
                other.display()
            ),
            Self::OtherChannel { reads, files } => format!(
                "its .ferryman/bridge.toml reads {} but the root files the channel at {}. \
                 Left as it is: this is a second channel made by 'ferry enable', and which \
                 one is real is for a person to decide (docs/FERRYMAN_IN_EVERY_PROJECT.md)",
                reads.display(),
                files.display()
            ),
            Self::Failed(why) => why.clone(),
        }
    }
}

/// What attaching one checkout did, or would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attach {
    /// Done (or, in a dry run, would be): what changed.
    Attached { actions: Vec<String> },
    /// Everything was already in place. Nothing was written.
    Already,
    /// Left alone, and why.
    Skipped(Skip),
}

impl Attach {
    /// The one word a listing leads with.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Attached { .. } => "attached",
            Self::Already => "already",
            Self::Skipped(_) => "skipped",
        }
    }
}

/// One checkout found by [`attach_all`], and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The folder's own name.
    pub name: String,
    pub clone: PathBuf,
    /// The project it was matched to.
    pub project: String,
    pub outcome: Attach,
}

/// Whether two paths are the same place. Compared after resolving where they can be, and
/// folded on Windows, where `X:\Ferry` and `x:\ferry` are one directory.
pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |path: &Path| {
        fs::canonicalize(path).map_or_else(
            |_| path.to_path_buf(),
            |resolved| ferryman_channel::real_path(&resolved),
        )
    };
    let (a, b) = (norm(a), norm(b));
    if cfg!(windows) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

/// Whether a line of an ignore file already covers `/.ferryman/`, written however anyone
/// would have written it.
fn covers_attachment(text: &str) -> bool {
    text.lines().map(str::trim).any(|line| {
        matches!(
            line,
            ".ferryman" | ".ferryman/" | "/.ferryman" | "/.ferryman/" | ".ferryman/**"
        )
    })
}

/// The clone's own, untracked exclude file. A `.git` directory holds it directly; a
/// worktree or submodule has a `.git` file, and git is asked where the shared one is.
fn exclude_file(clone: &Path) -> Result<PathBuf> {
    let dot_git = clone.join(".git");
    if dot_git.is_dir() {
        return Ok(dot_git.join("info").join("exclude"));
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(["rev-parse", "--git-path", "info/exclude"])
        .output()
        .context("ask git where this checkout keeps its exclude file")?;
    if !out.status.success() {
        bail!(
            "git could not say where {} keeps its exclude file: {}",
            clone.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let printed = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let path = PathBuf::from(printed);
    Ok(if path.is_absolute() {
        path
    } else {
        clone.join(path)
    })
}

/// Whether git, in this clone, already leaves `.ferryman` alone: through its exclude file
/// or a tracked `.gitignore`.
fn already_excluded(clone: &Path) -> bool {
    let in_gitignore =
        fs::read_to_string(clone.join(".gitignore")).is_ok_and(|t| covers_attachment(&t));
    in_gitignore
        || exclude_file(clone)
            .ok()
            .and_then(|path| fs::read_to_string(path).ok())
            .is_some_and(|t| covers_attachment(&t))
}

/// Add `/.ferryman/` to the clone's `.git/info/exclude`, never to a tracked file. Adds,
/// and never rewrites what is there.
fn exclude_attachment(clone: &Path) -> Result<PathBuf> {
    let path = exclude_file(clone)?;
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(
        "# Ferryman's attachment: this machine's config and its PRIVATE SIGNING KEY.\n\
         # Never committed. Added by 'ferry root attach'.\n\
         /.ferryman/\n",
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, updated).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// The `bridge.toml` `ferry enable` writes, naming `channel` instead of a new one.
fn bridge_text(project: &str, clone: &Path, attachment: &Path, channel: &Path) -> String {
    format!(
        "project = \"{project}\"\n\
         workspace = \"{}\"\n\
         attachment = \"{}\"\n\
         communications = \"{}\"\n\
         shared_remote = \"{project}-ferryman\"\n\
         grants = \"open\"\n",
        clone.display(),
        attachment.display(),
        channel.display(),
    )
}

/// What the checkout's own `bridge.toml` says, against the channel the root files.
enum Bridge {
    Absent,
    /// Names this project and this channel.
    Matches,
    /// Reads a different channel, or a different project, or cannot be read at all.
    Differs(PathBuf),
}

fn bridge_state(attachment: &Path, project: &str, channel: &Path) -> Bridge {
    if !attachment.join("bridge.toml").is_file() {
        return Bridge::Absent;
    }
    match ferryman_channel::load_route(attachment) {
        Ok(route) if route.project_id == project && same_path(&route.communications, channel) => {
            Bridge::Matches
        }
        Ok(route) => Bridge::Differs(route.communications),
        Err(_) => Bridge::Differs(attachment.join("bridge.toml")),
    }
}

/// Attach one checkout to the channel the root files for its project.
///
/// `project` names the project when the folder's own name is not it. A dry run says what
/// would be done and writes nothing.
///
/// # Errors
/// The checkout does not exist, or a write failed part way (the exclude line goes first, so
/// a failure never leaves a key-bearing directory git can see).
pub fn attach(root: &Root, clone: &Path, project: Option<&str>, dry_run: bool) -> Result<Attach> {
    let clone = fs::canonicalize(clone)
        .map(|resolved| ferryman_channel::real_path(&resolved))
        .with_context(|| format!("{} does not exist", clone.display()))?;
    if !clone.join(".git").exists() {
        return Ok(Attach::Skipped(Skip::NotGit));
    }
    let id = match project {
        Some(id) => id.to_owned(),
        None => clone
            .file_name()
            .and_then(|name| name.to_str())
            .map(crate::identity::slug)
            .filter(|id| !id.is_empty())
            .context("could not name the project from the folder; pass --project")?,
    };
    if !ferryman_channel::is_safe_component(&id) {
        bail!("project id '{id}' is not a path-safe identifier");
    }
    let Some(entry) = root
        .read()
        .projects
        .into_iter()
        .find(|entry| entry.project_id == id)
    else {
        return Ok(Attach::Skipped(Skip::NotFiled(id)));
    };
    attach_entry(root, &entry, &clone, dry_run, false)
}

/// Attach Ferryman's own managed clone of a project to the channel the root files for it,
/// replacing whichever checkout was filed as the worker's: that one (a person's working
/// copy) is remembered as a human checkout and not touched. What `ferry repos sync` calls.
///
/// # Errors
/// A write failed part way, as for [`attach`].
pub fn attach_managed(root: &Root, entry: &Entry, clone: &Path, dry_run: bool) -> Result<Attach> {
    attach_entry(root, entry, clone, dry_run, true)
}

fn attach_entry(
    root: &Root,
    entry: &Entry,
    clone: &Path,
    dry_run: bool,
    take_over: bool,
) -> Result<Attach> {
    let id = entry.project_id.as_str();
    if !entry.channel.is_dir() {
        return Ok(Attach::Skipped(Skip::NoChannel));
    }
    if entry.is_archived() {
        return Ok(Attach::Skipped(Skip::Archived));
    }
    // One checkout per project is the one the root files. A second clone is not a reason to
    // move the first: filing merges, and the last to be filed would win every time this ran.
    if !take_over
        && let Some(filed) = entry.attachment()
        && let Some(other) = filed.parent()
        && !same_path(other, clone)
    {
        return Ok(Attach::Skipped(Skip::AttachedElsewhere(
            other.to_path_buf(),
        )));
    }
    let attachment = clone.join(".ferryman");
    let bridge = bridge_state(&attachment, id, &entry.channel);
    if let Bridge::Differs(reads) = &bridge {
        return Ok(Attach::Skipped(Skip::OtherChannel {
            reads: reads.clone(),
            files: entry.channel.clone(),
        }));
    }
    let excluded = already_excluded(clone);
    let filed = entry
        .repo
        .as_ref()
        .is_some_and(|repo| same_path(repo, clone));
    if matches!(bridge, Bridge::Matches) && excluded && filed {
        return Ok(Attach::Already);
    }

    let mut actions = Vec::new();
    if !excluded {
        actions.push("add /.ferryman/ to .git/info/exclude".to_owned());
    }
    if matches!(bridge, Bridge::Absent) {
        actions.push(format!(
            "write .ferryman/bridge.toml reading {}",
            entry.channel.display()
        ));
    }
    if !filed {
        actions.push(format!(
            "file the checkout of {id} in {}",
            root.path.display()
        ));
    }
    if dry_run {
        return Ok(Attach::Attached { actions });
    }

    // The exclude line first: there is then no moment in which a directory that is about to
    // hold a key is visible to `git add -A`.
    if !excluded {
        exclude_attachment(clone)?;
    }
    if matches!(bridge, Bridge::Absent) {
        fs::create_dir_all(&attachment)
            .with_context(|| format!("create {}", attachment.display()))?;
        let path = attachment.join("bridge.toml");
        fs::write(&path, bridge_text(id, clone, &attachment, &entry.channel))
            .with_context(|| format!("write {}", path.display()))?;
    }
    if !filed {
        if !root.adopt(id, &entry.channel, Some(clone))? {
            bail!(
                "not filed: {} is under this machine's temporary directory",
                entry.channel.display()
            );
        }
        let _ = root.link_repo(id, clone);
    }
    // Prove it the way every other command will read it, rather than trust what was just
    // written.
    let after = root
        .read()
        .projects
        .into_iter()
        .find(|e| e.project_id == id)
        .with_context(|| format!("{id} is no longer filed in {}", root.path.display()))?;
    after
        .route(root)
        .with_context(|| format!("attached {id}, but the result does not read back"))?;
    Ok(Attach::Attached { actions })
}

/// Attach every checkout directly under `folder` whose name is a project the root files.
///
/// A folder that is not named for a filed project is not this command's business and is
/// not listed. `skip` names folders or projects to leave out. One checkout failing never
/// stops the rest.
///
/// # Errors
/// `folder` cannot be read.
pub fn attach_all(
    root: &Root,
    folder: &Path,
    skip: &[String],
    dry_run: bool,
) -> Result<Vec<Report>> {
    let filed = root.read().projects;
    let mut found: Vec<PathBuf> = fs::read_dir(folder)
        .with_context(|| format!("read {}", folder.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    found.sort();
    let mut reports = Vec::new();
    for path in found {
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        let slug = crate::identity::slug(&name);
        let Some(entry) = filed
            .iter()
            .find(|entry| entry.project_id == slug || entry.project_id.eq_ignore_ascii_case(&name))
        else {
            continue;
        };
        let left_out = skip
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&name) || s.eq_ignore_ascii_case(&entry.project_id));
        let outcome = if left_out {
            Attach::Skipped(Skip::ByName)
        } else if !path.join(".git").exists() {
            Attach::Skipped(Skip::NotGit)
        } else {
            let clone = fs::canonicalize(&path)
                .map(|resolved| ferryman_channel::real_path(&resolved))
                .unwrap_or_else(|_| path.clone());
            attach_entry(root, entry, &clone, dry_run, false)
                .unwrap_or_else(|error| Attach::Skipped(Skip::Failed(format!("{error:#}"))))
        };
        reports.push(Report {
            name,
            clone: path,
            project: entry.project_id.clone(),
            outcome,
        });
    }
    Ok(reports)
}

/// The projects the root files that no folder under `folder` was matched to, so a listing
/// can say which have no clone here.
#[must_use]
pub fn without_clone(root: &Root, reports: &[Report]) -> Vec<String> {
    root.read()
        .projects
        .into_iter()
        .map(|entry| entry.project_id)
        .filter(|id| !reports.iter().any(|report| report.project == *id))
        .collect()
}

#[cfg(test)]
mod tests;

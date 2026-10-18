//! `ferry repos sync` - Ferryman's own clone of every project, in the one fixed place.
//!
//! # The rule
//!
//! Every machine has the same layout under its ferry root:
//!
//! ```text
//! comms/<project>-ferryman      the channel (synced)
//! repos/<project>               Ferryman's own clone of the project; only its workers use it
//! work/<project>/<order>        per-order worktrees made from repos/<project>
//! ```
//!
//! A person's working copy (`X:\ferryman`, `~/code/fructly`) is a different thing and is
//! never it. It holds uncommitted work and a Claude session's context, so Ferryman does not
//! move it, clean it, fetch into it or write into it. When a project is already attached to
//! such a copy, the managed clone becomes the worker's checkout and the manifest keeps the
//! copy as a `human_checkouts` entry, for information. Nothing is deleted.
//!
//! # What a sync does, per project
//!
//! 1. Leaves it alone, saying why, when it is archived, its master turned the swarm off for
//!    it, this machine excludes it (`[swarm] exclude` in `ferry.toml`), its channel is not
//!    on this machine, or no remote is known for it.
//! 2. Clones the remote into `repos/<project>` when that is not there yet. Never over
//!    something that exists. A link left at that path by an earlier `ferry root adopt` (it
//!    points at a person's checkout) is removed - the link only, never what it pointed at -
//!    and the checkout is remembered.
//! 3. Fetches. Never resets or cleans, and a clone with local changes keeps them. One thing
//!    more, and only for a clone this command made (it leaves `.git/ferryman-managed` in
//!    it): when the clone has no changes of its own and its branch is strictly behind its
//!    upstream, the branch is fast-forwarded (`git merge --ff-only`), so the files the
//!    worker reads from the clone - a project's `[policy]` files - are the merged ones and
//!    not the ones from the day it was cloned. A clone someone else made is only fetched.
//! 4. Attaches the clone to the channel the root already files for the project: its
//!    `.ferryman/bridge.toml` names that channel, `/.ferryman/` goes in the clone's
//!    `.git/info/exclude` (never a tracked file), and the root files the clone. No roster,
//!    key, device or Syncthing folder is touched, and nothing is signed.
//!
//! # Which remote
//!
//! In this order: `[git.remotes]` for the project, the machine's `[git] remote_template`,
//! its `[git] fallback_template`, then the `origin` of a checkout of it this machine already
//! has. Each is tried until one clones. A password in any of them is refused, and the origin
//! of a person's checkout has any credential stripped before it is used. Credentials are the
//! machine's: a credential helper, an ssh alias, a read-only token the helper holds.
//!
//! A remote that needs a helper program git does not have is skipped with the reason, not
//! tried: `sov://bucket/repo` (SovGit) needs `git-remote-sov` on PATH, and without it the
//! next remote is used (the fallback template is the GitHub one), or, with none left, the
//! project is reported as not synced and why. Ferryman knows nothing of SovGit beyond
//! running `git clone` and `git fetch`; the helper does the rest.
//!
//! Safe to run again and again: it is what `ferry fleet setup` runs, and what the watchdog
//! runs as "repair layout".

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use ferryman_channel::ferry::{Entry, Root};

use crate::attach::{self, Attach};
use crate::rootconfig::{self, RootConfig};

/// Why a project was not synced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    Archived,
    /// Its master signed `swarm = off`.
    SwarmOff,
    /// This machine's `ferry.toml` keeps it out.
    Excluded,
    /// The root files it, but its channel folder is not here.
    NoChannel,
    /// Placed by hand (`placement: custom`): Ferryman works from the paths recorded for it and
    /// does not make a clone of its own beside them.
    Custom,
    /// Nothing says where to clone it from.
    NoRemote,
    /// `repos/<project>` holds something that is not a git clone.
    NotAClone(PathBuf),
    /// Git failed, or the attach could not be completed. Nothing past it was done.
    Failed(String),
}

impl Skip {
    /// The sentence a listing shows after `skipped`.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Archived => "archived: its master finished it".into(),
            Self::SwarmOff => "swarm = off: its master keeps it out of the swarm".into(),
            Self::Excluded => {
                "excluded on this machine ([swarm] exclude in the root's ferry.toml)".into()
            }
            Self::NoChannel => "its channel folder is not on this machine".into(),
            Self::Custom => "placed by hand (custom): Ferryman uses the paths recorded for it \
                              and keeps no clone of its own"
                .into(),
            Self::NoRemote => "no known remote: set [git] remote_template (or [git.remotes]) in \
                               the root's ferry.toml"
                .into(),
            Self::NotAClone(path) => format!(
                "{} exists and is not a git clone; left exactly as it is",
                path.display()
            ),
            Self::Failed(why) => why.clone(),
        }
    }
}

/// What a sync did, or would do, for one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// These steps, in order: `cloned`, `fetched`, `attached`.
    Done(Vec<&'static str>),
    /// A clone is there, attached, and a fetch brought nothing new: nothing was changed.
    AlreadyOk,
    Skipped(Skip),
}

/// One project's line in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub project: String,
    pub status: Status,
    /// What was (or, in a dry run, would be) done, in words.
    pub details: Vec<String>,
}

impl Row {
    /// `cloned, attached`, `already-ok`, or `skipped`.
    #[must_use]
    pub fn word(&self) -> String {
        match &self.status {
            Status::Done(steps) => steps.join(", "),
            Status::AlreadyOk => "already-ok".into(),
            Status::Skipped(_) => "skipped".into(),
        }
    }
}

/// How a sync is asked to run.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Only this project.
    pub only: Option<String>,
    /// Say what would be done and change nothing.
    pub dry_run: bool,
    /// Do not fetch (no network). Clones and attaches still happen.
    pub no_fetch: bool,
    /// Folders searched for remote helpers (`git-remote-<scheme>`) before PATH, and put in
    /// front of PATH for the git commands this runs. Empty in normal use.
    pub helper_dirs: Vec<PathBuf>,
}

/// Run git, with `extra_path` folders in front of PATH so a remote helper in one is found.
fn git_with(
    dir: Option<&Path>,
    args: &[&str],
    extra_path: &[PathBuf],
) -> std::io::Result<std::process::Output> {
    let mut command = Command::new("git");
    if let Some(dir) = dir {
        command.arg("-C").arg(dir);
    }
    command
        .args(args)
        // Never wait for a person on a machine nobody is sitting at.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .stdin(Stdio::null());
    if !extra_path.is_empty() {
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let folders = extra_path
            .iter()
            .cloned()
            .chain(std::env::split_paths(&existing));
        if let Ok(joined) = std::env::join_paths(folders) {
            command.env("PATH", joined);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command.output()
}

fn git_ok(dir: Option<&Path>, args: &[&str]) -> Result<String, String> {
    git_ok_with(dir, args, &[])
}

fn git_ok_with(
    dir: Option<&Path>,
    args: &[&str],
    extra_path: &[PathBuf],
) -> Result<String, String> {
    match git_with(dir, args, extra_path) {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
        }
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
        Err(error) => Err(format!("could not run git: {error}")),
    }
}

/// The remotes git can use on this machine, and the reasons it cannot use the others. A
/// remote that needs a helper program is checked for it before git is asked.
fn split_usable(remotes: Vec<String>, extra: &[PathBuf]) -> (Vec<String>, Vec<String>) {
    let mut folders: Option<Vec<PathBuf>> = None;
    let (mut usable, mut unusable) = (Vec::new(), Vec::new());
    for remote in remotes {
        if rootconfig::helper_scheme(&remote).is_none() {
            usable.push(remote);
            continue;
        }
        let folders = folders.get_or_insert_with(|| {
            let mut folders = extra.to_vec();
            folders.extend(rootconfig::helper_folders());
            folders
        });
        match rootconfig::helper_missing_in(&remote, folders) {
            Some(why) => unusable.push(why),
            None => usable.push(remote),
        }
    }
    (usable, unusable)
}

/// Marks a clone `ferry repos sync` made, so that only such a clone is ever fast-forwarded.
const MANAGED_MARKER: &str = "ferryman-managed";

/// Fast-forward a clone Ferryman made when that cannot lose anything: it has no changes to
/// tracked files, and its branch is strictly behind its upstream. Returns what it did.
fn advance(clone: &Path) -> Option<String> {
    if !clone.join(".git").join(MANAGED_MARKER).is_file() {
        return None;
    }
    if !git_ok(
        Some(clone),
        &["status", "--porcelain", "--untracked-files=no"],
    )
    .ok()?
    .is_empty()
    {
        return None;
    }
    let branch = git_ok(Some(clone), &["symbolic-ref", "--quiet", "--short", "HEAD"]).ok()?;
    let upstream = git_ok(
        Some(clone),
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )
    .ok()?;
    let (head, tip) = (
        git_ok(Some(clone), &["rev-parse", "HEAD"]).ok()?,
        git_ok(Some(clone), &["rev-parse", "@{upstream}"]).ok()?,
    );
    if head == tip
        || git_ok(
            Some(clone),
            &["merge-base", "--is-ancestor", "HEAD", "@{upstream}"],
        )
        .is_err()
    {
        return None;
    }
    git_ok(
        Some(clone),
        &["merge", "--ff-only", "--quiet", "@{upstream}"],
    )
    .ok()?;
    Some(format!("fast-forwarded {branch} to {upstream}"))
}

/// The `origin` of a checkout, with any credential taken out.
fn origin_of(checkout: &Path) -> Option<String> {
    if !checkout.join(".git").exists() {
        return None;
    }
    git_ok(Some(checkout), &["remote", "get-url", "origin"])
        .ok()
        .filter(|url| !url.is_empty())
        .map(|url| rootconfig::without_credentials(&url))
}

/// Where a project could be cloned from, best first.
fn candidates(entry: &Entry, config: &RootConfig, root: &Root) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut push = |remote: String| {
        if rootconfig::check_remote(&remote).is_ok() && !found.contains(&remote) {
            found.push(remote);
        }
    };
    if let Some(remote) = config.remotes.get(&entry.project_id) {
        push(remote.clone());
    }
    if let Some(template) = &config.remote_template {
        push(template.replace("{project}", &entry.project_id));
    }
    if let Some(template) = &config.fallback_template {
        push(template.replace("{project}", &entry.project_id));
    }
    let managed = root.managed_clone(&entry.project_id);
    for checkout in entry
        .repo
        .iter()
        .chain(entry.human_checkouts.iter())
        .filter(|checkout| **checkout != managed)
    {
        if let Some(remote) = origin_of(checkout) {
            push(remote);
        }
    }
    found
}

/// A link left at `path` by an earlier adopt, and where it points. `None` for anything that
/// is not a link.
fn link_at(path: &Path) -> Option<PathBuf> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    Some(fs::read_link(path).unwrap_or_default())
}

/// Remove a link and only the link. Never recurses.
fn remove_link(path: &Path) -> std::io::Result<()> {
    fs::remove_dir(path).or_else(|_| fs::remove_file(path))
}

/// The remote-tracking refs of a clone, to tell whether a fetch brought anything.
fn remote_refs(clone: &Path) -> String {
    git_ok(
        Some(clone),
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/remotes",
        ],
    )
    .unwrap_or_default()
}

/// Whether the clone has uncommitted changes. Information only.
fn dirty(clone: &Path) -> bool {
    git_ok(Some(clone), &["status", "--porcelain"]).is_ok_and(|status| !status.is_empty())
}

/// Sync one project.
fn sync_one(root: &Root, entry: &Entry, config: &RootConfig, options: &Options) -> Row {
    let id = entry.project_id.clone();
    let skipped = |why: Skip| Row {
        project: id.clone(),
        status: Status::Skipped(why),
        details: Vec::new(),
    };
    if entry.is_archived() {
        return skipped(Skip::Archived);
    }
    if config.excluded(&id) {
        return skipped(Skip::Excluded);
    }
    if entry.channel.is_dir() && entry.swarm_off() {
        return skipped(Skip::SwarmOff);
    }
    if !entry.channel.is_dir() {
        return skipped(Skip::NoChannel);
    }
    // The layout is what Ferryman does when nobody decides; a project someone placed is
    // left as they recorded it, and nothing here assumes it sits under projects/<id>.
    if entry.placement_in(root) == ferryman_channel::ferry::Placement::Custom {
        return skipped(Skip::Custom);
    }
    let managed = root.managed_clone(&id);
    let mut steps: Vec<&'static str> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let dry = options.dry_run;

    // 1. A link where the clone belongs is a leftover of `root adopt`; it points at a
    //    person's checkout. Only the link goes.
    let linked_to = link_at(&managed);
    if let Some(target) = &linked_to {
        details.push(format!(
            "{} {} (a link to {}; the checkout it points at is not touched)",
            if dry {
                "would replace the link"
            } else {
                "replaced the link"
            },
            managed.display(),
            target.display()
        ));
        if !dry && let Err(error) = remove_link(&managed) {
            return skipped(Skip::Failed(format!(
                "could not remove the link at {}: {error}",
                managed.display()
            )));
        }
    }

    // 2. Clone, when there is no clone.
    let present = linked_to.is_none() && managed.exists();
    let have_clone = present && managed.join(".git").exists();
    if present && !have_clone {
        let empty = fs::read_dir(&managed).is_ok_and(|mut entries| entries.next().is_none());
        if !empty {
            return skipped(Skip::NotAClone(managed));
        }
    }
    if !have_clone {
        let (remotes, unusable) =
            split_usable(candidates(entry, config, root), &options.helper_dirs);
        details.extend(unusable.iter().map(|why| format!("skipped {why}")));
        if remotes.is_empty() {
            return if unusable.is_empty() {
                skipped(Skip::NoRemote)
            } else {
                skipped(Skip::Failed(format!(
                    "no remote can be used here: {}",
                    unusable.join("; ")
                )))
            };
        }
        if dry {
            details.push(format!(
                "would clone {} into {}",
                remotes[0],
                managed.display()
            ));
            steps.push("cloned");
        } else {
            let holder = managed
                .parent()
                .map_or_else(|| root.repos(), Path::to_path_buf);
            if let Err(error) = fs::create_dir_all(&holder) {
                return skipped(Skip::Failed(format!(
                    "create {}: {error}",
                    holder.display()
                )));
            }
            let target = managed.to_string_lossy().into_owned();
            let mut last = String::new();
            let mut cloned_from = None;
            for remote in &remotes {
                match git_ok_with(
                    None,
                    &["clone", "--quiet", "--", remote, &target],
                    &options.helper_dirs,
                ) {
                    Ok(_) => {
                        cloned_from = Some(remote.clone());
                        break;
                    }
                    Err(error) => {
                        last = format!("{remote}: {error}");
                        details.push(format!("could not clone {last}"));
                    }
                }
            }
            let Some(remote) = cloned_from else {
                return Row {
                    project: id,
                    status: Status::Skipped(Skip::Failed(format!("could not clone ({last})"))),
                    details,
                };
            };
            // Only a clone made here is ever fast-forwarded: the mark says so.
            let _ = fs::write(
                managed.join(".git").join(MANAGED_MARKER),
                "made by `ferry repos sync`; it may be fast-forwarded when it has no changes\n",
            );
            details.push(format!("cloned {remote} into {}", managed.display()));
            steps.push("cloned");
        }
    } else {
        if dirty(&managed) {
            details.push(format!(
                "{} has local changes; fetching only, nothing reset or cleaned",
                managed.display()
            ));
        }
        // 3. Fetch. A clone just made is current. "fetched" means it brought something.
        if !options.no_fetch {
            let origin = git_ok(Some(&managed), &["remote", "get-url", "origin"]).ok();
            let (_, unusable) = split_usable(origin.into_iter().collect(), &options.helper_dirs);
            if let Some(why) = unusable.first() {
                details.push(format!("not fetched - {why}"));
            } else if dry {
                details.push("would fetch".into());
            } else {
                let before = remote_refs(&managed);
                match git_ok_with(
                    Some(&managed),
                    &["fetch", "--quiet", "--prune", "origin"],
                    &options.helper_dirs,
                ) {
                    Ok(_) => {
                        if remote_refs(&managed) != before {
                            steps.push("fetched");
                        }
                        if let Some(done) = advance(&managed) {
                            details.push(done);
                            steps.push("advanced");
                        }
                    }
                    Err(error) => details.push(format!("fetch failed: {error}")),
                }
            }
        }
    }

    // 4. Attach to the channel the root files.
    let attached = if dry && !have_clone {
        // Nothing to inspect yet: say what attaching will do.
        Ok(Attach::Attached {
            actions: vec![
                "write .ferryman/bridge.toml reading the filed channel".into(),
                "add /.ferryman/ to .git/info/exclude".into(),
                "file the clone as the worker's checkout".into(),
            ],
        })
    } else {
        attach::attach_managed(root, entry, &managed, dry)
    };
    match attached {
        Ok(Attach::Attached { actions }) => {
            steps.push("attached");
            details.extend(actions.into_iter().map(|action| {
                if dry {
                    format!("would: {action}")
                } else {
                    action
                }
            }));
        }
        Ok(Attach::Already) => {}
        Ok(Attach::Skipped(why)) => {
            return Row {
                project: id,
                status: Status::Skipped(Skip::Failed(format!(
                    "not attached ({}): {}",
                    why.label(),
                    why.reason()
                ))),
                details,
            };
        }
        Err(error) => {
            return Row {
                project: id,
                status: Status::Skipped(Skip::Failed(format!("not attached: {error:#}"))),
                details,
            };
        }
    }
    // The person's checkout the link pointed at is remembered, as information.
    if let Some(target) = linked_to
        && !dry
        && !target.as_os_str().is_empty()
    {
        let _ = root.note_human_checkout(&id, &target);
    }
    let status = if steps.is_empty() {
        Status::AlreadyOk
    } else {
        Status::Done(steps)
    };
    Row {
        project: id,
        status,
        details,
    }
}

/// Make sure every live project of `root` has its managed clone, fetched and attached.
///
/// Returns one row per project, in order. A project that cannot be synced is a row, never
/// an error: the rest are still done.
///
/// # Errors
/// Only `only` naming a project the root does not file.
pub fn sync(root: &Root, options: &Options) -> Result<Vec<Row>> {
    let config = RootConfig::load(root);
    let projects = root.read().projects;
    if let Some(only) = &options.only
        && !projects.iter().any(|entry| entry.project_id == *only)
    {
        anyhow::bail!(
            "the ferry root files no project '{only}' ({}); `ferry root` lists them",
            root.path.display()
        );
    }
    if !options.dry_run {
        for (_, dir) in root.top_folders() {
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }
    }
    Ok(projects
        .iter()
        .filter(|entry| {
            options
                .only
                .as_ref()
                .is_none_or(|only| *only == entry.project_id)
        })
        .map(|entry| sync_one(root, entry, &config, options))
        .collect())
}

/// The projects whose managed clone is missing or not attached, as sentences. What
/// `doctor --layout` and the watchdog read to decide whether a sync is called for.
#[must_use]
pub fn unsynced(root: &Root) -> Vec<(String, String)> {
    let config = RootConfig::load(root);
    let mut out = Vec::new();
    for entry in root.read().projects {
        if entry.is_archived()
            || config.excluded(&entry.project_id)
            || !entry.channel.is_dir()
            || entry.swarm_off()
            || entry.placement_in(root) == ferryman_channel::ferry::Placement::Custom
        {
            continue;
        }
        let managed = root.managed_clone(&entry.project_id);
        let problem = if !managed.join(".git").exists() {
            Some(format!("{} is not a clone", managed.display()))
        } else if entry.repo.as_deref() != Some(managed.as_path())
            && !entry
                .repo
                .as_deref()
                .is_some_and(|repo| attach::same_path(repo, &managed))
        {
            Some(format!(
                "the root files {} as its checkout, not {}",
                entry
                    .repo
                    .as_deref()
                    .map_or_else(|| "nothing".to_owned(), |repo| repo.display().to_string()),
                managed.display()
            ))
        } else if entry.attachment().is_none() {
            Some(format!(
                "{} has no .ferryman/bridge.toml",
                managed.display()
            ))
        } else {
            None
        };
        if let Some(problem) = problem {
            out.push((entry.project_id, problem));
        }
    }
    out
}

#[cfg(test)]
mod tests;

//! `ferry root migrate`: move a layout-1 root (`comms/ repos/ work/`) to layout 2
//! (`projects/<id>/{repo,comms,handins,work,tmp}`), one project at a time.
//!
//! Dry run by default. A dry run reads the manifest, the disk and (read-only) the git
//! worktree list, and writes nothing at all: no folder, no log, no manifest, no Syncthing
//! change. `apply` does the work, and every filesystem change in this file is behind it.
//!
//! What moves, per managed project:
//!
//! - the channel to `projects/<id>/comms` (the folder and channel id do not change, so no
//!   other machine re-pairs); every `bridge.toml` that named the old path is rewritten,
//!   which is also how the worker and its iroh lane find the channel;
//! - the Syncthing folder, when Syncthing still has it: paused, its PATH changed through
//!   Ferryman's own REST with the id kept, resumed;
//! - hand-ins from `<channel>/handins` to `projects/<id>/handins`;
//! - Ferryman's own clone, `repos/<id>` to `projects/<id>/repo`, and `git worktree prune`.
//!
//! What never moves: a custom project (a person placed it; ADR 0019 and 0024), a human
//! checkout, anything under a project's `.ferryman/`. A project with a running worker, a
//! live lock or a live worktree is refused, with the reason. Stale worktrees under
//! `work/` are left and reported.
//!
//! Nothing is deleted. Anything a move superseded goes to `<root>/_to_delete/` and is
//! listed. The manifest becomes version 2 only when no managed project is left behind.
//! Running it again finds nothing to do.

use anyhow::{Context, Result, bail};
use ferryman_channel::ferry::{self, Entry, Placement, Root, same_place};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::machine::{Kind, Scan, Worker};

/// What to do and what to hold back for.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Act. Without it nothing is written.
    pub apply: bool,
    /// Update Ferryman's Syncthing for folders it still has. Off in tests, which must not
    /// touch a running service.
    pub syncthing: bool,
    /// Why nothing may move on this machine right now (a running worker). Applies to
    /// every project, since one worker serves them all.
    pub machine_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Moved (apply).
    Migrated,
    /// Would move (dry run).
    Planned,
    /// Already in layout 2.
    AlreadyDone,
    /// Placed by hand: left exactly where it is.
    Custom,
    /// Something running or in the way; nothing of this project was touched.
    Blocked(Vec<String>),
    /// The channel is not on this machine, so there is nothing here to move.
    NotHere,
    /// A step failed. Earlier steps are recorded in the manifest, so the project is
    /// consistent and a second run continues.
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ProjectReport {
    pub project: String,
    pub status: Status,
    pub steps: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub applied: bool,
    pub root: PathBuf,
    pub projects: Vec<ProjectReport>,
    /// Worktree directories left under `work/`, with the project they belonged to.
    pub stale_worktrees: Vec<String>,
    /// What went to `_to_delete`.
    pub to_delete: Vec<PathBuf>,
    /// The manifest is now (apply) or would become (dry run) version 2.
    pub bumped: bool,
    pub would_bump: bool,
    pub log: Option<PathBuf>,
}

impl Report {
    /// Whether anything stands in the way of finishing.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.projects
            .iter()
            .all(|p| !matches!(p.status, Status::Blocked(_) | Status::Failed(_)))
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "ferry root migrate: {} ({})\n",
            self.root.display(),
            if self.applied {
                "applied"
            } else {
                "dry run, nothing was changed"
            }
        );
        for p in &self.projects {
            let head = match &p.status {
                Status::Migrated => "migrated".to_string(),
                Status::Planned => "would migrate".to_string(),
                Status::AlreadyDone => "already in layout 2".to_string(),
                Status::Custom => "left in place (custom)".to_string(),
                Status::Blocked(_) => "BLOCKED".to_string(),
                Status::NotHere => "channel not on this machine, nothing to move".to_string(),
                Status::Failed(why) => format!("FAILED: {why}"),
            };
            out.push_str(&format!("  {}: {head}\n", p.project));
            if let Status::Blocked(why) = &p.status {
                for line in why {
                    out.push_str(&format!("      blocked by: {line}\n"));
                }
            }
            for step in &p.steps {
                out.push_str(&format!("      {step}\n"));
            }
            for note in &p.notes {
                out.push_str(&format!("      note: {note}\n"));
            }
        }
        if !self.stale_worktrees.is_empty() {
            out.push_str("stale worktrees left under work/ (not touched):\n");
            for line in &self.stale_worktrees {
                out.push_str(&format!("  {line}\n"));
            }
        }
        if !self.to_delete.is_empty() {
            out.push_str("superseded, parked in _to_delete (delete when you are satisfied):\n");
            for path in &self.to_delete {
                out.push_str(&format!("  {}\n", path.display()));
            }
        }
        out.push_str(&format!(
            "manifest: {}\n",
            if self.bumped {
                "now version 2"
            } else if self.would_bump {
                "would become version 2"
            } else {
                "stays as it was (a managed project is not migrated yet)"
            }
        ));
        if let Some(log) = &self.log {
            out.push_str(&format!("log: {}\n", log.display()));
        }
        out
    }
}

/// The running workers on this machine, as reasons for `Options::machine_blockers`.
/// A worker that is merely enabled does not block: only one that is working now.
#[must_use]
pub fn blockers_from_scan(scan: &Scan) -> Vec<String> {
    scan.workers
        .iter()
        .filter(|worker| working_now(worker))
        .map(|worker| format!("a ferry worker is running: {}", worker.describe()))
        .collect()
}

fn working_now(worker: &Worker) -> bool {
    match &worker.kind {
        Kind::Process { .. } => true,
        Kind::Unit { active, .. } => *active,
        Kind::Task { running, .. } => *running,
    }
}

struct Ctx {
    apply: bool,
    stamp: String,
    park: PathBuf,
    parked: Vec<PathBuf>,
    backed_up: bool,
}

/// Plan, and with `options.apply` perform, the migration of every project in `root`.
///
/// # Errors
/// Only for what stops the whole run (the log or `_to_delete` cannot be made). A problem
/// with one project is that project's status.
pub fn run(root: &Root, options: &Options) -> Result<Report> {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut ctx = Ctx {
        apply: options.apply,
        stamp,
        park: root.path.join("_to_delete"),
        parked: Vec::new(),
        backed_up: false,
    };
    let mut report = Report {
        applied: options.apply,
        root: root.path.clone(),
        ..Report::default()
    };
    let entries = root.read().projects;
    for entry in &entries {
        let one = project(root, entry, options, &mut ctx);
        if let Some(repo) = &entry.repo
            && one.status != Status::Custom
        {
            for stale in stale_worktrees(root, repo) {
                report.stale_worktrees.push(format!(
                    "{} (of {})",
                    stale.display(),
                    entry.project_id
                ));
            }
        }
        report.projects.push(one);
    }
    let behind = report
        .projects
        .iter()
        .any(|p| matches!(p.status, Status::Blocked(_) | Status::Failed(_)));
    let already = root.layout_version() >= 2;
    report.would_bump = !already && !behind;
    if options.apply && report.would_bump {
        if !ctx.backed_up {
            backup_manifest(root, &mut ctx);
        }
        root.set_layout_v2()?;
        report.bumped = true;
    } else if already {
        report.bumped = true;
    }
    report.to_delete = ctx.parked.clone();
    if options.apply {
        fs::create_dir_all(root.logs())
            .with_context(|| format!("create {}", root.logs().display()))?;
        let log = root.logs().join(format!("migrate-{}.md", ctx.stamp));
        fs::write(
            &log,
            format!(
                "# ferry root migrate {}\n\n```\n{}```\n",
                ctx.stamp,
                report.render()
            ),
        )
        .with_context(|| format!("write {}", log.display()))?;
        report.log = Some(log);
    }
    Ok(report)
}

fn project(root: &Root, entry: &Entry, options: &Options, ctx: &mut Ctx) -> ProjectReport {
    let id = entry.project_id.clone();
    let mut rep = ProjectReport {
        project: id.clone(),
        status: Status::AlreadyDone,
        steps: Vec::new(),
        notes: Vec::new(),
    };
    if entry.placement_in(root) == Placement::Custom {
        rep.status = Status::Custom;
        rep.notes.push(format!(
            "channel {}{}",
            entry.channel.display(),
            entry
                .repo
                .as_ref()
                .map_or_else(String::new, |r| format!(", repo {}", r.display()))
        ));
        return rep;
    }
    let dir = root.project_dir(&id);
    let comms_to = dir.join("comms");
    let handins_to = dir.join("handins");
    let repo_to = dir.join("repo");

    let channel_here = entry.channel.is_dir();
    let move_channel = channel_here && !same_place(&entry.channel, &comms_to);
    let handins_from_now = entry.channel.join("handins");
    let move_handins = channel_here && non_empty(&handins_from_now);
    let move_repo = entry
        .repo
        .as_ref()
        .filter(|repo| repo.is_dir() && same_place(repo, &root.repos().join(&id)))
        .cloned();

    if !move_channel && !move_handins && move_repo.is_none() {
        rep.status = if channel_here || entry.repo.is_some() {
            Status::AlreadyDone
        } else {
            Status::NotHere
        };
        return rep;
    }

    // Refusals first, and all of them, so the person sees everything at once.
    let mut blocked: Vec<String> = options.machine_blockers.clone();
    let mut places: Vec<PathBuf> = Vec::new();
    places.extend(entry.repo.iter().cloned());
    for place in &places {
        blocked.extend(live_locks(place));
        match live_worktrees(place) {
            Ok(list) => {
                for tree in list {
                    blocked.push(format!("a live worktree at {}", tree.display()));
                }
            }
            Err(why) => blocked.push(format!(
                "worktrees of {} unreadable: {why}",
                place.display()
            )),
        }
    }
    if move_channel && non_empty(&comms_to) {
        blocked.push(format!("{} already holds something", comms_to.display()));
    }
    if move_handins && non_empty(&handins_to) {
        blocked.push(format!("{} already holds something", handins_to.display()));
    }
    if move_repo.is_some() && non_empty(&repo_to) {
        blocked.push(format!("{} already holds something", repo_to.display()));
    }
    if !blocked.is_empty() {
        rep.status = Status::Blocked(blocked);
        return rep;
    }

    let folder = format!("{id}-ferryman");
    let in_syncthing =
        options.syncthing && ferryman_channel::syncthing_folder_state(&folder).is_some();

    if move_channel {
        rep.steps.push(format!(
            "channel {} -> {}",
            entry.channel.display(),
            comms_to.display()
        ));
        if in_syncthing {
            rep.steps.push(format!(
                "syncthing folder {folder}: pause, set path, resume (id kept)"
            ));
        }
    }
    if move_handins {
        rep.steps
            .push(format!("hand-ins -> {}", handins_to.display()));
    }
    if let Some(repo) = &move_repo {
        rep.steps.push(format!(
            "managed clone {} -> {}, then git worktree prune",
            repo.display(),
            repo_to.display()
        ));
    }
    if !ctx.apply {
        rep.status = Status::Planned;
        return rep;
    }

    match perform(root, entry, options, ctx, in_syncthing, &mut rep) {
        Ok(()) => rep.status = Status::Migrated,
        Err(error) => rep.status = Status::Failed(format!("{error:#}")),
    }
    rep
}

fn perform(
    root: &Root,
    entry: &Entry,
    options: &Options,
    ctx: &mut Ctx,
    in_syncthing: bool,
    rep: &mut ProjectReport,
) -> Result<()> {
    let id = &entry.project_id;
    let dir = root.project_dir(id);
    let comms_to = dir.join("comms");
    let handins_to = dir.join("handins");
    let repo_to = dir.join("repo");
    let folder = format!("{id}-ferryman");
    let mut channel_now = entry.channel.clone();

    if !ctx.backed_up {
        backup_manifest(root, ctx);
    }

    if entry.channel.is_dir() && !same_place(&entry.channel, &comms_to) {
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        if in_syncthing {
            let _ = ferryman_channel::syncthing_pause_folder(&folder, true);
        }
        if let Err(error) = safe_move(&entry.channel, &comms_to, ctx) {
            if in_syncthing {
                let _ = ferryman_channel::syncthing_pause_folder(&folder, false);
            }
            return Err(error);
        }
        let old = entry.channel.display().to_string();
        let mut bridges: Vec<PathBuf> = entry.attachment().into_iter().collect();
        for human in &entry.human_checkouts {
            let attachment = human.join(".ferryman");
            if fs::read_to_string(attachment.join("bridge.toml"))
                .is_ok_and(|text| text.contains(&old))
            {
                bridges.push(attachment);
            }
        }
        for attachment in bridges {
            ferry::repoint_bridge_in(&attachment, &[("communications", &comms_to)])?;
        }
        root.update_entry(id, |e| e.channel = comms_to.clone())?;
        channel_now = comms_to.clone();
        if in_syncthing {
            match ferryman_channel::syncthing_move_folder(&folder, &comms_to) {
                Ok(true) => rep.notes.push(format!(
                    "syncthing folder {folder} now at {}",
                    comms_to.display()
                )),
                Ok(false) | Err(_) => {
                    let _ = ferryman_channel::syncthing_pause_folder(&folder, false);
                    rep.notes.push(format!(
                        "syncthing folder {folder} could not be re-pointed; fix its path in \
                         Ferryman's Syncthing (127.0.0.1:8385) to {}",
                        comms_to.display()
                    ));
                }
            }
        }
        rep.notes.push(
            "the iroh lane reads this channel from bridge.toml (rewritten): restart the worker"
                .to_string(),
        );
    }

    let handins_from = channel_now.join("handins");
    if non_empty(&handins_from) {
        if handins_to.exists() && !non_empty(&handins_to) {
            fs::remove_dir(&handins_to)?;
        }
        safe_move(&handins_from, &handins_to, ctx)?;
        if in_syncthing {
            let fresh = root
                .read()
                .projects
                .into_iter()
                .find(|e| &e.project_id == id)
                .unwrap_or_else(|| entry.clone());
            match fresh.route(root) {
                Ok((route, _)) => {
                    if let Err(error) =
                        ferryman_channel::syncthing_register_work_folder(&route, &handins_to)
                    {
                        rep.notes.push(format!(
                            "syncthing folder {id}-handins not registered: {error:#}"
                        ));
                    }
                }
                Err(error) => rep.notes.push(format!(
                    "syncthing folder {id}-handins not registered: {error:#}"
                )),
            }
        }
    }

    if let Some(repo) = entry
        .repo
        .as_ref()
        .filter(|repo| repo.is_dir() && same_place(repo, &root.repos().join(id)))
    {
        fs::create_dir_all(&dir)?;
        safe_move(repo, &repo_to, ctx)?;
        let attachment = repo_to.join(".ferryman");
        ferry::repoint_bridge_in(
            &attachment,
            &[("workspace", &repo_to), ("attachment", &attachment)],
        )?;
        root.update_entry(id, |e| e.repo = Some(repo_to.clone()))?;
        if repo_to.join(".git").exists() {
            let pruned = Command::new("git")
                .arg("-C")
                .arg(&repo_to)
                .args(["worktree", "prune"])
                .output();
            if !pruned.is_ok_and(|o| o.status.success()) {
                rep.notes
                    .push("git worktree prune did not run; run it in the clone".to_string());
            }
        }
    }
    // The rest of the project folder, so doctor finds the layout whole.
    for name in ["work", "tmp"] {
        fs::create_dir_all(dir.join(name))?;
    }
    let _ = options;
    Ok(())
}

fn non_empty(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// Keep a copy of the manifest as it was, in `_to_delete`, before the first change.
fn backup_manifest(root: &Root, ctx: &mut Ctx) {
    ctx.backed_up = true;
    let manifest = root.manifest_path();
    if !manifest.is_file() || fs::create_dir_all(&ctx.park).is_err() {
        return;
    }
    let copy = ctx
        .park
        .join(format!("ferry-manifest-before-migrate-{}.json", ctx.stamp));
    if fs::copy(&manifest, &copy).is_ok() {
        ctx.parked.push(copy);
    }
}

/// Move a directory without ever deleting. A rename where the volume allows it; across
/// volumes a copy, after which the original is parked in `_to_delete` rather than removed.
fn safe_move(from: &Path, to: &Path, ctx: &mut Ctx) -> Result<()> {
    if to.exists() {
        if non_empty(to) {
            bail!("{} already holds something", to.display());
        }
        fs::remove_dir(to)?;
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    if let Err(error) = ferry::copy_tree(from, to) {
        park(to, ctx);
        return Err(error.context(format!("copy {} to {}", from.display(), to.display())));
    }
    park(from, ctx);
    Ok(())
}

fn park(path: &Path, ctx: &mut Ctx) {
    if fs::create_dir_all(&ctx.park).is_err() {
        return;
    }
    let name = path
        .file_name()
        .map_or_else(|| "dir".to_string(), |n| n.to_string_lossy().into_owned());
    let target = ctx.park.join(format!("{name}-{}", ctx.stamp));
    let mut candidate = target.clone();
    let mut n = 1;
    while candidate.exists() {
        candidate = ctx.park.join(format!("{name}-{}-{n}", ctx.stamp));
        n += 1;
    }
    if fs::rename(path, &candidate).is_ok() {
        ctx.parked.push(candidate);
    }
}

/// Worker locks in a checkout whose process is alive.
fn live_locks(repo: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(repo.join(".ferryman")) else {
        return out;
    };
    for file in entries.flatten() {
        let name = file.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("worker-") && name.ends_with(".lock")) {
            continue;
        }
        let pid = fs::read_to_string(file.path())
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        if pid.is_some_and(crate::agent::process_alive) {
            out.push(format!(
                "a worker holds the lock {} (pid {})",
                file.path().display(),
                pid.unwrap_or(0)
            ));
        }
    }
    out
}

/// Registered worktrees of `repo` other than the checkout itself whose directory exists.
fn live_worktrees(repo: &Path) -> std::result::Result<Vec<PathBuf>, String> {
    if !repo.join(".git").exists() {
        return Ok(Vec::new());
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .map(PathBuf::from)
        .filter(|tree| !same_place(tree, repo) && tree.exists())
        .collect())
}

/// Directories under `work/` (one or two levels down) whose `.git` file points into
/// `repo`. They are reported and left: a task may still want them, and deleting a
/// worktree is not this command's decision.
fn stale_worktrees(root: &Root, repo: &Path) -> Vec<PathBuf> {
    let fold = |p: &Path| {
        let t = p.display().to_string().replace('\\', "/");
        if cfg!(windows) { t.to_lowercase() } else { t }
    };
    let needle = fold(repo);
    let points_here = |dir: &Path| {
        fs::read_to_string(dir.join(".git"))
            .is_ok_and(|text| fold(Path::new(&text)).contains(&needle))
    };
    let mut found = Vec::new();
    let Ok(top) = fs::read_dir(root.work()) else {
        return found;
    };
    for first in top.flatten() {
        let first = first.path();
        if first.is_dir() && points_here(&first) {
            found.push(first.clone());
        }
        if let Ok(second) = fs::read_dir(&first) {
            for entry in second.flatten() {
                let path = entry.path();
                if path.is_dir() && points_here(&path) {
                    found.push(path);
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests;

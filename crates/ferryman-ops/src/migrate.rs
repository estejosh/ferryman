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
//! - the Syncthing folder, when Syncthing still has it: paused before anything moves and
//!   held paused while the hand-ins move out (`<channel>/handins` to
//!   `projects/<id>/handins`), `handins` is added to the channel's `.stignore` and
//!   `<id>-handins` is registered; only then is its PATH changed through Ferryman's own REST
//!   with the id kept, and the folder resumed. Resuming earlier would announce the hand-ins
//!   as deleted to a peer that has not migrated;
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
    /// The Syncthing to drive instead of Ferryman's own (tests). With `syncthing` off and
    /// no backend, Syncthing is not touched.
    pub backend: Option<std::sync::Arc<dyn Syncthing>>,
    /// Move the registered worktrees that no running order uses to `_to_delete` and run
    /// `git worktree prune`. Without it they are listed ("would prune") and left.
    pub prune_stale_worktrees: bool,
    /// Why nothing may move on this machine right now (a running worker). Applies to
    /// every project, since one worker serves them all.
    pub machine_blockers: Vec<String>,
}

/// The parts of Syncthing a migration drives, so the order of the calls can be tested
/// against a stand-in.
pub trait Syncthing: std::fmt::Debug + Send + Sync {
    /// Whether Syncthing has the folder.
    fn has_folder(&self, id: &str) -> bool;
    /// Pause or resume a folder.
    ///
    /// # Errors
    /// The call to Syncthing failed.
    fn pause(&self, id: &str, paused: bool) -> Result<()>;
    /// Point the folder at `to` and resume it. `false` when it could not be re-pointed.
    ///
    /// # Errors
    /// The call to Syncthing failed.
    fn move_folder(&self, id: &str, to: &Path) -> Result<bool>;
    /// Register the project's hand-ins folder as `<id>-handins`.
    ///
    /// # Errors
    /// The call to Syncthing failed.
    fn register_handins(&self, route: &ferryman_channel::ProjectRoute, dir: &Path) -> Result<()>;
}

/// Ferryman's own Syncthing (127.0.0.1:8385, never the person's).
#[derive(Debug)]
struct Live;

impl Syncthing for Live {
    fn has_folder(&self, id: &str) -> bool {
        ferryman_channel::syncthing_folder_state(id).is_some()
    }
    fn pause(&self, id: &str, paused: bool) -> Result<()> {
        ferryman_channel::syncthing_pause_folder(id, paused).map(|_| ())
    }
    fn move_folder(&self, id: &str, to: &Path) -> Result<bool> {
        ferryman_channel::syncthing_move_folder(id, to)
    }
    fn register_handins(&self, route: &ferryman_channel::ProjectRoute, dir: &Path) -> Result<()> {
        ferryman_channel::syncthing_register_work_folder(route, dir).map(|_| ())
    }
}

fn syncthing_for(options: &Options) -> Option<std::sync::Arc<dyn Syncthing>> {
    if let Some(backend) = &options.backend {
        return Some(backend.clone());
    }
    options
        .syncthing
        .then(|| std::sync::Arc::new(Live) as std::sync::Arc<dyn Syncthing>)
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
    /// A step failed. Syncthing's folder is resumed on the way out. The channel's new place
    /// is written to the manifest and bridges straight after it moves, and a rerun that
    /// finds the channel at `projects/<id>/comms` with the manifest still naming the old
    /// place finishes that record, so a second run continues from where this one stopped.
    /// The exception is a copy that could not be set aside after a cross-volume move: both
    /// copies exist, the message says which to remove, and the project waits for you.
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
            out.push_str("worktrees under work/ left where they are (a stale one is yours to remove; a live one blocks its project):\n");
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
    // A run that died after the channel moved and before the manifest was told: the old
    // place is gone and the new one holds the channel. Finishing it is recording where it is.
    let repair = !channel_here && non_empty(&comms_to) && !same_place(&entry.channel, &comms_to);
    let current = if channel_here {
        entry.channel.clone()
    } else if repair {
        comms_to.clone()
    } else {
        entry.channel.clone()
    };
    let handins_from_now = current.join("handins");
    let move_handins = (channel_here || repair) && non_empty(&handins_from_now);
    let move_repo = entry
        .repo
        .as_ref()
        .filter(|repo| movable_clone(root, entry, repo))
        .cloned();

    if !move_channel && !repair && !move_handins && move_repo.is_none() {
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
    let mut stale_registered: Vec<PathBuf> = Vec::new();
    for place in &places {
        blocked.extend(live_locks(place));
        match worktrees_of(place, &current) {
            Ok(trees) => {
                for tree in trees.live {
                    blocked.push(format!(
                        "a worktree at {} is running an order",
                        tree.display()
                    ));
                }
                stale_registered.extend(trees.stale);
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

    let folder = format!("{id}-ferryman");
    let syncthing = syncthing_for(options);
    let in_syncthing = syncthing
        .as_ref()
        .is_some_and(|syncthing| syncthing.has_folder(&folder));

    if move_channel {
        rep.steps.push(format!(
            "channel {} -> {}",
            entry.channel.display(),
            comms_to.display()
        ));
    }
    if repair {
        rep.steps.push(format!(
            "an earlier run moved the channel to {}; record it in the manifest and bridges",
            comms_to.display()
        ));
    }
    if in_syncthing && (move_channel || repair || move_handins) {
        rep.steps.push(format!(
            "syncthing folder {folder}: held paused while the hand-ins move out and `handins` \
             is added to the channel's .stignore, then set path, resume (id kept)"
        ));
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
    for tree in &stale_registered {
        rep.steps.push(if options.prune_stale_worktrees {
            format!(
                "stale worktree {}: would move to _to_delete, then git worktree prune",
                tree.display()
            )
        } else {
            format!(
                "stale worktree {}: would prune (left where it is; --prune-stale-worktrees \
                 moves it to _to_delete)",
                tree.display()
            )
        });
    }
    // Blocked projects still show what would move once the block is gone, so the plan can
    // be read before anything is stopped.
    if !blocked.is_empty() {
        rep.status = Status::Blocked(blocked);
        return rep;
    }
    if !ctx.apply {
        rep.status = Status::Planned;
        return rep;
    }

    let syncthing = syncthing.filter(|_| in_syncthing);
    if options.prune_stale_worktrees {
        for place in &places {
            if let Err(error) = prune_stale(place, &current, ctx, &mut rep) {
                rep.status = Status::Failed(format!("{error:#}"));
                return rep;
            }
        }
    }
    match perform(root, entry, ctx, syncthing.as_deref(), &mut rep) {
        Ok(()) => rep.status = Status::Migrated,
        Err(error) => rep.status = Status::Failed(format!("{error:#}")),
    }
    rep
}

/// Keep the channel's `handins` out of what Syncthing sends: the hand-ins live beside the
/// channel now, and a copy moved out of it must not read as a deletion on a peer that has
/// not migrated. (`.stignore` is never synced, so this is this machine's alone.)
fn ignore_handins(channel: &Path) -> Result<()> {
    let path = channel.join(".stignore");
    let mut text = fs::read_to_string(&path).unwrap_or_default();
    if text.lines().any(|line| {
        matches!(
            line.trim(),
            "/handins" | "handins" | "/handins/" | "handins/"
        )
    }) {
        return Ok(());
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(
        "// layout 2: hand-ins live in projects/<id>/handins, beside the channel\n/handins\n",
    );
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

/// Rewrite the bridges (the attachment's and any human checkout's) that name `old`, and the
/// manifest, to the channel at `to`.
fn record_channel(root: &Root, entry: &Entry, old: &Path, to: &Path) -> Result<()> {
    root.update_entry(&entry.project_id, |e| e.channel = to.to_path_buf())?;
    let old = old.display().to_string();
    let mut bridges: Vec<PathBuf> = entry.attachment().into_iter().collect();
    for human in &entry.human_checkouts {
        let attachment = human.join(".ferryman");
        if fs::read_to_string(attachment.join("bridge.toml")).is_ok_and(|text| text.contains(&old))
        {
            bridges.push(attachment);
        }
    }
    for attachment in bridges {
        ferry::repoint_bridge_in(&attachment, &[("communications", to)])?;
    }
    Ok(())
}

/// The channel and its hand-ins. While Syncthing has the channel's folder it is held paused
/// from before the first change until the last one that could read as a deletion: the
/// hand-ins have left, `handins` is ignored, and `<id>-handins` is registered. Only then is
/// the folder pointed at its new path and resumed, and it is given back on every way out,
/// so a failure never leaves it paused.
fn perform_channel(
    root: &Root,
    entry: &Entry,
    ctx: &mut Ctx,
    syncthing: Option<&dyn Syncthing>,
    rep: &mut ProjectReport,
) -> Result<()> {
    let id = &entry.project_id;
    let dir = root.project_dir(id);
    let comms_to = dir.join("comms");
    let handins_to = dir.join("handins");
    let folder = format!("{id}-ferryman");

    let moving = entry.channel.is_dir() && !same_place(&entry.channel, &comms_to);
    let repairing = !entry.channel.is_dir() && non_empty(&comms_to);
    let current = if moving || !repairing {
        entry.channel.clone()
    } else {
        comms_to.clone()
    };
    let has_handins = non_empty(&current.join("handins"));
    if !moving && !repairing && !has_handins {
        return Ok(());
    }

    if let Some(syncthing) = syncthing {
        syncthing
            .pause(&folder, true)
            .with_context(|| format!("pause syncthing folder {folder}"))?;
    }
    // Where the channel is now, for pointing Syncthing at it afterwards.
    let mut at = current.clone();
    let result = (|| -> Result<()> {
        if moving {
            fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
            safe_move(&entry.channel, &comms_to, ctx)?;
            at.clone_from(&comms_to);
        }
        if moving || repairing {
            // Straight after the move: the manifest and bridges say where the channel is,
            // so a failure from here on leaves a project a rerun can finish.
            record_channel(root, entry, &entry.channel, &comms_to)?;
            at.clone_from(&comms_to);
            rep.notes.push(
                "the iroh lane reads this channel from bridge.toml (rewritten): restart the worker"
                    .to_string(),
            );
        }
        // Before anything leaves the folder Syncthing is watching.
        ignore_handins(&at)?;
        let handins_from = at.join("handins");
        if non_empty(&handins_from) {
            if handins_to.exists() && !non_empty(&handins_to) {
                fs::remove_dir(&handins_to)?;
            }
            safe_move(&handins_from, &handins_to, ctx)?;
        }
        if let Some(syncthing) = syncthing {
            let fresh = root
                .read()
                .projects
                .into_iter()
                .find(|e| &e.project_id == id)
                .unwrap_or_else(|| entry.clone());
            match fresh.route(root) {
                Ok((route, _)) => {
                    if let Err(error) = syncthing.register_handins(&route, &handins_to) {
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
        Ok(())
    })();

    // Give the folder back, where the channel is now, whatever happened above.
    if let Some(syncthing) = syncthing {
        if !same_place(&at, &entry.channel) {
            match syncthing.move_folder(&folder, &at) {
                Ok(true) => rep
                    .notes
                    .push(format!("syncthing folder {folder} now at {}", at.display())),
                Ok(false) | Err(_) => {
                    let _ = syncthing.pause(&folder, false);
                    rep.notes.push(format!(
                        "syncthing folder {folder} could not be re-pointed; fix its path in \
                         Ferryman's Syncthing (127.0.0.1:8385) to {}",
                        at.display()
                    ));
                }
            }
        } else {
            let _ = syncthing.pause(&folder, false);
        }
    }
    result
}

fn perform(
    root: &Root,
    entry: &Entry,
    ctx: &mut Ctx,
    syncthing: Option<&dyn Syncthing>,
    rep: &mut ProjectReport,
) -> Result<()> {
    let id = &entry.project_id;
    let dir = root.project_dir(id);
    let repo_to = dir.join("repo");

    if !ctx.backed_up {
        backup_manifest(root, ctx);
    }

    perform_channel(root, entry, ctx, syncthing, rep)?;

    if let Some(repo) = entry
        .repo
        .as_ref()
        .filter(|repo| movable_clone(root, entry, repo))
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
    Ok(())
}

/// Ferryman's own clone at `repos/<id>`, and nothing else: not an adopted repository, not a
/// link to somebody's checkout, not a folder that merely resolves elsewhere.
fn movable_clone(root: &Root, entry: &Entry, repo: &Path) -> bool {
    !entry.adopted
        && repo.is_dir()
        && !fs::symlink_metadata(repo).is_ok_and(|meta| meta.file_type().is_symlink())
        && same_place(repo, &root.repos().join(&entry.project_id))
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
        // A partial copy is set aside so a rerun starts clean; if even that fails, say so,
        // because the half copy is then still in the way.
        return Err(match park(to, ctx) {
            Ok(()) => error.context(format!("copy {} to {}", from.display(), to.display())),
            Err(why) => error.context(format!(
                "copy {} to {} failed, and the partial copy could not be set aside ({why:#}); \
                 remove {} by hand before running this again",
                from.display(),
                to.display(),
                to.display()
            )),
        });
    }
    // Copied. The original has to leave its place, or there are two. Not deleting is the
    // rule, so it goes to `_to_delete`; if that fails the project stops here, with both.
    park(from, ctx).with_context(|| {
        format!(
            "{} was copied to {} but the original could not be moved to {}; both exist now. \
             Move or remove {} by hand, then run this again",
            from.display(),
            to.display(),
            ctx.park.display(),
            from.display()
        )
    })
}

/// Move `path` into `_to_delete` under a name that is not taken.
fn park(path: &Path, ctx: &mut Ctx) -> Result<()> {
    fs::create_dir_all(&ctx.park).with_context(|| format!("create {}", ctx.park.display()))?;
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
    fs::rename(path, &candidate)
        .with_context(|| format!("move {} to {}", path.display(), candidate.display()))?;
    ctx.parked.push(candidate);
    Ok(())
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

/// The registered worktrees of a clone, other than the checkout itself, whose directory
/// still exists: the ones a running order is using, and the ones nothing is.
#[derive(Debug, Default)]
struct Trees {
    live: Vec<PathBuf>,
    stale: Vec<PathBuf>,
}

/// Branches of the orders running on this machine now: a heartbeat in the channel whose
/// process is alive here and recent. (A heartbeat's pid means something only on the
/// machine that wrote it, which is exactly where this runs.)
fn running_branches(channel: &Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut dirs = vec![channel.join("tasks")];
    let mut depth = 0;
    while depth < 3 && !dirs.is_empty() {
        let mut next = Vec::new();
        for dir in dirs.drain(..) {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if path.is_dir() {
                    next.push(path);
                } else if name.starts_with("heartbeat.")
                    && name.ends_with(".json")
                    && let Some(beat) = fs::read_to_string(&path).ok().and_then(|text| {
                        serde_json::from_str::<ferryman_channel::Heartbeat>(&text).ok()
                    })
                    && (chrono::Utc::now() - beat.at).num_seconds().abs() < 900
                    && crate::agent::process_alive(beat.pid)
                {
                    out.insert(ferryman_channel::worktree::branch_name(
                        &beat.order_id,
                        &beat.agent,
                    ));
                }
            }
        }
        dirs = next;
        depth += 1;
    }
    out
}

/// Registered worktrees of `repo` other than the checkout itself whose directory exists,
/// split by whether a running order uses them. A worktree nothing is using is stale, not
/// live, and does not hold a project back.
fn worktrees_of(repo: &Path, channel: &Path) -> std::result::Result<Trees, String> {
    let mut trees = Trees::default();
    if !repo.join(".git").exists() {
        return Ok(trees);
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
    let running = running_branches(channel);
    let text = String::from_utf8_lossy(&output.stdout);
    for block in text.split("\n\n") {
        let mut path: Option<PathBuf> = None;
        let mut branch: Option<String> = None;
        for line in block.lines() {
            if let Some(p) = line.strip_prefix("worktree ") {
                path = Some(PathBuf::from(p.trim()));
            } else if let Some(b) = line.strip_prefix("branch ") {
                branch = Some(b.trim().trim_start_matches("refs/heads/").to_string());
            }
        }
        let Some(path) = path else { continue };
        if same_place(&path, repo) || !path.exists() {
            continue;
        }
        if branch.as_ref().is_some_and(|b| running.contains(b)) {
            trees.live.push(path);
        } else {
            trees.stale.push(path);
        }
    }
    Ok(trees)
}

/// Move each stale worktree of `repo` to `_to_delete` (never deleting it) and prune.
fn prune_stale(repo: &Path, channel: &Path, ctx: &mut Ctx, rep: &mut ProjectReport) -> Result<()> {
    let trees = worktrees_of(repo, channel).map_err(anyhow::Error::msg)?;
    if trees.stale.is_empty() {
        return Ok(());
    }
    for path in &trees.stale {
        park(path, ctx)
            .with_context(|| format!("set aside the stale worktree {}", path.display()))?;
        rep.notes.push(format!(
            "stale worktree {} moved to _to_delete",
            path.display()
        ));
    }
    let pruned = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["worktree", "prune"])
        .output();
    if !pruned.is_ok_and(|o| o.status.success()) {
        rep.notes
            .push("git worktree prune did not run; run it in the clone".to_string());
    }
    Ok(())
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

//! `ferry root attach`, `ferry fleet setup` and `ferry order reoffer`: the commands that
//! make one worker per machine a thing you type once. The work is in `ferryman-ops`;
//! this file is what is printed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use ferryman_channel::ferry::Root;
use ferryman_ops::attach::{self, Attach};
use ferryman_ops::{layout, machine, orders, repos, rootconfig, setup};

/// `ferry root attach`.
pub fn attach_command(
    root: &Root,
    folder: &Path,
    project: Option<&str>,
    all: bool,
    skip: &[String],
    dry_run: bool,
) -> Result<()> {
    let verb = if dry_run { "would attach" } else { "attached" };
    if all {
        let reports = attach::attach_all(root, folder, skip, dry_run)?;
        if reports.is_empty() {
            println!(
                "no clone under {} is named for a project this root files",
                folder.display()
            );
        }
        let (mut done, mut already, mut skipped) = (0, 0, 0);
        for report in &reports {
            match &report.outcome {
                Attach::Attached { actions } => {
                    done += 1;
                    println!("{verb:<12} {} ({})", report.name, report.project);
                    for action in actions {
                        println!("             - {action}");
                    }
                }
                Attach::Already => {
                    already += 1;
                    println!("already      {} ({})", report.name, report.project);
                }
                Attach::Skipped(why) => {
                    skipped += 1;
                    println!(
                        "skipped      {} ({}): {} - {}",
                        report.name,
                        report.project,
                        why.label(),
                        why.reason()
                    );
                }
            }
        }
        println!("{done} {verb}, {already} already, {skipped} skipped");
        let missing = attach::without_clone(root, &reports);
        if !missing.is_empty() {
            println!(
                "filed here with no clone found under {}: {}",
                folder.display(),
                missing.join(", ")
            );
        }
        return Ok(());
    }

    match attach::attach(root, folder, project, dry_run)? {
        Attach::Attached { actions } => {
            println!("{verb} {}", folder.display());
            for action in actions {
                println!("  - {action}");
            }
            if dry_run {
                println!("dry run: nothing was written");
            }
            Ok(())
        }
        Attach::Already => {
            println!("{} is already attached; nothing to do", folder.display());
            Ok(())
        }
        Attach::Skipped(why) => {
            bail!("not attached ({}): {}", why.label(), why.reason())
        }
    }
}

// --- ferry repos sync -------------------------------------------------------------------

#[derive(Subcommand, Clone)]
pub enum ReposCommand {
    /// Give every live project its own clone in `repos/<project>`, attached to its channel.
    ///
    /// Every machine has the same layout under its ferry root: `comms/<project>-ferryman`
    /// is the channel, `repos/<project>` is Ferryman's own clone, and `work/<project>/<order>`
    /// are the worktrees made from it. A person's working copy (`X:\ferryman`, `~/code/x`)
    /// is never any of these: it is not moved, cleaned, fetched into or written to. Where a
    /// project was attached to one, the managed clone becomes the worker's checkout and the
    /// person's copy is noted in the manifest, for information.
    ///
    /// For each live project it clones the remote when `repos/<project>` is not there,
    /// fetches, and attaches the clone to the channel the root already files (a
    /// `.ferryman/bridge.toml`, and `/.ferryman/` in the clone's `.git/info/exclude`). No
    /// roster, key, device or Syncthing folder is touched and nothing is signed. Archived
    /// projects, projects the master took out of the swarm, projects this machine excludes,
    /// projects with no channel here and projects with no known remote are skipped, each
    /// with the reason.
    ///
    /// Where to clone from: `[git.remotes]` in the root's `ferry.toml`, else its
    /// `[git] remote_template` (for example `https://github.com/estejosh/{project}.git`, or
    /// `git@github-estejosh:estejosh/{project}.git`), else the `origin` of a checkout this
    /// machine already has. A password in a URL is refused. Credentials are the machine's: a
    /// credential helper or an ssh alias.
    Sync {
        /// Only this project.
        #[arg(long)]
        project: Option<String>,
        /// Say what would be done and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not fetch (no network). Clones and attaches still happen.
        #[arg(long)]
        no_fetch: bool,
    },
}

pub fn repos_command(command: ReposCommand) -> Result<()> {
    let ReposCommand::Sync {
        project,
        dry_run,
        no_fetch,
    } = command;
    let Some(root) = ferryman_channel::ferry::find_root() else {
        bail!("no ferry root yet - make one with `ferry root init`")
    };
    if let Some(only) = &project
        && !root
            .read()
            .projects
            .iter()
            .any(|entry| &entry.project_id == only)
    {
        bail!("no project '{only}' in {}", root.manifest_path().display());
    }
    let rows = repos::sync(
        &root,
        &repos::Options {
            only: project,
            dry_run,
            no_fetch,
            ..repos::Options::default()
        },
    )?;
    print_repo_rows(&rows, dry_run);
    let failed = rows
        .iter()
        .filter(|row| matches!(row.status, repos::Status::Skipped(repos::Skip::Failed(_))))
        .count();
    if failed > 0 {
        bail!("{failed} project(s) could not be synced");
    }
    Ok(())
}

fn print_repo_rows(rows: &[repos::Row], dry_run: bool) {
    let (mut did, mut ok, mut skipped) = (0, 0, 0);
    for row in rows {
        match &row.status {
            repos::Status::Done(_) => {
                did += 1;
                println!(
                    "{:<20} {}{}",
                    row.project,
                    if dry_run { "would: " } else { "" },
                    row.word()
                );
            }
            repos::Status::AlreadyOk => {
                ok += 1;
                println!("{:<20} already-ok", row.project);
            }
            repos::Status::Skipped(why) => {
                skipped += 1;
                println!("{:<20} skipped ({})", row.project, why.reason());
            }
        }
        for detail in &row.details {
            println!("    {detail}");
        }
    }
    println!(
        "{did} {}, {ok} already ok, {skipped} skipped",
        if dry_run { "to change" } else { "changed" }
    );
    if dry_run {
        println!("dry run: nothing was written");
    }
}

// --- ferry fleet setup ------------------------------------------------------------------

#[derive(Subcommand, Clone)]
pub enum FleetCommand {
    /// Put this machine into the one layout, with the one worker.
    ///
    /// Makes `comms/`, `repos/` and `work/` under the ferry root; runs `repos sync`; picks
    /// or makes the machine's one worker identity (default `ichabod-<machine>-swarm`, or
    /// the one a worker here already runs as) and gives it a home in a managed clone;
    /// and prints, exactly, the lines only the project master can run. It never signs.
    ///
    /// With `--service` it also writes ONE service that runs `ferry agent run
    /// --all-projects` (a systemd user unit with restart and resource limits on Linux; a
    /// Scheduled Task and a PowerShell wrapper on Windows that loads its environment from
    /// `service/worker.env`, never inline), turns every other ferry worker service or task
    /// off (disabled, never deleted, and backed up first), and runs Syncthing as a service
    /// of its own so it outlives the worker. A running process is never stopped; its stop
    /// command is printed. Anything that needs elevation is printed, not attempted.
    ///
    /// `--dry-run` shows all of it and writes nothing.
    Setup {
        /// The worker identity. Without it: the one a worker here already runs as, else
        /// `ichabod-<machine>-swarm`.
        #[arg(long, value_parser = super::agent_name)]
        identity: Option<String>,
        /// The project whose managed clone holds the worker's `agent.toml` and key.
        #[arg(long)]
        home: Option<String>,
        /// An identity this machine used to run as and no longer will: the master's
        /// `team revoke --all` line for it is printed. Repeatable.
        #[arg(long, value_parser = super::agent_name)]
        retire: Vec<String>,
        /// Keep a project out of the swarm on THIS machine (the root's `ferry.toml`).
        /// Repeatable. The master's signed `root swarm off` line is printed too.
        #[arg(long)]
        exclude: Vec<String>,
        /// Where projects are cloned from, `{project}` standing for the id. For example
        /// `https://github.com/estejosh/{project}.git` or
        /// `git@github-estejosh:estejosh/{project}.git`. Written to the root's `ferry.toml`.
        #[arg(long)]
        remote_template: Option<String>,
        /// Make the ferry root here when there is none.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Show everything and write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Write and enable the one service, and turn the others off.
        #[arg(long)]
        service: bool,
        /// Do not run Syncthing as a service of its own.
        #[arg(long)]
        no_syncthing: bool,
        /// Do not fetch (no network). Clones and attaches still happen.
        #[arg(long)]
        no_fetch: bool,
    },
}

pub fn fleet_command(command: FleetCommand) -> Result<()> {
    let FleetCommand::Setup {
        identity,
        home,
        retire,
        exclude,
        remote_template,
        root,
        dry_run,
        service,
        no_syncthing,
        no_fetch,
    } = command;
    let root = match ferryman_channel::ferry::find_root() {
        Some(root) => root,
        None => match root {
            Some(path) if dry_run => bail!(
                "no ferry root yet. A dry run does not make {}; run `ferry root init {}` or \
                 drop --dry-run",
                path.display(),
                path.display()
            ),
            Some(path) => Root::create(&path)?,
            None => bail!(
                "no ferry root yet - pass --root <folder> to make one here, or run \
                 `ferry root init <folder>`"
            ),
        },
    };
    let mut options = setup::Options::here();
    options.identity = identity;
    options.home = home;
    options.retire = retire;
    options.exclude = exclude;
    options.remote_template = remote_template;
    options.dry_run = dry_run;
    options.service = service;
    options.no_fetch = no_fetch;
    if no_syncthing {
        options.with_syncthing = false;
    }
    let scan = machine::scan();
    let report = setup::setup(&root, &options, &scan, &mut setup::run_quietly)?;
    print!("{}", report.render());
    Ok(())
}

// --- doctor --layout --------------------------------------------------------------------

/// `ferry doctor --layout [--fix]`. Returns whether every check passed (after a fix).
pub fn layout_command(fix: bool, json: bool) -> Result<bool> {
    let Some(root) = ferryman_channel::ferry::find_root() else {
        bail!("no ferry root yet - `ferry fleet setup --root <folder>` makes the layout")
    };
    let scan = machine::scan();
    let mut report = layout::inspect_live(&root, &scan);
    let mut did: Vec<String> = Vec::new();
    if fix && !report.ok() {
        for folder in [root.comms(), root.repos(), root.work()] {
            if !folder.is_dir() && std::fs::create_dir_all(&folder).is_ok() {
                did.push(format!("made {}", folder.display()));
            }
        }
        match repos::sync(&root, &repos::Options::default()) {
            Ok(rows) => {
                for row in rows {
                    if matches!(row.status, repos::Status::Done(_)) {
                        did.push(format!("repos sync {}: {}", row.project, row.word()));
                    }
                }
            }
            Err(error) => did.push(format!("repos sync failed: {error:#}")),
        }
        for line in layout::archive_stale(&report.stale) {
            did.push(format!("stale lock moved aside: {line}"));
        }
        for line in layout::unshare_strays(&root) {
            did.push(line);
        }
        report = layout::inspect_live(&root, &machine::scan());
    }
    if json {
        let checks: Vec<serde_json::Value> = report
            .checks
            .iter()
            .map(|check| {
                serde_json::json!({
                    "name": check.name,
                    "ok": check.ok,
                    "detail": check.detail,
                    "fix": check.fix,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": report.ok(),
                "root": root.path,
                "checks": checks,
                "fixed": did,
            }))?
        );
    } else {
        for line in &did {
            println!("fixed: {line}");
        }
        print!("{}", report.render());
        if report.ok() {
            println!("\nlayout ok: {}", root.path.display());
        } else {
            println!(
                "\nlayout not ok. `ferry doctor --layout --fix` repairs what is safe; \
                 `ferry fleet setup` does the rest"
            );
        }
    }
    Ok(report.ok())
}

/// The doctor line about workers on this machine, for plain `ferry doctor`.
pub fn workers_line() -> (bool, String) {
    machine::doctor_line(&machine::scan())
}

// --- one worker per machine -------------------------------------------------------------

/// Look at what else is running or set to run before a worker starts. Refuses (an error)
/// when `--all-projects` would be the second all-projects worker and `allow_second` was not
/// given; otherwise warns on standard error and goes on.
pub fn guard_worker_start(all_projects: bool, allow_second: bool) -> Result<()> {
    let scan = machine::scan();
    match machine::judge_start(&scan, all_projects, allow_second) {
        machine::Start::Clear => Ok(()),
        machine::Start::Warn(lines) => {
            for line in lines {
                eprintln!("warning: {line}");
            }
            Ok(())
        }
        machine::Start::Refuse(why) => bail!("{why}"),
    }
}

// --- ferry order reoffer / release ------------------------------------------------------

#[derive(Subcommand, Clone)]
pub enum OrderCommand {
    /// Offer an order to a different identity, without editing the signed order.
    ///
    /// Writes a new signed record (`offer.<signer>.<time>.json`) beside the order and a
    /// history line. The order, its claims and every earlier offer stay as they are; the
    /// newest valid offer decides who may claim it. Signed by the order's issuer or the
    /// project's master (the default). For an order addressed to an identity that has been
    /// retired or revoked: `ferry order reoffer t-12 --to ichabod-beastly-swarm`.
    Reoffer {
        /// The order id.
        id: String,
        /// Who it is offered to now.
        #[arg(long, value_parser = super::agent_name, conflicts_with = "queue")]
        to: Option<String>,
        /// Offer it to nobody in particular: whoever picks it up first.
        #[arg(long)]
        queue: bool,
        /// The project, when the order id alone is not enough to find it.
        #[arg(long)]
        project: Option<String>,
        /// Who signs: the order's issuer or the project's master. Default: the master.
        #[arg(long = "as", value_parser = super::agent_name)]
        as_signer: Option<String>,
        /// Why, for the record.
        #[arg(long, default_value = "re-offered")]
        reason: String,
    },
    /// Release the unfinished claims a retired identity still holds, back to the queue.
    ///
    /// Signed by the project's master and recorded in its history. The claim, the order and
    /// everything else stay where they are; nothing is deleted. Refuses to release a name
    /// whose worker is alive on this machine. Projects another person masters are skipped.
    Release {
        /// The identity whose claims are released.
        #[arg(long, value_parser = super::agent_name)]
        held_by: String,
        /// Every project the signing master owns.
        #[arg(long)]
        all: bool,
        /// Who signs. Default: whoever masters the most projects here.
        #[arg(long = "as", value_parser = super::agent_name)]
        as_master: Option<String>,
        /// Say what would be released and sign nothing.
        #[arg(long)]
        dry_run: bool,
        /// Why, for the record.
        #[arg(long, default_value = "retired")]
        reason: String,
    },
}

pub fn order_command(command: OrderCommand) -> Result<()> {
    let root = ferryman_channel::ferry::find_root()
        .context("no ferry root yet - make one with `ferry root init`")?;
    match command {
        OrderCommand::Reoffer {
            id,
            to,
            queue,
            project,
            as_signer,
            reason,
        } => {
            if to.is_none() && !queue {
                bail!("say who it is offered to: --to <identity>, or --queue for whoever is first");
            }
            let project = match project {
                Some(project) => project,
                None => project_of_order(&root, &id)?,
            };
            let mut signer = super::bulk_signer(&root);
            let offer = orders::reoffer(
                &root,
                &project,
                &id,
                to.as_deref(),
                &reason,
                as_signer.as_deref(),
                &mut signer,
            )?;
            println!(
                "{project}: {id} offered to {} (was {}), signed by {}",
                offer.to.as_deref().unwrap_or("whoever is first"),
                offer.from.as_deref().unwrap_or("whoever was first"),
                offer.offered_by
            );
            println!("the signed order is unchanged; the new record sits beside it");
            Ok(())
        }
        OrderCommand::Release {
            held_by,
            all,
            as_master,
            dry_run,
            reason,
        } => {
            if !all {
                bail!("--all: release in every project the signing master owns");
            }
            let master = match as_master {
                Some(master) => master,
                None => ferryman_ops::fleet::dominant_master(&root).context(
                    "no project here has a master yet; claim them with 'ferry root master', or \
                     say who signs with --as",
                )?,
            };
            let mut signer = super::bulk_signer(&root);
            let rows =
                orders::release_held(&root, &held_by, &master, &reason, dry_run, &mut signer);
            let mut released = 0;
            for (project, order, outcome) in &rows {
                match outcome {
                    orders::Released::Done => {
                        released += 1;
                        println!(
                            "  {project}: {order}  {} {held_by}'s claim",
                            if dry_run { "would release" } else { "released" }
                        );
                    }
                    orders::Released::Skipped(why) => {
                        println!("  {project}: skipped - {why}");
                    }
                }
            }
            println!(
                "{released} claim(s) {}{}",
                if dry_run {
                    "would be released"
                } else {
                    "released"
                },
                if dry_run { " (nothing signed)" } else { "" }
            );
            Ok(())
        }
    }
}

/// The one project that has an order with this id.
fn project_of_order(root: &Root, id: &str) -> Result<String> {
    let mut found = Vec::new();
    for entry in root.read().projects {
        if !entry.channel.is_dir() {
            continue;
        }
        let Ok((route, _)) = (ferryman_channel::ferry::Entry {
            repo: None,
            ..entry.clone()
        })
        .route(root) else {
            continue;
        };
        if ferryman_channel::read_task(&route, id).is_ok() {
            found.push(entry.project_id);
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("no project here has an order '{id}'; pass --project"),
        many => bail!(
            "order '{id}' exists in {}; say which with --project",
            many.join(", ")
        ),
    }
}

// --- ferry root swarm -------------------------------------------------------------------

#[derive(Subcommand, Clone)]
pub enum SwarmCommand {
    /// Which projects the swarm works: the master's signed setting, and this machine's own
    /// exclusions.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Put a project back in the swarm. Signed by its master; the default is on.
    On {
        #[arg(long)]
        project: String,
        /// Who signs. Default: the project's master.
        #[arg(long = "as", value_parser = super::agent_name)]
        as_master: Option<String>,
    },
    /// Keep a project out of the swarm, on every machine that syncs its channel.
    ///
    /// A `SWARM` file in the channel, signed by the project's master like `ARCHIVED` and
    /// `ENGINE_POLICY`. `repos sync`, `agent run --all-projects` and `team approve --all`
    /// all honour it. Only the master can set it, and a file anyone else wrote is ignored.
    Off {
        #[arg(long)]
        project: String,
        /// Who signs. Default: the project's master.
        #[arg(long = "as", value_parser = super::agent_name)]
        as_master: Option<String>,
    },
    /// Keep a project out of the swarm on THIS machine only (the root's `ferry.toml`).
    /// Needs no signature, and nobody else sees it.
    Exclude { project: String },
    /// Undo `exclude` on this machine.
    Include { project: String },
}

pub fn swarm_command(command: SwarmCommand) -> Result<()> {
    let root = ferryman_channel::ferry::find_root()
        .context("no ferry root yet - make one with `ferry root init`")?;
    match command {
        SwarmCommand::Show { json } => {
            let config = rootconfig::RootConfig::load(&root);
            let rows: Vec<serde_json::Value> = root
                .read()
                .projects
                .iter()
                .map(|entry| {
                    let setting = entry.channel.is_dir().then(|| {
                        ferryman_channel::ferry::swarm_setting(&entry.channel, &entry.project_id)
                    });
                    let setting = setting.flatten();
                    serde_json::json!({
                        "project": entry.project_id,
                        "swarm": setting.as_ref().is_none_or(|s| s.on),
                        "signed_by": setting.as_ref().map(|s| s.signed_by.clone()),
                        "excluded_here": config.excluded(&entry.project_id),
                        "archived": entry.is_archived(),
                    })
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
                return Ok(());
            }
            for row in &rows {
                let on = row["swarm"].as_bool().unwrap_or(true);
                let here = row["excluded_here"].as_bool().unwrap_or(false);
                println!(
                    "{:<20} swarm {}{}{}",
                    row["project"].as_str().unwrap_or(""),
                    if on { "on" } else { "OFF" },
                    row["signed_by"]
                        .as_str()
                        .map(|by| format!(" (signed by {by})"))
                        .unwrap_or_default(),
                    if here {
                        "  [excluded on this machine]"
                    } else {
                        ""
                    }
                );
            }
            Ok(())
        }
        SwarmCommand::On { project, as_master } => swarm_switch(&project, true, as_master),
        SwarmCommand::Off { project, as_master } => swarm_switch(&project, false, as_master),
        SwarmCommand::Exclude { project } => {
            let project = require_project(&root, &project)?;
            if rootconfig::set_excluded(&root, &project, true)? {
                println!(
                    "{project} is out of the swarm on this machine ({})",
                    rootconfig::path(&root).display()
                );
            } else {
                println!("{project} was already excluded here");
            }
            Ok(())
        }
        SwarmCommand::Include { project } => {
            if rootconfig::set_excluded(&root, &project, false)? {
                println!("{project} is back in the swarm on this machine");
            } else {
                println!("{project} was not excluded here");
            }
            Ok(())
        }
    }
}

/// The id of the project `project` names: its id, its name or an old name (ADR 0024).
fn require_project(root: &Root, project: &str) -> Result<String> {
    Ok(root.resolve(project)?.project_id)
}

/// `swarm on` / `swarm off`: the master's signed setting.
pub fn swarm_switch(project: &str, on: bool, as_master: Option<String>) -> Result<()> {
    let root = ferryman_channel::ferry::find_root()
        .context("no ferry root yet - make one with `ferry root init`")?;
    require_project(&root, project)?;
    let (project, channel, attachment) = super::improve_project(&super::ImproveProject {
        project: Some(project.to_owned()),
        workspace: None,
        all: false,
    })?;
    let (master, identity) = super::mastered_signer(&channel, &attachment, as_master.as_deref())?;
    let word = if on { "on" } else { "off" };
    if ferryman_channel::ferry::set_swarm(&channel, &project, on, &identity)? {
        println!(
            "swarm is {word} for {project}, signed by {master}; every machine that syncs the \
             channel sees it"
        );
    } else {
        println!("swarm was already {word} for {project}");
    }
    Ok(())
}

/// After `ferry enable`: give a project that the root files its managed clone. Soft: a clone
/// that cannot be made now (no remote known, no network) is a note, and `ferry repos sync`
/// does it later.
pub fn managed_clone_after_enable(project: &str, quiet: bool) {
    let Some(root) = ferryman_channel::ferry::find_root() else {
        return;
    };
    if !root
        .read()
        .projects
        .iter()
        .any(|entry| entry.project_id == project)
    {
        return;
    }
    let options = repos::Options {
        only: Some(project.to_owned()),
        dry_run: false,
        no_fetch: false,
        ..repos::Options::default()
    };
    match repos::sync(&root, &options) {
        Ok(rows) => {
            for row in rows {
                if quiet {
                    continue;
                }
                match &row.status {
                    repos::Status::Skipped(why) => println!(
                        "  managed clone: not made ({}); `ferry repos sync --project {project}` does it later",
                        why.reason()
                    ),
                    _ => println!(
                        "  managed clone: {} ({})",
                        row.word(),
                        root.managed_clone(project).display()
                    ),
                }
            }
        }
        Err(error) => {
            if !quiet {
                println!("  managed clone: not made ({error:#})");
            }
        }
    }
}

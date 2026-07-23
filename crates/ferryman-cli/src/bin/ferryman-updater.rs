#![forbid(unsafe_code)]
//! Explicit, system-wide update helper.  It never adds a Git remote, commits a
//! project, or changes a project that has not opted in through bridge-project.toml.
//!
//! Update flow is an explicit approve/deny gate — nothing is ever applied
//! automatically:
//!   1. `check-remote` (read-only) fetches the configured origin and reports
//!      whether the Bridge install is behind, listing the pending commits so an
//!      operator can review them. It changes nothing and exits 10 when updates
//!      are pending.
//!   2. `update-bridge --confirm` is the APPROVE action: it fast-forwards a
//!      clean checkout from its already-configured origin. Without `--confirm`
//!      it only shows the pending diff and refuses (so it can never apply blind).
//!      Denying is simply not running it — the Bridge stays pinned.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Parser)]
#[command(about = "Opt-in Ferryman updater")]
struct Cli {
    /// Root containing one private Bridge project directory per project.
    #[arg(long, default_value = "./.data/projects")]
    projects_root: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Show which project workspaces explicitly allow this release.
    Check {
        #[arg(long, default_value=env!("CARGO_PKG_VERSION"))]
        release: String,
    },
    /// Record the selected Bridge release in every opted-in project workspace.
    /// It does not modify project code, Git remotes, or commit history.
    Apply {
        #[arg(long, default_value=env!("CARGO_PKG_VERSION"))]
        release: String,
    },
    /// READ-ONLY. Report whether the Bridge installation is behind its
    /// configured origin, without changing anything. Fetches the remote and
    /// lists the pending commits so an operator can approve (`update-bridge
    /// --confirm`) or deny (do nothing). Exits 10 when updates are pending.
    CheckRemote {
        #[arg(long)]
        checkout: PathBuf,
        #[arg(long, default_value = "main")]
        branch: String,
    },
    /// APPROVE + apply. Fast-forward the Bridge installation itself from its
    /// already configured origin. The checkout must be clean and the command
    /// must be invoked by an operator. Requires `--confirm`; without it, prints
    /// the pending changes and refuses so it can never apply blind.
    UpdateBridge {
        #[arg(long)]
        checkout: PathBuf,
        #[arg(long, default_value = "main")]
        branch: String,
        /// Required to actually apply. Without it, show the pending diff and stop.
        #[arg(long)]
        confirm: bool,
    },
}
#[derive(Serialize)]
struct Item {
    project: String,
    eligible: bool,
    reason: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Action::Check { release } => print_plan(&cli.projects_root, &release, false),
        Action::Apply { release } => print_plan(&cli.projects_root, &release, true),
        Action::CheckRemote { checkout, branch } => check_remote(&checkout, &branch),
        Action::UpdateBridge {
            checkout,
            branch,
            confirm,
        } => update_bridge(&checkout, &branch, confirm),
    }
}
fn print_plan(root: &Path, release: &str, apply: bool) -> Result<()> {
    let mut items = Vec::new();
    if !root.exists() {
        bail!("project root does not exist: {}", root.display());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let project = entry.path();
        let manifest = project.join("bridge-project.toml");
        if !manifest.exists() {
            continue;
        }
        let contents = fs::read_to_string(&manifest)?;
        let opted_in = contents.lines().any(|line| line.trim() == "opt_in = true");
        let id = project
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("unknown")
            .to_string();
        if opted_in && apply {
            let state = project.join(".orchestrator");
            fs::create_dir_all(&state)?;
            fs::write(
                state.join("bridge-update-state.json"),
                format!(
                    "{{\n  \"release\": {release:?},\n  \"updated_at\": {timestamp:?},\n  \"method\": \"explicit-system-opt-in\"\n}}\n",
                    timestamp = chrono::Utc::now().to_rfc3339()
                ),
            )?;
        }
        items.push(Item {
            project: id,
            eligible: opted_in,
            reason: if opted_in {
                if apply {
                    format!("recorded Bridge release {release}")
                } else {
                    format!("eligible for Bridge release {release}")
                }
            } else {
                "updates.opt_in is not true".into()
            },
        });
    }
    println!("{}", serde_json::to_string_pretty(&items)?);
    Ok(())
}
fn check_remote(checkout: &Path, branch: &str) -> Result<()> {
    run(checkout, &["rev-parse", "--is-inside-work-tree"])?;
    run(checkout, &["remote", "get-url", "origin"])
        .context("Bridge checkout needs an explicitly configured origin")?;
    // Read-only: fetch updates the remote-tracking ref only; the work tree and
    // current branch are never touched. Nothing is applied here.
    run(checkout, &["fetch", "--prune", "origin", branch])?;
    let current = run(checkout, &["rev-parse", "--short", "HEAD"])?
        .trim()
        .to_string();
    let target = run(checkout, &["rev-parse", "--short", "FETCH_HEAD"])?
        .trim()
        .to_string();
    let pending = run(checkout, &["log", "--oneline", "HEAD..FETCH_HEAD"])?;
    let pending = pending.trim();
    if pending.is_empty() {
        println!(
            "up to date: Bridge is at {current}; origin/{branch} has nothing newer. No action."
        );
        return Ok(());
    }
    let count = pending.lines().count();
    println!(
        "UPDATE AVAILABLE: {current} -> {target} on origin/{branch} ({count} commit(s) pending)"
    );
    println!("--- pending changes (review before approving) ---");
    println!("{pending}");
    println!("-------------------------------------------------");
    println!(
        "This command changed NOTHING. To APPROVE and apply:\n  ferryman-updater update-bridge --checkout <path> --branch {branch} --confirm"
    );
    println!("To DENY: do nothing; the Bridge stays at {current}.");
    // Distinct exit code so scripts/agents can surface "update pending" without
    // ever applying it themselves.
    std::process::exit(10);
}
fn update_bridge(checkout: &Path, branch: &str, confirm: bool) -> Result<()> {
    run(checkout, &["rev-parse", "--is-inside-work-tree"])?;
    if !run(checkout, &["status", "--porcelain"])?.trim().is_empty() {
        bail!("refusing to update a dirty Bridge checkout");
    }
    // `origin` must already exist; this tool intentionally never configures it.
    run(checkout, &["remote", "get-url", "origin"])
        .context("Bridge checkout needs an explicitly configured origin")?;
    run(checkout, &["fetch", "--prune", "origin", branch])?;
    let pending = run(checkout, &["log", "--oneline", "HEAD..FETCH_HEAD"])?;
    let pending = pending.trim();
    if pending.is_empty() {
        println!("already up to date with origin/{branch}; nothing to apply.");
        return Ok(());
    }
    if !confirm {
        println!("UPDATE PENDING on origin/{branch}:");
        println!("{pending}");
        bail!(
            "refusing to apply without approval. Re-run with --confirm to apply, or do nothing to deny."
        );
    }
    run(checkout, &["merge", "--ff-only", "FETCH_HEAD"])?;
    println!("APPROVED: Bridge installation fast-forwarded from its configured origin/{branch}.");
    Ok(())
}
fn run(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

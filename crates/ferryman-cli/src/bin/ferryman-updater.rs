#![forbid(unsafe_code)]
//! Explicit, system-wide update helper.  It never adds a Git remote, commits a
//! project, or changes a project that has not opted in through bridge-project.toml.

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
    /// Fast-forward the Bridge installation itself from its already configured
    /// origin. The checkout must be clean and the command must be invoked by an operator.
    UpdateBridge {
        #[arg(long)]
        checkout: PathBuf,
        #[arg(long, default_value = "main")]
        branch: String,
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
        Action::UpdateBridge { checkout, branch } => update_bridge(&checkout, &branch),
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
fn update_bridge(checkout: &Path, branch: &str) -> Result<()> {
    run(checkout, &["rev-parse", "--is-inside-work-tree"])?;
    if !run(checkout, &["status", "--porcelain"])?.trim().is_empty() {
        bail!("refusing to update a dirty Bridge checkout");
    }
    // `origin` must already exist; this tool intentionally never configures it.
    run(checkout, &["remote", "get-url", "origin"])
        .context("Bridge checkout needs an explicitly configured origin")?;
    run(checkout, &["fetch", "--prune", "origin", branch])?;
    run(checkout, &["merge", "--ff-only", "FETCH_HEAD"])?;
    println!("Bridge installation fast-forwarded from its configured origin/{branch}.");
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

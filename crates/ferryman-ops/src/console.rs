//! Cross-project master console: one aggregate view over every project a
//! machine runs.
//!
//! Discovery is deliberately simple. [`fleet_summary`] looks at the parent of
//! the current directory - the folder that holds one checkout per project - and
//! asks [`ferryman_channel::route_for`] about each sibling directory. Any
//! sibling with a `.ferryman/bridge.toml` is a project, so there is no registry
//! to keep in sync: a project appears the moment its channel is on disk.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ferryman_channel::{ProjectRoute, TaskState};

/// One project's slice of the fleet.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectSummary {
    pub project_id: String,
    /// Total task directories in the project channel.
    pub tasks: usize,
    /// Tasks that are not in a terminal state yet.
    pub open: usize,
    /// Tasks that are [`TaskState::Accepted`] or [`TaskState::Done`].
    pub done: usize,
    pub engines: Vec<ferryman_channel::learning::EngineStats>,
}

/// Aggregate every project found beside the current workspace.
pub fn fleet_summary() -> Result<Vec<ProjectSummary>> {
    let current = std::env::current_dir().context("read the current directory")?;
    let parent = current
        .parent()
        .with_context(|| format!("{} has no parent directory", current.display()))?;
    fleet_summary_from(parent)
}

/// Aggregate projects whose channel directories sit directly under `parent`.
///
/// Each child directory is offered to [`ferryman_channel::route_for`]. Children
/// without a channel are simply not projects, so they are skipped. This accepts
/// both a checkout named for the project and the Syncthing folder convention of
/// naming a project's channel `<project>-ferryman`.
fn fleet_summary_from(parent: &Path) -> Result<Vec<ProjectSummary>> {
    if !parent.is_dir() {
        return Ok(Vec::new());
    }
    let mut summaries = Vec::new();
    for entry in fs::read_dir(parent).with_context(|| format!("read {}", parent.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Ok(route) = ferryman_channel::route_for(&path) else {
            continue;
        };
        let summary =
            summarize_project(&route).with_context(|| format!("summarize {}", path.display()))?;
        summaries.push(summary);
    }
    summaries.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    Ok(summaries)
}

fn summarize_project(route: &ProjectRoute) -> Result<ProjectSummary> {
    let tasks = ferryman_channel::list_tasks(route)?;
    let done = tasks
        .iter()
        .filter(|task| matches!(task.state(), TaskState::Accepted | TaskState::Done))
        .count();
    let open = tasks.len() - done;
    let engines = ferryman_channel::learning::engine_stats(route)?;
    Ok(ProjectSummary {
        project_id: route.project_id.clone(),
        tasks: tasks.len(),
        open,
        done,
        engines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Keep this test binary's machine state out of the developer's home.
    fn hermetic_machine() {
        let dir = std::env::temp_dir().join(format!(
            "ferryman-console-test-machine-{}-{}",
            env!("CARGO_CRATE_NAME"),
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir);
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ferryman-console-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write a minimal fake project channel under `workspace`: a bridge, one
    /// task directory per id, and one learnings line per engine outcome.
    fn write_project(
        workspace: &Path,
        project: &str,
        task_ids: &[&str],
        learnings: &[(&str, bool)],
    ) {
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&communications).unwrap();
        fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"{project}\"\n\
                 workspace = \"{}\"\n\
                 attachment = \"{}\"\n\
                 communications = \"{}\"\n\
                 shared_remote = \"{project}-ferryman\"\n",
                workspace.display(),
                attachment.display(),
                communications.display(),
            ),
        )
        .unwrap();

        for id in task_ids {
            let dir = communications.join("tasks").join(id);
            fs::create_dir_all(&dir).unwrap();
            let order = serde_json::json!({
                "id": id,
                "project_id": project,
                "issued_by": "operator",
                "created_at": "2026-01-01T00:00:00Z",
                "payload": {},
            });
            fs::write(
                dir.join("order.json"),
                serde_json::to_vec_pretty(&order).unwrap(),
            )
            .unwrap();
        }

        let learnings_path = communications.join("learnings.jsonl");
        for (engine, accepted) in learnings {
            let line = serde_json::json!({
                "at": "2026-01-01T00:00:00Z",
                "engine": engine,
                "task_id": "t-1",
                "source": "eval",
                "accepted": accepted,
                "note": "",
            });
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&learnings_path)
                .unwrap();
            writeln!(file, "{}", serde_json::to_string(&line).unwrap()).unwrap();
        }
    }

    #[test]
    fn fleet_summary_aggregates_sibling_projects() {
        hermetic_machine();
        let parent = tempdir();
        let acme = parent.join("acme-ferryman");
        let beta = parent.join("beta-ferryman");
        write_project(
            &acme,
            "acme",
            &["t-1", "t-2"],
            &[("claude", true), ("claude", false), ("deepseek", true)],
        );
        write_project(&beta, "beta", &["t-3"], &[("claude", true)]);

        let summaries = fleet_summary_from(&parent).unwrap();
        assert_eq!(summaries.len(), 2);

        let acme_summary = summaries
            .iter()
            .find(|summary| summary.project_id == "acme")
            .unwrap();
        assert_eq!(acme_summary.tasks, 2);
        assert_eq!(acme_summary.open, 2);
        assert_eq!(acme_summary.done, 0);
        assert_eq!(acme_summary.engines.len(), 2);
        let claude = acme_summary
            .engines
            .iter()
            .find(|engine| engine.engine == "claude")
            .unwrap();
        assert_eq!(claude.total, 2);
        assert_eq!(claude.accepted, 1);

        let beta_summary = summaries
            .iter()
            .find(|summary| summary.project_id == "beta")
            .unwrap();
        assert_eq!(beta_summary.tasks, 1);
        assert_eq!(beta_summary.open, 1);
        assert_eq!(beta_summary.done, 0);
        assert_eq!(beta_summary.engines.len(), 1);
        assert_eq!(beta_summary.engines[0].engine, "claude");
        assert_eq!(beta_summary.engines[0].total, 1);
        assert_eq!(beta_summary.engines[0].accepted, 1);
    }
}

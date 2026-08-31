//! Cross-project master console: one aggregate view over every project a
//! machine runs.
//!
//! Discovery used to read the directory beside wherever it was launched. That found a
//! fleet kept as siblings and silently missed a checkout on another drive. It now reads
//! the machine-local `.ferry` manifest first (see ADR 0019): every project the machine
//! has adopted, wherever its repository actually is. The directory scan is kept, demoted
//! to the thing that notices a channel nobody has recorded yet.

use std::collections::HashSet;
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

/// Aggregate every project this machine knows about.
///
/// Sources, in order: the `.ferry` manifest, channels under the root's `comms/`, and
/// finally the legacy scan of the launch directory's parent. Later sources only add
/// projects nobody has recorded yet.
pub fn fleet_summary() -> Result<Vec<ProjectSummary>> {
    let known = ferryman_channel::root::known();
    let comms = ferryman_channel::root::comms_dir();
    let legacy_parent = std::env::current_dir()
        .ok()
        .and_then(|cwd| cwd.parent().map(Path::to_path_buf));
    discover(&known, comms.as_deref(), legacy_parent.as_deref())
}

/// The whole of discovery, as a pure function of its inputs so it can be tested without
/// moving the process's working directory.
fn discover(
    known: &[ferryman_channel::root::KnownProject],
    comms: Option<&Path>,
    legacy_parent: Option<&Path>,
) -> Result<Vec<ProjectSummary>> {
    let mut summaries = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // The manifest is the index: a project recorded there is found wherever its
    // repository actually lives. A recorded path that no longer exists has already been
    // dropped by `known`, and a project whose channel cannot be read is skipped rather
    // than silencing every other project.
    for project in known {
        if let Ok(route) = ferryman_channel::route_for(&project.repository)
            && seen.insert(route.project_id.clone())
            && let Ok(summary) = summarize_project(&route)
        {
            summaries.push(summary);
        }
    }

    // Channels sitting under the root's comms/ that nobody recorded yet.
    if let Some(dir) = comms {
        for route in channel_routes_under(dir)? {
            if seen.insert(route.project_id.clone())
                && let Ok(summary) = summarize_project(&route)
            {
                summaries.push(summary);
            }
        }
    }

    // The legacy scan, demoted to noticing a channel nobody has recorded yet.
    if let Some(dir) = legacy_parent {
        for route in channel_routes_under(dir)? {
            if seen.insert(route.project_id.clone())
                && let Ok(summary) = summarize_project(&route)
            {
                summaries.push(summary);
            }
        }
    }

    summaries.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    Ok(summaries)
}

/// The project routes whose channel directories sit directly under `parent`.
fn channel_routes_under(parent: &Path) -> Result<Vec<ProjectRoute>> {
    if !parent.is_dir() {
        return Ok(Vec::new());
    }
    let mut routes = Vec::new();
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
        if let Ok(route) = ferryman_channel::route_for(&path) {
            routes.push(route);
        }
    }
    Ok(routes)
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

        let summaries = discover(&[], None, Some(&parent)).unwrap();
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

    /// A project recorded in the manifest is found wherever its repository actually is,
    /// with no sibling scan and no launch directory involved.
    #[test]
    fn a_known_project_is_found_wherever_its_repository_is() {
        hermetic_machine();
        let base = tempdir();
        let repo = base.join("elsewhere").join("acme");
        write_project(&repo, "acme", &["t-1"], &[("claude", true)]);
        let known = vec![ferryman_channel::root::KnownProject {
            project_id: "acme".into(),
            channel: repo.join(".ferryman").join("ferryman"),
            repository: repo,
        }];
        let summaries = discover(&known, None, None).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].project_id, "acme");
        assert_eq!(summaries[0].tasks, 1);
    }

    /// The index and the scan can agree on a project; it must still appear once.
    #[test]
    fn a_project_is_reported_once_when_indexed_and_on_disk() {
        hermetic_machine();
        let base = tempdir();
        let repo = base.join("elsewhere").join("acme");
        write_project(&repo, "acme", &["t-1"], &[("claude", true)]);
        let known = vec![ferryman_channel::root::KnownProject {
            project_id: "acme".into(),
            channel: repo.join(".ferryman").join("ferryman"),
            repository: repo,
        }];
        let parent = base.join("fleet");
        fs::create_dir_all(&parent).unwrap();
        write_project(&parent.join("acme-ferryman"), "acme", &["t-1"], &[]);

        let summaries = discover(&known, None, Some(&parent)).unwrap();
        assert_eq!(summaries.len(), 1, "the same project must not appear twice");
        assert_eq!(summaries[0].project_id, "acme");
    }
}

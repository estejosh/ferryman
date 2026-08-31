//! Where this machine has seen projects, learned by using them.
//!
//! # Why an index and not a scan
//!
//! Finding projects by reading the directory next to wherever you happened to launch is
//! guesswork dressed as discovery. It finds a fleet kept as siblings, finds nothing from
//! a checkout on another drive, and cannot see across two locations at once - and it
//! fails *silently*, showing one project as though one is all there is.
//!
//! So: a small index, updated as a side effect of ordinary use. Every time this machine
//! resolves a project, it notes where that project was. Nothing to set up, nothing to
//! maintain, and it gets more complete the more the fleet is used.
//!
//! # Why it is not a registry
//!
//! It is never authority. A project missing from the index but present on disk works
//! exactly as it always did; an entry whose channel has gone is dropped on the next read
//! rather than reported. Delete the file and nothing breaks - it refills itself. That is
//! the difference between an index and a registry, and it is the whole reason this is
//! safe to add to a system whose entire thesis is that the files are the truth.
//!
//! # Why it lives beside the machine's own state
//!
//! The obvious home is a `.ferry` file where the repositories are. The trouble is
//! circular: to read an index at the root of the fleet you must already know where the
//! fleet is, which is the question being asked. Kept with the machine's device id and
//! keys, it is somewhere nothing has to look for - and the paths in it are machine-
//! specific, so this is machine state by nature. It must never travel in the channel: a
//! path from another machine is worse than no path at all.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ProjectRoute;

/// One project, and where it was when this machine last used it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownProject {
    pub project_id: String,
    pub workspace: PathBuf,
    pub communications: PathBuf,
    /// When it was last resolved here. Only used to decide what to rewrite.
    #[serde(default)]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

fn index_path() -> Option<PathBuf> {
    crate::licensing::machine_state_dir().map(|dir| dir.join("known-projects.json"))
}

fn read_index() -> Vec<KnownProject> {
    let Some(path) = index_path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

/// Every project this machine has used and can still find.
///
/// An entry whose channel has gone is dropped rather than returned: a picker offering a
/// project that no longer resolves would silently fall back to the current one, which
/// looks like the switch did nothing.
#[must_use]
pub fn known() -> Vec<KnownProject> {
    let mut out: Vec<KnownProject> = read_index()
        .into_iter()
        .filter(|project| project.communications.is_dir())
        .collect();
    out.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    out.dedup_by(|a, b| a.project_id == b.project_id);
    out
}

/// Note that this machine used this project. Best-effort and silent on failure.
///
/// Called from the one place every command already funnels through, so no command has to
/// remember to do it - a discovery feature that depends on being called correctly is one
/// that will be wrong exactly when it matters.
pub fn remember(route: &ProjectRoute) {
    let Some(path) = index_path() else {
        return;
    };
    let mut index = read_index();
    let now = chrono::Utc::now();

    if let Some(existing) = index
        .iter_mut()
        .find(|project| project.project_id == route.project_id)
    {
        // Rewriting on every resolve would mean a file write per command for no gain.
        // An hour is often enough to keep a moved project current and rare enough to
        // cost nothing.
        let fresh = existing
            .last_seen
            .is_some_and(|seen| (now - seen).num_minutes() < 60);
        if fresh && existing.workspace == route.workspace {
            return;
        }
        existing.workspace.clone_from(&route.workspace);
        existing.communications.clone_from(&route.communications);
        existing.last_seen = Some(now);
    } else {
        index.push(KnownProject {
            project_id: route.project_id.clone(),
            workspace: route.workspace.clone(),
            communications: route.communications.clone(),
            last_seen: Some(now),
        });
    }

    index.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    let _ = write_index(&path, &index);
}

fn write_index(path: &Path, index: &[KnownProject]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(index)?;
    // Written whole through a temporary, so a reader never sees half an index - and a
    // crash mid-write leaves the previous one rather than a broken file.
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, json)?;
    std::fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dir: &Path, id: &str) -> ProjectRoute {
        let workspace = dir.join(id);
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        ProjectRoute {
            project_id: id.into(),
            workspace,
            attachment,
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    #[test]
    fn using_a_project_is_what_puts_it_on_the_list() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));

        assert!(known().is_empty());
        remember(&route(dir.path(), "alpha"));
        remember(&route(dir.path(), "beta"));

        let ids: Vec<String> = known().into_iter().map(|p| p.project_id).collect();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[test]
    fn a_project_that_has_gone_is_dropped_rather_than_offered() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));

        let gone = route(dir.path(), "gone");
        remember(&gone);
        remember(&route(dir.path(), "here"));
        std::fs::remove_dir_all(&gone.workspace).unwrap();

        let ids: Vec<String> = known().into_iter().map(|p| p.project_id).collect();
        assert_eq!(
            ids,
            vec!["here"],
            "a picker must not offer what it cannot open"
        );
    }

    #[test]
    fn a_project_that_moved_is_found_where_it_now_is() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));

        remember(&route(dir.path(), "alpha"));
        let moved = route(&dir.path().join("elsewhere"), "alpha");
        remember(&moved);

        let found = known();
        assert_eq!(found.len(), 1, "one project, not two entries for it");
        assert_eq!(found[0].workspace, moved.workspace);
    }

    /// The index is a convenience, never authority: losing it must cost nothing but the
    /// convenience.
    #[test]
    fn a_deleted_index_simply_refills() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));

        remember(&route(dir.path(), "alpha"));
        std::fs::remove_file(index_path().unwrap()).unwrap();
        assert!(known().is_empty());

        remember(&route(dir.path(), "alpha"));
        assert_eq!(known().len(), 1);
    }
}

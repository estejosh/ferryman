//! One machine-local root called `ferry`, described by a `.ferry` manifest.
//!
//! # The problem this exists to stop
//!
//! Discovery used to read the directory *beside wherever it was launched*. A fleet
//! kept as siblings was found; a checkout on another drive was not; and the miss was
//! silent. The root gives every machine one place to look that does not depend on
//! where a command happened to run.
//!
//! # What `.ferry` is, and what it is not
//!
//! `.ferry` is a machine-local JSON file at the root. It describes the layout and, for
//! every project this machine has adopted, the channel path and the repository path
//! wherever that repository actually is. Those paths are machine-specific, which is
//! exactly why the file must never travel in a channel.
//!
//! It is an **index, not authority**. A project present on disk but absent from
//! `.ferry` still works; deleting `.ferry` costs nothing but convenience. A recorded
//! path that no longer exists is dropped on read, not reported.
//!
//! # Adoption is in place, never a move
//!
//! Recording a repository into `.ferry` writes down where it already is. It never
//! relocates a directory the user made. See ADR 0019 for why moving is refused.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The manifest file name, at the root.
pub const MANIFEST_FILE: &str = ".ferry";

/// The layout segment names, used when the manifest does not say otherwise.
const DEFAULT_COMMS: &str = "comms";
const DEFAULT_REPOS: &str = "repos";
const DEFAULT_WORK: &str = "work";

/// One project's machine-local entry: where its channel and its repository are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLocation {
    pub channel: PathBuf,
    pub repository: PathBuf,
}

/// A project the root knows about, with the paths that matter on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownProject {
    pub project_id: String,
    pub channel: PathBuf,
    pub repository: PathBuf,
}

/// The `.ferry` manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_comms")]
    pub comms: String,
    #[serde(default = "default_repos")]
    pub repos: String,
    #[serde(default = "default_work")]
    pub work: String,
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectLocation>,
}

fn default_version() -> u32 {
    1
}
fn default_comms() -> String {
    DEFAULT_COMMS.to_string()
}
fn default_repos() -> String {
    DEFAULT_REPOS.to_string()
}
fn default_work() -> String {
    DEFAULT_WORK.to_string()
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: 1,
            comms: DEFAULT_COMMS.to_string(),
            repos: DEFAULT_REPOS.to_string(),
            work: DEFAULT_WORK.to_string(),
            projects: BTreeMap::new(),
        }
    }
}

static ROOT_DIR: OnceLock<PathBuf> = OnceLock::new();
static PER_THREAD: AtomicBool = AtomicBool::new(false);

/// Point the root at a given directory, for the rest of the process.
///
/// Mirrors [`crate::licensing::use_machine_state_dir`]: tests and embedders need a
/// hermetic root, and a `cfg(test)` redirect is per-crate so it cannot reach
/// dependent crates.
pub fn use_root_dir(dir: PathBuf) {
    let _ = ROOT_DIR.set(dir);
}

/// As [`use_root_dir`], but each thread gets its own directory underneath, for test
/// binaries that run in parallel and share project names.
pub fn use_root_dir_per_thread(base: PathBuf) {
    PER_THREAD.store(true, Ordering::Relaxed);
    let _ = ROOT_DIR.set(base);
}

fn thread_scoped(base: &Path) -> PathBuf {
    let who: String = std::thread::current()
        .name()
        .unwrap_or("main")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    base.join(who)
}

/// The per-user home directory, resolved the same way the rest of the machine state is.
#[must_use]
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return Some(PathBuf::from(profile));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
        .map(PathBuf::from)
}

/// The root directory `ferry/`.
///
/// Found deterministically, never by asking which directory a command was launched in:
/// `FERRYMAN_ROOT` when set, otherwise the home directory's `ferry/`. This crate's own
/// tests are redirected to a temp directory automatically; dependent crates use
/// [`use_root_dir_per_thread`]. Reading does not create the root.
#[must_use]
pub fn root_dir() -> Option<PathBuf> {
    #[cfg(test)]
    if ROOT_DIR.get().is_none() {
        use_root_dir_per_thread(
            std::env::temp_dir().join(format!("ferryman-root-selftest-{}", std::process::id())),
        );
    }
    if let Some(forced) = ROOT_DIR.get() {
        let dir = if PER_THREAD.load(Ordering::Relaxed) {
            thread_scoped(forced)
        } else {
            forced.clone()
        };
        return Some(dir);
    }
    if let Ok(explicit) = std::env::var("FERRYMAN_ROOT")
        && !explicit.trim().is_empty()
    {
        return Some(PathBuf::from(explicit));
    }
    home_dir().map(|home| home.join("ferry"))
}

fn segment_of(manifest: &Manifest, key: &str) -> String {
    let value = match key {
        "comms" => &manifest.comms,
        "repos" => &manifest.repos,
        "work" => &manifest.work,
        _ => "",
    };
    if value.trim().is_empty() {
        fallback_segment(key).to_string()
    } else {
        value.to_string()
    }
}

fn fallback_segment(key: &str) -> &'static str {
    match key {
        "repos" => DEFAULT_REPOS,
        "work" => DEFAULT_WORK,
        _ => DEFAULT_COMMS,
    }
}

/// Read the manifest, tolerating its absence.
///
/// A missing or unreadable manifest is an empty index, not an error: the whole point is
/// that deleting `.ferry` costs nothing but convenience.
fn load_manifest_opt() -> Option<Manifest> {
    let path = manifest_path()?;
    let text = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Load the manifest, defaulting to an empty one when absent.
pub fn load() -> Manifest {
    load_manifest_opt().unwrap_or_default()
}

/// The absolute path of the manifest file, when a root is available.
#[must_use]
pub fn manifest_path() -> Option<PathBuf> {
    root_dir().map(|root| root.join(MANIFEST_FILE))
}

/// Where channels live, when a root is available.
#[must_use]
pub fn comms_dir() -> Option<PathBuf> {
    let segment = load_manifest_opt()
        .as_ref()
        .map_or_else(|| DEFAULT_COMMS.to_string(), |m| segment_of(m, "comms"));
    root_dir().map(|root| root.join(segment))
}

/// Where repositories Ferryman clones live, when a root is available.
#[must_use]
pub fn repos_dir() -> Option<PathBuf> {
    let segment = load_manifest_opt()
        .as_ref()
        .map_or_else(|| DEFAULT_REPOS.to_string(), |m| segment_of(m, "repos"));
    root_dir().map(|root| root.join(segment))
}

/// Where task worktrees live, when a root is available.
#[must_use]
pub fn work_dir() -> Option<PathBuf> {
    let segment = load_manifest_opt()
        .as_ref()
        .map_or_else(|| DEFAULT_WORK.to_string(), |m| segment_of(m, "work"));
    root_dir().map(|root| root.join(segment))
}

/// The projects this machine has adopted, with dead paths already dropped.
///
/// The drop is silent on purpose: a project whose recorded repository no longer exists
/// cannot be opened, and offering it in a picker looks like the switch did nothing.
#[must_use]
pub fn known() -> Vec<KnownProject> {
    let manifest = load();
    manifest
        .projects
        .into_iter()
        .filter_map(|(project_id, location)| {
            location.repository.is_dir().then_some(KnownProject {
                project_id,
                channel: location.channel,
                repository: location.repository,
            })
        })
        .collect()
}

/// Record a project's channel and repository into the manifest, in place.
///
/// This writes where things already are; it never moves or touches either directory.
/// Idempotent, and atomic (temp then rename) so a concurrent reader never sees a
/// half-written manifest. Returns `true` when the entry was new or changed, `false`
/// when it was already recorded exactly so (in which case nothing is written).
pub fn record(project_id: &str, channel: &Path, repository: &Path) -> Result<bool> {
    let root = root_dir().context("no root directory to record into")?;
    let mut manifest = load();
    let location = ProjectLocation {
        channel: channel.to_path_buf(),
        repository: repository.to_path_buf(),
    };
    let previous = manifest
        .projects
        .insert(project_id.to_string(), location.clone());
    let changed = previous.is_none_or(|old| old != location);
    if changed {
        save_to(&root, &manifest)?;
    }
    Ok(changed)
}

/// Write the manifest atomically at `root/.ferry`.
fn save_to(root: &Path, manifest: &Manifest) -> Result<()> {
    fs::create_dir_all(root).with_context(|| format!("create root {}", root.display()))?;
    let path = root.join(MANIFEST_FILE);
    let temporary = root.join(format!(".{MANIFEST_FILE}.tmp"));
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(manifest).context("serialise the manifest")?,
    )
    .with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("rename {} into place", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hermetic_root() -> PathBuf {
        let base = std::env::temp_dir().join(format!("ferryman-root-test-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        use_root_dir_per_thread(base);
        // `root_dir` applies the per-thread scoping, so each parallel test gets its own
        // directory while every test in this crate agrees on the base.
        root_dir().expect("a root directory was just set")
    }

    #[test]
    fn a_manifest_round_trips_through_the_file() {
        let root = hermetic_root();
        let repo = root.join("elsewhere").join("acme");
        let channel = root.join("comms").join("acme-ferryman");
        fs::create_dir_all(&repo).unwrap();
        record("acme", &channel, &repo).unwrap();

        let manifest = load();
        let location = manifest.projects.get("acme").expect("recorded");
        assert_eq!(location.repository, repo);
        assert_eq!(location.channel, channel);

        let known = known();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].project_id, "acme");
    }

    #[test]
    fn a_recorded_path_that_no_longer_exists_is_dropped() {
        let root = hermetic_root();
        let repo = root.join("gone").join("acme");
        let channel = root.join("comms").join("acme-ferryman");
        record("acme", &channel, &repo).unwrap();
        // The channel exists but the repository does not: the project cannot be opened.
        fs::create_dir_all(&channel).unwrap();
        assert!(
            known().is_empty(),
            "a project with no repository is dropped"
        );
    }

    #[test]
    fn deleting_the_manifest_costs_nothing() {
        let root = hermetic_root();
        let repo = root.join("elsewhere").join("acme");
        let channel = root.join("comms").join("acme-ferryman");
        fs::create_dir_all(&repo).unwrap();
        record("acme", &channel, &repo).unwrap();

        fs::remove_file(manifest_path().unwrap()).unwrap();
        assert!(known().is_empty(), "no manifest means no index");
        assert!(load().projects.is_empty());
        // And a fresh record still works afterwards.
        record("acme", &channel, &repo).unwrap();
        assert_eq!(known().len(), 1);
    }

    #[test]
    fn recording_does_not_touch_the_recorded_directories() {
        let root = hermetic_root();
        let repo = root.join("elsewhere").join("acme");
        let channel = root.join("comms").join("acme-ferryman");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&channel).unwrap();
        let marker = repo.join("keep.txt");
        fs::write(&marker, "untouched").unwrap();

        record("acme", &channel, &repo).unwrap();

        assert!(marker.is_file(), "adoption must not move or alter the repo");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "untouched");
        assert!(
            !root.join("repos").join("acme").exists(),
            "adoption writes an index entry, not a copy or a move"
        );
    }

    #[test]
    fn the_work_segment_is_configurable_in_the_manifest() {
        let root = hermetic_root();
        let manifest = Manifest {
            work: "scratch".to_string(),
            ..Manifest::default()
        };
        save_to(&root, &manifest).unwrap();
        assert_eq!(work_dir().unwrap(), root.join("scratch"));
    }
}

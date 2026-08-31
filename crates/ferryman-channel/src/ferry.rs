//! One place called `ferry`, and a manifest that says where everything is.
//!
//! ADR 0019.
//!
//! ```text
//! ferry/
//!   comms/     every channel:  <project>-ferryman/
//!   repos/     repositories Ferryman cloned, and links to ones it adopted
//!   work/      task worktrees, which are transient
//!   .ferry     this manifest
//! ```
//!
//! # Why a manifest rather than a scan
//!
//! Finding projects by reading the directory beside wherever a command happened to be
//! launched is guesswork dressed as discovery: it finds a fleet kept as siblings, finds
//! nothing from a checkout on another drive, cannot see two locations at once, and fails
//! *silently* - showing one project as though one were all there is.
//!
//! # What is never done
//!
//! **A repository the user made is never moved.** It is adopted where it stands and the
//! manifest records where that is. `create_worktree` puts worktrees beside the
//! repository, so moving one breaks every existing worktree - a worktree's `.git` is a
//! file holding an absolute path back to its repo, and [`crate::worktree`] already
//! documents that failure because it happened. `repos/` may hold a *link* to an adopted
//! repository, which costs nothing to break.
//!
//! The rule underneath: the files are the truth, and this carries the channel rather than
//! the work. Coordinating work does not entitle it to somebody's filesystem.
//!
//! # Machine-local, always
//!
//! Every path here is machine-specific - which is exactly why one machine can see
//! nineteen projects and another two. The manifest never travels in a channel: a path
//! from another machine is worse than no path at all.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The file that marks a ferry root and describes what is in it.
pub const MANIFEST: &str = ".ferry";

/// One project, and where its two halves live on this machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub project_id: String,
    /// The channel directory - the thing Syncthing carries.
    pub channel: PathBuf,
    /// The repository the work happens in, wherever it actually is. `None` for a project
    /// that is only a channel here, which is the normal state on a machine that syncs a
    /// channel but does not run the work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<PathBuf>,
    /// Whether this repository was adopted where it stood rather than created here.
    /// Recorded so nothing ever assumes it may be moved or removed.
    #[serde(default)]
    pub adopted: bool,
}

/// What a ferry root holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Manifest {
    /// Format tag, so a future layout can be told from this one.
    #[serde(default = "manifest_version")]
    pub version: u32,
    #[serde(default)]
    pub projects: Vec<Entry>,
}

fn manifest_version() -> u32 {
    1
}

/// A ferry root on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub path: PathBuf,
}

impl Root {
    #[must_use]
    pub fn comms(&self) -> PathBuf {
        self.path.join("comms")
    }
    #[must_use]
    pub fn repos(&self) -> PathBuf {
        self.path.join("repos")
    }
    /// Where task worktrees go.
    ///
    /// Not beside the repository, which is where they went before. They are transient and
    /// belong to Ferryman, and putting them in a directory the user made both litters it
    /// and makes a scan of it find things that are not projects.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.path.join("work")
    }
    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        self.path.join(MANIFEST)
    }

    /// Create the layout and an empty manifest. Safe to run again.
    pub fn create(path: &Path) -> Result<Self> {
        let root = Self {
            path: path.to_path_buf(),
        };
        for dir in [root.comms(), root.repos(), root.work()] {
            std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }
        if !root.manifest_path().is_file() {
            root.write(&Manifest {
                version: manifest_version(),
                projects: Vec::new(),
            })?;
        }
        remember_root(&root.path);
        Ok(root)
    }

    /// Read the manifest. A missing or unreadable one is an empty manifest, never an
    /// error: this is an index, and a broken index must cost only its convenience.
    #[must_use]
    pub fn read(&self) -> Manifest {
        std::fs::read_to_string(self.manifest_path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn write(&self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec_pretty(manifest)?;
        let temporary = self.path.join(".ferry.tmp");
        std::fs::write(&temporary, json)
            .with_context(|| format!("write {}", temporary.display()))?;
        std::fs::rename(&temporary, self.manifest_path())
            .with_context(|| format!("write {}", self.manifest_path().display()))
    }

    /// Record a project, and where its repository is. Nothing on disk is moved.
    ///
    /// `repo` is taken as given. If it sits outside this root it is marked adopted, which
    /// is the flag everything else reads before deciding whether it may touch it.
    pub fn adopt(&self, project_id: &str, channel: &Path, repo: Option<&Path>) -> Result<()> {
        let mut manifest = self.read();
        let adopted = repo.is_some_and(|repo| !repo.starts_with(&self.path));
        let entry = Entry {
            project_id: project_id.to_string(),
            channel: channel.to_path_buf(),
            repo: repo.map(Path::to_path_buf),
            adopted,
        };
        match manifest
            .projects
            .iter_mut()
            .find(|existing| existing.project_id == project_id)
        {
            // Merge rather than replace. One project can be adopted from two places on
            // one machine - a checkout that has the work, and a synced channel directory
            // that does not - and letting the second overwrite the first threw away the
            // repository path it had already learned. Losing what you knew is worse than
            // not learning anything, and it is silent, which is worse again.
            Some(existing) => {
                existing.channel = entry.channel;
                if entry.repo.is_some() {
                    existing.repo = entry.repo;
                    existing.adopted = entry.adopted;
                }
            }
            None => manifest.projects.push(entry),
        }
        manifest
            .projects
            .sort_by(|a, b| a.project_id.cmp(&b.project_id));
        self.write(&manifest)
    }

    /// Everything the manifest lists that is still on disk.
    ///
    /// An entry whose channel has gone is dropped rather than returned: offering a
    /// project that cannot be opened looks, to the person who picks it, exactly like the
    /// software ignoring them.
    #[must_use]
    pub fn projects(&self) -> Vec<Entry> {
        self.read()
            .projects
            .into_iter()
            .filter(|entry| entry.channel.is_dir())
            .collect()
    }

    /// Put a link to an adopted repository in `repos/`, so the tidy view exists without
    /// anything having been moved.
    ///
    /// Best-effort by design: a link is a convenience, and a platform or filesystem that
    /// will not make one loses nothing that matters. The manifest is what discovery
    /// reads.
    pub fn link_repo(&self, project_id: &str, repo: &Path) -> Result<Option<PathBuf>> {
        if repo.starts_with(&self.path) {
            return Ok(None);
        }
        std::fs::create_dir_all(self.repos())?;
        let link = self.repos().join(project_id);
        if link.exists() {
            return Ok(Some(link));
        }
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(repo, &link).is_ok();
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(repo, &link).is_ok();
        #[cfg(not(any(unix, windows)))]
        let made = false;
        Ok(made.then_some(link))
    }
}

fn root_pointer() -> Option<PathBuf> {
    crate::licensing::machine_state_dir().map(|dir| dir.join("ferry-root"))
}

fn remember_root(path: &Path) {
    if let Some(pointer) = root_pointer() {
        if let Some(parent) = pointer.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(pointer, path.display().to_string());
    }
}

/// The ferry root for this machine, if there is one.
///
/// Looked for in the order that respects what the person actually did: an explicit
/// override, then a root they are standing inside, then the one they made.
#[must_use]
pub fn find_root() -> Option<Root> {
    if let Ok(explicit) = std::env::var("FERRYMAN_ROOT")
        && !explicit.is_empty()
    {
        let path = PathBuf::from(explicit);
        if looks_like_root(&path) {
            return Some(Root { path });
        }
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Some(root) = find_root_from(&cwd)
    {
        return Some(root);
    }
    let pointer = root_pointer()?;
    let recorded = std::fs::read_to_string(pointer).ok()?;
    let path = PathBuf::from(recorded.trim());
    looks_like_root(&path).then_some(Root { path })
}

/// Whether a directory is a ferry root.
///
/// The manifest marks one, but the LAYOUT is enough on its own. Deleting `.ferry` was
/// meant to cost only the index; it orphaned the whole root instead, so `ferry root show`
/// answered "no ferry root yet" while comms, repos and work sat there full of things. An
/// index whose loss destroys the thing it indexes is not an index.
fn looks_like_root(dir: &Path) -> bool {
    dir.join(MANIFEST).is_file() || (dir.join("comms").is_dir() && dir.join("work").is_dir())
}

/// Walk up from a directory looking for a root, so being anywhere inside one is enough.
#[must_use]
pub fn find_root_from(start: &Path) -> Option<Root> {
    let mut here = Some(start);
    while let Some(dir) = here {
        if looks_like_root(dir) {
            return Some(Root {
                path: dir.to_path_buf(),
            });
        }
        here = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(dir: &Path) -> Root {
        Root::create(&dir.join("ferry")).unwrap()
    }

    fn channel(dir: &Path, id: &str) -> PathBuf {
        let path = dir.join("comms").join(format!("{id}-ferryman"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_root_is_a_layout_and_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        assert!(root.comms().is_dir());
        assert!(root.repos().is_dir());
        assert!(root.work().is_dir());
        assert!(root.manifest_path().is_file());
        assert!(root.projects().is_empty());
    }

    /// The rule this whole module exists to keep: adoption records, it does not move.
    #[test]
    fn adopting_a_repository_leaves_it_exactly_where_it_was() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = dir.path().join("somewhere/else/my-repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("marker"), "mine").unwrap();
        let channel = channel(&root.path, "alpha");

        root.adopt("alpha", &channel, Some(&repo)).unwrap();

        assert!(
            repo.join("marker").is_file(),
            "the repository must not have moved"
        );
        let entry = &root.projects()[0];
        assert_eq!(entry.repo.as_deref(), Some(repo.as_path()));
        assert!(
            entry.adopted,
            "a repo outside the root is adopted, never owned"
        );
    }

    #[test]
    fn a_repository_created_inside_the_root_is_not_marked_adopted() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = root.repos().join("ours");
        std::fs::create_dir_all(&repo).unwrap();
        root.adopt("ours", &channel(&root.path, "ours"), Some(&repo))
            .unwrap();

        assert!(!root.projects()[0].adopted);
    }

    #[test]
    fn a_project_whose_channel_has_gone_is_dropped_rather_than_offered() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let gone = channel(&root.path, "gone");
        root.adopt("gone", &gone, None).unwrap();
        root.adopt("here", &channel(&root.path, "here"), None)
            .unwrap();
        std::fs::remove_dir_all(&gone).unwrap();

        let ids: Vec<String> = root.projects().into_iter().map(|p| p.project_id).collect();
        assert_eq!(ids, vec!["here"]);
    }

    #[test]
    fn adopting_the_same_project_twice_updates_it_rather_than_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        let channel = channel(&root.path, "alpha");

        let first = dir.path().join("a");
        let second = dir.path().join("b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();

        root.adopt("alpha", &channel, Some(&first)).unwrap();
        root.adopt("alpha", &channel, Some(&second)).unwrap();

        let projects = root.projects();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].repo.as_deref(), Some(second.as_path()));
    }

    /// Found by running it: one project can be adopted twice on one machine - once from
    /// the checkout that has the work, once from a synced channel directory that does
    /// not - and the second must not erase what the first knew.
    #[test]
    fn adopting_a_channel_only_copy_does_not_forget_where_the_repository_is() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let repo = dir.path().join("checkout");
        std::fs::create_dir_all(&repo).unwrap();
        let from_checkout = channel(&root.path, "alpha");
        root.adopt("alpha", &from_checkout, Some(&repo)).unwrap();

        // The same project, reached through a synced channel with no repo beside it.
        let synced = dir.path().join("synced/alpha-ferryman");
        std::fs::create_dir_all(&synced).unwrap();
        root.adopt("alpha", &synced, None).unwrap();

        let entry = &root.projects()[0];
        assert_eq!(entry.channel, synced, "the newer channel path wins");
        assert_eq!(
            entry.repo.as_deref(),
            Some(repo.as_path()),
            "but the repository it already knew is not forgotten"
        );
        assert!(entry.adopted);
    }

    /// The manifest is an index, never authority. Losing it costs its convenience and
    /// nothing else.
    #[test]
    fn a_broken_manifest_reads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        root.adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();

        std::fs::write(root.manifest_path(), "{ not json at all").unwrap();
        assert!(
            root.projects().is_empty(),
            "a broken index must not be fatal"
        );

        // And it heals by being used again.
        root.adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();
        assert_eq!(root.projects().len(), 1);
    }

    /// The promise the index makes: losing it costs the index, not the root.
    #[test]
    fn deleting_the_manifest_does_not_lose_the_root() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());
        root.adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();

        std::fs::remove_file(root.manifest_path()).unwrap();

        let found = find_root_from(&root.path).expect("the layout is still a root");
        assert_eq!(found.path, root.path);
        assert!(found.projects().is_empty());

        // And it refills by being used.
        found
            .adopt("alpha", &channel(&root.path, "alpha"), None)
            .unwrap();
        assert_eq!(found.projects().len(), 1);
    }

    #[test]
    fn standing_anywhere_inside_a_root_finds_it() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = root(dir.path());

        let deep = root.work().join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(find_root_from(&deep).unwrap().path, root.path);

        // And outside one, nothing is invented.
        assert!(find_root_from(dir.path()).is_none());
    }
}

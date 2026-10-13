//! The Syncthing scope guard: only channels travel.
//!
//! In a ferry root, `comms/<project>-ferryman` is the only thing Syncthing may carry.
//! `repos/` and `work/` hold git clones and task worktrees. They are machine-local, and
//! git is what carries code between machines. Sharing them is how two machines end up
//! writing into one `.git` directory, so Ferryman refuses to create or share a Syncthing
//! folder at the root itself, anywhere above it, or under `repos/` or `work/`, and
//! `ferry doctor --layout` flags any such folder it finds already configured.
//!
//! The rule is structural. Nothing here relies on a person or an agent remembering it.

use std::path::Path;

use anyhow::{Result, bail};
use serde_json::Value;

use crate::ferry::{Root, find_root, find_root_from};

/// One folder as Syncthing has it configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub id: String,
    pub label: String,
    pub path: String,
}

/// Ids Ferryman itself gives folders. Anything else in a Syncthing config is somebody's
/// own and is never flagged for being elsewhere.
const FERRYMAN_SUFFIXES: [&str; 2] = ["-ferryman", "-work"];

fn normalise(path: &str) -> String {
    let p = path.trim().replace('\\', "/");
    let p = p.trim_end_matches('/').to_string();
    if cfg!(windows) { p.to_lowercase() } else { p }
}

/// Whether `child` is `parent` or lies under it. Text comparison, like Syncthing's own
/// config: the path may not exist on this machine, and separators and case may differ.
fn within(child: &str, parent: &str) -> bool {
    child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Why `path` may not be a Syncthing folder in this root, or `None` when it may.
#[must_use]
pub fn refusal(root: &Path, path: &Path) -> Option<String> {
    let root_text = normalise(&root.display().to_string());
    let target = normalise(&path.display().to_string());
    if root_text.is_empty() || target.is_empty() {
        return None;
    }
    let reason = if target == root_text {
        "is the ferry root itself, which holds repos and worktrees"
    } else if within(&target, &format!("{root_text}/repos")) {
        "is under repos/, which holds git clones"
    } else if within(&target, &format!("{root_text}/work")) {
        "is under work/, which holds git worktrees"
    } else if within(&root_text, &target) {
        "contains the ferry root, so it would carry repos/ and work/ as well"
    } else {
        return None;
    };
    Some(format!(
        "{} {reason}. Only channel folders under {}/comms are ever shared; git carries the code",
        path.display(),
        root.display()
    ))
}

/// Refuse a Syncthing folder outside the roots this path or this machine belongs to.
///
/// # Errors
/// When the path is the root, above it, or under its `repos/` or `work/`.
pub fn guard(path: &Path) -> Result<()> {
    let mut roots: Vec<Root> = Vec::new();
    if let Some(root) = find_root_from(path) {
        roots.push(root);
    }
    if let Some(root) = find_root() {
        roots.push(root);
    }
    for root in &roots {
        if let Some(why) = refusal(&root.path, path) {
            bail!("refusing to share this with Syncthing: {why}");
        }
    }
    Ok(())
}

/// Every folder the local Syncthing has configured. `None` when it cannot be reached,
/// which is not the same as having none.
#[must_use]
pub fn configured_folders() -> Option<Vec<Folder>> {
    let key = crate::syncthing_api_key()?;
    let base = crate::syncthing_api_base();
    let config = crate::syncthing_get(&base, "/rest/config/folders", &key)
        .ok()
        .flatten()?;
    Some(folders_in(&config))
}

/// The folders in a `/rest/config/folders` answer.
#[must_use]
pub fn folders_in(config: &Value) -> Vec<Folder> {
    let text = |folder: &Value, key: &str| {
        folder
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    config
        .as_array()
        .map(|folders| {
            folders
                .iter()
                .map(|folder| Folder {
                    id: text(folder, "id"),
                    label: text(folder, "label"),
                    path: text(folder, "path"),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The configured folders that sit outside `comms/` and should not.
///
/// Two kinds. Any folder at the root, above it, or under `repos/` or `work/`, whoever
/// made it. And a folder with one of Ferryman's own ids (`<project>-ferryman`,
/// `<project>-work`) that is anywhere other than under `comms/`. A folder a person set
/// up for their own purposes elsewhere is theirs and is left alone.
#[must_use]
pub fn strays<'a>(root: &Path, folders: &'a [Folder]) -> Vec<&'a Folder> {
    let comms = format!("{}/comms", normalise(&root.display().to_string()));
    folders
        .iter()
        .filter(|folder| {
            let path = Path::new(&folder.path);
            let target = normalise(&folder.path);
            if folder.path.trim().is_empty() || within(&target, &comms) {
                return false;
            }
            refusal(root, path).is_some()
                || FERRYMAN_SUFFIXES
                    .iter()
                    .any(|suffix| folder.id.ends_with(suffix))
        })
        .collect()
}

/// Whether this stray is one Ferryman made itself and may stop sharing: its own id, and
/// a place the guard forbids. Only the Syncthing registration goes; no file does.
#[must_use]
pub fn is_ours_to_unshare(root: &Path, folder: &Folder) -> bool {
    FERRYMAN_SUFFIXES
        .iter()
        .any(|suffix| folder.id.ends_with(suffix))
        && refusal(root, Path::new(&folder.path)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn root() -> std::path::PathBuf {
        std::path::PathBuf::from(if cfg!(windows) {
            r"X:\ferry"
        } else {
            "/home/josh/ferry"
        })
    }

    #[test]
    fn the_root_and_repos_and_work_are_refused() {
        let root = root();
        for refused in [
            root.clone(),
            root.join("repos"),
            root.join("repos").join("pc-secrets"),
            root.join("work"),
            root.join("work").join("pc-secrets").join("order-1"),
            root.parent().unwrap().to_path_buf(),
        ] {
            let why = refusal(&root, &refused);
            assert!(why.is_some(), "{} should be refused", refused.display());
            assert!(why.unwrap().contains("Only channel folders"));
        }
    }

    #[test]
    fn channel_folders_under_comms_are_allowed() {
        let root = root();
        assert!(refusal(&root, &root.join("comms").join("pc-secrets-ferryman")).is_none());
        assert!(
            refusal(
                &root,
                &root.join("comms").join("a-ferryman").join("handins")
            )
            .is_none()
        );
        // Beside the root is somebody else's folder, not ours to judge.
        assert!(refusal(&root, &root.parent().unwrap().join("elsewhere")).is_none());
        // A name that merely starts like `work` is not `work/`.
        assert!(refusal(&root, &root.join("workbench")).is_none());
    }

    #[test]
    fn separators_and_a_trailing_slash_do_not_get_a_folder_past_the_guard() {
        let root = std::path::PathBuf::from("/home/josh/ferry");
        assert!(refusal(&root, Path::new("/home/josh/ferry/")).is_some());
        assert!(refusal(&root, Path::new("/home/josh/ferry/work/x/")).is_some());
    }

    #[test]
    fn registering_a_folder_in_repos_fails_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::ferry::Root::create(&dir.path().join("ferry")).unwrap();
        let clone = root.repos().join("pc-secrets");
        std::fs::create_dir_all(&clone).unwrap();
        let error = guard(&clone).unwrap_err().to_string();
        assert!(error.contains("repos/"), "{error}");
        assert!(guard(&root.path).is_err());
        assert!(guard(&root.work().join("p").join("order")).is_err());
        assert!(guard(&root.comms().join("p-ferryman")).is_ok());

        let attempt = crate::register_folder("p-work", &root.work().join("p"), "t", &[]);
        assert!(attempt.is_err());
        assert!(
            !root.work().join("p").join(".stfolder").exists(),
            "no marker may be written for a refused folder"
        );
    }

    #[test]
    fn strays_are_ferrymans_own_folders_in_the_wrong_place_and_anything_in_repos() {
        let root = root();
        let at = |id: &str, path: std::path::PathBuf| Folder {
            id: id.to_string(),
            label: String::new(),
            path: path.display().to_string(),
        };
        let folders = vec![
            at("p-ferryman", root.join("comms").join("p-ferryman")),
            at("p-work", root.join("work").join("p")),
            at("q-ferryman", std::path::PathBuf::from("/srv/old/q-comms")),
            at("photos", std::path::PathBuf::from("/srv/photos")),
            at("by-hand", root.join("repos").join("p")),
            at("ferryman-fleet", std::path::PathBuf::from("/srv/fleet")),
        ];
        let found: Vec<&str> = strays(&root, &folders)
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(found, ["p-work", "q-ferryman", "by-hand"]);
        assert!(is_ours_to_unshare(&root, &folders[1]));
        assert!(
            !is_ours_to_unshare(&root, &folders[2]),
            "not in a forbidden place"
        );
        assert!(!is_ours_to_unshare(&root, &folders[4]), "not a Ferryman id");
    }

    #[test]
    fn the_syncthing_folder_list_is_read_as_given() {
        let config = json!([
            {"id": "a-ferryman", "label": "a", "path": "/x/comms/a-ferryman"},
            {"id": "b"}
        ]);
        let folders = folders_in(&config);
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].path, "/x/comms/a-ferryman");
        assert_eq!(folders[1].path, "");
        assert!(folders_in(&json!({})).is_empty());
    }
}

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
const FERRYMAN_SUFFIXES: [&str; 3] = ["-ferryman", "-handins", "-work"];

/// A path as plain text for comparing: forward slashes, `.` and `..` resolved, no
/// trailing slash, no Windows `\\?\` prefix, and lower case on Windows. Without the
/// `..` step, `comms/../repos/x` would read as a place under `comms/`.
fn normalise(path: &str) -> String {
    let p = path.trim().replace('\\', "/");
    let p = p.strip_prefix("//?/").unwrap_or(&p);
    let absolute = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    let p = if absolute {
        format!("/{joined}")
    } else {
        joined
    };
    if cfg!(windows) { p.to_lowercase() } else { p }
}

/// The ways a path can be written: as given, and with symlinks (and Windows short names)
/// resolved as far as the path exists. A link inside `comms/` that leads into `repos/`
/// is `repos/` as far as Syncthing is concerned.
fn forms(path: &Path) -> Vec<String> {
    let mut found = vec![normalise(&path.display().to_string())];
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut at = path.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&at) {
            let mut full = real;
            for part in tail.iter().rev() {
                full.push(part);
            }
            let text = normalise(&full.display().to_string());
            if !found.contains(&text) {
                found.push(text);
            }
            break;
        }
        match (at.file_name().map(std::ffi::OsString::from), at.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                at = parent.to_path_buf();
            }
            _ => break,
        }
    }
    found
}

/// The parts of a ferry root nothing may share besides `comms/`.
const FORBIDDEN_UNDER_ROOT: [(&str, &str); 6] = [
    ("repos", "is under repos/, which holds git clones"),
    ("work", "is under work/, which holds git worktrees"),
    (
        "service",
        "is under service/, which holds the worker's environment file",
    ),
    ("secrets", "is under secrets/, which holds credentials"),
    ("logs", "is under logs/, which holds this machine's logs"),
    (
        "fleet/local",
        "is under fleet/local/, this machine's own part of the fleet folder",
    ),
];

/// Whether `child` is `parent` or lies under it. Text comparison, like Syncthing's own
/// config: the path may not exist on this machine, and separators and case may differ.
fn within(child: &str, parent: &str) -> bool {
    let parent = parent.trim_end_matches('/');
    child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether a path names an environment file (`.env`, `fleet.env`, `deploy.env`): the files
/// that hold keys. Nothing that is one is ever a Syncthing folder.
fn is_env_file(target: &str) -> bool {
    target
        .rsplit('/')
        .next()
        .is_some_and(|name| name == ".env" || name.ends_with(".env"))
}

/// Layout 2: under `projects/` only `<id>/comms` and `<id>/handins` may be shared.
fn layout_two_reason(projects: &str, target: &str) -> Option<&'static str> {
    if !within(target, projects) {
        return None;
    }
    let rest = target
        .strip_prefix(projects)
        .unwrap_or_default()
        .trim_start_matches('/');
    let mut parts = rest.split('/').filter(|part| !part.is_empty());
    match (parts.next(), parts.next()) {
        (None, _) => Some("is projects/, which holds every project's repo, worktrees and keys"),
        (Some(_), None) => Some(
            "is a project folder, which holds its repo, worktrees, scratch and keys as well as its channel",
        ),
        (Some(_), Some("comms" | "handins")) => None,
        (Some(_), Some(_)) => Some(
            "is inside a project folder but is not its comms or handins; repo, work, tmp and .env stay on the machine",
        ),
    }
}

fn reason_for(root_text: &str, target: &str) -> Option<&'static str> {
    if root_text.is_empty() || target.is_empty() {
        return None;
    }
    if target == root_text {
        return Some("is the ferry root itself, which holds repos and worktrees");
    }
    for (part, reason) in FORBIDDEN_UNDER_ROOT {
        if within(target, &format!("{root_text}/{part}")) {
            return Some(reason);
        }
    }
    if let Some(reason) = layout_two_reason(&format!("{root_text}/projects"), target) {
        return Some(reason);
    }
    if is_env_file(target) {
        return Some("is an environment file, which holds keys and never leaves the machine");
    }
    if within(root_text, target) {
        return Some("contains the ferry root, so it would carry repos/ and work/ as well");
    }
    None
}

/// Why `path` may not be a Syncthing folder in this root, or `None` when it may.
#[must_use]
pub fn refusal(root: &Path, path: &Path) -> Option<String> {
    let reason = forms(root).iter().find_map(|root_text| {
        forms(path)
            .iter()
            .find_map(|target| reason_for(root_text, target))
    })?;
    Some(format!(
        "{} {reason}. Only channel folders (a project's comms and handins, under {}) are ever shared; git carries the code",
        path.display(),
        root.display()
    ))
}

/// Why `path` may not be shared because of what it would carry along: a folder that contains
/// a project's `.env`, its repo, or the root's `secrets/` is refused even when it is not
/// inside the root (a custom placement can put a channel anywhere, and a person can point a
/// folder at a parent of it). Uses the places the manifest records.
fn carries(root: &Root, path: &Path) -> Option<String> {
    let target = forms(path);
    let holds = |inner: &Path| {
        forms(inner)
            .iter()
            .any(|inner| target.iter().any(|outer| within(inner, outer)))
    };
    if holds(&root.secrets()) {
        return Some("would carry secrets/".to_string());
    }
    for entry in root.projects() {
        if let Some(env) = entry.env.as_deref().filter(|env| holds(env)) {
            return Some(format!(
                "would carry {}'s environment file {}",
                entry.project_id,
                env.display()
            ));
        }
    }
    // The default `projects/<id>/.env` is covered by the structural rules above: a folder
    // that holds it is the project folder or something above it.
    // A project's data is machine-local wherever it is recorded: a folder that holds it, or
    // lies inside it, is never shared.
    for entry in root.projects() {
        let data = entry.data_path(root);
        let data_forms = forms(&data);
        if holds(&data)
            || data_forms
                .iter()
                .any(|data| target.iter().any(|outer| within(outer, data)))
        {
            return Some(format!(
                "would carry {}'s data folder {}, which is machine-local",
                entry.project_id,
                data.display()
            ));
        }
    }
    None
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
        if let Some(why) = carries(root, path) {
            bail!(
                "refusing to share {} with Syncthing: it {why}. Only a project's channel and hand-ins are ever shared",
                path.display()
            );
        }
    }
    Ok(())
}

/// Whether the manifest records `folder_path` as a project's channel or hand-ins: a custom
/// placement is a place a person chose, so a Ferryman folder id there is not a stray.
fn is_recorded(root: &Root, folder_path: &str) -> bool {
    let target = normalise(folder_path);
    root.projects().iter().any(|entry| {
        [entry.channel.clone(), entry.handins_path(root)]
            .iter()
            .any(|recorded| normalise(&recorded.display().to_string()) == target)
    })
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

/// The configured folders that sit where Ferryman never shares and should not.
///
/// Two kinds. Any folder at the root, above it, or under a place nothing may share
/// (`repos/`, `work/`, `secrets/`, a project's repo, work, tmp or `.env`), whoever made it.
/// And a folder with one of Ferryman's own ids (`<project>-ferryman`, `<project>-handins`,
/// legacy `<project>-work`) that is not in a place the layout or the manifest gives it:
/// `comms/` (layout 1), `projects/<id>/comms` or `projects/<id>/handins` (layout 2), or a
/// path the manifest records for the project (a custom placement is a person's choice and
/// is respected). A folder a person set up for their own purposes elsewhere is theirs and
/// is left alone.
#[must_use]
pub fn strays<'a>(root: &Path, folders: &'a [Folder]) -> Vec<&'a Folder> {
    let base = normalise(&root.display().to_string());
    let comms = format!("{base}/comms");
    let projects = format!("{base}/projects");
    let manifest = Root {
        path: root.to_path_buf(),
    };
    folders
        .iter()
        .filter(|folder| {
            let path = Path::new(&folder.path);
            let target = normalise(&folder.path);
            if folder.path.trim().is_empty() {
                return false;
            }
            // Where it really leads counts, so a link from comms/ into repos/ is a stray.
            if refusal(root, path).is_some() {
                return true;
            }
            let ours = FERRYMAN_SUFFIXES
                .iter()
                .any(|suffix| folder.id.ends_with(suffix));
            let in_a_place = within(&target, &comms)
                || target == format!("{base}/fleet")
                || (within(&target, &projects) && layout_two_reason(&projects, &target).is_none())
                || is_recorded(&manifest, &folder.path);
            ours && !in_a_place
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
    fn dot_dot_cannot_walk_a_folder_out_of_comms_into_a_forbidden_place() {
        let root = root();
        let sneaky = root.join("comms").join("..").join("repos").join("pc");
        assert!(refusal(&root, &sneaky).is_some(), "{}", sneaky.display());
        let sneaky = root
            .join("comms")
            .join("x")
            .join("..")
            .join("..")
            .join("work");
        assert!(refusal(&root, &sneaky).is_some(), "{}", sneaky.display());
        // The service folder holds the worker's environment file.
        assert!(refusal(&root, &root.join("service")).is_some());
        assert!(refusal(&root, &root.join("service").join("backups")).is_some());
        // Walking up and back down to a real channel folder is fine.
        let fine = root.join("comms").join("x").join("..").join("p-ferryman");
        assert!(refusal(&root, &fine).is_none(), "{}", fine.display());
        if cfg!(windows) {
            let verbatim = format!(r"\\?\{}\repos\pc", root.display());
            assert!(refusal(&root, Path::new(&verbatim)).is_some(), "{verbatim}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_inside_comms_that_leads_into_repos_is_refused_and_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::ferry::Root::create(&dir.path().join("ferry")).unwrap();
        let clone = root.repos().join("pc");
        std::fs::create_dir_all(&clone).unwrap();
        std::fs::create_dir_all(root.comms()).unwrap();
        let link = root.comms().join("pc-ferryman");
        std::os::unix::fs::symlink(&clone, &link).unwrap();
        assert!(refusal(&root.path, &link).is_some());
        assert!(guard(&link).is_err());
        let folders = vec![Folder {
            id: "pc-ferryman".into(),
            label: String::new(),
            path: link.display().to_string(),
        }];
        assert_eq!(strays(&root.path, &folders).len(), 1);
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
    fn layout_two_shares_only_comms_and_handins() {
        let root = root();
        let project = root.join("projects").join("pc");
        // Allowed: the channel and the hand-ins, and what is inside them.
        for allowed in [
            project.join("comms"),
            project.join("handins"),
            project.join("handins").join("nebra"),
            project.join("comms").join("tasks"),
        ] {
            assert!(
                refusal(&root, &allowed).is_none(),
                "{} should be allowed",
                allowed.display()
            );
        }
        // Refused: the root, projects/, the project folder, and everything else in it.
        for refused in [
            root.clone(),
            root.join("projects"),
            project.clone(),
            project.join("repo"),
            project.join("repo").join("src"),
            project.join("work"),
            project.join("work").join("order-1"),
            project.join("tmp"),
            project.join(".env"),
            root.join("secrets"),
            root.join("secrets").join("fleet.env"),
            root.join("service"),
            root.join("logs"),
            // A .env is never a folder, wherever it is.
            std::path::PathBuf::from("/srv/custom/.env"),
            std::path::PathBuf::from("/srv/custom/deploy.env"),
        ] {
            assert!(refusal(&root, &refused).is_some(), "{}", refused.display());
        }
        // `..` cannot walk out of comms into repo.
        let sneaky = project.join("comms").join("..").join("repo");
        assert!(refusal(&root, &sneaky).is_some(), "{}", sneaky.display());
    }

    #[test]
    fn a_folder_that_would_carry_the_secrets_or_a_recorded_env_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::ferry::Root::create_with_layout(&dir.path().join("ferry"), 2).unwrap();
        // A custom project keeps its keys beside its channel, outside the root.
        let mine = dir.path().join("mine");
        std::fs::create_dir_all(mine.join("comms")).unwrap();
        root.record_custom(
            "pc",
            &crate::ferry::CustomPlaces {
                channel: mine.join("comms"),
                repo: None,
                handins: Some(mine.join("handins")),
                env: Some(mine.join("keys.env")),
                work: None,
                data: None,
            },
        )
        .unwrap();
        assert!(
            guard(&mine.join("comms")).is_ok(),
            "the channel itself is fine"
        );
        assert!(guard(&mine.join("handins")).is_ok());
        // The folder around the key is not.
        let error = guard(&mine).unwrap_err().to_string();
        assert!(error.contains("environment file"), "{error}");
        // And the secrets folder never.
        assert!(guard(&root.secrets()).is_err());
        assert!(guard(&root.project_dir("pc").join("repo")).is_err());
        assert!(guard(&root.comms_home("pc")).is_ok());
        assert!(guard(&root.handins_dir("pc")).is_ok());
    }

    #[test]
    fn layout_two_strays_and_a_custom_placement_that_is_recorded() {
        let root = root();
        let at = |id: &str, path: std::path::PathBuf| Folder {
            id: id.to_string(),
            label: String::new(),
            path: path.display().to_string(),
        };
        let project = root.join("projects").join("p");
        let folders = vec![
            at("p-ferryman", project.join("comms")),
            at("p-handins", project.join("handins")),
            // The old work folder id, sitting where it was.
            at("p-work", root.join("work").join("p")),
            // A handins folder pointed at the project's worktrees.
            at("p-handins", project.join("work")),
            // A Ferryman id somewhere nothing records: flagged.
            at("q-ferryman", std::path::PathBuf::from("/srv/old/q-comms")),
        ];
        let found: Vec<&str> = strays(&root, &folders)
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(
            !found
                .iter()
                .any(|p| p.ends_with("comms") && p.contains("projects"))
        );
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

    #[test]
    fn a_projects_data_and_the_fleet_folders_local_part_are_never_shared() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::ferry::Root::create_with_layout(&dir.path().join("ferry"), 2).unwrap();
        // The default data folder is a project-folder child that is not comms or handins.
        let why = refusal(&root.path, &root.project_data("demo")).unwrap();
        assert!(why.contains("not its comms or handins"), "{why}");
        assert!(guard(&root.project_data("demo")).is_err());
        // The fleet folder is a channel; its local part is this machine's own.
        assert!(guard(&root.fleet_dir()).is_ok());
        assert!(refusal(&root.path, &root.fleet_local()).is_some());
        assert!(refusal(&root.path, &root.fleet_local().join("agents-pinned")).is_some());
        let at = |id: &str, path: std::path::PathBuf| Folder {
            id: id.to_string(),
            label: String::new(),
            path: path.display().to_string(),
        };
        let folders = vec![
            at("fleet-ferryman", root.fleet_dir()),
            at("fleet-ferryman", root.fleet_local()),
        ];
        let stray: Vec<_> = strays(&root.path, &folders)
            .into_iter()
            .map(|f| f.path.clone())
            .collect();
        assert_eq!(stray, vec![root.fleet_local().display().to_string()]);

        // A custom project that keeps its data beside its channel, or inside it.
        let mine = dir.path().join("mine");
        std::fs::create_dir_all(mine.join("comms")).unwrap();
        root.record_custom(
            "pc",
            &crate::ferry::CustomPlaces {
                channel: mine.join("comms"),
                repo: None,
                handins: Some(mine.join("handins")),
                env: None,
                work: None,
                data: Some(mine.join("data")),
            },
        )
        .unwrap();
        assert!(guard(&mine.join("comms")).is_ok());
        assert!(guard(&mine.join("data")).is_err());
        assert!(guard(&mine.join("data").join("sub")).is_err());
        let error = guard(&mine).unwrap_err().to_string();
        assert!(error.contains("data folder"), "{error}");
        // Pointing the data inside the channel is refused when it is recorded, and a data
        // folder inside a channel that is already recorded would stop that channel being shared.
        assert!(
            root.set_data("pc", Some(&mine.join("comms").join("data")))
                .is_err()
        );
        assert!(
            root.set_data("pc", Some(&root.fleet_dir().join("data")))
                .is_err()
        );
        assert!(
            root.set_data("pc", Some(std::path::Path::new("relative")))
                .is_err()
        );
        assert!(
            root.set_data("pc", Some(&dir.path().join("elsewhere")))
                .unwrap()
        );
        assert!(root.set_data("pc", None).unwrap());
    }
}

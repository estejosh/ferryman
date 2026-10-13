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
//! [git.remotes]
//! # A project whose remote is not the template's.
//! odd-one = "https://example.com/odd/one.git"
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
    Ok(())
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
    if git.get("remote_template").and_then(toml::Value::as_str) == Some(template) {
        return Ok(false);
    }
    git.insert(
        "remote_template".into(),
        toml::Value::String(template.to_owned()),
    );
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

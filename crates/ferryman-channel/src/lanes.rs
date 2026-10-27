//! Lanes: several agents, one repository, no collisions (ADR 0031).
//!
//! A git working tree has one index and one HEAD. Two agents in one checkout therefore
//! share a staging area (`git add -A` commits the other agent's files), share a branch
//! (a `pull` moves files under the other mid-task) and race for the next number. A lane
//! gives each agent its own worktree and branch, declares which paths it owns, and has
//! its work reach `main` only through one serialized, rebasing landing.
//!
//! Where things live:
//!
//! * the worktree: `<repo>/.lanes/<lane>`, on branch `lane/<lane>`. Inside the repo (so it
//!   is part of the project's housing and `ferry root show` can find it), excluded through
//!   the repo's `info/exclude` (so `git status` in the main checkout never mentions it) and
//!   outside `work/` (which is transient and pruned; a lane is long-lived).
//! * the lane manifest: one signed record per lane at `<channel>/lanes/<lane>.json`, written
//!   only by the lane's owner, so Syncthing/iroh never see two writers for one path.
//! * the landing lock: a signed claim at `<channel>/lanes/landing/<agent>.<machine>.json`,
//!   plus a machine-local OS lock in the repo's git dir. The OS lock is what serializes
//!   agents on one machine; the claim makes the holder visible to other machines.
//! * hooks: a wrapper set per worktree (`extensions.worktreeConfig` and
//!   `git config --worktree core.hooksPath`), the pre-commit one running the ownership
//!   check and every one chaining to the repository's own hooks (its `core.hooksPath`, such
//!   as husky's, or `<common>/hooks`).
//!
//! Nothing here writes a credential anywhere: a push token is handed in as a value and
//! reaches git only through environment variables of the one child process.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature, is_safe_component};

/// The `format` of a lane record.
pub const LANE_FORMAT: &str = "ferryman-lane-v1";

/// The oldest git that has `extensions.worktreeConfig` and `git config --worktree`.
pub const MIN_GIT: (u32, u32) = (2, 20);

/// Files any lane may edit, because they are shared by nature. Edits to them are allowed
/// but reported, and they reach `main` only through a landing (which rebases them). A
/// project may add its own with `--shared`.
pub const DEFAULT_SHARED: &[&str] = &[
    "DECISIONS.md",
    "docs/DECISIONS.md",
    "README.md",
    "CHANGELOG.md",
];

/// How long a landing claim stands before others may ignore it as left by a crash.
const LANDING_TTL_MINUTES: i64 = 15;

/// A session that has not been heard from for this long is no longer "live".
pub const SESSION_LIVE_SECONDS: i64 = 900;

/// The client-side hooks a lane's wrapper set covers (beside any the repo's hooks dir holds).
const CLIENT_HOOKS: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-auto-gc",
    "post-rewrite",
    "post-index-change",
];

// ---------------------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------------------

fn wild(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') if p.get(1) == Some(&b'*') => {
            let rest = &p[2..];
            // `**/` may match no directory at all.
            if rest.first() == Some(&b'/') && wild(&rest[1..], s) {
                return true;
            }
            (0..=s.len()).any(|i| wild(rest, &s[i..]))
        }
        Some(b'*') => {
            for i in 0..=s.len() {
                if wild(&p[1..], &s[i..]) {
                    return true;
                }
                if i < s.len() && s[i] == b'/' {
                    break;
                }
            }
            false
        }
        Some(b'?') => !s.is_empty() && s[0] != b'/' && wild(&p[1..], &s[1..]),
        Some(c) => s.first() == Some(c) && wild(&p[1..], &s[1..]),
    }
}

fn normal(path: &str) -> String {
    let path = path.replace('\\', "/");
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

/// Whether `path` (repo-relative) is covered by `glob`. `*` stays inside one directory,
/// `**` crosses directories, and a glob that names a directory covers everything below it
/// (`art` and `art/` both cover `art/hero.png`).
#[must_use]
pub fn path_matches(glob: &str, path: &str) -> bool {
    let glob = normal(glob);
    let glob = glob.trim_end_matches('/');
    if glob.is_empty() {
        return false;
    }
    let path = normal(path);
    wild(glob.as_bytes(), path.as_bytes()) || wild(format!("{glob}/**").as_bytes(), path.as_bytes())
}

fn any_match(globs: &[String], path: &str) -> bool {
    globs.iter().any(|g| path_matches(g, path))
}

// ---------------------------------------------------------------------------------------
// git and paths
// ---------------------------------------------------------------------------------------

fn git_env(dir: &Path, args: &[&str], env: &[(String, String)]) -> Result<String> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_EDITOR", "true")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    let out = command
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    git_env(dir, args, &[])
}

fn git_ok(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A NUL-separated git listing (`-z`) as paths, exactly as git spells them (no quoting).
fn nul_list(text: &str) -> Vec<String> {
    text.split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// A path as one spelling: canonical, without the Windows `\\?\` prefix. git prints
/// forward slashes and long names; a temp dir may be an 8.3 short name; both name the same
/// folder, and comparing them as text is how a lane goes missing.
#[must_use]
pub fn clean(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = canonical.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\")
        && !rest.starts_with("UNC\\")
    {
        return PathBuf::from(rest);
    }
    canonical
}

fn path_key(path: &Path) -> String {
    let key = slashes(&clean(path));
    if cfg!(windows) {
        key.to_lowercase()
    } else {
        key
    }
}

/// Whether two paths are the same folder.
#[must_use]
pub fn same_path(a: &Path, b: &Path) -> bool {
    path_key(a) == path_key(b)
}

fn git_version() -> Option<(u32, u32)> {
    let out = Command::new("git").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let version = text.split_whitespace().nth(2)?;
    let mut parts = version.split('.').map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??))
}

fn require_git(min: (u32, u32), what: &str) -> Result<()> {
    match git_version() {
        Some(found) if found >= min => Ok(()),
        Some((a, b)) => bail!(
            "{what} needs git {}.{} or later; this is git {a}.{b}",
            min.0,
            min.1
        ),
        None => bail!(
            "could not run `git --version`; {what} needs git {}.{} or later",
            min.0,
            min.1
        ),
    }
}

/// One worktree of a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeInfo {
    pub path: PathBuf,
    pub branch: Option<String>,
}

/// Every worktree of the repository `repo` belongs to; the first is the primary one.
/// Paths are [`clean`]ed, so they compare equal to the same folder spelled any other way.
pub fn worktrees(repo: &Path) -> Result<Vec<WorktreeInfo>> {
    let listing = git(repo, &["worktree", "list", "--porcelain"])?;
    let mut out = Vec::new();
    for block in listing.split("\n\n") {
        let mut path = None;
        let mut branch = None;
        for line in block.lines() {
            if let Some(p) = line.strip_prefix("worktree ") {
                path = Some(clean(Path::new(p.trim())));
            } else if let Some(b) = line.strip_prefix("branch refs/heads/") {
                branch = Some(b.trim().to_string());
            }
        }
        if let Some(path) = path {
            out.push(WorktreeInfo { path, branch });
        }
    }
    Ok(out)
}

/// The repository's primary working tree: the checkout a person made, not a lane.
pub fn primary_worktree(repo: &Path) -> Result<PathBuf> {
    worktrees(repo)?
        .into_iter()
        .next()
        .map(|w| w.path)
        .context("git lists no worktree for this repository")
}

fn common_dir(repo: &Path) -> Result<PathBuf> {
    Ok(clean(Path::new(&git(
        repo,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?)))
}

fn git_dir_of(worktree: &Path) -> Result<PathBuf> {
    Ok(clean(Path::new(&git(
        worktree,
        &["rev-parse", "--absolute-git-dir"],
    )?)))
}

fn branch_exists(repo: &Path, branch: &str) -> bool {
    git_ok(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
    )
}

fn default_base(primary: &Path) -> Result<String> {
    for candidate in ["main", "master"] {
        if branch_exists(primary, candidate) {
            return Ok(candidate.to_string());
        }
    }
    let head = git(primary, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    if head == "HEAD" {
        bail!("cannot tell the base branch: no main, no master, and HEAD is detached; pass --base");
    }
    Ok(head)
}

fn append_line_once(path: &Path, line: &str) -> Result<bool> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(line);
    text.push('\n');
    fs::write(path, text)?;
    Ok(true)
}

/// This machine's name, as written in lane records and claims.
#[must_use]
pub fn this_machine() -> String {
    hostname::get()
        .map(|h| {
            h.to_string_lossy()
                .split('.')
                .next()
                .unwrap_or("")
                .to_lowercase()
        })
        .unwrap_or_default()
}

/// A machine name as it appears in a claim's file name: lowercase letters, digits and `-`.
#[must_use]
pub fn machine_slug(machine: &str) -> String {
    let slug: String = machine
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "unknown".into()
    } else {
        slug
    }
}

/// Environment for ONE git child process that gives it a push/fetch credential without
/// the credential ever being written: not to disk, not to a git config file, not to the
/// child's argument list (which other processes can read). Scoped to the remote's own
/// origin, so a redirect elsewhere never sees it. It appends to any `GIT_CONFIG_COUNT`
/// entries already in this process's environment instead of replacing them. Empty for a
/// remote that is not https or when there is no token. Needs git 2.31.
#[must_use]
pub fn auth_env(remote_url: &str, token: Option<&str>) -> Vec<(String, String)> {
    let existing = std::env::var("GIT_CONFIG_COUNT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    auth_env_at(existing, remote_url, token)
}

/// [`auth_env`] with the number of config entries already present given.
#[must_use]
pub fn auth_env_at(
    existing: usize,
    remote_url: &str,
    token: Option<&str>,
) -> Vec<(String, String)> {
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return Vec::new();
    };
    let Some(rest) = remote_url.strip_prefix("https://") else {
        return Vec::new();
    };
    let host = rest.split('/').next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    if host.is_empty() {
        return Vec::new();
    }
    let header = format!(
        "AUTHORIZATION: basic {}",
        base64(format!("x-access-token:{token}").as_bytes())
    );
    vec![
        ("GIT_CONFIG_COUNT".into(), (existing + 1).to_string()),
        (
            format!("GIT_CONFIG_KEY_{existing}"),
            format!("http.https://{host}/.extraheader"),
        ),
        (format!("GIT_CONFIG_VALUE_{existing}"), header),
    ]
}

/// Run a network git command (fetch, push) for `repo` with the credential in `env`, hooks
/// switched off for this one call, and nothing else changed about the environment.
fn net_git(repo: &Path, common: &Path, args: &[&str], env: &[(String, String)]) -> Result<String> {
    let nohooks = common.join("ferry-no-hooks");
    fs::create_dir_all(&nohooks)?;
    let setting = format!("core.hooksPath={}", slashes(&nohooks));
    let mut full = vec!["-c", setting.as_str()];
    full.extend_from_slice(args);
    git_env(repo, &full, env)
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------------------------------
// The lane manifest
// ---------------------------------------------------------------------------------------

/// One lane, as signed by its owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaneRecord {
    pub format: String,
    pub project_id: String,
    pub lane: String,
    pub branch: String,
    /// The branch the lane lands on.
    pub base: String,
    /// Globs of the paths only this lane may change.
    pub owns: Vec<String>,
    /// Extra shared files (on top of [`DEFAULT_SHARED`]) any lane may touch.
    #[serde(default)]
    pub shared: Vec<String>,
    /// Files whose concurrent additions are merged by union (git's `merge=union`) when this
    /// lane is rebased: only logs that are appended to, never rewritten.
    #[serde(default)]
    pub append_only: Vec<String>,
    /// The agent that owns the lane, and so who is told about a failed landing.
    pub owner: String,
    pub machine: String,
    pub created_at: DateTime<Utc>,
    /// `active` or `retired`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl LaneRecord {
    #[must_use]
    pub fn active(&self) -> bool {
        self.status == "active"
    }

    fn payload(&self) -> String {
        format!(
            "{LANE_FORMAT}\n{}\n{}\n{}\n{}\nowns:{}\nshared:{}\nappend:{}\n{}\n{}\n{}\n{}",
            self.project_id,
            self.lane,
            self.branch,
            self.base,
            self.owns.join("\u{1f}"),
            self.shared.join("\u{1f}"),
            self.append_only.join("\u{1f}"),
            self.owner,
            self.machine,
            self.created_at.to_rfc3339(),
            self.status,
        )
    }

    fn sign(&mut self, identity: &AgentIdentity) {
        let signature = identity.signing.sign(self.payload().as_bytes());
        self.signed_by = Some(identity.name().to_owned());
        self.signature = Some(hex::encode(signature.to_bytes()));
    }
}

/// The branch a lane lives on.
#[must_use]
pub fn lane_branch(lane: &str) -> String {
    format!("lane/{lane}")
}

/// Where a lane's worktree is, given the primary checkout.
#[must_use]
pub fn lane_dir(primary: &Path, lane: &str) -> PathBuf {
    primary.join(".lanes").join(lane)
}

fn lanes_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("lanes")
}

fn record_path(route: &ProjectRoute, lane: &str) -> PathBuf {
    lanes_dir(route).join(format!("{lane}.json"))
}

/// Files in `dir` that Syncthing set aside as conflicts. They are never read as records or
/// claims; callers report them.
#[must_use]
pub fn conflict_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().contains(".sync-conflict-"))
        })
        .collect()
}

/// The lanes of a project, with whatever did not verify.
#[derive(Debug, Default)]
pub struct Loaded {
    pub lanes: Vec<LaneRecord>,
    pub problems: Vec<String>,
}

/// Read and verify every lane record in the channel. A record that does not verify is
/// reported and ignored: it neither grants ownership nor blocks anyone. A Syncthing
/// conflict copy is named and ignored.
pub fn load(route: &ProjectRoute) -> Result<Loaded> {
    let mut loaded = Loaded::default();
    let dir = lanes_dir(route);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Ok(loaded);
    };
    let roster = crate::read_agent_roster(&route.communications)?;
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        if name.contains(".sync-conflict-") {
            loaded.problems.push(format!(
                "{name}: a Syncthing conflict copy of a lane record; ignored (the owner's own file stands)"
            ));
            continue;
        }
        let record: LaneRecord = match fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|b| serde_json::from_slice(&b).map_err(anyhow::Error::from))
        {
            Ok(r) => r,
            Err(e) => {
                loaded.problems.push(format!("{name}: unreadable ({e})"));
                continue;
            }
        };
        let check = check_signature(
            record.signed_by.as_ref(),
            record.signature.as_ref(),
            &record.payload(),
            &roster,
        );
        if check != SignatureCheck::Valid {
            loaded.problems.push(format!(
                "lane '{}': record is not validly signed ({check:?}); ignored",
                record.lane
            ));
            continue;
        }
        if record.project_id != route.project_id || format!("{}.json", record.lane) != name {
            loaded.problems.push(format!(
                "lane '{}': record does not belong here; ignored",
                record.lane
            ));
            continue;
        }
        loaded.lanes.push(record);
    }
    Ok(loaded)
}

/// What to create.
pub struct NewLane<'a> {
    pub lane: &'a str,
    pub owns: Vec<String>,
    pub shared: Vec<String>,
    /// Files merged by union on rebase: logs that are only ever appended to.
    pub append_only: Vec<String>,
    pub base: Option<String>,
    /// The `ferry` binary the hook should call.
    pub exe: PathBuf,
}

/// The marker a lane worktree keeps in its own git dir, so the hook and the CLI can find
/// the channel from inside it without asking anyone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneMarker {
    pub project_id: String,
    pub lane: String,
    pub attachment: PathBuf,
    pub owner: String,
}

fn marker_path(gitdir: &Path) -> PathBuf {
    gitdir.join("ferry-lane.json")
}

/// The marker of the worktree whose git dir is `gitdir`, if it is a lane.
pub fn read_marker(gitdir: &Path) -> Option<LaneMarker> {
    serde_json::from_slice(&fs::read(marker_path(gitdir)).ok()?).ok()
}

/// Where the repository's own hooks are.
enum OriginalHooks {
    /// An absolute folder (the default `<common>/hooks`, or an absolute `core.hooksPath`).
    Absolute(PathBuf),
    /// A `core.hooksPath` relative to the worktree (husky's `.husky/_`).
    Relative(String),
}

fn original_hooks(primary: &Path, common: &Path) -> Result<OriginalHooks> {
    let configured = git(primary, &["config", "--get", "core.hooksPath"])
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let Some(path) = configured else {
        return Ok(OriginalHooks::Absolute(common.join("hooks")));
    };
    let path = path.replace('\\', "/");
    let absolute =
        path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') || path.starts_with("~/");
    if absolute {
        return Ok(OriginalHooks::Absolute(PathBuf::from(path)));
    }
    if path.contains(['"', '$', '`', '\'', '\n']) {
        bail!(
            "core.hooksPath ('{path}') has characters a hook wrapper cannot carry; set a plainer path"
        );
    }
    Ok(OriginalHooks::Relative(path))
}

fn sq(text: &str) -> String {
    text.replace('\'', "'\\''")
}

fn hook_script(name: &str, exe: &Path, original: &OriginalHooks) -> String {
    let mut script = String::from(
        "#!/bin/sh\n# Installed by `ferry lanes new`; rewritten each time it runs. Chains to the\n# repository's own hook of the same name.\n",
    );
    if name == "pre-commit" {
        script.push_str(&format!(
            "# Refuses staged paths another lane owns. Override (logged): FERRY_LANE_OVERRIDE=\"why\" git commit ...\n\
             FERRY='{}'\n\
             [ -x \"$FERRY\" ] || FERRY=ferry\n\
             \"$FERRY\" lanes check || exit $?\n",
            sq(&slashes(exe))
        ));
    }
    match original {
        OriginalHooks::Absolute(dir) => {
            script.push_str(&format!("ORIG='{}'\n", sq(&slashes(dir))));
        }
        OriginalHooks::Relative(rel) => {
            script.push_str(&format!(
                "ORIG=\"$(git rev-parse --show-toplevel)/{rel}\"\n"
            ));
        }
    }
    script.push_str(&format!(
        "if [ -x \"$ORIG/{name}\" ]; then exec \"$ORIG/{name}\" \"$@\"; fi\n\
         if [ -f \"$ORIG/{name}\" ]; then exec sh \"$ORIG/{name}\" \"$@\"; fi\n\
         exit 0\n"
    ));
    script
}

fn install_hooks(
    primary: &Path,
    lane_dir: &Path,
    exe: &Path,
    marker: &LaneMarker,
    append_only: &[String],
) -> Result<()> {
    git(lane_dir, &["config", "extensions.worktreeConfig", "true"])?;
    let common = common_dir(primary)?;
    let original = original_hooks(primary, &common)?;
    let gitdir = git_dir_of(lane_dir)?;
    let hooks = gitdir.join("ferry-hooks");
    if hooks.exists() {
        fs::remove_dir_all(&hooks)?;
    }
    fs::create_dir_all(&hooks)?;
    let listed = match &original {
        OriginalHooks::Absolute(dir) => dir.clone(),
        OriginalHooks::Relative(rel) => lane_dir.join(rel),
    };
    let mut names: BTreeSet<String> = CLIENT_HOOKS.iter().map(|s| (*s).to_owned()).collect();
    for entry in fs::read_dir(&listed).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().is_file() && !name.contains('.') {
            names.insert(name);
        }
    }
    for name in &names {
        let script = hooks.join(name);
        fs::write(&script, hook_script(name, exe, &original))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
        }
    }
    git(
        lane_dir,
        &["config", "--worktree", "core.hooksPath", &slashes(&hooks)],
    )?;
    // Union merge for the declared append-only logs, in this worktree only.
    let attributes = gitdir.join("ferry-attributes");
    fs::write(&attributes, attributes_text(append_only))?;
    git(
        lane_dir,
        &[
            "config",
            "--worktree",
            "core.attributesFile",
            &slashes(&attributes),
        ],
    )?;
    fs::write(marker_path(&gitdir), serde_json::to_vec_pretty(marker)?)?;
    Ok(())
}

fn attributes_text(append_only: &[String]) -> String {
    append_only
        .iter()
        .filter(|g| !g.trim().is_empty() && !g.contains(char::is_whitespace))
        .map(|g| format!("{g} merge=union\n"))
        .collect()
}

/// Make a lane: a worktree on its own branch, the hooks, the exclusion, and the signed
/// record. Safe to run again for the same lane: it repairs the hooks and returns the lane.
pub fn new_lane(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    spec: NewLane<'_>,
) -> Result<(LaneRecord, PathBuf)> {
    require_git(MIN_GIT, "lanes")?;
    let lane = spec.lane;
    if !is_safe_component(lane) || lane.starts_with('.') || lane.len() > 40 {
        bail!(
            "a lane name is letters, digits, '-', '_' and '.' (not leading), at most 40: '{lane}'"
        );
    }
    if spec.owns.is_empty() {
        bail!("a lane owns something: pass --owns <glob> at least once");
    }
    let primary = primary_worktree(&route.workspace)
        .with_context(|| format!("{} is not a git repository", route.workspace.display()))?;
    let dir = lane_dir(&primary, lane);
    let loaded = load(route)?;
    let existing = loaded
        .lanes
        .iter()
        .find(|r| r.lane == lane && r.active())
        .cloned();
    for other in loaded.lanes.iter().filter(|r| r.active() && r.lane != lane) {
        for mine in &spec.owns {
            for theirs in &other.owns {
                if normal(mine) == normal(theirs) {
                    bail!("lane '{}' already owns '{theirs}'", other.lane);
                }
            }
        }
    }
    let base = match (&existing, spec.base) {
        (Some(r), _) => r.base.clone(),
        (None, Some(b)) => b,
        (None, None) => default_base(&primary)?,
    };
    let branch = lane_branch(lane);
    if let Some(elsewhere) = worktrees(&primary)?
        .into_iter()
        .find(|w| w.branch.as_deref() == Some(branch.as_str()) && !same_path(&w.path, &dir))
    {
        bail!(
            "branch {branch} is already checked out at {}; move it into place with \
             `git worktree move {} {}` and run this again",
            elsewhere.path.display(),
            elsewhere.path.display(),
            dir.display()
        );
    }
    if dir.exists() {
        if existing.is_none() || !git_ok(&dir, &["rev-parse", "--is-inside-work-tree"]) {
            bail!(
                "{} already exists and is not an active lane of this project",
                dir.display()
            );
        }
    } else {
        fs::create_dir_all(dir.parent().context("lane dir has no parent")?)?;
        let dir_str = dir.to_str().context("lane path is not valid UTF-8")?;
        if branch_exists(&primary, &branch) {
            git(&primary, &["worktree", "add", dir_str, &branch])?;
        } else {
            git(
                &primary,
                &["worktree", "add", "-b", &branch, dir_str, &base],
            )?;
        }
    }
    let common = common_dir(&primary)?;
    append_line_once(&common.join("info").join("exclude"), "/.lanes/")?;
    let append_only = match &existing {
        Some(r) => r.append_only.clone(),
        None => spec.append_only.clone(),
    };
    let marker = LaneMarker {
        project_id: route.project_id.clone(),
        lane: lane.to_owned(),
        attachment: route.attachment.clone(),
        owner: identity.name().to_owned(),
    };
    install_hooks(&primary, &dir, &spec.exe, &marker, &append_only)?;

    let record = match existing {
        Some(r) => r,
        None => {
            let mut record = LaneRecord {
                format: LANE_FORMAT.into(),
                project_id: route.project_id.clone(),
                lane: lane.to_owned(),
                branch,
                base,
                owns: spec.owns,
                shared: spec.shared,
                append_only,
                owner: identity.name().to_owned(),
                machine: this_machine(),
                created_at: Utc::now(),
                status: "active".into(),
                signed_by: None,
                signature: None,
            };
            record.sign(identity);
            crate::atomic_json(&record_path(route, lane), &record)?;
            record
        }
    };
    Ok((record, dir))
}

/// Retire a lane: remove its worktree and branch and sign the record as retired, which
/// frees its globs. It never loses work: it refuses a worktree with any uncommitted or
/// untracked file, a live session, commits not on the base, or a count it cannot make,
/// unless `force`; and even with `force` the branch tip is first saved under
/// `refs/ferry/retired/<lane>/`.
pub fn retire_lane(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    lane: &str,
    force: bool,
) -> Result<String> {
    let loaded = load(route)?;
    let mut record = loaded
        .lanes
        .iter()
        .find(|r| r.lane == lane && r.active())
        .cloned()
        .with_context(|| format!("no active lane '{lane}'"))?;
    let primary = primary_worktree(&route.workspace)?;
    let dir = lane_dir(&primary, lane);
    let branch = record.branch.clone();
    let has_branch = branch_exists(&primary, &branch);

    if dir.is_dir() && !force {
        let status = git(&dir, &["status", "--porcelain"]).with_context(|| {
            format!("could not read the state of lane '{lane}'; not retiring it")
        })?;
        if !status.is_empty() {
            bail!(
                "lane '{lane}' has uncommitted or untracked files; commit or move them, or pass --force"
            );
        }
        let live = git_dir_of(&dir)
            .map(|g| live_sessions(&g, Utc::now()))
            .unwrap_or_default();
        if !live.is_empty() {
            bail!(
                "lane '{lane}' has {} live session(s) registered ({}); end them (ferry lanes leave) or pass --force",
                live.len(),
                live.iter()
                    .map(|m| format!("{}:{}", m.agent, m.session))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let unlanded: Option<u32> = if has_branch {
        git(
            &primary,
            &["rev-list", "--count", &format!("{}..{branch}", record.base)],
        )
        .ok()
        .and_then(|n| n.parse().ok())
    } else {
        Some(0)
    };
    match unlanded {
        None if !force => bail!(
            "cannot tell how many commits of lane '{lane}' are not on {}; not retiring it (pass --force to retire anyway)",
            record.base
        ),
        Some(n) if n > 0 && !force => bail!(
            "lane '{lane}' has {n} commit(s) not on {}; land them (ferry lanes land {lane}) or pass --force",
            record.base
        ),
        _ => {}
    }
    if force && has_branch {
        // Even a forced retire leaves a way back.
        git(
            &primary,
            &[
                "update-ref",
                &format!("refs/ferry/retired/{lane}/{}", Utc::now().timestamp()),
                &format!("refs/heads/{branch}"),
            ],
        )?;
    }
    if dir.is_dir() {
        let dir_str = dir.to_str().context("lane path is not valid UTF-8")?;
        if force {
            git(&primary, &["worktree", "remove", "--force", dir_str])?;
        } else {
            git(&primary, &["worktree", "remove", dir_str])?;
        }
    }
    let _ = git(&primary, &["worktree", "prune"]);
    if has_branch {
        git(&primary, &["branch", "-D", &branch])?;
    }
    record.status = "retired".into();
    record.sign(identity);
    crate::atomic_json(&record_path(route, lane), &record)?;
    Ok(branch)
}

// ---------------------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------------------

/// What the ownership check found in a set of staged paths.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CheckReport {
    pub lane: String,
    /// Paths this lane owns.
    pub owned: Vec<String>,
    /// (path, lane that owns it): the commit is refused over these.
    pub refused: Vec<(String, String)>,
    /// Paths nobody owns: allowed, reported.
    pub unowned: Vec<String>,
    /// Shared files: allowed, reported.
    pub shared: Vec<String>,
}

/// Sort `paths` into owned, refused, unowned and shared from the point of view of `me`.
#[must_use]
pub fn classify(lanes: &[LaneRecord], me: &str, paths: &[String]) -> CheckReport {
    let mut report = CheckReport {
        lane: me.to_owned(),
        ..CheckReport::default()
    };
    let mut shared_globs: Vec<String> = DEFAULT_SHARED.iter().map(|s| (*s).to_owned()).collect();
    for lane in lanes.iter().filter(|r| r.active()) {
        shared_globs.extend(lane.shared.iter().cloned());
    }
    let mine = lanes.iter().find(|r| r.lane == me && r.active());
    for path in paths {
        if any_match(&shared_globs, path) {
            report.shared.push(path.clone());
        } else if mine.is_some_and(|m| any_match(&m.owns, path)) {
            report.owned.push(path.clone());
        } else if let Some(other) = lanes
            .iter()
            .find(|r| r.active() && r.lane != me && any_match(&r.owns, path))
        {
            report.refused.push((path.clone(), other.lane.clone()));
        } else {
            report.unowned.push(path.clone());
        }
    }
    report
}

fn override_line(
    project_id: &str,
    identity: Option<&AgentIdentity>,
    lane: &str,
    reason: &str,
    paths: &[String],
) -> serde_json::Value {
    let at = Utc::now();
    let payload = format!(
        "ferryman-lane-override-v1\n{project_id}\n{lane}\n{}\n{reason}\n{}",
        at.to_rfc3339(),
        paths.join("\u{1f}")
    );
    let mut line = json!({
        "project_id": project_id, "lane": lane, "at": at.to_rfc3339(),
        "reason": reason, "paths": paths,
    });
    if let Some(identity) = identity {
        line["signed_by"] = json!(identity.name());
        line["signature"] = json!(hex::encode(
            identity.signing.sign(payload.as_bytes()).to_bytes()
        ));
    }
    line
}

fn append_jsonl(path: &Path, line: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Append a signed line to the override log for `lane`. The channel keeps the record of
/// every time somebody went around an ownership boundary on purpose.
pub fn log_override(
    route: &ProjectRoute,
    identity: Option<&AgentIdentity>,
    lane: &str,
    reason: &str,
    paths: &[String],
) -> Result<()> {
    let line = override_line(&route.project_id, identity, lane, reason, paths);
    append_jsonl(
        &lanes_dir(route)
            .join("overrides")
            .join(format!("{lane}.jsonl")),
        &line,
    )
}

/// What `ferry lanes check` (the pre-commit hook) decided.
pub struct CheckOutcome {
    pub report: CheckReport,
    pub overridden: Option<String>,
    pub problems: Vec<String>,
    /// Set when the channel could not be read: what the check used instead.
    pub offline: Option<String>,
}

/// The pre-commit check, run from inside a lane worktree.
///
/// The manifest is read from the channel. Each successful read is cached in the worktree's
/// git dir; when the channel is unreachable the cached manifest decides, so the paths known
/// to be owned stay protected (fail closed). With no cache there is nothing to check
/// against: the commit is allowed, with a warning, and the gap is logged in the worktree.
pub fn check_staged(
    cwd: &Path,
    override_reason: Option<&str>,
    identity_for: impl FnOnce(&ProjectRoute, &str) -> Option<AgentIdentity>,
) -> Result<Option<CheckOutcome>> {
    let gitdir = git_dir_of(cwd)?;
    let Some(marker) = read_marker(&gitdir) else {
        return Ok(None); // not a lane: nothing to enforce
    };
    let cache = gitdir.join("ferry-lanes-cache.json");
    let reachable = crate::load_route(&marker.attachment)
        .ok()
        .filter(|route| route.communications.is_dir())
        .and_then(|route| load(&route).ok().map(|loaded| (route, loaded)));
    let (route, lanes, mut problems, offline) = match reachable {
        Some((route, loaded)) => {
            if let Ok(bytes) = serde_json::to_vec(&loaded.lanes) {
                let _ = fs::write(&cache, bytes);
            }
            (Some(route), loaded.lanes, loaded.problems, None)
        }
        None => match fs::read(&cache)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<LaneRecord>>(&b).ok())
        {
            Some(lanes) => (
                None,
                lanes,
                Vec::new(),
                Some("the channel is not reachable; checking against the manifest cached by the last check".to_owned()),
            ),
            None => {
                let note = "the channel is not reachable and no manifest is cached yet; nothing can be checked, so this commit is allowed".to_owned();
                let _ = append_jsonl(
                    &gitdir.join("ferry-lanes-warnings.jsonl"),
                    &json!({ "at": Utc::now().to_rfc3339(), "lane": marker.lane, "note": note }),
                );
                (None, Vec::new(), Vec::new(), Some(note))
            }
        },
    };
    let raw = git(
        cwd,
        &["diff", "--cached", "--name-only", "-z", "--no-renames"],
    )?;
    let staged = nul_list(&raw);
    let report = classify(&lanes, &marker.lane, &staged);
    if offline.is_none() && !lanes.iter().any(|r| r.lane == marker.lane && r.active()) {
        problems.push(format!(
            "no active record for lane '{}' in the channel (not synced yet, or retired); nothing is owned",
            marker.lane
        ));
    }
    let mut overridden = None;
    if !report.refused.is_empty()
        && let Some(reason) = override_reason.filter(|r| !r.trim().is_empty())
    {
        let paths: Vec<String> = report.refused.iter().map(|(p, _)| p.clone()).collect();
        match &route {
            Some(route) => {
                let identity = identity_for(route, &marker.owner);
                log_override(route, identity.as_ref(), &marker.lane, reason, &paths)?;
            }
            None => append_jsonl(
                &gitdir.join("ferry-lane-overrides.jsonl"),
                &override_line(&marker.project_id, None, &marker.lane, reason, &paths),
            )?,
        }
        overridden = Some(reason.to_owned());
    }
    let session = session_id_for(&marker.owner, cwd);
    let _ = register_session(&gitdir, &session, &marker.owner, None);
    Ok(Some(CheckOutcome {
        report,
        overridden,
        problems,
        offline,
    }))
}

// ---------------------------------------------------------------------------------------
// Sessions (who is working in a worktree)
// ---------------------------------------------------------------------------------------

/// A running agent session registered in a worktree's git dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMark {
    pub session: String,
    pub agent: String,
    #[serde(default)]
    pub pid: Option<u32>,
    pub started: DateTime<Utc>,
    pub heartbeat: DateTime<Utc>,
}

/// The session id the environment names, if any.
#[must_use]
pub fn current_session_id() -> Option<String> {
    [
        "FERRY_SESSION",
        "CLAUDE_SESSION_ID",
        "CLAUDE_CODE_SESSION_ID",
    ]
    .iter()
    .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

/// A session id that is the same every time the same agent works in the same worktree on
/// the same machine, so a commit refreshes the registered session instead of adding a
/// phantom second one.
#[must_use]
pub fn stable_session_id(agent: &str, worktree: &Path) -> String {
    let digest =
        Sha256::digest(format!("{agent}\n{}\n{}", this_machine(), path_key(worktree)).as_bytes());
    format!("w-{}", hex::encode(&digest[..6]))
}

/// The environment's session id, else the stable one for `agent` in `worktree`.
#[must_use]
pub fn session_id_for(agent: &str, worktree: &Path) -> String {
    current_session_id().unwrap_or_else(|| stable_session_id(agent, worktree))
}

fn session_file(gitdir: &Path, session: &str) -> PathBuf {
    let safe: String = session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    gitdir.join("ferry-sessions").join(format!("{safe}.json"))
}

/// Register (or refresh) a session in the worktree whose git dir is `gitdir`.
pub fn register_session(gitdir: &Path, session: &str, agent: &str, pid: Option<u32>) -> Result<()> {
    let path = session_file(gitdir, session);
    let now = Utc::now();
    let previous = fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<SessionMark>(&b).ok());
    let started = previous.as_ref().map_or(now, |m| m.started);
    let pid = pid.or_else(|| previous.and_then(|m| m.pid));
    let mark = SessionMark {
        session: session.to_owned(),
        agent: agent.to_owned(),
        pid,
        started,
        heartbeat: now,
    };
    crate::atomic_json(&path, &mark)
}

/// Forget a session (it ended).
pub fn release_session(gitdir: &Path, session: &str) {
    let _ = fs::remove_file(session_file(gitdir, session));
}

/// Whether a process with this id is running. Unknown counts as running: a session is only
/// dropped on evidence.
#[must_use]
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_or(true, |s| s.success())
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map_or(true, |o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .any(|w| w == pid.to_string())
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

/// The sessions heard from within [`SESSION_LIVE_SECONDS`] whose process (when one was
/// recorded) is still running, newest first.
#[must_use]
pub fn live_sessions(gitdir: &Path, now: DateTime<Utc>) -> Vec<SessionMark> {
    let mut out: Vec<SessionMark> = fs::read_dir(gitdir.join("ferry-sessions"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
        .filter(|m: &SessionMark| now - m.heartbeat < Duration::seconds(SESSION_LIVE_SECONDS))
        .filter(|m| m.pid.is_none_or(pid_alive))
        .collect();
    out.sort_by_key(|m| std::cmp::Reverse(m.heartbeat));
    out
}

// ---------------------------------------------------------------------------------------
// Listing and doctor
// ---------------------------------------------------------------------------------------

/// One lane for display.
#[derive(Debug, Clone, Serialize)]
pub struct LaneLine {
    pub lane: String,
    pub owner: String,
    pub machine: String,
    pub status: String,
    pub branch: String,
    pub base: String,
    pub owns: Vec<String>,
    pub path: Option<PathBuf>,
    pub ahead: Option<u32>,
    pub behind: Option<u32>,
    pub dirty: Option<bool>,
    pub live_sessions: usize,
}

/// The lanes of a project with what this machine can see of each.
pub fn summary(route: &ProjectRoute, include_retired: bool) -> Result<Vec<LaneLine>> {
    let loaded = load(route)?;
    let primary = primary_worktree(&route.workspace).ok();
    let mut lines = Vec::new();
    for r in loaded
        .lanes
        .iter()
        .filter(|r| include_retired || r.active())
    {
        let dir = primary
            .as_ref()
            .map(|p| lane_dir(p, &r.lane))
            .filter(|d| d.is_dir());
        let count = |range: String| {
            primary
                .as_ref()
                .and_then(|p| git(p, &["rev-list", "--count", &range]).ok())
                .and_then(|n| n.parse::<u32>().ok())
        };
        let (ahead, behind) = if dir.is_some() {
            (
                count(format!("{}..{}", r.base, r.branch)),
                count(format!("{}..{}", r.branch, r.base)),
            )
        } else {
            (None, None)
        };
        let dirty = dir
            .as_ref()
            .and_then(|d| git(d, &["status", "--porcelain"]).ok())
            .map(|s| !s.is_empty());
        let live = dir
            .as_ref()
            .and_then(|d| git_dir_of(d).ok())
            .map_or(0, |g| live_sessions(&g, Utc::now()).len());
        lines.push(LaneLine {
            lane: r.lane.clone(),
            owner: r.owner.clone(),
            machine: r.machine.clone(),
            status: r.status.clone(),
            branch: r.branch.clone(),
            base: r.base.clone(),
            owns: r.owns.clone(),
            path: dir,
            ahead,
            behind,
            dirty,
            live_sessions: live,
        });
    }
    Ok(lines)
}

/// One thing `ferry doctor` has to say about lanes.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// `warn` or `note`.
    pub level: &'static str,
    pub what: String,
}

/// Lane checks for `ferry doctor`: two agents in one working tree, stale lanes, lanes far
/// behind their base, and records that do not verify.
#[must_use]
pub fn doctor(route: &ProjectRoute, stale_days: i64, behind_max: u32) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(wts) = worktrees(&route.workspace) else {
        return out;
    };
    let now = Utc::now();
    for w in &wts {
        let Ok(gitdir) = git_dir_of(&w.path) else {
            continue;
        };
        let live = live_sessions(&gitdir, now);
        let mut ids: Vec<&str> = live.iter().map(|m| m.session.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() >= 2 {
            out.push(Finding {
                level: "warn",
                what: format!(
                    "{} agents share the working tree {} ({}); they share one index and one HEAD. \
                     Give each its own lane: ferry lanes new {} <lane> --owns <glob>",
                    ids.len(),
                    w.path.display(),
                    live.iter()
                        .map(|m| format!("{}:{}", m.agent, m.session))
                        .collect::<Vec<_>>()
                        .join(", "),
                    route.project_id
                ),
            });
        }
    }
    let Ok(loaded) = load(route) else { return out };
    for problem in &loaded.problems {
        out.push(Finding {
            level: "warn",
            what: problem.clone(),
        });
    }
    let Some(primary) = wts.first().map(|w| w.path.clone()) else {
        return out;
    };
    let me = this_machine();
    for r in loaded.lanes.iter().filter(|r| r.active()) {
        let dir = lane_dir(&primary, &r.lane);
        if !dir.is_dir() {
            if r.machine == me {
                out.push(Finding {
                    level: "warn",
                    what: format!(
                        "lane '{}' is recorded for this machine but has no worktree at {}",
                        r.lane,
                        dir.display()
                    ),
                });
            }
            continue;
        }
        let ahead = git(
            &primary,
            &["rev-list", "--count", &format!("{}..{}", r.base, r.branch)],
        )
        .ok()
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
        let behind = git(
            &primary,
            &["rev-list", "--count", &format!("{}..{}", r.branch, r.base)],
        )
        .ok()
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
        let mut last = r.created_at;
        if ahead > 0
            && let Some(t) = git(&primary, &["log", "-1", "--format=%ct", &r.branch])
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .and_then(|s| DateTime::from_timestamp(s, 0))
        {
            last = last.max(t);
        }
        if let Ok(gitdir) = git_dir_of(&dir)
            && let Ok(entries) = fs::read_dir(gitdir.join("ferry-sessions"))
        {
            for e in entries.flatten() {
                if let Some(m) = fs::read(e.path())
                    .ok()
                    .and_then(|b| serde_json::from_slice::<SessionMark>(&b).ok())
                {
                    last = last.max(m.heartbeat);
                }
            }
        }
        let idle = (now - last).num_days();
        if idle >= stale_days {
            out.push(Finding {
                level: "warn",
                what: format!(
                    "lane '{}' (owner {}) is stale: no commit or session activity for {idle} day(s). \
                     Land it (ferry lanes land {0}) or retire it (ferry lanes retire {0})",
                    r.lane, r.owner
                ),
            });
        }
        if behind >= behind_max {
            out.push(Finding {
                level: "warn",
                what: format!(
                    "lane '{}' is {behind} commit(s) behind {}; landing will rebase over them",
                    r.lane, r.base
                ),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Landing
// ---------------------------------------------------------------------------------------

/// A signed claim to be the one landing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandingClaim {
    pub project_id: String,
    pub lane: String,
    pub agent: String,
    pub machine: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl LandingClaim {
    fn payload(&self) -> String {
        format!(
            "ferryman-landing-claim-v1\n{}\n{}\n{}\n{}\n{}\n{}",
            self.project_id,
            self.lane,
            self.agent,
            self.machine,
            self.acquired_at.to_rfc3339(),
            self.expires_at.to_rfc3339()
        )
    }

    /// Mint a signed claim. Public so a test (or a tool) can stand in for another machine.
    #[must_use]
    pub fn signed(
        route: &ProjectRoute,
        identity: &AgentIdentity,
        lane: &str,
        machine: &str,
        acquired_at: DateTime<Utc>,
    ) -> Self {
        let mut claim = Self {
            project_id: route.project_id.clone(),
            lane: lane.to_owned(),
            agent: identity.name().to_owned(),
            machine: machine.to_owned(),
            acquired_at,
            expires_at: acquired_at + Duration::minutes(LANDING_TTL_MINUTES),
            signed_by: None,
            signature: None,
        };
        let signature = identity.signing.sign(claim.payload().as_bytes());
        claim.signed_by = Some(identity.name().to_owned());
        claim.signature = Some(hex::encode(signature.to_bytes()));
        claim
    }

    /// Publish this claim in the channel (what the holder does on acquiring).
    pub fn publish(&self, route: &ProjectRoute) -> Result<()> {
        crate::atomic_json(&claim_path(route, &self.agent, &self.machine), self)
    }
}

fn claim_path(route: &ProjectRoute, agent: &str, machine: &str) -> PathBuf {
    lanes_dir(route)
        .join("landing")
        .join(format!("{agent}.{}.json", machine_slug(machine)))
}

/// Unexpired, validly signed landing claims by anyone other than `(agent, machine)`.
fn other_claims(route: &ProjectRoute, agent: &str, machine: &str) -> Vec<LandingClaim> {
    let Ok(roster) = crate::read_agent_roster(&route.communications) else {
        return Vec::new();
    };
    let now = Utc::now();
    let dir = lanes_dir(route).join("landing");
    let me = machine_slug(machine);
    let mut out: Vec<LandingClaim> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            // Only a claim in the file its signer's name and machine give it counts; a
            // Syncthing conflict copy or a misfiled one is not a claim.
            e.file_name().to_string_lossy().ends_with(".json")
                && !e.file_name().to_string_lossy().contains(".sync-conflict-")
        })
        .filter_map(|e| {
            let claim = serde_json::from_slice::<LandingClaim>(&fs::read(e.path()).ok()?).ok()?;
            let expected = claim_path(route, &claim.agent, &claim.machine);
            (expected.file_name() == Some(&e.file_name())).then_some(claim)
        })
        .filter(|c| {
            !(c.agent == agent && machine_slug(&c.machine) == me)
                && c.project_id == route.project_id
                && c.expires_at > now
                && check_signature(
                    c.signed_by.as_ref(),
                    c.signature.as_ref(),
                    &c.payload(),
                    &roster,
                ) == SignatureCheck::Valid
        })
        .collect();
    out.sort_by(|a, b| {
        (a.acquired_at, &a.agent, &a.machine).cmp(&(b.acquired_at, &b.agent, &b.machine))
    });
    out
}

#[derive(Debug)]
struct LandingGuard {
    _file: fs::File,
    claim: PathBuf,
}

impl Drop for LandingGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.claim);
    }
}

fn acquire_landing(
    route: &ProjectRoute,
    common: &Path,
    identity: &AgentIdentity,
    lane: &str,
    wait: StdDuration,
    settle: StdDuration,
) -> Result<LandingGuard> {
    let deadline = Instant::now() + wait;
    let machine = this_machine();
    let mine_path = claim_path(route, identity.name(), &machine);
    loop {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(common.join("ferry-landing.lock"))?;
        if file.try_lock_exclusive().is_ok() {
            let mine = LandingClaim::signed(route, identity, lane, &machine, Utc::now());
            mine.publish(route)?;
            if !settle.is_zero() {
                std::thread::sleep(settle);
            }
            // The earliest unexpired claim wins; a later one steps aside.
            let earlier = other_claims(route, identity.name(), &machine)
                .into_iter()
                .find(|c| {
                    (c.acquired_at, c.agent.as_str(), c.machine.as_str())
                        < (mine.acquired_at, mine.agent.as_str(), mine.machine.as_str())
                });
            match earlier {
                None => {
                    return Ok(LandingGuard {
                        _file: file,
                        claim: mine_path,
                    });
                }
                Some(holder) => {
                    // Only our own claim file, named for our agent and machine.
                    let _ = fs::remove_file(&mine_path);
                    drop(file);
                    if Instant::now() >= deadline {
                        bail!(
                            "{} on {} is landing lane '{}' (since {}); try again in a moment, or pass --wait",
                            holder.agent,
                            holder.machine,
                            holder.lane,
                            holder.acquired_at
                        );
                    }
                }
            }
        } else if Instant::now() >= deadline {
            bail!(
                "another landing is running on this machine; try again in a moment, or pass --wait"
            );
        }
        std::thread::sleep(StdDuration::from_millis(150));
    }
}

/// How to land.
#[derive(Debug, Clone)]
pub struct LandOptions {
    pub remote: String,
    /// Fetch the remote first and fast-forward the base from it.
    pub fetch: bool,
    /// Push the base afterwards.
    pub push: bool,
    /// Land even if the lane touched paths another lane owns (logged).
    pub allow_foreign: Option<String>,
    pub wait_secs: u64,
    pub settle_ms: u64,
    /// A push/fetch credential, held in memory for the git child only.
    pub token: Option<String>,
}

impl Default for LandOptions {
    fn default() -> Self {
        Self {
            remote: "origin".into(),
            fetch: false,
            push: false,
            allow_foreign: None,
            wait_secs: 60,
            settle_ms: 0,
            token: None,
        }
    }
}

/// How a landing ended.
#[derive(Debug)]
pub enum LandOutcome {
    Landed {
        base: String,
        commits: u32,
        old_tip: String,
        new_tip: String,
        pushed: bool,
        push_note: Option<String>,
        /// Set when the base moved but the lane itself could not be moved onto it (the
        /// lane changed in the meantime); the lane keeps its own files and old tip.
        lane_note: Option<String>,
    },
    NothingToLand,
    /// The rebase hit conflicts. The lane was not touched.
    Conflict {
        files: Vec<String>,
        notified: bool,
    },
    /// Something has to change first; nothing was touched.
    Refused(String),
}

fn notify(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    to: &str,
    body: serde_json::Value,
) -> bool {
    let mut message = crate::Message::new(
        route.project_id.clone(),
        identity.name(),
        to,
        "text/plain",
        body,
        false,
        None,
    );
    identity.sign(&mut message);
    crate::persist_message(&crate::delivery_path(route, &message), &message).is_ok()
}

fn advance_base(primary: &Path, base: &str, old: &str, new: &str) -> Result<()> {
    let wts = worktrees(primary)?;
    if let Some(w) = wts.iter().find(|w| w.branch.as_deref() == Some(base)) {
        if git(&w.path, &["rev-parse", "HEAD"])? != old {
            bail!("{base} moved while landing; run the landing again");
        }
        if !git(&w.path, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
            bail!(
                "the {base} checkout at {} has uncommitted changes, and landing would move files under them; \
                 commit or stash there first",
                w.path.display()
            );
        }
        git(&w.path, &["merge", "--ff-only", new])?;
    } else {
        git(
            primary,
            &["update-ref", &format!("refs/heads/{base}"), new, old],
        )?;
    }
    Ok(())
}

/// Whether the lane is still exactly as the landing found it: same tip, no uncommitted
/// tracked change, and no untracked file in the way of what the landing brings. `None` when
/// it is; otherwise what changed.
fn lane_changed(
    dir: &Path,
    branch: &str,
    expected_tip: &str,
    new_tip: &str,
) -> Result<Option<String>> {
    if git(dir, &["rev-parse", branch])? != expected_tip {
        return Ok(Some("the lane's branch moved".into()));
    }
    if !git(dir, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
        return Ok(Some("the lane has uncommitted changes".into()));
    }
    let untracked: BTreeSet<String> = nul_list(&git(
        dir,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?)
    .into_iter()
    .collect();
    let touched = nul_list(&git(
        dir,
        &[
            "diff",
            "-z",
            "--no-renames",
            "--name-only",
            expected_tip,
            new_tip,
        ],
    )?);
    if let Some(path) = touched.iter().find(|p| untracked.contains(*p)) {
        return Ok(Some(format!("an untracked file, {path}, is in the way")));
    }
    Ok(None)
}

/// Land a lane: rebase it onto its base and fast-forward the base, one landing at a time.
///
/// The rebase happens in a scratch worktree, so the lane's own files never pass through a
/// half-rebased state, and on a conflict the lane is exactly as it was. Just before the base
/// moves the lane is checked again (tip, uncommitted changes, files in the way); if anything
/// changed, nothing is touched. The lane's pre-landing tip is always kept under
/// `refs/ferry/landed/<lane>/`.
pub fn land(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    lane: &str,
    opts: &LandOptions,
) -> Result<LandOutcome> {
    let loaded = load(route)?;
    let rec = loaded
        .lanes
        .iter()
        .find(|r| r.lane == lane && r.active())
        .cloned()
        .with_context(|| format!("no active lane '{lane}' in this project"))?;
    let primary = primary_worktree(&route.workspace)?;
    let dir = lane_dir(&primary, lane);
    if !dir.is_dir() {
        return Ok(LandOutcome::Refused(format!(
            "lane '{lane}' has no worktree on this machine ({}); land it where it lives ({})",
            dir.display(),
            rec.machine
        )));
    }
    if !git(&dir, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
        return Ok(LandOutcome::Refused(format!(
            "lane '{lane}' has uncommitted changes; commit them first (landing moves the lane's files)"
        )));
    }
    let base = rec.base.clone();
    let branch = rec.branch.clone();
    let remote_url = git(&primary, &["remote", "get-url", &opts.remote]).ok();
    let env = remote_url
        .as_deref()
        .map(|u| auth_env(u, opts.token.as_deref()))
        .unwrap_or_default();
    if !env.is_empty() {
        require_git((2, 31), "using a sealed push token")?;
    }

    let common = common_dir(&primary)?;
    let _guard = acquire_landing(
        route,
        &common,
        identity,
        lane,
        StdDuration::from_secs(opts.wait_secs),
        StdDuration::from_millis(opts.settle_ms),
    )?;

    let fetched = if opts.fetch && remote_url.is_some() {
        match net_git(&primary, &common, &["fetch", &opts.remote, &base], &env) {
            Ok(_) => true,
            Err(e) => {
                eprintln!(
                    "ferry lanes: note: could not fetch {}/{base}; landing on the local {base} ({e:#})",
                    opts.remote
                );
                false
            }
        }
    } else {
        false
    };
    if fetched {
        let remote_ref = format!("refs/remotes/{}/{base}", opts.remote);
        if git_ok(&primary, &["rev-parse", "--verify", "--quiet", &remote_ref]) {
            let local = git(&primary, &["rev-parse", &format!("refs/heads/{base}")])?;
            let remote = git(&primary, &["rev-parse", &remote_ref])?;
            if local != remote {
                if git_ok(&primary, &["merge-base", "--is-ancestor", &local, &remote]) {
                    advance_base(&primary, &base, &local, &remote)?;
                } else if !git_ok(&primary, &["merge-base", "--is-ancestor", &remote, &local]) {
                    return Ok(LandOutcome::Refused(format!(
                        "local {base} and {}/{base} have diverged; reconcile them first",
                        opts.remote
                    )));
                }
            }
        }
    }

    let old_tip = git(&primary, &["rev-parse", &branch])?;
    let base_tip = git(&primary, &["rev-parse", &format!("refs/heads/{base}")])?;
    let merge_base = git(&primary, &["merge-base", &base, &branch])?;
    // The same listing the hook reads: NUL-separated, no rename detection, so a path moved
    // out of another lane's folder counts as a change to it and non-ASCII names are not quoted.
    let changed = nul_list(&git(
        &primary,
        &[
            "diff",
            "-z",
            "--no-renames",
            "--name-only",
            &merge_base,
            &branch,
        ],
    )?);
    let report = classify(&loaded.lanes, lane, &changed);
    if !report.refused.is_empty() {
        let list = report
            .refused
            .iter()
            .map(|(p, o)| format!("{p} (lane {o})"))
            .collect::<Vec<_>>()
            .join(", ");
        match &opts.allow_foreign {
            Some(reason) => {
                let paths: Vec<String> = report.refused.iter().map(|(p, _)| p.clone()).collect();
                log_override(route, Some(identity), lane, reason, &paths)?;
            }
            None => {
                return Ok(LandOutcome::Refused(format!(
                    "lane '{lane}' changed paths other lanes own: {list}. Move those changes to the owning lane, \
                     or land with --allow-foreign \"reason\" (logged)"
                )));
            }
        }
    }
    let commits: u32 = git(
        &primary,
        &["rev-list", "--count", &format!("{base}..{branch}")],
    )?
    .parse()
    .unwrap_or(0);
    if commits == 0 {
        return Ok(LandOutcome::NothingToLand);
    }

    // Rebase in a scratch worktree.
    let scratch = primary.join(".lanes").join(format!(".land-{lane}"));
    if scratch.exists() {
        let _ = git(
            &primary,
            &[
                "worktree",
                "remove",
                "--force",
                scratch.to_str().unwrap_or(""),
            ],
        );
        let _ = fs::remove_dir_all(&scratch);
        let _ = git(&primary, &["worktree", "prune"]);
    }
    git(
        &primary,
        &[
            "worktree",
            "add",
            "--detach",
            scratch.to_str().context("path is not valid UTF-8")?,
            &branch,
        ],
    )?;
    let finish = |scratch: &Path| {
        let _ = git(
            &primary,
            &[
                "worktree",
                "remove",
                "--force",
                scratch.to_str().unwrap_or(""),
            ],
        );
        let _ = fs::remove_dir_all(scratch);
        let _ = git(&primary, &["worktree", "prune"]);
    };
    // The lane's append-only logs merge by union for this rebase.
    let attributes = common.join(format!("ferry-attributes-{lane}"));
    fs::write(&attributes, attributes_text(&rec.append_only))?;
    let attributes_setting = format!("core.attributesFile={}", slashes(&attributes));
    if git(&scratch, &["-c", &attributes_setting, "rebase", &base_tip]).is_err() {
        let files: Vec<String> = nul_list(
            &git(&scratch, &["diff", "-z", "--name-only", "--diff-filter=U"]).unwrap_or_default(),
        );
        let _ = git(&scratch, &["rebase", "--abort"]);
        finish(&scratch);
        let notified = notify(
            route,
            identity,
            &rec.owner,
            json!({
                "kind": "lane-conflict",
                "lane": lane,
                "text": format!(
                    "landing lane '{lane}' onto {base} stopped on conflicts in: {}. The lane was not touched. \
                     Rebase it yourself (git rebase {base} in .lanes/{lane}), resolve, then land again.",
                    files.join(", ")
                ),
                "files": files,
            }),
        );
        return Ok(LandOutcome::Conflict { files, notified });
    }
    let new_tip = git(&scratch, &["rev-parse", "HEAD"])?;
    finish(&scratch);

    // The lane must still be what the landing found. Checked under the lock, before anything
    // moves; a change aborts with everything as it was.
    if let Some(why) = lane_changed(&dir, &branch, &old_tip, &new_tip)? {
        return Ok(LandOutcome::Refused(format!(
            "lane '{lane}' changed while landing ({why}); nothing was changed, land again"
        )));
    }
    git(
        &primary,
        &[
            "update-ref",
            &format!("refs/ferry/landed/{lane}/{}", Utc::now().timestamp()),
            &old_tip,
        ],
    )?;
    advance_base(&primary, &base, &base_tip, &new_tip)?;
    // `--keep` moves the lane only if that cannot lose a local change.
    let lane_note = git(&dir, &["reset", "--keep", &new_tip]).err().map(|e| {
        format!(
            "{base} moved, but the lane could not be moved onto it ({e}); it keeps its files, and its old tip is at refs/ferry/landed/{lane}/*"
        )
    });

    let (mut pushed, mut push_note) = (false, None);
    if opts.push {
        match net_git(
            &primary,
            &common,
            &["push", "--no-verify", &opts.remote, &base],
            &env,
        ) {
            Ok(_) => pushed = true,
            Err(e) => push_note = Some(format!("landed locally; push failed: {e}")),
        }
    }
    Ok(LandOutcome::Landed {
        base,
        commits,
        old_tip,
        new_tip,
        pushed,
        push_note,
        lane_note,
    })
}

#[cfg(test)]
mod tests;

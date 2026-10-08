//! Hand-ins: finished work that travels as a signed patch, not as a push (ADR 0023).
//!
//! A worker that is not the project's head never pushes. When it finishes an order it
//! writes `<work>/<order>/handin.patch` (a `git format-patch` stream, so authorship and
//! messages survive) and `handin.json` (who, against which base, which files, the patch's
//! sha256, and the agent's signature over all of it). The folder is synced like comms, so
//! the head sees it, checks it, applies it with `git am` in its own checkout and pushes.
//!
//! Only the assigned worker writes into its order folder, and only the head writes
//! `accepted.json` / `rejected.json` beside it, so no file ever has two writers. Git
//! checkouts are never synced.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::worktree::{END_OF_OPTIONS, plain_argument};
use crate::{AgentIdentity, ProjectRoute, SignatureCheck, is_safe_component};

/// The `format` tag in `handin.json`.
pub const FORMAT: &str = "ferryman-handin/v1";

/// Where a project's hand-ins live on this machine.
///
/// In a ferry root, `<root>/work/<project>`. Without one, beside a `comms` folder, the
/// sibling `work/<project>`. Otherwise inside the already-synced channel, so the hand-in
/// still reaches the head's machine whatever the layout.
#[must_use]
pub fn work_dir(route: &ProjectRoute) -> PathBuf {
    work_dir_with(crate::ferry::find_root().as_ref(), route)
}

/// [`work_dir`], with the ferry root given rather than looked for.
#[must_use]
pub fn work_dir_with(root: Option<&crate::ferry::Root>, route: &ProjectRoute) -> PathBuf {
    if let Some(root) = root {
        return root.work().join(&route.project_id);
    }
    let comms = &route.communications;
    if let Some(parent) = comms.parent()
        && parent.file_name().is_some_and(|name| name == "comms")
        && let Some(base) = parent.parent()
    {
        return base.join("work").join(&route.project_id);
    }
    comms.join("handins")
}

/// Whether the hand-in folder lies inside the channel folder (and so syncs with it).
#[must_use]
pub fn is_in_channel(route: &ProjectRoute) -> bool {
    work_dir(route).starts_with(&route.communications)
}

/// What [`ensure_work_ready`] found and did.
#[derive(Debug, Clone)]
pub struct WorkReady {
    pub path: PathBuf,
    /// The folder did not exist and was made.
    pub created: bool,
    /// One line for the log: how this folder reaches the other machines.
    pub sync: String,
}

/// Make sure this machine can hand work in or receive it: the work folder exists and, when
/// it is not inside the channel, Syncthing syncs it as `<project>-work` with the same
/// devices as the channel. Idempotent; safe to call on every worker start and from
/// `doctor --fix`. A Syncthing that is down or missing is reported, never an error.
pub fn ensure_work_ready(route: &ProjectRoute) -> Result<WorkReady> {
    let path = work_dir(route);
    let created = !path.is_dir();
    fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    let sync = if path.starts_with(&route.communications) {
        "inside the channel folder, so it syncs with the channel".to_string()
    } else {
        let setup = crate::syncthing_register_work_folder(route, &path)?;
        if setup.available {
            format!("folder {}: {}", setup.folder_id, setup.note)
        } else {
            format!("not synced yet: {}", setup.note)
        }
    };
    Ok(WorkReady {
        path,
        created,
        sync,
    })
}

/// `handin.json`: what was handed in, and the worker's signature over it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format: String,
    pub order: String,
    pub project: String,
    pub agent: String,
    pub base: String,
    pub branch: String,
    pub files: Vec<String>,
    pub patch_sha256: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The bytes the signature covers: the manifest's fields and the patch's digest.
fn payload(manifest: &Manifest) -> String {
    format!(
        "ferryman-handin-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        manifest.order,
        manifest.project,
        manifest.agent,
        manifest.base,
        manifest.branch,
        hex::encode(Sha256::digest(manifest.files.join("\n").as_bytes())),
        manifest.patch_sha256,
        manifest.created_at.to_rfc3339(),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn git_out(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("run git {}", args.first().copied().unwrap_or("")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&git_out(dir, args)?)
        .trim()
        .to_string())
}

/// The commit a hand-in should be cut against when the caller does not say: where the
/// checkout diverged from the project's default branch.
pub fn default_base(repo: &Path, head: &str) -> Result<String> {
    let (start, _) = crate::worktree::task_base(repo);
    plain_argument(head, "the head revision")?;
    git_text(repo, &["merge-base", END_OF_OPTIONS, &start, head])
        .with_context(|| format!("find where {head} left {start}; pass --base"))
}

/// What to cut a hand-in from.
#[derive(Debug, Clone, Copy)]
pub struct Cut<'a> {
    /// The git checkout (or repository) holding the commits.
    pub repo: &'a Path,
    /// The commit the work started from; the merge-base with the default branch if absent.
    pub base: Option<&'a str>,
    /// The revision at the tip of the work: HEAD, or the task branch.
    pub head: &'a str,
    /// The branch name to record.
    pub branch: &'a str,
}

/// Cut a signed hand-in for `order_id` from the commits `base..head` in `repo`, write it to
/// `dir/<order>/`, and return that folder.
///
/// Refuses an empty patch, and refuses to overwrite another agent's hand-in for the same
/// order: only the assigned worker writes into an order folder.
pub fn create(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    dir: &Path,
    order_id: &str,
    cut: &Cut<'_>,
) -> Result<PathBuf> {
    let Cut {
        repo,
        base,
        head,
        branch,
    } = *cut;
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier");
    }
    plain_argument(head, "the head revision")?;
    let base = match base.filter(|base| !base.trim().is_empty()) {
        Some(base) => {
            plain_argument(base, "the base commit")?;
            git_text(repo, &["rev-parse", "--verify", END_OF_OPTIONS, base])?
        }
        None => default_base(repo, head)?,
    };
    let range = format!("{base}..{head}");
    let patch = git_out(
        repo,
        &[
            "format-patch",
            "--stdout",
            "--binary",
            END_OF_OPTIONS,
            &range,
        ],
    )?;
    if patch.iter().all(u8::is_ascii_whitespace) {
        bail!("nothing to hand in: no commits between {base} and {head}");
    }
    let mut files: Vec<String> = git_out(
        repo,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            END_OF_OPTIONS,
            &base,
            head,
        ],
    )?
    .split(|byte| *byte == 0)
    .filter(|path| !path.is_empty())
    .map(|path| String::from_utf8_lossy(path).into_owned())
    .collect();
    files.sort();

    let folder = dir.join(order_id);
    let manifest_path = folder.join("handin.json");
    if let Ok(text) = fs::read_to_string(&manifest_path)
        && let Ok(existing) = serde_json::from_str::<Manifest>(&text)
        && !existing.agent.eq_ignore_ascii_case(identity.name())
    {
        bail!(
            "order {order_id} already holds a hand-in from {}; only the assigned worker writes there",
            existing.agent
        );
    }
    let mut manifest = Manifest {
        format: FORMAT.to_string(),
        order: order_id.to_string(),
        project: route.project_id.clone(),
        agent: identity.name().to_string(),
        base,
        branch: branch.to_string(),
        files,
        patch_sha256: sha256_hex(&patch),
        created_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    manifest.signed_by = Some(identity.name().to_string());
    manifest.signature = Some(identity.sign_bytes(payload(&manifest).as_bytes()));

    fs::create_dir_all(&folder).with_context(|| format!("create {}", folder.display()))?;
    // Patch first, manifest last: a reader that sees a manifest finds its patch.
    write_atomic(&folder.join("handin.patch"), &patch)?;
    write_atomic(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
    Ok(folder)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    fs::write(&temp, bytes).with_context(|| format!("write {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| format!("write {}", path.display()))
}

/// Read and check one hand-in folder: the signature against the roster, and the patch
/// against the digest the signature covers. The manifest comes back with the signature
/// verdict; a patch that does not match its digest is an error.
pub fn read(route: &ProjectRoute, folder: &Path) -> Result<(Manifest, SignatureCheck, Vec<u8>)> {
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(folder.join("handin.json"))
            .with_context(|| format!("read {}/handin.json", folder.display()))?,
    )
    .context("handin.json is not valid")?;
    if manifest.format != FORMAT {
        bail!("unknown hand-in format {:?}", manifest.format);
    }
    let patch = fs::read(folder.join("handin.patch"))
        .with_context(|| format!("read {}/handin.patch", folder.display()))?;
    let mut check = crate::check_signature(
        manifest.signed_by.as_ref(),
        manifest.signature.as_ref(),
        &payload(&manifest),
        &crate::gate::roster(route),
    );
    // The signer must be the agent the hand-in says it is from.
    if check == SignatureCheck::Valid
        && !manifest
            .signed_by
            .as_deref()
            .is_some_and(|by| by.eq_ignore_ascii_case(&manifest.agent))
    {
        check = SignatureCheck::Invalid;
    }
    if sha256_hex(&patch) != manifest.patch_sha256 {
        bail!("the patch does not match the digest the hand-in was signed over");
    }
    Ok((manifest, check, patch))
}

/// Where a hand-in stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Waiting,
    Accepted,
    Rejected,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// `accepted.json`, written by the head after the patch is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accepted {
    pub by: String,
    pub at: DateTime<Utc>,
    pub commit: String,
    /// Which patch was applied, so a revised hand-in is not mistaken for it.
    #[serde(default)]
    pub patch_sha256: String,
    #[serde(default)]
    pub pushed: bool,
}

/// `rejected.json`, written by the head; the order goes back for revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejected {
    pub by: String,
    pub at: DateTime<Utc>,
    pub reason: String,
}

fn status_of(folder: &Path, manifest: &Manifest) -> Status {
    if let Some(done) = fs::read_to_string(folder.join("accepted.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Accepted>(&text).ok())
        && done.patch_sha256 == manifest.patch_sha256
    {
        return Status::Accepted;
    }
    // A rejection only counts against the hand-in it answered; a revision made after it
    // is waiting again.
    if let Some(no) = fs::read_to_string(folder.join("rejected.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Rejected>(&text).ok())
        && no.at >= manifest.created_at
    {
        return Status::Rejected;
    }
    Status::Waiting
}

/// One row of `ferry work list`.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub order: String,
    pub agent: String,
    pub status: Status,
    /// `valid`, `unsigned`, `invalid`, `unknown` or `key_changed`.
    pub signature: &'static str,
    pub created_at: DateTime<Utc>,
    pub files: usize,
    pub branch: String,
    pub path: PathBuf,
}

fn signature_label(check: &SignatureCheck) -> &'static str {
    match check {
        SignatureCheck::Valid => "valid",
        SignatureCheck::Unsigned => "unsigned",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnknownSigner => "unknown",
        SignatureCheck::KeyChanged { .. } => "key_changed",
    }
}

/// Every hand-in under `dir`, newest first. A folder that cannot be read is listed as an
/// invalid signature, not skipped, so a damaged hand-in is seen rather than lost.
pub fn list(route: &ProjectRoute, dir: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(entries);
    };
    for item in read_dir.flatten() {
        let folder = item.path();
        let Some(order) = folder
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if !folder.join("handin.json").is_file() || !is_safe_component(&order) {
            continue;
        }
        let Some(manifest) = fs::read_to_string(folder.join("handin.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Manifest>(&text).ok())
        else {
            continue;
        };
        let signature = match read(route, &folder) {
            Ok((_, check, _)) => signature_label(&check),
            Err(_) => "invalid",
        };
        entries.push(Entry {
            status: status_of(&folder, &manifest),
            order,
            agent: manifest.agent.clone(),
            signature,
            created_at: manifest.created_at,
            files: manifest.files.len(),
            branch: manifest.branch.clone(),
            path: folder,
        });
    }
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(entries)
}

fn require_head(route: &ProjectRoute, agent: &str) -> Result<()> {
    if crate::head::is_head(&route.communications, &route.project_id, agent)? {
        return Ok(());
    }
    let head = crate::head::current(&route.communications, &route.project_id)?
        .map_or_else(|| "nobody".to_string(), |head| head.agent);
    bail!(
        "'{agent}' is not the head of {}, so it does not accept or reject hand-ins \
         (the head is {head}; the master names one in plain words)",
        route.project_id
    );
}

/// What `accept` did.
#[derive(Debug, Clone)]
pub struct Applied {
    pub commit: String,
    pub pushed: bool,
}

/// Accept a hand-in as `agent`, who must be the head: verify it, apply it with `git am
/// --3way` in `workspace` (the worker stays the author, `agent` becomes the committer, no
/// trailers), record `accepted.json`, then push unless `push` is false.
///
/// When `git am` fails the half-applied state is aborted and the checkout is as it was.
pub fn accept(
    route: &ProjectRoute,
    dir: &Path,
    order_id: &str,
    agent: &str,
    workspace: &Path,
    push: bool,
) -> Result<Applied> {
    require_head(route, agent)?;
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier");
    }
    let folder = dir.join(order_id);
    if !folder.join("handin.json").is_file() {
        bail!("no hand-in for order {order_id} under {}", dir.display());
    }
    let (manifest, check, _patch) = read(route, &folder)?;
    if check != SignatureCheck::Valid {
        bail!(
            "the hand-in for {order_id} is not validly signed ({}); not applying it",
            signature_label(&check)
        );
    }
    match status_of(&folder, &manifest) {
        Status::Accepted => bail!("{order_id} was already accepted"),
        Status::Rejected => bail!("{order_id} was rejected; it needs a revised hand-in"),
        Status::Waiting => {}
    }

    if !git_text(
        workspace,
        &["status", "--porcelain", "--untracked-files=no"],
    )?
    .is_empty()
    {
        bail!(
            "{} has uncommitted changes; commit or stash them before accepting",
            workspace.display()
        );
    }
    if !git_text(workspace, &["remote"])?.is_empty() {
        git_out(workspace, &["fetch"])?;
        // Catch up with upstream when that is a plain fast-forward; a checkout that has
        // diverged is left alone and `push` will say so.
        let _ = git_out(workspace, &["merge", "--ff-only", "--quiet", "@{upstream}"]);
    }

    let patch_path = folder
        .join("handin.patch")
        .canonicalize()
        .context("locate handin.patch")?;
    let patch_arg = patch_path.to_string_lossy().into_owned();
    let patch_arg = patch_arg.strip_prefix(r"\\?\").unwrap_or(&patch_arg);
    let name = format!("user.name={agent}");
    let email = format!("user.email={agent}@ferryman.invalid");
    let applied = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["-c", &name, "-c", &email, "-c", "commit.gpgsign=false"])
        .args(["am", "--3way", "--quiet", patch_arg])
        .output()
        .context("run git am")?;
    if !applied.status.success() {
        let why = format!(
            "{} {}",
            String::from_utf8_lossy(&applied.stdout).trim(),
            String::from_utf8_lossy(&applied.stderr).trim()
        );
        let _ = git_out(workspace, &["am", "--abort"]);
        bail!(
            "the patch from {} did not apply cleanly onto {}; the checkout is back as it was. \
             Reject it for a rebase: {}",
            manifest.agent,
            workspace.display(),
            why.trim()
        );
    }
    let commit = git_text(workspace, &["rev-parse", "HEAD"])?;
    let mut done = Accepted {
        by: agent.to_string(),
        at: Utc::now(),
        commit: commit.clone(),
        patch_sha256: manifest.patch_sha256.clone(),
        pushed: false,
    };
    write_atomic(
        &folder.join("accepted.json"),
        &serde_json::to_vec_pretty(&done)?,
    )?;
    if push {
        git_out(workspace, &["push"]).with_context(|| {
            format!(
                "applied as {commit} but could not push; push from {} by hand",
                workspace.display()
            )
        })?;
        done.pushed = true;
        write_atomic(
            &folder.join("accepted.json"),
            &serde_json::to_vec_pretty(&done)?,
        )?;
    }
    Ok(Applied {
        commit,
        pushed: done.pushed,
    })
}

/// Reject a hand-in as `agent`, who must be the head. The order goes back for revision.
pub fn reject(
    route: &ProjectRoute,
    dir: &Path,
    order_id: &str,
    agent: &str,
    reason: &str,
) -> Result<PathBuf> {
    require_head(route, agent)?;
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier");
    }
    if reason.trim().is_empty() {
        bail!("say why: a rejection without a reason sends the worker in the dark");
    }
    let folder = dir.join(order_id);
    if !folder.join("handin.json").is_file() {
        bail!("no hand-in for order {order_id} under {}", dir.display());
    }
    let path = folder.join("rejected.json");
    write_atomic(
        &path,
        &serde_json::to_vec_pretty(&Rejected {
            by: agent.to_string(),
            at: Utc::now(),
            reason: reason.trim().to_string(),
        })?,
    )?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    fn route_at(communications: &Path) -> ProjectRoute {
        ProjectRoute {
            project_id: "proj".into(),
            workspace: communications.join("..").join("proj"),
            attachment: communications.join("..").join("attachment"),
            communications: communications.to_path_buf(),
            shared_remote: "proj-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    #[test]
    fn work_dir_follows_the_ferry_root_then_a_comms_sibling_then_the_channel() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));

        // 1. A ferry root wins.
        let root = crate::ferry::Root::create(&dir.path().join("ferry")).unwrap();
        let route = route_at(&dir.path().join("elsewhere").join("proj-ferryman"));
        assert_eq!(work_dir_with(Some(&root), &route), root.work().join("proj"));

        // 2. No root, channel under a folder called `comms`: the sibling `work/<project>`.
        let route = route_at(&dir.path().join("x").join("comms").join("proj-ferryman"));
        assert_eq!(
            work_dir_with(None, &route),
            dir.path().join("x").join("work").join("proj")
        );

        // 3. Anything else: inside the channel, which already syncs.
        let route = route_at(&dir.path().join("x").join("channels").join("proj-ferryman"));
        assert_eq!(
            work_dir_with(None, &route),
            route.communications.join("handins")
        );
    }

    fn make(
        fleet: &Fleet,
        who: &AgentIdentity,
        order: &str,
        repo: &Path,
        base: Option<&str>,
    ) -> Result<PathBuf> {
        let work = fleet.dir.path().join("work").join("proj");
        create(
            &fleet.route,
            who,
            &work,
            order,
            &Cut {
                repo,
                base,
                head: "HEAD",
                branch: "b",
            },
        )
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn repo_with_commit(path: &Path) {
        fs::create_dir_all(path).unwrap();
        git(path, &["init", "-q", "--template=", "-b", "main"]);
        git(path, &["config", "user.email", "t@example.com"]);
        git(path, &["config", "user.name", "tester"]);
        git(path, &["config", "commit.gpgsign", "false"]);
        fs::write(path.join("f.txt"), "hello\n").unwrap();
        git(path, &["add", "f.txt"]);
        git(path, &["commit", "-q", "-m", "init"]);
    }

    struct Fleet {
        dir: tempfile::TempDir,
        route: ProjectRoute,
        josh: AgentIdentity,
        worker: AgentIdentity,
        stranger: AgentIdentity,
    }

    /// A channel whose master is josh, a worker on the roster, and josh named head.
    fn fleet() -> Fleet {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let channel = dir.path().join("comms").join("proj-ferryman");
        fs::create_dir_all(&channel).unwrap();
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
        let worker = AgentIdentity::from_seed("worker", [8u8; 32]);
        let stranger = AgentIdentity::from_seed("stranger", [9u8; 32]);
        let mut route = route_at(&channel);
        for member in [&josh, &worker] {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        crate::head::record_said(&channel, "proj", &josh, "josh is head").unwrap();
        crate::head::claim(&channel, "proj", &josh, None).unwrap();
        Fleet {
            dir,
            route,
            josh,
            worker,
            stranger,
        }
    }

    /// A checkout with one commit of work on top of `main`, returning (checkout, base).
    fn worker_checkout(fleet: &Fleet) -> (PathBuf, String) {
        let repo = fleet.dir.path().join("worker-repo");
        repo_with_commit(&repo);
        let base = git(&repo, &["rev-parse", "HEAD"]);
        fs::write(repo.join("new.txt"), "work\n").unwrap();
        git(&repo, &["add", "new.txt"]);
        git(&repo, &["commit", "-q", "-m", "do the thing"]);
        (repo, base)
    }

    #[test]
    fn a_hand_in_signs_and_verifies_and_a_change_breaks_it() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let folder = make(&fleet, &fleet.worker, "order-1", &repo, Some(&base)).unwrap();

        let (manifest, check, patch) = read(&fleet.route, &folder).unwrap();
        assert_eq!(check, SignatureCheck::Valid);
        assert_eq!(manifest.agent, "worker");
        assert_eq!(manifest.base, base);
        assert_eq!(manifest.files, vec!["new.txt".to_string()]);
        assert!(String::from_utf8_lossy(&patch).contains("do the thing"));

        // Editing the manifest invalidates the signature.
        let mut forged = manifest.clone();
        forged.files.push("secrets.txt".into());
        fs::write(
            folder.join("handin.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read(&fleet.route, &folder).unwrap().1,
            SignatureCheck::Invalid
        );

        // Editing the patch breaks the digest.
        fs::write(
            folder.join("handin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(folder.join("handin.patch"), b"tampered").unwrap();
        assert!(read(&fleet.route, &folder).is_err());
    }

    #[test]
    fn an_unrostered_signer_is_not_valid_and_an_empty_patch_is_refused() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let folder = make(&fleet, &fleet.stranger, "o-2", &repo, Some(&base)).unwrap();
        assert_eq!(
            read(&fleet.route, &folder).unwrap().1,
            SignatureCheck::UnknownSigner
        );
        let head = git(&repo, &["rev-parse", "HEAD"]);
        let empty = make(&fleet, &fleet.worker, "o-3", &repo, Some(&head));
        assert!(
            empty
                .unwrap_err()
                .to_string()
                .contains("nothing to hand in")
        );
    }

    #[test]
    fn another_agent_cannot_overwrite_a_hand_in() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        make(&fleet, &fleet.worker, "o-4", &repo, Some(&base)).unwrap();
        let again = make(&fleet, &fleet.josh, "o-4", &repo, Some(&base));
        assert!(
            again
                .unwrap_err()
                .to_string()
                .contains("only the assigned worker")
        );
    }

    #[test]
    fn only_the_head_accepts_and_accept_applies_and_records() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        make(&fleet, &fleet.worker, "o-5", &repo, Some(&base)).unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Waiting
        );

        // The head's checkout, at the base.
        let mine = fleet.dir.path().join("head-repo");
        repo_with_commit(&mine);
        let before = git(&mine, &["rev-parse", "HEAD"]);

        let refused = accept(&fleet.route, &work, "o-5", "worker", &mine, false);
        assert!(refused.unwrap_err().to_string().contains("not the head"));
        assert_eq!(git(&mine, &["rev-parse", "HEAD"]), before);

        let applied = accept(&fleet.route, &work, "o-5", "josh", &mine, false).unwrap();
        assert!(!applied.pushed);
        assert!(mine.join("new.txt").is_file());
        assert_eq!(
            git(&mine, &["log", "-1", "--format=%an|%cn"]),
            "tester|josh"
        );
        assert!(!git(&mine, &["log", "-1", "--format=%B"]).contains("Co-Authored-By"));
        let row = &list(&fleet.route, &work).unwrap()[0];
        assert_eq!(row.status, Status::Accepted);
        assert_eq!(row.signature, "valid");

        let twice = accept(&fleet.route, &work, "o-5", "josh", &mine, false);
        assert!(twice.unwrap_err().to_string().contains("already accepted"));
    }

    #[test]
    fn a_patch_that_does_not_apply_leaves_the_checkout_as_it_was() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        make(&fleet, &fleet.worker, "o-6", &repo, Some(&base)).unwrap();

        // The head already has a different new.txt, so the new-file patch conflicts.
        let mine = fleet.dir.path().join("head-repo");
        repo_with_commit(&mine);
        fs::write(mine.join("new.txt"), "something else\n").unwrap();
        git(&mine, &["add", "new.txt"]);
        git(&mine, &["commit", "-q", "-m", "collide"]);
        let before = git(&mine, &["rev-parse", "HEAD"]);

        let failed = accept(&fleet.route, &work, "o-6", "josh", &mine, false).unwrap_err();
        assert!(
            failed.to_string().contains("did not apply cleanly"),
            "{failed}"
        );
        assert_eq!(git(&mine, &["rev-parse", "HEAD"]), before);
        assert_eq!(git(&mine, &["status", "--porcelain"]), "");
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Waiting
        );
    }

    #[test]
    fn reject_is_the_heads_and_a_revision_is_waiting_again() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        make(&fleet, &fleet.worker, "o-7", &repo, Some(&base)).unwrap();

        assert!(reject(&fleet.route, &work, "o-7", "worker", "no").is_err());
        assert!(reject(&fleet.route, &work, "o-7", "josh", "  ").is_err());
        reject(&fleet.route, &work, "o-7", "josh", "wrong approach").unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Rejected
        );

        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(repo.join("more.txt"), "x\n").unwrap();
        git(&repo, &["add", "more.txt"]);
        git(&repo, &["commit", "-q", "-m", "revise"]);
        make(&fleet, &fleet.worker, "o-7", &repo, Some(&base)).unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Waiting
        );
    }
}

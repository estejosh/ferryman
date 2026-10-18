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
/// In a layout-2 root that is `projects/<id>/handins`, a folder of its own beside the channel
/// (or the path a person recorded for it with `ferry enable --handins`). It is synced like
/// the channel, by the same lanes, and it is what makes a read-only channel workable: a
/// worker whose channel it may not write hands in, and says everything else it has to say,
/// through here. Each agent writes only `handins/<agent>/`.
///
/// In a layout-1 root, and for a project whose channel was placed by hand with no hand-in
/// folder recorded, it is still `handins` inside the channel folder, which already syncs.
/// (It was once `work/<project>` in the ferry root, shared as a second Syncthing folder.
/// That put the task worktrees under a shared folder, and `work/` and `repos/` are
/// machine-local, so the Syncthing scope guard (`syncscope`) refuses it.)
#[must_use]
pub fn work_dir(route: &ProjectRoute) -> PathBuf {
    crate::ferry::handins_dir_for(&route.communications, &route.project_id)
}
/// Whether the hand-in folder lies inside the channel folder (and so syncs with it).
#[must_use]
pub fn is_in_channel(route: &ProjectRoute) -> bool {
    work_dir(route).starts_with(&route.communications)
}

/// The folder `agent` writes its own hand-ins into: `handins/<agent>` when the folder is
/// separate from the channel, and the folder itself when it is inside the channel (layout 1,
/// where hand-ins were `handins/<order>`).
#[must_use]
pub fn write_dir(route: &ProjectRoute, agent: &str) -> PathBuf {
    let dir = work_dir(route);
    if dir.starts_with(&route.communications) {
        dir
    } else {
        dir.join(crate::canonical_agent_name(agent))
    }
}

/// A real directory: not a symlink or junction to one. A hand-ins folder is written by
/// workers, and a link in it would make the head read (or `accept` apply) something from
/// outside it.
pub(crate) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        && fs::read_link(path).is_err()
}

/// A regular file, not a link.
fn is_real_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

/// The folders hand-ins are looked for in, for `dir` (normally [`work_dir`]): `dir`, then,
/// while a peer or an interrupted `ferry root migrate` may still have left hand-ins in the
/// old place, the `handins` folder inside the channel. The first is where new ones go.
fn search_dirs(route: &ProjectRoute, dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![dir.to_path_buf()];
    let legacy = route.communications.join("handins");
    if crate::ferry::same_place(dir, &work_dir(route))
        && !crate::ferry::same_place(&legacy, dir)
        && is_real_dir(&legacy)
    {
        dirs.push(legacy);
    }
    dirs
}

/// The folder of hand-in `order_id` under `dir`: `dir/<order>`, or `dir/<agent>/<order>`.
/// `None` when there is none, and an error when two agents handed in the same order id and
/// the caller has to say which. Links are not followed.
fn locate(dir: &Path, order_id: &str) -> Result<Option<PathBuf>> {
    let direct = dir.join(order_id);
    if is_real_dir(&direct) && is_real_file(&direct.join("handin.json")) {
        return Ok(Some(direct));
    }
    let mut found = Vec::new();
    if let Ok(read_dir) = fs::read_dir(dir) {
        for item in read_dir.flatten() {
            let agent_dir = item.path();
            let inner = agent_dir.join(order_id);
            if is_real_dir(&agent_dir)
                && is_real_dir(&inner)
                && is_real_file(&inner.join("handin.json"))
            {
                found.push(inner);
            }
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => bail!(
            "more than one agent handed in order {order_id}; accept or reject each from its \
             own folder under {}",
            dir.display()
        ),
    }
}

/// [`locate`] over [`search_dirs`]: the folder, and the directory it was found under.
fn locate_anywhere(
    route: &ProjectRoute,
    dir: &Path,
    order_id: &str,
) -> Result<Option<(PathBuf, PathBuf)>> {
    for base in search_dirs(route, dir) {
        if let Some(folder) = locate(&base, order_id)? {
            return Ok(Some((base, folder)));
        }
    }
    Ok(None)
}

/// For a hand-in under an agent's folder (`dir/<agent>/<order>`), whether the folder is the
/// agent the hand-in says it is from: only the assigned agent writes in its own subfolder.
fn in_its_agents_folder(dir: &Path, folder: &Path, manifest: &Manifest) -> bool {
    match folder.parent() {
        Some(parent) if parent == dir => true,
        Some(parent) => parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| crate::canonical_agent_name(&manifest.agent) == name),
        None => false,
    }
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
/// it is not inside the channel, Syncthing syncs it as `<project>-handins` with the same
/// devices as the channel (the fallback for the iroh lane, which syncs it too). Idempotent; safe to call on every worker start and from
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

/// The branch a checkout is on, or `HEAD` when it is detached.
#[must_use]
pub fn branch_of(repo: &Path) -> String {
    git_text(repo, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|_| "HEAD".to_string())
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
    /// A verdict file is there but cannot be verified: written before verdicts were
    /// signed, or not by the master or a head. Neither accepted nor rejected, and neither
    /// `accept` nor `reject` acts on it without `--force`.
    Unverified,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Unverified => "unverified",
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
    /// The head's (or master's) signature over the verdict. A verdict without a valid one is
    /// ignored: the file sits in a folder that syncs, and anyone who can write it could
    /// otherwise mark a hand-in accepted or rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// `rejected.json`, written by the head; the order goes back for revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejected {
    pub by: String,
    pub at: DateTime<Utc>,
    pub reason: String,
    /// Which patch was rejected (empty on a verdict written before they were signed).
    #[serde(default)]
    pub patch_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// What a verdict's signature covers.
fn verdict_payload(
    kind: &str,
    order: &str,
    patch_sha256: &str,
    by: &str,
    at: &DateTime<Utc>,
    detail: &str,
) -> String {
    format!(
        "ferryman-verdict-v1\n{kind}\n{order}\n{patch_sha256}\n{by}\n{}\n{detail}",
        at.to_rfc3339()
    )
}

/// Whether a verdict was signed by `by` itself and `by` had the standing to give it: the
/// master, the head now, or the agent that held the head appointment when the verdict was
/// given. The last keeps a verdict good after the head role is passed on.
fn verdict_valid(
    route: &ProjectRoute,
    by: &str,
    signed_by: Option<&String>,
    signature: Option<&String>,
    payload: &str,
    at: &DateTime<Utc>,
) -> bool {
    signed_by.is_some_and(|signer| signer.eq_ignore_ascii_case(by))
        && crate::check_signature(signed_by, signature, payload, &crate::gate::roster(route))
            == SignatureCheck::Valid
        && (crate::access::level_of(&route.communications, &route.project_id, by)
            == crate::access::Level::Orchestrator
            || crate::head::held_at(&route.communications, &route.project_id, by, *at))
}

/// `Some(true)` for an accepted.json that checks out, `Some(false)` for one that is there
/// about this hand-in but cannot be verified (written before verdicts were signed, forged,
/// or from a signer without standing), `None` for none or one about another patch.
fn accepted_state(route: &ProjectRoute, folder: &Path, manifest: &Manifest) -> Option<bool> {
    let path = folder.join("accepted.json");
    if !is_real_file(&path) {
        return None;
    }
    let Some(done) = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Accepted>(&text).ok())
    else {
        return Some(false);
    };
    if !done.patch_sha256.is_empty() && done.patch_sha256 != manifest.patch_sha256 {
        return None;
    }
    Some(
        !done.patch_sha256.is_empty()
            && verdict_valid(
                route,
                &done.by,
                done.signed_by.as_ref(),
                done.signature.as_ref(),
                &verdict_payload(
                    "accepted",
                    &manifest.order,
                    &done.patch_sha256,
                    &done.by,
                    &done.at,
                    &done.commit,
                ),
                &done.at,
            ),
    )
}

/// Like [`accepted_state`], for rejected.json. A rejection only counts against the
/// hand-in it answered; a revision made after it is waiting again.
fn rejected_state(route: &ProjectRoute, folder: &Path, manifest: &Manifest) -> Option<bool> {
    let path = folder.join("rejected.json");
    if !is_real_file(&path) {
        return None;
    }
    let Some(no) = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Rejected>(&text).ok())
    else {
        return Some(false);
    };
    if no.at < manifest.created_at
        || (!no.patch_sha256.is_empty() && no.patch_sha256 != manifest.patch_sha256)
    {
        return None;
    }
    Some(
        !no.patch_sha256.is_empty()
            && verdict_valid(
                route,
                &no.by,
                no.signed_by.as_ref(),
                no.signature.as_ref(),
                &verdict_payload(
                    "rejected",
                    &manifest.order,
                    &no.patch_sha256,
                    &no.by,
                    &no.at,
                    &no.reason,
                ),
                &no.at,
            ),
    )
}

fn status_of(route: &ProjectRoute, folder: &Path, manifest: &Manifest) -> Status {
    let accepted = accepted_state(route, folder, manifest);
    if accepted == Some(true) {
        return Status::Accepted;
    }
    let rejected = rejected_state(route, folder, manifest);
    if rejected == Some(true) {
        return Status::Rejected;
    }
    if accepted == Some(false) || rejected == Some(false) {
        return Status::Unverified;
    }
    Status::Waiting
}

/// A legacy verdict `adopt_verdicts` found (or re-signed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyVerdict {
    pub order: String,
    /// `accepted` or `rejected`.
    pub kind: &'static str,
}

/// The verdicts written before they were signed (v0.5.30 and earlier): each sits as an
/// unverifiable `accepted.json` / `rejected.json`. With `apply`, the master or head `signer`
/// signs them as their own, keeping what they said and when; without it, only the list.
/// A person should read the list first: signing says "yes, this was decided".
///
/// Verdicts that carry a signature that does not check out are not touched: those are not
/// legacy, and `accept` / `reject` `--force` is the way past them.
pub fn adopt_verdicts(
    route: &ProjectRoute,
    dir: &Path,
    signer: &AgentIdentity,
    apply: bool,
) -> Result<Vec<LegacyVerdict>> {
    let name = signer.name();
    if apply
        && crate::access::level_of(&route.communications, &route.project_id, name)
            != crate::access::Level::Orchestrator
    {
        bail!("only the master or the head re-signs old verdicts; '{name}' is neither");
    }
    let mut found = Vec::new();
    for entry in list(route, dir)? {
        if entry.status != Status::Unverified {
            continue;
        }
        let (manifest, _, _) = read(route, &entry.path)?;
        let path = entry.path.join("accepted.json");
        if accepted_state(route, &entry.path, &manifest) == Some(false)
            && let Some(mut done) = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Accepted>(&text).ok())
            && done.signature.is_none()
        {
            found.push(LegacyVerdict {
                order: entry.order.clone(),
                kind: "accepted",
            });
            if apply {
                done.by = name.to_string();
                done.patch_sha256.clone_from(&manifest.patch_sha256);
                done.signed_by = Some(name.to_string());
                done.signature = Some(
                    signer.sign_bytes(
                        verdict_payload(
                            "accepted",
                            &manifest.order,
                            &done.patch_sha256,
                            name,
                            &done.at,
                            &done.commit,
                        )
                        .as_bytes(),
                    ),
                );
                write_atomic(&path, &serde_json::to_vec_pretty(&done)?)?;
            }
        }
        let path = entry.path.join("rejected.json");
        if rejected_state(route, &entry.path, &manifest) == Some(false)
            && let Some(mut no) = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Rejected>(&text).ok())
            && no.signature.is_none()
        {
            found.push(LegacyVerdict {
                order: entry.order.clone(),
                kind: "rejected",
            });
            if apply {
                no.by = name.to_string();
                no.patch_sha256.clone_from(&manifest.patch_sha256);
                no.signed_by = Some(name.to_string());
                no.signature = Some(
                    signer.sign_bytes(
                        verdict_payload(
                            "rejected",
                            &manifest.order,
                            &no.patch_sha256,
                            name,
                            &no.at,
                            &no.reason,
                        )
                        .as_bytes(),
                    ),
                );
                write_atomic(&path, &serde_json::to_vec_pretty(&no)?)?;
            }
        }
    }
    Ok(found)
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
    for base in search_dirs(route, dir) {
        list_one(route, &base, &mut entries);
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
    Ok(entries)
}

fn list_one(route: &ProjectRoute, dir: &Path, entries: &mut Vec<Entry>) {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    // `dir/<order>` (hand-ins inside the channel) and `dir/<agent>/<order>` (a separate
    // hand-ins folder, one subfolder per agent). Links are skipped, not followed.
    let mut folders: Vec<PathBuf> = Vec::new();
    for item in read_dir.flatten() {
        let folder = item.path();
        if !is_real_dir(&folder) {
            continue;
        }
        if is_real_file(&folder.join("handin.json")) {
            folders.push(folder);
        } else if let Ok(inner) = fs::read_dir(&folder) {
            folders.extend(
                inner
                    .flatten()
                    .map(|item| item.path())
                    .filter(|path| is_real_dir(path) && is_real_file(&path.join("handin.json"))),
            );
        }
    }
    for folder in folders {
        let Some(order) = folder
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if !is_safe_component(&order) {
            continue;
        }
        let Some(manifest) = fs::read_to_string(folder.join("handin.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Manifest>(&text).ok())
        else {
            continue;
        };
        let signature = match read(route, &folder) {
            // A hand-in found in some other agent's folder is not that agent's to write.
            Ok(_) if !in_its_agents_folder(dir, &folder, &manifest) => "invalid",
            Ok((_, check, _)) => signature_label(&check),
            Err(_) => "invalid",
        };
        entries.push(Entry {
            status: status_of(route, &folder, &manifest),
            order,
            agent: manifest.agent.clone(),
            signature,
            created_at: manifest.created_at,
            files: manifest.files.len(),
            branch: manifest.branch.clone(),
            path: folder,
        });
    }
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
    signer: &AgentIdentity,
    workspace: &Path,
    push: bool,
    force: bool,
) -> Result<Applied> {
    let agent = signer.name();
    require_head(route, agent)?;
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier");
    }
    let Some((dir, folder)) = locate_anywhere(route, dir, order_id)? else {
        bail!("no hand-in for order {order_id} under {}", dir.display());
    };
    let dir = dir.as_path();
    let (manifest, check, _patch) = read(route, &folder)?;
    if !in_its_agents_folder(dir, &folder, &manifest) {
        bail!(
            "the hand-in at {} says it is from {}, but it is in another agent's folder; only \
             the assigned agent writes there",
            folder.display(),
            manifest.agent
        );
    }
    if check != SignatureCheck::Valid {
        bail!(
            "the hand-in for {order_id} is not validly signed ({}); not applying it",
            signature_label(&check)
        );
    }
    match status_of(route, &folder, &manifest) {
        Status::Accepted => bail!("{order_id} was already accepted"),
        Status::Rejected => bail!("{order_id} was rejected; it needs a revised hand-in"),
        Status::Waiting => {}
        Status::Unverified if force => {}
        Status::Unverified => bail!(
            "{order_id} has a verdict file that cannot be verified (an old unsigned one, or not \
             from the master or a head). If it was accepted, applying it again would apply it \
             twice: check `git log` first. Re-sign old verdicts with `ferry work adopt-verdicts`, \
             or pass --force to go ahead anyway"
        ),
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
        // Best effort, like the fast-forward below: an offline head can still apply and
        // review with --no-push, and a real push will report the network itself.
        let _ = git_out(workspace, &["fetch"]);
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
    let at = Utc::now();
    let mut done = Accepted {
        by: agent.to_string(),
        at,
        commit: commit.clone(),
        patch_sha256: manifest.patch_sha256.clone(),
        pushed: false,
        signed_by: Some(agent.to_string()),
        signature: Some(
            signer.sign_bytes(
                verdict_payload(
                    "accepted",
                    &manifest.order,
                    &manifest.patch_sha256,
                    agent,
                    &at,
                    &commit,
                )
                .as_bytes(),
            ),
        ),
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
    signer: &AgentIdentity,
    reason: &str,
    force: bool,
) -> Result<PathBuf> {
    let agent = signer.name();
    require_head(route, agent)?;
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier");
    }
    if reason.trim().is_empty() {
        bail!("say why: a rejection without a reason sends the worker in the dark");
    }
    let Some((_, folder)) = locate_anywhere(route, dir, order_id)? else {
        bail!("no hand-in for order {order_id} under {}", dir.display());
    };
    let (manifest, _, _) = read(route, &folder)?;
    if status_of(route, &folder, &manifest) == Status::Unverified && !force {
        bail!(
            "{order_id} has a verdict file that cannot be verified; `ferry work adopt-verdicts` \
             re-signs old ones, or pass --force to replace it"
        );
    }
    let path = folder.join("rejected.json");
    let at = Utc::now();
    let reason = reason.trim().to_string();
    write_atomic(
        &path,
        &serde_json::to_vec_pretty(&Rejected {
            by: agent.to_string(),
            at,
            patch_sha256: manifest.patch_sha256.clone(),
            signed_by: Some(agent.to_string()),
            signature: Some(
                signer.sign_bytes(
                    verdict_payload(
                        "rejected",
                        &manifest.order,
                        &manifest.patch_sha256,
                        agent,
                        &at,
                        &reason,
                    )
                    .as_bytes(),
                ),
            ),
            reason,
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
    fn hand_ins_live_in_the_channel_so_no_folder_under_work_is_ever_shared() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));

        let root = crate::ferry::Root::create(&dir.path().join("ferry")).unwrap();
        let route = route_at(&root.comms().join("proj-ferryman"));
        assert_eq!(work_dir(&route), route.communications.join("handins"));
        assert!(is_in_channel(&route));
        assert!(!work_dir(&route).starts_with(root.work()));
        assert!(crate::syncscope::guard(&work_dir(&route)).is_ok());

        // Wherever the channel is, the hand-in folder is inside it.
        let route = route_at(&dir.path().join("x").join("channels").join("proj-ferryman"));
        assert_eq!(work_dir(&route), route.communications.join("handins"));
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

        let refused = accept(
            &fleet.route,
            &work,
            "o-5",
            &fleet.worker,
            &mine,
            false,
            false,
        );
        assert!(refused.unwrap_err().to_string().contains("not the head"));
        assert_eq!(git(&mine, &["rev-parse", "HEAD"]), before);

        let applied = accept(&fleet.route, &work, "o-5", &fleet.josh, &mine, false, false).unwrap();
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

        let twice = accept(&fleet.route, &work, "o-5", &fleet.josh, &mine, false, false);
        assert!(twice.unwrap_err().to_string().contains("already accepted"));
    }

    #[test]
    fn an_unsigned_or_forged_verdict_is_ignored() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        let folder = make(&fleet, &fleet.worker, "o-8", &repo, Some(&base)).unwrap();
        let (manifest, _, _) = read(&fleet.route, &folder).unwrap();

        // Unsigned: anyone who can write the folder could have put it there.
        let forged = Accepted {
            by: "josh".into(),
            at: Utc::now(),
            commit: "abc".into(),
            patch_sha256: manifest.patch_sha256.clone(),
            pushed: false,
            signed_by: None,
            signature: None,
        };
        fs::write(
            folder.join("accepted.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Unverified
        );

        // Signed, but by an agent that is not the head or the master.
        let at = Utc::now();
        let payload = verdict_payload(
            "rejected",
            "o-8",
            &manifest.patch_sha256,
            "worker",
            &at,
            "no",
        );
        let by_worker = Rejected {
            by: "worker".into(),
            at,
            reason: "no".into(),
            patch_sha256: manifest.patch_sha256.clone(),
            signed_by: Some("worker".into()),
            signature: Some(fleet.worker.sign_bytes(payload.as_bytes())),
        };
        fs::write(
            folder.join("rejected.json"),
            serde_json::to_vec(&by_worker).unwrap(),
        )
        .unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Unverified
        );

        // The head's own, signed, counts.
        reject(
            &fleet.route,
            &work,
            "o-8",
            &fleet.josh,
            "wrong approach",
            true,
        )
        .unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Rejected
        );
    }

    #[test]
    fn a_linked_folder_in_the_hand_ins_is_skipped() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        let folder = make(&fleet, &fleet.worker, "o-9", &repo, Some(&base)).unwrap();
        let outside = fleet.dir.path().join("elsewhere");
        fs::create_dir_all(&outside).unwrap();
        // A copy of the hand-in reached through a link under another name.
        let linked = work.join("sneaky");
        let made = {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(folder.parent().unwrap(), &linked).is_ok()
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::symlink_dir(folder.parent().unwrap(), &linked).is_ok()
            }
        };
        if !made {
            return; // no permission to make links on this machine
        }
        let rows = list(&fleet.route, &work).unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(!is_real_dir(&linked));
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

        let failed =
            accept(&fleet.route, &work, "o-6", &fleet.josh, &mine, false, false).unwrap_err();
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

        assert!(reject(&fleet.route, &work, "o-7", &fleet.worker, "no", false).is_err());
        assert!(reject(&fleet.route, &work, "o-7", &fleet.josh, "  ", false).is_err());
        reject(
            &fleet.route,
            &work,
            "o-7",
            &fleet.josh,
            "wrong approach",
            false,
        )
        .unwrap();
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

    fn legacy_rejected(folder: &Path, by: &str) {
        let old = Rejected {
            by: by.into(),
            at: Utc::now(),
            reason: "wrong approach".into(),
            patch_sha256: String::new(),
            signed_by: None,
            signature: None,
        };
        fs::write(
            folder.join("rejected.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn an_old_unsigned_rejection_is_unverified_and_is_not_applied() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        let folder = make(&fleet, &fleet.worker, "o-10", &repo, Some(&base)).unwrap();
        legacy_rejected(&folder, "josh");
        let status = || list(&fleet.route, &work).unwrap()[0].status;
        assert_eq!(status(), Status::Unverified);

        // Not applied by accident, and not silently replaced.
        let mine = fleet.dir.path().join("head-repo");
        repo_with_commit(&mine);
        let before = git(&mine, &["rev-parse", "HEAD"]);
        let refused = accept(
            &fleet.route,
            &work,
            "o-10",
            &fleet.josh,
            &mine,
            false,
            false,
        );
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("cannot be verified")
        );
        assert_eq!(git(&mine, &["rev-parse", "HEAD"]), before);
        assert!(reject(&fleet.route, &work, "o-10", &fleet.josh, "again", false).is_err());

        // Listing is read-only; only a master or head signs, and only on request.
        let found = adopt_verdicts(&fleet.route, &work, &fleet.josh, false).unwrap();
        assert_eq!(
            found,
            vec![LegacyVerdict {
                order: "o-10".into(),
                kind: "rejected"
            }]
        );
        assert_eq!(status(), Status::Unverified);
        assert!(adopt_verdicts(&fleet.route, &work, &fleet.worker, true).is_err());
        adopt_verdicts(&fleet.route, &work, &fleet.josh, true).unwrap();
        assert_eq!(status(), Status::Rejected);
    }

    #[test]
    fn an_old_unsigned_acceptance_is_unverified_so_it_is_not_applied_twice() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        let folder = make(&fleet, &fleet.worker, "o-11", &repo, Some(&base)).unwrap();
        let old = Accepted {
            by: "josh".into(),
            at: Utc::now(),
            commit: "abc123".into(),
            patch_sha256: String::new(),
            pushed: true,
            signed_by: None,
            signature: None,
        };
        fs::write(
            folder.join("accepted.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        let status = || list(&fleet.route, &work).unwrap()[0].status;
        assert_eq!(status(), Status::Unverified);

        let mine = fleet.dir.path().join("head-repo");
        repo_with_commit(&mine);
        let before = git(&mine, &["rev-parse", "HEAD"]);
        let refused = accept(
            &fleet.route,
            &work,
            "o-11",
            &fleet.josh,
            &mine,
            false,
            false,
        );
        assert!(refused.unwrap_err().to_string().contains("twice"));
        assert_eq!(git(&mine, &["rev-parse", "HEAD"]), before);

        adopt_verdicts(&fleet.route, &work, &fleet.josh, true).unwrap();
        assert_eq!(status(), Status::Accepted);
        let again = accept(
            &fleet.route,
            &work,
            "o-11",
            &fleet.josh,
            &mine,
            false,
            false,
        );
        assert!(again.unwrap_err().to_string().contains("already accepted"));
    }

    #[test]
    fn force_goes_past_an_unverified_verdict() {
        let fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        let folder = make(&fleet, &fleet.worker, "o-12", &repo, Some(&base)).unwrap();
        legacy_rejected(&folder, "josh");
        reject(&fleet.route, &work, "o-12", &fleet.josh, "still no", true).unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Rejected
        );
    }

    #[test]
    fn a_verdict_outlives_the_head_who_gave_it() {
        let mut fleet = fleet();
        let (repo, base) = worker_checkout(&fleet);
        let work = fleet.dir.path().join("work").join("proj");
        let channel = fleet.route.communications.clone();
        let kit = AgentIdentity::from_seed("kit", [11u8; 32]);
        let agent = AgentRoute {
            name: "kit".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(kit.public_key_hex()),
            encryption_key: None,
        };
        crate::register_agent(&fleet.route, &agent).unwrap();
        fleet.route.agents.push(agent);

        // The master names kit head; kit rejects a hand-in.
        std::thread::sleep(std::time::Duration::from_millis(20));
        crate::head::record_said(&channel, "proj", &fleet.josh, "kit is head").unwrap();
        crate::head::claim(&channel, "proj", &kit, None).unwrap();
        make(&fleet, &fleet.worker, "o-13", &repo, Some(&base)).unwrap();
        reject(&fleet.route, &work, "o-13", &kit, "not like this", false).unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Rejected
        );

        // The master moves the role to the worker; kit is nobody now.
        std::thread::sleep(std::time::Duration::from_millis(20));
        crate::head::record_said(&channel, "proj", &fleet.josh, "worker is head").unwrap();
        crate::head::claim(&channel, "proj", &fleet.worker, None).unwrap();
        assert!(!crate::head::is_head(&channel, "proj", "kit").unwrap());
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Rejected,
            "kit held the head appointment when it spoke"
        );

        // But kit cannot speak for a time it no longer held it.
        let folder = list(&fleet.route, &work).unwrap()[0].path.clone();
        let (manifest, _, _) = read(&fleet.route, &folder).unwrap();
        let later = Utc::now() + chrono::Duration::hours(1);
        let payload = verdict_payload(
            "accepted",
            "o-13",
            &manifest.patch_sha256,
            "kit",
            &later,
            "abc",
        );
        let after = Accepted {
            by: "kit".into(),
            at: later,
            commit: "abc".into(),
            patch_sha256: manifest.patch_sha256.clone(),
            pushed: false,
            signed_by: Some("kit".into()),
            signature: Some(kit.sign_bytes(payload.as_bytes())),
        };
        // (Its rejection stands on its own; take it away to see only this.)
        fs::remove_file(folder.join("rejected.json")).unwrap();
        fs::write(
            folder.join("accepted.json"),
            serde_json::to_vec(&after).unwrap(),
        )
        .unwrap();
        assert_eq!(
            list(&fleet.route, &work).unwrap()[0].status,
            Status::Unverified
        );
    }
}

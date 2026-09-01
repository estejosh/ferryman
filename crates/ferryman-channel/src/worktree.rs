//! Worktree-per-task: one git worktree per signed order, so parallel agents
//! never collide in the same checkout.
//!
//! Borrowed from groundcrew, made better by tying it to the trust model: the
//! branch name derives from the signed order id and the agent rather than a
//! random uuid, so a re-dispatched task lands in the *same* worktree
//! (idempotent) and every commit is attributable to the order it belongs to.
//! The head commit is meant to be signed into the result so a reviewer can
//! verify the work matches the commit.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// The deterministic branch name for one (order, agent) pair. Git-branch-safe.
#[must_use]
pub fn branch_name(order_id: &str, agent: &str) -> String {
    format!(
        "ferryman-{}-{}",
        crate::source::slug(order_id),
        crate::source::slug(agent)
    )
}

/// Whether `path` is inside a git working tree.
pub fn is_git_repo(path: &Path) -> bool {
    let Some(dir) = path.to_str() else {
        return false;
    };
    Command::new("git")
        .args(["-C", dir, "rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Where a task's branch should start.
///
/// # The bug this exists to stop
///
/// `git worktree add -b <branch> <dir>` with no start point branches from whatever
/// the repository's HEAD happens to be. For a checkout a person uses that is
/// usually the default branch and the omission never shows. For the checkout a
/// worker makes task worktrees from it is whatever the last thing to touch that
/// repo left behind - and on one machine in this fleet that was a task branch from
/// six days earlier, so a new task's worktree began forty commits behind the work
/// it was supposed to extend. Nothing failed. The agent worked, committed, pushed,
/// and produced a branch that quietly reverted a week.
///
/// So the start point is chosen deliberately, in the order of what is most likely
/// to be the shared truth:
///
/// 1. `origin/HEAD` - what the remote says its default branch is.
/// 2. `origin/main`, then `origin/master` - when nobody ever set `origin/HEAD`,
///    which is the common case for a clone made with older git.
/// 3. local `main`, then `master` - a project with no remote at all, which
///    ADR 0006 makes a first-class case.
/// 4. `HEAD`, and only here, because a repository can legitimately have none of
///    the above: a fresh project on its first commit, or a deliberate detached
///    checkout. Falling back silently would restore exactly the bug above, so the
///    caller is told this happened.
///
/// Deliberately does not fetch. Basing on a remote-tracking ref that is a few
/// hours stale is a merge; reaching for the network inside worktree creation is a
/// failure mode at the worst moment, and whether to fetch is the operator's
/// decision to make in the layer that already knows about remotes.
pub fn task_base(repo: &Path) -> (String, bool) {
    let Some(dir) = repo.to_str() else {
        return ("HEAD".to_string(), true);
    };
    if let Some(head) = symbolic_ref(dir, "refs/remotes/origin/HEAD") {
        return (head, false);
    }
    for candidate in [
        "refs/remotes/origin/main",
        "refs/remotes/origin/master",
        "refs/heads/main",
        "refs/heads/master",
    ] {
        if rev_exists(dir, candidate) {
            return (candidate.to_string(), false);
        }
    }
    ("HEAD".to_string(), true)
}

/// The short name a symbolic ref points at, e.g. `origin/main`. `None` when the
/// ref does not exist, which is normal rather than exceptional.
fn symbolic_ref(repo_dir: &str, name: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["-C", repo_dir, "symbolic-ref", "--short", name])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn rev_exists(repo_dir: &str, rev: &str) -> bool {
    Command::new("git")
        .args(["-C", repo_dir, "rev-parse", "--verify", "--quiet", rev])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether the worktree at `dir` is a checkout of `repo` and not of some other
/// repository that happened to want the same directory name.
///
/// Compares the common git directory, which every worktree of a repo shares and no two
/// repos do. A failure to ask - git missing, a directory that is no longer a checkout -
/// answers no, because the cost of a wrong yes is running a task in the wrong project.
fn belongs_to(dir: &Path, repo: &Path) -> bool {
    fn common_git_dir(path: &Path) -> Option<PathBuf> {
        let path = path.to_str()?;
        let output = Command::new("git")
            .args([
                "-C",
                path,
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let found = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());
        Some(found.canonicalize().unwrap_or(found))
    }
    match (common_git_dir(dir), common_git_dir(repo)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The `work/` subdirectory that holds one repository's worktrees.
///
/// Readable half so a person can see whose scratch this is; digest half so two repos
/// with the same folder name in different places never share it.
#[must_use]
fn worktree_holder(repo: &Path) -> String {
    use sha2::{Digest, Sha256};
    let name = repo
        .file_name()
        .and_then(|n| n.to_str())
        .map(crate::source::slug)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "repo".to_string());
    // The path as written is what distinguishes two checkouts, so that is what is
    // hashed. Case is folded because Windows would otherwise give one repo two homes.
    let digest = Sha256::digest(repo.to_string_lossy().to_lowercase().as_bytes());
    format!(
        "{name}-{:06x}",
        u32::from_be_bytes([0, digest[0], digest[1], digest[2]])
    )
}

/// Create a worktree for an (order, agent) pair next to `repo`, returning the
/// worktree path and the branch. Idempotent: a re-dispatched task finds its own
/// worktree again instead of creating a second one.
pub fn create_worktree(repo: &Path, order_id: &str, agent: &str) -> Result<(PathBuf, String)> {
    let repo_dir = repo.to_str().context("repo path is not valid UTF-8")?;
    let branch = branch_name(order_id, agent);
    // Where a worktree goes.
    //
    // It used to be `repo.parent()` - beside the user's repository. That litters a
    // directory that is not ours, and it is also why scanning that directory finds
    // things which are not projects: a task worktree looks exactly like a sibling
    // checkout. Transient, Ferryman-owned scratch belongs in the ferry root's `work/`.
    //
    // The old location is still honoured when a worktree is already sitting there, so an
    // install that has been running for weeks does not suddenly abandon work in
    // progress - and a machine with no ferry root behaves exactly as it always did.
    let parent = repo
        .parent()
        .context("repo has no parent to hold a worktree")?;
    let plain = parent.join(&branch);
    // The legacy location is stepped around in exactly one case: a LIVE worktree of
    // another repository is sitting in it. Two repos side by side, given the same order
    // id and the same agent, both want this exact path - and the second must neither be
    // handed the first one's checkout nor delete it as stale. A broken leftover is a
    // different thing and is still reclaimed below; only somebody's working checkout is
    // sacred.
    let occupied_by_another = plain.exists() && is_git_repo(&plain) && !belongs_to(&plain, repo);
    let beside = if occupied_by_another {
        parent.join(format!("{branch}-{}", worktree_holder(repo)))
    } else {
        plain
    };
    let dir = if beside.exists() {
        beside
    } else {
        match crate::ferry::find_root_from(repo).or_else(crate::ferry::find_root) {
            Some(root) => {
                // One subdirectory per repository, not one flat pile of branches.
                //
                // The branch name is (order, agent). That was unambiguous while worktrees
                // lived beside their own repo, because the repo's own path did the
                // disambiguating. Under one shared ferry root it stops being: order ids
                // are short human names like `update-0828`, and two projects in the same
                // root can easily both have one. Both would resolve to the same
                // directory, the second would find a valid checkout sitting there and
                // reuse it, and an agent would run a whole task - and commit - in the
                // wrong repository. Centralising `work/` is what introduced that, so
                // centralising `work/` is what has to pay for it.
                let work = root.work().join(worktree_holder(repo));
                std::fs::create_dir_all(&work)
                    .with_context(|| format!("create {}", work.display()))?;
                work.join(&branch)
            }
            None => beside,
        }
    };
    if dir.exists() {
        // Reuse is deliberate - a re-dispatched task should land in its own worktree
        // rather than a fresh one - but only if this is still a working tree of this
        // repo. A leftover directory whose gitdir has been pruned, or whose repo has
        // moved, looks identical from out here and is not a checkout at all: git
        // refuses to operate in it, `git status` fails, and an agent runs a whole task
        // in a directory whose changes cannot be committed. Silently doing nothing with
        // an hour of work is worse than starting over.
        // ...and only if it is a checkout of THIS repository. `is_git_repo` answers
        // "is there a git worktree here", which is not the question. The directory name
        // is (order, agent); two repositories that share a parent - or share one ferry
        // root - can both produce it, and the loser used to be handed a perfectly valid
        // checkout of somebody else's project. It would run the task there, commit
        // there, and report success.
        if is_git_repo(&dir) && belongs_to(&dir, repo) {
            return Ok((dir, branch));
        }
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("clear the stale worktree at {}", dir.display()))?;
        // Both are best-effort tidying of state that may or may not exist, so their
        // complaints go nowhere: "branch not found" printed during a successful repair
        // reads like a failure, and output that has to be ignored teaches people to
        // ignore output.
        let _ = Command::new("git")
            .args(["-C", repo_dir, "worktree", "prune"])
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("git")
            .args(["-C", repo_dir, "branch", "-D", &branch])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    // The start point is explicit. Without it git branches from this repository's
    // HEAD, which is whatever the last thing to touch the checkout left behind -
    // see `task_base`.
    let (base, guessed) = task_base(repo);
    if guessed {
        eprintln!(
            "ferryman: {} has no origin/HEAD, main or master; branching {branch} from HEAD",
            repo.display()
        );
    }
    let status = Command::new("git")
        .args([
            "-C",
            repo_dir,
            "worktree",
            "add",
            "-b",
            &branch,
            dir.to_str().context("worktree path is not valid UTF-8")?,
            &base,
        ])
        .status()
        .with_context(|| format!("git worktree add -b {branch} {base}"))?;
    if !status.success() {
        bail!("git worktree add -b {branch} {base} failed");
    }
    Ok((dir, branch))
}

/// The commit at the tip of a worktree's branch, to sign into the result.
pub fn worktree_head(repo: &Path, branch: &str) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-C",
            repo.to_str().context("repo path is not valid UTF-8")?,
            "rev-parse",
            branch,
        ])
        .output()
        .with_context(|| format!("git rev-parse {branch}"))?;
    if !output.status.success() {
        bail!("git rev-parse {branch} failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Refuse a directory that is not itself the root of a git worktree.
///
/// # Why this is not paranoia
///
/// `git -C <dir> status` walks *upwards* until it finds a repository. Ask it about a
/// directory that is not a repo and it will happily answer about some ancestor - and on
/// a machine where the home directory is itself a repo (which happens, and did), every
/// scratch directory under it reads as a clean-or-dirty checkout of that repo.
///
/// That is not a cosmetic error. [`commit_all`] runs `git add -A` and commits whatever
/// git says is there. Pointed at a directory whose only repository is an ancestor, it
/// would stage that ancestor's entire tree - the operator's home directory, credentials
/// and all - and commit it to an agent branch that then gets pushed.
///
/// Every worktree this module makes is created by `git worktree add`, so its path *is*
/// the top level. Requiring that exactly closes the hole, and turns "some ancestor is a
/// repo" from a silent data leak into a refusal that names the directory it found.
fn is_a_worktree_root(worktree: &Path, dir: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["-C", dir, "rev-parse", "--show-toplevel"])
        .output()
        .with_context(|| format!("git rev-parse in {dir}"))?;
    if !output.status.success() {
        bail!(
            "{dir} is not a git worktree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let toplevel = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());

    // Canonicalise both sides before comparing. `--show-toplevel` prints forward slashes
    // on Windows and either side may reach the same directory through a symlink or a
    // short name, and a false mismatch here would refuse a perfectly good worktree.
    let same = match (toplevel.canonicalize(), worktree.canonicalize()) {
        (Ok(found), Ok(asked)) => found == asked,
        _ => toplevel == worktree,
    };
    if !same {
        bail!(
            "{dir} is not a git worktree of its own; git resolved to {}. Refusing rather \
             than reporting on a repository this directory merely sits inside.",
            toplevel.display()
        );
    }
    Ok(())
}

/// What git thinks has changed in the worktree: modified, added and untracked
/// files, in `--porcelain` form. Empty means the agent changed nothing.
///
/// Fallible on purpose. The question underneath is "did the agent do anything",
/// and the answer "git could not tell me" must not collapse into "no" - that is
/// how work gets thrown away without anyone being told.
pub fn status_of(worktree: &Path) -> Result<String> {
    let dir = worktree
        .to_str()
        .context("worktree path is not valid UTF-8")?;
    is_a_worktree_root(worktree, dir)?;
    let output = Command::new("git")
        .args(["-C", dir, "status", "--porcelain"])
        .output()
        .with_context(|| format!("git status in {dir}"))?;
    if !output.status.success() {
        bail!(
            "git status failed in {dir}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Whether the worktree has changes git would care about. A directory git cannot
/// read reports `false` here; callers that must not lose work use [`status_of`].
#[must_use]
pub fn is_dirty(worktree: &Path) -> bool {
    status_of(worktree).is_ok_and(|status| !status.trim().is_empty())
}

/// Commit everything in the worktree, attributed to the agent. Returns the new
/// commit, or `None` when there was nothing to commit.
///
/// # Why the identity is passed rather than configured
///
/// `-c user.name=...` applies to this one command instead of writing to the repo's
/// config, so a fleet of agents sharing a checkout cannot end up renaming each
/// other's committer. The address is a `.invalid` domain per RFC 2606: it is a
/// machine, it has no mailbox, and inventing a deliverable-looking address for it
/// would be a small lie that survives in history forever.
///
/// # Why signing is forced off
///
/// A worker runs with nobody at the keyboard. If the repo sets `commit.gpgsign`,
/// the commit either blocks on a passphrase prompt no one will answer, or it
/// succeeds because the key sits unprotected on disk. Ferryman signs the *result*
/// with the agent's own key, which is the attribution that matters here; a git
/// signature would only restate it less verifiably.
pub fn commit_all(worktree: &Path, agent: &str, message: &str) -> Result<Option<String>> {
    let dir = worktree
        .to_str()
        .context("worktree path is not valid UTF-8")?;
    if status_of(worktree)?.trim().is_empty() {
        return Ok(None);
    }
    let status = Command::new("git")
        .args(["-C", dir, "add", "-A"])
        .status()
        .context("git add -A in the worktree")?;
    if !status.success() {
        bail!("git add -A failed in {dir}");
    }
    let author = format!("{agent} <{agent}@ferryman.invalid>");
    let output = Command::new("git")
        .args([
            "-C",
            dir,
            "-c",
            &format!("user.name={agent}"),
            "-c",
            &format!("user.email={agent}@ferryman.invalid"),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--author",
            &author,
            "-m",
            message,
        ])
        .output()
        .context("git commit in the worktree")?;
    if !output.status.success() {
        bail!(
            "git commit failed in {dir}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    head_of(worktree).map(Some)
}

/// The commit a worktree is currently on, read from inside the worktree itself.
pub fn head_of(worktree: &Path) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-C",
            worktree
                .to_str()
                .context("worktree path is not valid UTF-8")?,
            "rev-parse",
            "HEAD",
        ])
        .output()
        .context("git rev-parse HEAD")?;
    if !output.status.success() {
        bail!("git rev-parse HEAD failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Publish a branch to a remote, so the work leaves the machine that produced it.
///
/// `--force-with-lease` rather than `--force`: a re-dispatched task legitimately
/// rewrites its own branch, but only if the remote still holds what this machine
/// last saw there. If someone else has pushed to that branch in the meantime, the
/// push is refused instead of erasing them.
pub fn push_branch(repo: &Path, remote: &str, branch: &str) -> Result<()> {
    let dir = repo.to_str().context("repo path is not valid UTF-8")?;
    let output = Command::new("git")
        .args([
            "-C",
            dir,
            "push",
            "--force-with-lease",
            remote,
            &format!("{branch}:{branch}"),
        ])
        .output()
        .with_context(|| format!("git push {remote} {branch}"))?;
    if !output.status.success() {
        bail!(
            "git push {remote} {branch} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Tear a worktree down: remove the checkout and delete the branch. Idempotent
/// - tearing down a worktree that is already gone is not an error.
///
/// This deletes work. It is right for an operator who asked to discard a worktree,
/// and wrong as an automatic step after a task; see [`retire_worktree`].
pub fn remove_worktree(repo: &Path, branch: &str) -> Result<()> {
    let repo_dir = repo.to_str().context("repo path is not valid UTF-8")?;
    let parent = repo.parent().context("repo has no parent")?;
    let dir = parent.join(branch);
    if dir.exists() {
        let status = Command::new("git")
            .args([
                "-C",
                repo_dir,
                "worktree",
                "remove",
                "--force",
                dir.to_str().context("worktree path is not valid UTF-8")?,
            ])
            .status()
            .with_context(|| format!("git worktree remove {branch}"))?;
        if !status.success() {
            bail!("git worktree remove {branch} failed");
        }
    }
    let _ = Command::new("git")
        .args(["-C", repo_dir, "branch", "-D", branch])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

/// Put a finished task's worktree away without throwing the work out.
///
/// # The bug this exists to fix
///
/// The worker used to call [`remove_worktree`] here, which force-removes the
/// checkout and then runs `git branch -D`. An agent that committed had its commit
/// orphaned by the branch delete; an agent that did not had its files deleted
/// outright. There was no path where the work survived the task that produced it,
/// and the head recorded in the result was the commit the branch started from -
/// which reads like provenance and is really a record of where the work began
/// before it vanished.
///
/// So: the checkout always goes, because it is a scratch directory. The branch
/// goes only when it holds nothing that was not already reachable from `base`.
pub fn retire_worktree(repo: &Path, branch: &str, base: &str) -> Result<bool> {
    let repo_dir = repo.to_str().context("repo path is not valid UTF-8")?;
    let parent = repo.parent().context("repo has no parent")?;
    let dir = parent.join(branch);
    if dir.exists() {
        let status = Command::new("git")
            .args([
                "-C",
                repo_dir,
                "worktree",
                "remove",
                "--force",
                dir.to_str().context("worktree path is not valid UTF-8")?,
            ])
            .status()
            .with_context(|| format!("git worktree remove {branch}"))?;
        if !status.success() {
            bail!("git worktree remove {branch} failed");
        }
    }
    let kept = has_commits_beyond(repo, branch, base);
    if !kept {
        let _ = Command::new("git")
            .args(["-C", repo_dir, "branch", "-D", branch])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    Ok(kept)
}

/// Whether `branch` carries anything not already reachable from `base`.
///
/// Errs toward keeping: if the count cannot be read, the branch stays. A stale
/// branch costs a line in `git branch`; a wrongly deleted one costs the work.
#[must_use]
pub fn has_commits_beyond(repo: &Path, branch: &str, base: &str) -> bool {
    let Some(dir) = repo.to_str() else {
        return true;
    };
    let output = Command::new("git")
        .args([
            "-C",
            dir,
            "rev-list",
            "--count",
            &format!("{base}..{branch}"),
        ])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse::<u32>()
            .map(|n| n > 0)
            .unwrap_or(true),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_repo() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "ferryman-worktree-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let status = Command::new("git")
            .args(["-C", base.to_str().unwrap(), "init", "-q", "--template="])
            .status()
            .unwrap();
        assert!(status.success());
        let _ = Command::new("git")
            .args([
                "-C",
                base.to_str().unwrap(),
                "config",
                "user.email",
                "t@example.com",
            ])
            .status();
        let _ = Command::new("git")
            .args([
                "-C",
                base.to_str().unwrap(),
                "config",
                "user.name",
                "tester",
            ])
            .status();
        fs::write(base.join("f.txt"), "hello").unwrap();
        let _ = Command::new("git")
            .args(["-C", base.to_str().unwrap(), "add", "f.txt"])
            .status();
        let _ = Command::new("git")
            .args(["-C", base.to_str().unwrap(), "commit", "-q", "-m", "init"])
            .status();
        base
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let mut full = vec!["-C", repo.to_str().unwrap()];
        full.extend_from_slice(args);
        let status = Command::new("git").args(&full).status().unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    /// The bug in the flesh. A checkout parked on some other branch used to hand
    /// that branch's tip to the next task as its starting point, so the task began
    /// behind the work it was meant to extend - and nothing failed while it did.
    #[test]
    fn a_task_branches_from_main_not_from_wherever_the_repo_was_left() {
        let repo = temp_repo();
        run_git(&repo, &["branch", "-M", "main"]);
        let on_main = head_of(&repo).unwrap();

        // A side branch with a commit nobody wants as a base, left checked out.
        run_git(&repo, &["checkout", "-q", "-b", "old"]);
        fs::write(repo.join("detour.txt"), "not this").unwrap();
        run_git(&repo, &["add", "detour.txt"]);
        run_git(&repo, &["commit", "-q", "-m", "a detour"]);

        let (dir, branch) = create_worktree(&repo, "ENG-9", "wisp").unwrap();
        let started_at = head_of(&dir).unwrap();
        assert_eq!(
            started_at, on_main,
            "{branch} must start from main, not from the branch the repo was parked on"
        );
        assert!(
            !dir.join("detour.txt").exists(),
            "the detour must not appear in the task's tree"
        );
        let _ = remove_worktree(&repo, &branch);
        let _ = fs::remove_dir_all(&repo);
    }

    /// A project with no remote is a first-class case, not a degraded one.
    #[test]
    fn a_repo_with_no_remote_starts_from_its_own_main() {
        let repo = temp_repo();
        run_git(&repo, &["branch", "-M", "main"]);
        let (base, guessed) = task_base(&repo);
        assert_eq!(base, "refs/heads/main");
        assert!(!guessed, "a local main is an answer, not a fallback");
        let _ = fs::remove_dir_all(&repo);
    }

    /// And when there is genuinely nothing to point at, it says so rather than
    /// silently reintroducing the bug.
    #[test]
    fn with_no_main_and_no_remote_the_fallback_is_reported_as_a_guess() {
        let repo = temp_repo();
        run_git(&repo, &["branch", "-M", "trunk"]);
        let (base, guessed) = task_base(&repo);
        assert_eq!(base, "HEAD");
        assert!(guessed, "an unrecognisable repo is reported, not assumed");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn branch_names_are_deterministic_and_git_safe() {
        assert_eq!(branch_name("ENG-1", "Nebra"), "ferryman-eng-1-nebra");
        assert_eq!(branch_name("ENG-1", "Nebra"), branch_name("ENG-1", "Nebra"));
        assert!(!branch_name("a b/c", "x y").contains('/'));
        assert!(!branch_name("a b/c", "x y").contains(' '));
    }

    #[test]
    fn a_worktree_can_be_created_measured_and_removed() {
        let repo = temp_repo();
        assert!(is_git_repo(&repo));
        let (dir, branch) = create_worktree(&repo, "ENG-1", "nebra").unwrap();
        assert!(dir.exists());
        assert!(dir.join("f.txt").exists(), "the worktree sees the tree");
        let head = worktree_head(&repo, &branch).unwrap();
        assert_eq!(head.len(), 40, "a full sha1 commit hash: {head}");
        // Creating again is idempotent and returns the same branch.
        let (dir2, branch2) = create_worktree(&repo, "ENG-1", "nebra").unwrap();
        assert_eq!(dir, dir2);
        assert_eq!(branch, branch2);
        remove_worktree(&repo, &branch).unwrap();
        assert!(!dir.exists(), "the worktree is gone after cleanup");
        let _ = fs::remove_dir_all(&repo);
    }

    /// Two repositories, one order id, one agent - which is an ordinary Tuesday under
    /// ADR 0019, because a ferry root holds many projects and order ids are short human
    /// names like `update-0828` that nobody coordinates across projects.
    ///
    /// They used to resolve to the same directory. The second task would find a valid
    /// git checkout sitting there, reuse it, and run - and commit - in the wrong
    /// repository, reporting success the whole way.
    #[test]
    fn two_repos_sharing_an_order_id_do_not_share_a_worktree() {
        let one = temp_repo();
        let two = temp_repo();

        let (dir_one, _) = create_worktree(&one, "update-0828", "nebra").unwrap();
        let (dir_two, _) = create_worktree(&two, "update-0828", "nebra").unwrap();
        assert_ne!(
            dir_one, dir_two,
            "the same order id in two projects must not name the same directory"
        );

        // And each is a checkout of its own repository, which is the thing that actually
        // matters: a distinct path holding the wrong repo would be no better.
        fs::write(dir_one.join("mine.txt"), "one").unwrap();
        assert!(
            one.join("f.txt").exists() && dir_one.join("f.txt").exists(),
            "the first worktree tracks the first repo"
        );
        assert!(
            !dir_two.join("mine.txt").exists(),
            "work in one project must not appear in the other"
        );

        // Asking again finds each its own again, rather than a fresh one or the neighbour's.
        assert_eq!(
            create_worktree(&one, "update-0828", "nebra").unwrap().0,
            dir_one
        );
        assert_eq!(
            create_worktree(&two, "update-0828", "nebra").unwrap().0,
            dir_two
        );

        let _ = fs::remove_dir_all(&one);
        let _ = fs::remove_dir_all(&two);
    }

    /// The defect this whole module was quietly built around: a finished task's work
    /// was force-deleted along with its scratch directory.
    #[test]
    fn retiring_a_worktree_keeps_the_work_and_drops_the_scratch_directory() {
        let repo = temp_repo();
        let (dir, branch) = create_worktree(&repo, "ENG-2", "nebra").unwrap();
        let base = worktree_head(&repo, &branch).unwrap();

        fs::write(dir.join("answer.txt"), "the agent wrote this").unwrap();
        assert!(
            is_dirty(&dir),
            "an agent that changed a file leaves a dirty tree"
        );
        let made = commit_all(&dir, "nebra", "ENG-2: do the thing").unwrap();
        let made = made.expect("a dirty tree produces a commit");
        assert_ne!(made, base, "the commit is new work, not the branch point");

        let kept = retire_worktree(&repo, &branch, &base).unwrap();
        assert!(kept, "a branch with commits on it is kept");
        assert!(!dir.exists(), "the scratch checkout is gone");
        assert_eq!(
            worktree_head(&repo, &branch).unwrap(),
            made,
            "and the commit is still reachable by name afterwards"
        );
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn a_task_that_changed_nothing_leaves_no_branch_behind() {
        // The other half: an agent asked a question and wrote no files should not
        // leave a branch per task cluttering the repo forever.
        let repo = temp_repo();
        let (dir, branch) = create_worktree(&repo, "ENG-3", "nebra").unwrap();
        let base = worktree_head(&repo, &branch).unwrap();

        assert!(!is_dirty(&dir));
        assert_eq!(commit_all(&dir, "nebra", "nothing").unwrap(), None);

        let kept = retire_worktree(&repo, &branch, &base).unwrap();
        assert!(!kept, "an empty branch is not worth keeping");
        assert!(worktree_head(&repo, &branch).is_err(), "the branch is gone");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn the_committer_is_the_agent_and_the_address_is_not_deliverable() {
        // Attribution has to survive into git history, and a machine must not be
        // given an address that looks like it could receive mail.
        let repo = temp_repo();
        let (dir, branch) = create_worktree(&repo, "ENG-4", "fang").unwrap();
        fs::write(dir.join("x.txt"), "work").unwrap();
        commit_all(&dir, "fang", "ENG-4: work").unwrap().unwrap();

        let out = Command::new("git")
            .args([
                "-C",
                repo.to_str().unwrap(),
                "log",
                "-1",
                "--format=%an <%ae>",
                &branch,
            ])
            .output()
            .unwrap();
        let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(who, "fang <fang@ferryman.invalid>");
        let _ = fs::remove_dir_all(&repo);
    }

    /// Found by the test above failing for the wrong reason, which is the best way to
    /// find one: a worktree directory left behind by an earlier run - repo since gone -
    /// was handed straight back to the caller. git refuses to work in it, `git status`
    /// fails, and the old code read that failure as "nothing changed". An agent would
    /// have run a full task in that directory and had its work silently dropped.
    #[test]
    fn a_stale_worktree_directory_is_rebuilt_rather_than_reused() {
        let repo = temp_repo();
        let (dir, branch) = create_worktree(&repo, "ENG-5", "nebra").unwrap();

        // Exactly the state a deleted or moved repo leaves behind: the directory and
        // its .git pointer survive, the thing they point at does not.
        fs::write(
            dir.join(".git"),
            "gitdir: /tmp/does-not-exist/.git/worktrees/x",
        )
        .unwrap();
        assert!(!is_git_repo(&dir), "the leftover is not a working tree");
        assert!(
            status_of(&dir).is_err(),
            "and git will not answer questions about it"
        );

        let (again, branch2) = create_worktree(&repo, "ENG-5", "nebra").unwrap();
        assert_eq!(again, dir);
        assert_eq!(branch2, branch);
        assert!(is_git_repo(&again), "it was rebuilt into a real worktree");

        fs::write(again.join("work.txt"), "not lost").unwrap();
        assert!(
            commit_all(&again, "nebra", "ENG-5: work")
                .unwrap()
                .is_some()
        );
        let _ = fs::remove_dir_all(&repo);
        let _ = fs::remove_dir_all(&again);
    }

    /// The bug this exists to stop: a scratch directory *inside* somebody's repository
    /// is not a worktree, and must never be reported on - let alone committed - as if it
    /// were that repository. Found on a machine whose home directory was a git repo,
    /// where every temp directory under it read as a clean checkout.
    #[test]
    fn a_directory_inside_someone_elses_repo_is_refused_not_reported_on() {
        let repo = temp_repo();
        let inside = repo.join("scratch").join("deep");
        fs::create_dir_all(&inside).unwrap();
        fs::write(inside.join("agent-output.txt"), "work").unwrap();

        let error = status_of(&inside).unwrap_err().to_string();
        assert!(
            error.contains("not a git worktree of its own"),
            "expected a refusal naming the resolved repository, got: {error}"
        );
        // The committing path refuses too, which is the half that would otherwise have
        // staged the whole surrounding repository under an agent's name.
        assert!(commit_all(&inside, "nebra", "x").is_err());
        let _ = fs::remove_dir_all(&repo);
    }

    /// The distinction that matters: "clean" and "I cannot tell" are different answers,
    /// and only one of them means it is safe to throw the directory away.
    #[test]
    fn a_worktree_git_cannot_read_is_an_error_not_a_clean_tree() {
        let missing = std::env::temp_dir().join("ferryman-not-a-repo-at-all");
        let _ = fs::create_dir_all(&missing);
        assert!(status_of(&missing).is_err());
        assert!(
            !is_dirty(&missing),
            "the convenience form still answers false"
        );
        // ...and the committing path refuses rather than reporting "nothing to commit".
        assert!(commit_all(&missing, "nebra", "x").is_err());
        let _ = fs::remove_dir_all(&missing);
    }

    #[test]
    fn an_unreadable_count_keeps_the_branch_rather_than_guessing() {
        // has_commits_beyond errs toward keeping: a stale branch costs a line of
        // output, a wrongly deleted one costs the work.
        let repo = temp_repo();
        assert!(has_commits_beyond(&repo, "no-such-branch", "no-such-base"));
        let _ = fs::remove_dir_all(&repo);
    }
}

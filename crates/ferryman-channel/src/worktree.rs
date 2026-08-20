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

/// Create a worktree for an (order, agent) pair next to `repo`, returning the
/// worktree path and the branch. Idempotent: a re-dispatched task finds its own
/// worktree again instead of creating a second one.
pub fn create_worktree(repo: &Path, order_id: &str, agent: &str) -> Result<(PathBuf, String)> {
    let repo_dir = repo.to_str().context("repo path is not valid UTF-8")?;
    let branch = branch_name(order_id, agent);
    let parent = repo
        .parent()
        .context("repo has no parent to hold a worktree")?;
    let dir = parent.join(&branch);
    if dir.exists() {
        // Reuse is deliberate - a re-dispatched task should land in its own worktree
        // rather than a fresh one - but only if this is still a working tree of this
        // repo. A leftover directory whose gitdir has been pruned, or whose repo has
        // moved, looks identical from out here and is not a checkout at all: git
        // refuses to operate in it, `git status` fails, and an agent runs a whole task
        // in a directory whose changes cannot be committed. Silently doing nothing with
        // an hour of work is worse than starting over.
        if is_git_repo(&dir) {
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
    let status = Command::new("git")
        .args([
            "-C",
            repo_dir,
            "worktree",
            "add",
            "-b",
            &branch,
            dir.to_str().context("worktree path is not valid UTF-8")?,
        ])
        .status()
        .with_context(|| format!("git worktree add -b {branch}"))?;
    if !status.success() {
        bail!("git worktree add -b {branch} failed");
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
            .args(["-C", base.to_str().unwrap(), "init", "-q"])
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
        let (dir, branch) = create_worktree(&repo, "ENG-4", "grouchly").unwrap();
        fs::write(dir.join("x.txt"), "work").unwrap();
        commit_all(&dir, "grouchly", "ENG-4: work")
            .unwrap()
            .unwrap();

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
        assert_eq!(who, "grouchly <grouchly@ferryman.invalid>");
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

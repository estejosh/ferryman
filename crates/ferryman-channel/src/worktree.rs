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
use std::process::Command;

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
        return Ok((dir, branch));
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

/// Tear a worktree down: remove the checkout and delete the branch. Idempotent
/// - tearing down a worktree that is already gone is not an error.
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
        .status();
    Ok(())
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
}

//! Shared test fixtures for unit tests inside the crate.

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct RepoFixture {
    pub root: tempfile::TempDir,
    pub repo_path: PathBuf,
    pub head: Option<String>,
}

impl RepoFixture {
    pub fn repo(&self) -> &Path {
        &self.repo_path
    }
}

/// Create a throwaway git repository with one commit on `main`.
/// Panics are acceptable in tests only.
pub fn repo_fixture(name: &str) -> RepoFixture {
    let root = tempfile::Builder::new()
        .prefix(&format!("fdm-{name}-"))
        .tempdir()
        .expect("tempdir");
    let repo_path = root.path().join("project");
    std::fs::create_dir_all(&repo_path).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo_path)
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    run(&["init", "--quiet", "--initial-branch=main"]);
    std::fs::write(repo_path.join("hello.txt"), format!("hello from {name}\n")).unwrap();
    run(&["add", "."]);
    run(&["commit", "--quiet", "-m", "init"]);
    let head = {
        let out = run(&["rev-parse", "HEAD"]);
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    RepoFixture {
        root,
        repo_path,
        head,
    }
}

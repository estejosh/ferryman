//! Shared fixture for integration tests: a throwaway git repository.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct RepoFixture {
    pub root: tempfile::TempDir,
    pub repo_path: PathBuf,
}

impl RepoFixture {
    pub fn repo(&self) -> &Path {
        &self.repo_path
    }
}

pub fn repo_fixture(name: &str) -> RepoFixture {
    let root = tempfile::Builder::new()
        .prefix(&format!("fdm-it-{name}-"))
        .tempdir()
        .expect("tempdir");
    let repo_path = root.path().join("project");
    std::fs::create_dir_all(&repo_path).unwrap();
    git(&repo_path, &["init", "--quiet", "--initial-branch=main"]);
    std::fs::write(repo_path.join("hello.txt"), format!("hello from {name}\n")).unwrap();
    git(&repo_path, &["add", "."]);
    git(
        &repo_path,
        &["commit", "--quiet", "-m", "init", "--no-gpg-sign"],
    );
    RepoFixture { root, repo_path }
}

pub fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
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
}

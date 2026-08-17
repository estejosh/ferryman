//! Stamp the build's git commit into the binary.
//!
//! # Why this exists
//!
//! The first outside upgrade report closed with the sharpest finding in it: `ferry --version`
//! said `0.3.1` before the upgrade and `0.3.1` after it, across a day of changes. The task had
//! told that agent to check the version before trusting a download, and the one check it was
//! asked to perform could not work. It had to compare binary hashes and probe for the presence
//! of new subcommands to find out whether it had upgraded.
//!
//! A version bump fixes that at release boundaries. It does not fix it in between, which is
//! the normal case here: machines in this fleet build from `main`, so two builds days apart
//! legitimately share a version number. For a fleet, "did that machine get the new build?"
//! has to be answerable at any moment, not only just after a tag.
//!
//! So the commit goes in the binary. Failure is not fatal - a tarball with no `.git`, or a
//! machine with no `git`, still builds, and simply reports the version alone.

use std::process::Command;

fn main() {
    // Rebuild when HEAD moves, or this stays stale for the life of the target directory.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");

    let commit = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());

    // Whether the tree had uncommitted changes when this was built. A fleet debugging
    // "which build is this" needs to know that the answer is "not any commit at all".
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| !out.stdout.is_empty());

    let describe = match (commit, dirty) {
        (Some(commit), true) => format!(" ({commit}-dirty)"),
        (Some(commit), false) => format!(" ({commit})"),
        (None, _) => String::new(),
    };
    println!("cargo:rustc-env=FERRYMAN_BUILD={describe}");
}

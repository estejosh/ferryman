//! Stamp the build's release date, which is what a licence window is measured against.
//!
//! # Why the date and not the clock
//!
//! An offline licence with an expiry has one classic hole: the customer sets the system
//! clock back and the licence never ends. The usual fix is an activation server, which
//! Ferryman deliberately does not have.
//!
//! So the expiry is not measured against the clock at all. This stamps the release date
//! into the binary at compile time, and an entitlement covers every build released
//! while it was valid. The person holding the binary cannot move that date, moving their
//! clock achieves nothing, and staying on a build they were licensed for is explicitly
//! allowed rather than a loophole.
//!
//! The committer date rather than "now", so building the same commit twice gives the
//! same answer and a build is reproducible. Failure is never fatal: a tarball with no
//! `.git` stamps nothing, which reads as "no build date" and lets every entitlement
//! cover it - erring towards the customer.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");

    let built = Command::new("git")
        .args(["log", "-1", "--format=%cs"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());

    if let Some(built) = built {
        println!("cargo:rustc-env=FERRYMAN_BUILD_DATE={built}");
    }
}

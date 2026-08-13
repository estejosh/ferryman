//! What this machine's worker has actually been doing.
//!
//! # The gap this fills
//!
//! Ferryman's *audit* trail was never missing: every order, result and review is signed,
//! and `ferry channel log` shows them in order with who signed each one. That record is
//! stronger than a log, because a log can be edited and those cannot be, undetectably.
//!
//! What was missing is the *diagnostic* trail. The first outside user put it exactly:
//! work provably ran on their machine and left no record of having run. When the answer
//! to "why did nothing happen last night" is a signed artifact that does not exist, there
//! is nothing to look at at all - not the attempt, not the error, not the reason the loop
//! declined to claim.
//!
//! # Why it is local, and never synced
//!
//! This carries local paths, local errors and whatever the agent CLI printed to stderr.
//! None of that belongs on other people's machines, and a log in the channel would break
//! the one-writer rule the moment two machines wrote a line at the same time.
//!
//! It cannot leak by construction rather than by rule: the synced fleet folder is
//! `<machine state>/fleet`, and this file is its *sibling* at `<machine state>/worker.log`
//! - outside every directory Ferryman ever hands to Syncthing.
//!
//! # Why it is a plain file
//!
//! No rotation daemon, no logging framework, no configuration. One file, capped, with the
//! previous generation kept beside it. A diagnostic aid whose own failure modes need
//! diagnosing has missed the point.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::Progress;

/// Roll over at a megabyte, keeping one previous generation.
///
/// Small enough that the whole thing can be read at once when something is wrong, large
/// enough to hold days of an idle loop. Two files means a rollover mid-incident does not
/// take the evidence with it.
const MAX_BYTES: u64 = 1024 * 1024;

/// Where this machine records what its worker did.
#[must_use]
pub fn path() -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("worker.log"))
}

/// Append one line, with the time it happened.
///
/// Every failure here is swallowed on purpose. A full disk, a read-only directory or a
/// vanished parent must not stop an agent doing its work: losing a log line is a much
/// smaller harm than a fleet that stops because it could not describe itself.
pub fn append(level: &str, message: &str) {
    let Some(path) = path() else { return };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > MAX_BYTES) {
        let _ = fs::rename(&path, path.with_extension("log.1"));
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(
            file,
            "{} {level:<5} {message}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%SZ")
        );
    }
}

/// The last `lines` lines, oldest first.
///
/// Reads the whole file rather than seeking backwards: it is capped at a megabyte, and
/// the version of this that seeks is the version with an off-by-one nobody notices until
/// they are already debugging something else.
#[must_use]
pub fn tail(lines: usize) -> Vec<String> {
    let Some(path) = path() else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..]
        .iter()
        .map(|line| (*line).to_string())
        .collect()
}

/// Reports to the terminal *and* to the log.
///
/// This is what the `Progress` trait was separated out for: the worker loop describes
/// what it is doing once, and the caller decides where that goes. The loop itself did not
/// change to gain a log.
pub struct Logged<P> {
    pub inner: P,
}

impl<P: Progress> Progress for Logged<P> {
    fn info(&self, message: &str) {
        append("info", message);
        self.inner.info(message);
    }
    fn warn(&self, message: &str) {
        append("warn", message);
        self.inner.warn(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hermetic() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferryman-runlog-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("main")
                .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
        ));
        let _ = fs::create_dir_all(&dir);
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir);
        path().expect("a machine state directory was just set")
    }

    #[test]
    fn a_line_is_written_and_can_be_read_back() {
        let file = hermetic();
        let _ = fs::remove_file(&file);
        append("info", "claimed t-1");
        let lines = tail(10);
        assert_eq!(lines.len(), 1, "one line in, one line out");
        assert!(
            lines[0].contains("claimed t-1"),
            "the message must survive: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("info"),
            "and so must the level: {}",
            lines[0]
        );
    }

    #[test]
    fn logging_never_fails_even_with_nowhere_to_write() {
        // The property that matters: an agent must keep working when the log cannot be
        // written. This asserts the absence of a panic and of an error return, which is
        // the entire contract.
        append("info", "this may go nowhere, and that is fine");
    }
}

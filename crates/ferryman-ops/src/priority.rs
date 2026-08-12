//! Start the agent's process below the desk, not on it.
//!
//! # Why this exists
//!
//! Ferryman itself is not heavy - the worker loop idles at about 5 MB resident with one
//! thread. What it *starts* is heavy: an agent CLI is usually a Node process measured in
//! hundreds of megabytes, and a local model is measured in gigabytes. So when a machine
//! becomes unusable while Ferryman is running, the process eating it is Ferryman's
//! child, and to anyone reading a task manager that is a distinction without a
//! difference.
//!
//! Lowering the child's priority is the smallest thing that helps and the only one with
//! no failure mode. It needs no configuration, no thresholds and no policy: the agent
//! gets whatever the machine is not otherwise using, and yields the moment its operator
//! touches the keyboard. Nothing is capped, so no task can be starved to death; the work
//! just takes longer while someone is at the machine, which is the correct trade.
//!
//! # Why it is best-effort
//!
//! Every call here is allowed to fail silently. A machine where the priority cannot be
//! lowered should still run the agent at normal priority - refusing to work because a
//! nicety is unavailable would be a far worse bug than the one this fixes.
//!
//! # Why no `unsafe`
//!
//! The obvious Unix implementation is `setpriority` in a `pre_exec` hook, which is
//! `unsafe`, and this crate forbids that. Instead the child is spawned normally and
//! renice'd afterwards. That also keeps the spawn itself untouched, so
//! "is it installed and on PATH?" still comes from the agent command rather than from a
//! wrapper - a diagnosis the first outside user specifically relied on.

/// Windows: run the child in the below-normal priority class.
///
/// Applied at spawn through the documented safe `CommandExt` hook, so unlike the Unix
/// path there is no window in which the child runs at full priority.
#[cfg(windows)]
pub const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;

/// Ask the operating system to move a running child out of the foreground.
///
/// Unix only; on Windows the priority class is set at spawn instead. Both `renice` and
/// `ionice` are best-effort and their failures are deliberately ignored: neither exists
/// everywhere, and neither is worth an error.
#[cfg(unix)]
pub fn lower(pid: u32) {
    use std::process::{Command, Stdio};

    let quiet = |program: &str, args: &[&str]| {
        let _ = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };

    let pid = pid.to_string();
    // +10 is the conventional "background work" nice level: clearly yielding, without
    // being so far down that the agent makes no progress on a busy machine.
    quiet("renice", &["-n", "10", "-p", &pid]);
    // Class 3 is the idle I/O class. An agent that reads a repository should not make
    // someone else's editor wait for the disk.
    quiet("ionice", &["-c", "3", "-p", &pid]);
}

#[cfg(not(unix))]
pub fn lower(_pid: u32) {}

#[cfg(test)]
mod tests {
    /// Lowering our own priority must never fail, and must never panic, whatever the
    /// platform provides. The point of the test is the absence of an error path.
    #[test]
    fn lowering_is_always_safe_to_call() {
        super::lower(std::process::id());
        super::lower(u32::MAX); // a pid that cannot exist
    }

    /// The unit test above only proves nothing panics. This proves the child's priority
    /// actually moved - the thing that would silently stop working if `renice` changed
    /// its flags or vanished from the image.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_spawned_child_really_ends_up_at_a_lower_priority() {
        use std::process::{Command, Stdio};

        let mut child = match Command::new("sleep")
            .arg("5")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return, // no `sleep`; nothing to assert about this machine
        };

        let before = nice_of(child.id());
        super::lower(child.id());
        let after = nice_of(child.id());
        let _ = child.kill();
        let _ = child.wait();

        // `renice` is best-effort by design; if the field cannot be read there is
        // nothing to assert, and failing here would make the suite depend on the
        // container's tooling rather than on Ferryman.
        if let (Some(before), Some(after)) = (before, after) {
            assert!(
                after > before,
                "the child should have been moved down: before {before}, after {after}"
            );
        }
    }

    /// The nice value out of `/proc/<pid>/stat`, which is field 19 counting from one -
    /// read after the last `)` because the second field is a command name that may
    /// itself contain spaces and parentheses.
    #[cfg(target_os = "linux")]
    fn nice_of(pid: u32) -> Option<i64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let tail = &stat[stat.rfind(')')? + 1..];
        tail.split_whitespace().nth(16)?.parse().ok()
    }
}

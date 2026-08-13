//! Whether this machine can take on work right now.
//!
//! # The rule
//!
//! **The gate runs before claiming. Never during.**
//!
//! Once an agent has claimed a task and started, it runs to completion. Ferryman does
//! not suspend it, does not throttle it and does not kill it to free resources - the work
//! is in flight and the result would be lost, which is a worse outcome than a slow
//! machine. All backpressure happens at the claim boundary, where the cost of waiting is
//! nothing because nothing has started yet.
//!
//! That is what makes this safe to have on by default. The worst case is that a task
//! waits, and waiting is already the normal state of an unclaimed task.
//!
//! # Why memory, and why free rather than total
//!
//! Lowering the agent's priority (see [`crate::priority`]) stops it fighting the desktop
//! for CPU and disk. It does nothing about memory: a local model that wants eight
//! gigabytes will take eight gigabytes at any priority, and the machine falls over
//! anyway. Priority fixes *unresponsive*. Only declining to start fixes *out of memory*.
//!
//! The check is on memory the OS reports as **available** rather than free, because free
//! excludes reclaimable cache and would read as catastrophic on a perfectly healthy
//! machine.
//!
//! # Why this cannot strand a fleet
//!
//! A machine that declines does not fail the task or mark it in any way - it simply does
//! not claim, so the task stays open and another machine can take it. On a fleet, memory
//! pressure becomes placement. On a single machine it becomes a delay, which is the
//! honest outcome when there is genuinely no room to work.

use std::time::Duration;

use crate::agent::AgentConfig;

/// Whether a person is using this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Someone touched the keyboard or mouse this recently.
    Active(Duration),
    /// There is no desktop session to ask about - a server, a container, a machine
    /// nobody is sitting at. **Never a reason to pause**: the machines most likely to
    /// report this are the ones whose whole job is running agents unattended.
    Unknown,
}

/// Where a deliberate pause is recorded.
///
/// A file rather than a running service or a socket: the tray application, the CLI and
/// the worker loop are three separate processes that may not all be running, and a file
/// is the only thing all three can agree on without any of them having to be up. It also
/// means `ferry pause` works on a machine that has no tray at all, and that a pause
/// survives a reboot - which is what someone who paused it meant.
///
/// Machine-wide, not per project: "stop working on this computer" is the thing people
/// actually want, and pausing one repository while another keeps going is a surprise.
#[must_use]
pub fn pause_marker() -> Option<std::path::PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("paused"))
}

/// Why this machine was paused, if it was.
#[must_use]
pub fn paused() -> Option<String> {
    let path = pause_marker()?;
    let note = std::fs::read_to_string(&path).ok()?;
    let note = note.trim();
    Some(if note.is_empty() {
        "paused".to_string()
    } else {
        note.to_string()
    })
}

/// How long since the last keyboard or mouse input.
///
/// The obvious crates for this link X11 at build time and fail to compile on a headless
/// Linux box - which is a machine this product is specifically for. This one speaks the
/// X11 protocol in Rust rather than linking the C library, so it builds anywhere and
/// simply reports at runtime that there is no display to ask.
#[must_use]
pub fn presence() -> Presence {
    match system_idle_time::get_idle_time() {
        Ok(idle) => Presence::Active(idle),
        Err(_) => Presence::Unknown,
    }
}

/// What the loop should do, and - when the answer is no - what to tell the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// There is room. Claim.
    Go,
    /// There is not. The string is written to be read by a person, because its only
    /// consumers are a log line and, later, a tray menu. A structured enum here would
    /// need a new variant every time a reason is added, and every caller would only ever
    /// format it into a sentence anyway.
    Wait(String),
}

impl Decision {
    #[must_use]
    pub fn is_go(&self) -> bool {
        matches!(self, Decision::Go)
    }
}

/// Memory the operating system says is available, in megabytes.
///
/// `None` means it could not be determined, which is deliberately **not** treated as a
/// reason to wait: a machine whose memory cannot be read must still be able to work.
/// Refusing on missing information would turn a diagnostic gap into an outage.
#[must_use]
pub fn available_memory_mb() -> Option<u64> {
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    let available = system.available_memory();
    (available > 0).then_some(available / 1024 / 1024)
}

/// Decide whether to claim, given how much room the operator asked to keep free.
#[must_use]
pub fn may_claim(config: &AgentConfig) -> Decision {
    // A deliberate pause outranks everything. Someone said stop.
    if let Some(note) = paused() {
        return Decision::Wait(format!("{note} - run 'ferry resume' to start again"));
    }
    // Presence first: it is the cheap check, and it is the one whose answer a person
    // recognises as being about them.
    if config.pause_while_active {
        let decision = judge_presence(presence(), config.idle_after);
        if !decision.is_go() {
            return decision;
        }
    }
    judge(config.min_free_ram_mb, available_memory_mb())
}

/// Whether someone being at the machine should stop it taking on more.
fn judge_presence(presence: Presence, idle_after: Duration) -> Decision {
    match presence {
        // No session to ask about. A server has nobody to get in the way of.
        Presence::Unknown => Decision::Go,
        Presence::Active(idle) if idle >= idle_after => Decision::Go,
        Presence::Active(idle) => Decision::Wait(format!(
            "you used this machine {}s ago; work resumes after {}s idle, and anything \
             already running is unaffected (pause_while_active in agent.toml)",
            idle.as_secs(),
            idle_after.as_secs()
        )),
    }
}

/// The decision, separated from where its inputs come from, so the thresholds can be
/// tested without a machine that happens to be short of memory.
fn judge(min_free_mb: u64, available_mb: Option<u64>) -> Decision {
    if min_free_mb == 0 {
        return Decision::Go; // explicitly disabled
    }
    match available_mb {
        None => Decision::Go,
        Some(available) if available >= min_free_mb => Decision::Go,
        Some(available) => Decision::Wait(format!(
            "{available} MB of memory available, which is under the {min_free_mb} MB this \
             agent keeps free; the task stays open for another machine \
             (min_free_ram_mb in agent.toml)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn someone_at_the_keyboard_stops_new_work() {
        let Decision::Wait(reason) = judge_presence(
            Presence::Active(Duration::from_secs(5)),
            Duration::from_secs(300),
        ) else {
            panic!("input five seconds ago should hold work back")
        };
        assert!(
            reason.contains("already running is unaffected"),
            "the reason must say what is NOT interrupted: {reason}"
        );
    }

    #[test]
    fn a_machine_left_alone_gets_on_with_it() {
        assert_eq!(
            judge_presence(
                Presence::Active(Duration::from_secs(600)),
                Duration::from_secs(300)
            ),
            Decision::Go
        );
    }

    #[test]
    fn a_machine_with_nobody_at_it_never_pauses() {
        // Servers and containers report Unknown. They are the machines whose entire job
        // is running agents unattended, so treating "no session" as "someone is here"
        // would stop work exactly where it should never stop.
        assert_eq!(
            judge_presence(Presence::Unknown, Duration::from_secs(300)),
            Decision::Go
        );
    }

    #[test]
    fn plenty_of_room_means_go() {
        assert_eq!(judge(1024, Some(8000)), Decision::Go);
        assert_eq!(
            judge(1024, Some(1024)),
            Decision::Go,
            "at the line is still fine"
        );
    }

    #[test]
    fn too_little_room_waits_and_says_why() {
        let Decision::Wait(reason) = judge(2048, Some(500)) else {
            panic!("500 MB available against a 2048 MB floor should wait")
        };
        assert!(
            reason.contains("500"),
            "the reason must carry the number: {reason}"
        );
        assert!(
            reason.contains("min_free_ram_mb"),
            "the reason must name the setting that changes it: {reason}"
        );
    }

    #[test]
    fn zero_disables_the_check() {
        assert_eq!(judge(0, Some(1)), Decision::Go);
    }

    #[test]
    fn unknown_memory_never_blocks_work() {
        // A machine whose memory cannot be read must still be able to work. Treating
        // missing information as a reason to refuse turns a diagnostic gap into an
        // outage, and this is the assertion that stops someone "hardening" it later.
        assert_eq!(judge(4096, None), Decision::Go);
    }

    #[test]
    fn the_real_machine_reports_something_plausible() {
        if let Some(mb) = available_memory_mb() {
            assert!(mb > 0, "available memory should be a positive number of MB");
        }
    }

    /// sysinfo has changed its memory units between major versions - it used to report
    /// kilobytes and now reports bytes. Getting that wrong by a factor of 1024 would make
    /// the gate refuse every claim on a healthy machine, and nothing else here would
    /// notice. So the reading is checked against the kernel rather than trusted.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_reading_agrees_with_the_kernel() {
        let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
            return;
        };
        let Some(line) = meminfo.lines().find(|l| l.starts_with("MemAvailable:")) else {
            return;
        };
        let Some(kb) = line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok())
        else {
            return;
        };
        let Some(ours) = available_memory_mb() else {
            return;
        };
        let kernel_mb = kb / 1024;
        let drift = ours.abs_diff(kernel_mb);
        assert!(
            drift < kernel_mb / 5 + 64,
            "available memory should track the kernel: ours {ours} MB, kernel {kernel_mb} MB"
        );
    }
}

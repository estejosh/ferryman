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

use anyhow::{Context, Result, bail};
use chrono::{NaiveTime, Timelike};

use crate::agent::AgentConfig;

/// Hours of the day during which this machine will pick work up.
///
/// # Why a machine has opening hours
///
/// Several unrelated reasons, none of which Ferryman needs to know about:
/// electricity that is cheaper overnight, a metered connection with a free window, a
/// desktop that shares a room with someone asleep, an inference provider that discounts
/// off-peak hours. All of them are the same instruction - *take work between these
/// times* - so there is one setting rather than four, and no vendor is named anywhere.
///
/// # It is not a kill switch
///
/// Like every other check here it runs only before a claim. Work started inside the
/// window and still going when the window closes runs to completion; the alternative is
/// throwing away an hour of finished work to save a few cents of tokens.
///
/// # Local time by default, and why the suffix exists
///
/// "Don't run at 2am" is a statement about the clock on the wall. "The discount is
/// 16:30-00:30 UTC" is not. Guessing wrong either way produces a machine that works at
/// exactly the hours the operator asked it not to, and the failure is silent because a
/// window that is off by eight hours looks exactly like a window that is working - so the
/// operator says which they meant by appending `UTC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    start: NaiveTime,
    end: NaiveTime,
    /// Interpret against UTC rather than this machine's local time.
    utc: bool,
}

impl Window {
    /// Parse `HH:MM-HH:MM`, optionally followed by `UTC`.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let (span, utc) = match value
            .strip_suffix("UTC")
            .or_else(|| value.strip_suffix("utc"))
        {
            Some(span) => (span.trim_end(), true),
            None => (value, false),
        };
        let (start, end) = span
            .split_once('-')
            .with_context(|| format!("a window looks like '22:00-06:00', not '{value}'"))?;
        let time = |raw: &str| -> Result<NaiveTime> {
            NaiveTime::parse_from_str(raw.trim(), "%H:%M")
                .with_context(|| format!("'{}' is not a time of day like 09:30", raw.trim()))
        };
        let (start, end) = (time(start)?, time(end)?);
        if start == end {
            // Ambiguous between "always" and "never", and both readings are defensible.
            // Refusing costs the operator one edit; guessing costs them a night of work
            // or a night of noise, and they find out the next morning.
            bail!(
                "a window that starts and ends at the same time is ambiguous - remove it to work at any hour"
            );
        }
        Ok(Self { start, end, utc })
    }

    /// Whether `now` falls inside, handling a window that crosses midnight.
    ///
    /// The overnight case is the common one - cheap electricity and quiet houses are both
    /// nocturnal - so it is the case the arithmetic is arranged around rather than an
    /// afterthought. Half-open: the closing minute is outside, so `00:00-12:00` and
    /// `12:00-00:00` between them cover the day exactly once.
    #[must_use]
    fn contains(&self, now: NaiveTime) -> bool {
        if self.start <= self.end {
            now >= self.start && now < self.end
        } else {
            now >= self.start || now < self.end
        }
    }

    /// The current time of day, in whichever frame this window is expressed in.
    #[must_use]
    fn now(&self) -> NaiveTime {
        if self.utc {
            chrono::Utc::now().time()
        } else {
            chrono::Local::now().time()
        }
    }

    /// As the operator wrote it, for the message that explains a refusal.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{:02}:{:02}-{:02}:{:02}{}",
            self.start.hour(),
            self.start.minute(),
            self.end.hour(),
            self.end.minute(),
            if self.utc { " UTC" } else { " local time" }
        )
    }
}

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
    // The window before presence. Both can be true at once, and "this machine only works
    // overnight" is the more useful thing to be told at three in the afternoon than "you
    // are typing" - the second is temporary and obvious, the first is a setting somebody
    // configured a month ago and has forgotten.
    let window = judge_window(config.claim_window, config.claim_window.map(|w| w.now()));
    if !window.is_go() {
        return window;
    }
    // Presence next: it is the cheap check, and it is the one whose answer a person
    // recognises as being about them.
    if config.pause_while_active {
        let decision = judge_presence(presence(), config.idle_after);
        if !decision.is_go() {
            return decision;
        }
    }
    judge(config.min_free_ram_mb, available_memory_mb())
}

/// Whether the clock allows a claim. Separated from reading the clock so the boundaries
/// can be tested at midnight without waiting until midnight.
fn judge_window(window: Option<Window>, now: Option<NaiveTime>) -> Decision {
    let (Some(window), Some(now)) = (window, now) else {
        // No window configured means every hour is a working hour, which is what every
        // deployment that has never heard of this setting already does.
        return Decision::Go;
    };
    if window.contains(now) {
        return Decision::Go;
    }
    Decision::Wait(format!(
        "outside this machine's working hours of {}; the task stays open for another \
         machine, and anything already running is unaffected (claim_window in agent.toml)",
        window.describe()
    ))
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

    fn at(hour: u32, minute: u32) -> NaiveTime {
        NaiveTime::from_hms_opt(hour, minute, 0).expect("a valid time of day")
    }

    #[test]
    fn a_window_that_crosses_midnight_is_the_one_that_must_work() {
        // Cheap electricity, quiet houses and off-peak inference are all nocturnal, so
        // the wrapping case is the normal case rather than an edge one. The naive
        // implementation - start <= now && now < end - is false for every hour of this.
        let overnight = Window::parse("22:00-06:00").unwrap();
        assert!(overnight.contains(at(23, 0)), "before midnight");
        assert!(overnight.contains(at(2, 0)), "after midnight");
        assert!(
            overnight.contains(at(22, 0)),
            "the opening minute is inside"
        );
        assert!(
            !overnight.contains(at(6, 0)),
            "the closing minute is outside"
        );
        assert!(
            !overnight.contains(at(12, 0)),
            "the middle of the day is out"
        );
    }

    #[test]
    fn a_daytime_window_is_the_simple_case_and_still_has_to_be_right() {
        let daytime = Window::parse("09:00-17:00").unwrap();
        assert!(daytime.contains(at(9, 0)));
        assert!(daytime.contains(at(16, 59)));
        assert!(!daytime.contains(at(17, 0)));
        assert!(!daytime.contains(at(3, 0)));
    }

    #[test]
    fn back_to_back_windows_cover_the_day_exactly_once() {
        // Half-open at the close, so no minute is both inside two windows and outside
        // both. This is the assertion that catches someone "fixing" the boundary to <=.
        let morning = Window::parse("00:00-12:00").unwrap();
        let afternoon = Window::parse("12:00-00:00").unwrap();
        for hour in 0..24 {
            let now = at(hour, 0);
            assert_ne!(
                morning.contains(now),
                afternoon.contains(now),
                "{hour}:00 must be in exactly one of the two"
            );
        }
    }

    #[test]
    fn the_time_frame_is_stated_rather_than_guessed() {
        assert_eq!(
            Window::parse("16:30-00:30 UTC").unwrap().describe(),
            "16:30-00:30 UTC"
        );
        // The default is local, because "not at 2am" is a statement about the clock on
        // the wall, and the operator who meant UTC is the one who knows they did.
        assert_eq!(
            Window::parse("22:00-06:00").unwrap().describe(),
            "22:00-06:00 local time"
        );
    }

    #[test]
    fn an_ambiguous_or_malformed_window_is_refused_at_config_load() {
        // Refusing costs one edit. Guessing costs a night of work or a night of noise,
        // discovered the next morning.
        assert!(
            Window::parse("09:00-09:00")
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        assert!(Window::parse("22:00").is_err(), "no end time");
        assert!(Window::parse("22-06").is_err(), "not HH:MM");
        assert!(Window::parse("25:00-06:00").is_err(), "not a real hour");
    }

    #[test]
    fn no_window_means_every_hour_is_a_working_hour() {
        // Every existing deployment has no window, and none of them should change
        // behaviour by a single minute because this feature was added.
        assert_eq!(judge_window(None, None), Decision::Go);
    }

    #[test]
    fn outside_the_window_waits_and_names_the_setting() {
        let window = Window::parse("22:00-06:00").unwrap();
        let Decision::Wait(reason) = judge_window(Some(window), Some(at(14, 0))) else {
            panic!("two in the afternoon is outside an overnight window")
        };
        assert!(
            reason.contains("22:00-06:00 local time"),
            "the reason must state the window, in the frame it was written in: {reason}"
        );
        assert!(
            reason.contains("claim_window"),
            "the reason must name the setting that changes it: {reason}"
        );
        assert!(
            reason.contains("already running is unaffected"),
            "a closing window must not read as though it kills work: {reason}"
        );
        assert_eq!(judge_window(Some(window), Some(at(23, 0))), Decision::Go);
    }

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

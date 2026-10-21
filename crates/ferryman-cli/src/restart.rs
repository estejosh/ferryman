//! Coming back by itself after the worker stops to take an update.
//!
//! # The problem
//!
//! A long-running worker that has installed a newer binary stops between passes, because the
//! process still running is the old code. It used to stop with exit status 0, and a
//! supervisor set to `Restart=on-failure` (systemd) or "restart on failure" (a Windows
//! scheduled task) reads status 0 as "finished on purpose" and leaves it stopped. With no
//! supervisor at all it stays stopped too. A machine that auto-updated therefore sat idle
//! until someone noticed.
//!
//! # What it does now
//!
//! The worker asks to be restarted ([`ask`]) instead of just returning, and `main` carries
//! it out ([`perform`]) once everything is dropped (locks released, the lane closed):
//!
//! - **Unix**: `exec` the binary at the same path with the same arguments and environment.
//!   Same process id, so a supervisor sees one unbroken process, and with no supervisor the
//!   worker is simply running again. If the `exec` fails, exit [`EXIT_RESTART`] so a
//!   supervisor that restarts on failure does the job.
//! - **Windows, under a supervisor** (the scheduled-task wrapper sets
//!   `FERRYMAN_SUPERVISED`): exit [`EXIT_RESTART`] (75, `EX_TEMPFAIL`). The wrapper passes the
//!   exit code on, the task's restart-on-failure policy sees a failure and starts the worker
//!   again within a minute. Documented in docs/FLEET_SETUP.md. Spawning a child here instead
//!   would fight the task for the worker lock and could be killed with the task.
//! - **Windows, with no supervisor**: start the same command line as a detached process that
//!   waits a few seconds (so this process has exited and released its locks), then exit 0.
//!
//! # The guard
//!
//! A restart that goes wrong (an update that never finishes installing, a binary that
//! crashes on start and re-triggers the update check) must not become a loop. Every request
//! is recorded in `reexec.json` in the machine state directory, and more than
//! [`MAX_PER_HOUR`] in an hour is refused: the worker says so and keeps running the code it
//! has. The update check itself is rate limited to once in six hours, so this is the second
//! line, not the first.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// The exit status that means "stopped to be started again": `EX_TEMPFAIL`. Anything but 0
/// reads as a failure to a supervisor that restarts on failure.
pub const EXIT_RESTART: u8 = 75;

/// Most restarts the worker will ask for in any rolling hour.
pub const MAX_PER_HOUR: usize = 3;

/// The file, in the machine state directory, that remembers when restarts were asked for.
pub const STATE_FILE: &str = "reexec.json";

/// Set by a supervisor wrapper that restarts a non-zero exit (the Windows scheduled task).
pub const SUPERVISED_VAR: &str = "FERRYMAN_SUPERVISED";

/// Seconds a detached replacement waits before it starts, so the old process is gone.
pub const DELAY_VAR: &str = "FERRYMAN_REEXEC_DELAY_SECS";

static WANTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct History {
    #[serde(default)]
    at: Vec<DateTime<Utc>>,
}

/// Record a restart request in `dir` and say whether it may go ahead: false once
/// [`MAX_PER_HOUR`] have already been asked for in the last hour. A request that is refused
/// is not recorded, so the window empties by itself.
#[must_use]
pub fn allow(dir: &Path, now: DateTime<Utc>, max: usize) -> bool {
    let path = dir.join(STATE_FILE);
    let mut history: History = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let window = Duration::hours(1);
    history.at.retain(|at| now - *at < window && *at <= now);
    if history.at.len() >= max {
        return false;
    }
    history.at.push(now);
    let _ = std::fs::create_dir_all(dir);
    if let Ok(bytes) = serde_json::to_vec_pretty(&history) {
        let temp = path.with_extension("json.tmp");
        if std::fs::write(&temp, bytes).is_ok() {
            let _ = std::fs::rename(&temp, &path);
        }
    }
    true
}

/// How a restart is carried out on this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Replace the process image with the new binary (Unix).
    Exec,
    /// Exit [`EXIT_RESTART`] and let the supervisor start it (Windows task).
    ExitForSupervisor,
    /// Start a detached replacement and exit 0 (Windows with no supervisor).
    SpawnDetached,
}

/// The method for a platform and whether a supervisor that restarts on failure is known.
#[must_use]
pub fn method(unix: bool, supervised: bool) -> Method {
    if unix {
        Method::Exec
    } else if supervised {
        Method::ExitForSupervisor
    } else {
        Method::SpawnDetached
    }
}

/// The path to start again. On Linux a binary replaced while running is reported by the
/// kernel as `<path> (deleted)`; the new file is at the plain path.
#[must_use]
pub fn exe_to_start(reported: &Path) -> PathBuf {
    let text = reported.to_string_lossy();
    match text.strip_suffix(" (deleted)") {
        Some(plain) if !reported.exists() => PathBuf::from(plain),
        _ => reported.to_path_buf(),
    }
}

/// Ask for a restart after the worker returns, if the guard allows one. Returns whether the
/// worker should now stop; false means "carry on with the code you have".
#[must_use]
pub fn ask() -> bool {
    let Some(dir) = ferryman_channel::licensing::machine_state_dir() else {
        // Nowhere to keep the guard: restarting once is still better than staying stopped.
        WANTED.store(true, Ordering::SeqCst);
        return true;
    };
    if allow(&dir, Utc::now(), MAX_PER_HOUR) {
        WANTED.store(true, Ordering::SeqCst);
        true
    } else {
        false
    }
}

/// Whether [`ask`] succeeded and the process should restart on its way out.
#[must_use]
pub fn wanted() -> bool {
    WANTED.load(Ordering::SeqCst)
}

/// Wait out the replacement delay a detached restart asked for, at the start of a command.
pub fn honour_delay() {
    if let Some(seconds) = std::env::var(DELAY_VAR)
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_secs(seconds.min(30)));
    }
}

fn args() -> Vec<OsString> {
    std::env::args_os().skip(1).collect()
}

/// Carry out the restart. Only called when [`wanted`], after the worker has returned.
/// Returns the exit status to use when the process does not become the new one.
#[must_use]
pub fn perform() -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(path) => exe_to_start(&path),
        Err(error) => {
            eprintln!("cannot restart after the update ({error}); exiting {EXIT_RESTART}");
            return ExitCode::from(EXIT_RESTART);
        }
    };
    match method(
        cfg!(unix),
        std::env::var_os(SUPERVISED_VAR).is_some_and(|v| !v.is_empty() && v != "0"),
    ) {
        Method::Exec => exec(&exe),
        Method::ExitForSupervisor => {
            println!("restarting after the update: exiting {EXIT_RESTART} for the supervisor");
            ExitCode::from(EXIT_RESTART)
        }
        Method::SpawnDetached => spawn_detached(&exe),
    }
}

#[cfg(unix)]
fn exec(exe: &Path) -> ExitCode {
    use std::os::unix::process::CommandExt as _;
    println!("restarting after the update: {}", exe.display());
    let error = std::process::Command::new(exe)
        .args(args())
        .env_remove(DELAY_VAR)
        .exec();
    // Only reached when the exec failed.
    eprintln!(
        "could not start {}: {error}; exiting {EXIT_RESTART}",
        exe.display()
    );
    ExitCode::from(EXIT_RESTART)
}

#[cfg(not(unix))]
fn exec(_exe: &Path) -> ExitCode {
    ExitCode::from(EXIT_RESTART)
}

fn spawn_detached(exe: &Path) -> ExitCode {
    let mut command = std::process::Command::new(exe);
    command.args(args()).env(DELAY_VAR, "5");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW
        command.creation_flags(0x0000_0200 | 0x0000_0008 | 0x0800_0000);
    }
    match command.spawn() {
        Ok(_) => {
            println!(
                "restarting after the update: started a replacement from {}",
                exe.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "could not start {}: {error}; exiting {EXIT_RESTART}",
                exe.display()
            );
            ExitCode::from(EXIT_RESTART)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guard_allows_a_few_an_hour_and_then_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        for n in 0..MAX_PER_HOUR {
            let at = now + Duration::minutes(i64::try_from(n).unwrap());
            assert!(allow(dir.path(), at, MAX_PER_HOUR), "request {n}");
        }
        assert!(
            !allow(dir.path(), now + Duration::minutes(10), MAX_PER_HOUR),
            "a fourth in the hour is a loop"
        );
        // A refusal is not recorded, so the hour empties on its own.
        assert!(allow(dir.path(), now + Duration::minutes(61), MAX_PER_HOUR));
    }

    #[test]
    fn the_guard_survives_a_restart_of_the_process() {
        // The point of recording it in a file: the counter must outlive each exec.
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        assert!(allow(dir.path(), now, 1));
        assert!(!allow(dir.path(), now, 1));
        assert!(dir.path().join(STATE_FILE).is_file());
    }

    #[test]
    fn a_damaged_history_does_not_stop_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), "not json").unwrap();
        assert!(allow(dir.path(), Utc::now(), MAX_PER_HOUR));
    }

    #[test]
    fn a_clock_that_ran_ahead_does_not_hold_the_guard_shut() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        // Entries from the future (a clock set back) are dropped rather than counted forever.
        for n in 0..MAX_PER_HOUR {
            let future = now + Duration::days(1) + Duration::minutes(i64::try_from(n).unwrap());
            assert!(allow(dir.path(), future, MAX_PER_HOUR));
        }
        assert!(allow(dir.path(), now, MAX_PER_HOUR));
    }

    #[test]
    fn unix_execs_and_windows_depends_on_a_supervisor() {
        assert_eq!(method(true, false), Method::Exec);
        assert_eq!(method(true, true), Method::Exec);
        assert_eq!(method(false, true), Method::ExitForSupervisor);
        assert_eq!(method(false, false), Method::SpawnDetached);
    }

    #[test]
    fn the_restart_status_is_a_failure_to_a_supervisor() {
        assert_ne!(EXIT_RESTART, 0);
        assert_eq!(EXIT_RESTART, 75);
    }

    #[test]
    fn a_binary_replaced_while_running_is_started_at_its_plain_path() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("ferry");
        std::fs::write(&real, "new binary").unwrap();
        let reported = dir.path().join("ferry (deleted)");
        assert_eq!(exe_to_start(&reported), real);
        // A path that exists as reported is left alone, suffix or not.
        assert_eq!(exe_to_start(&real), real);
        // A plain path is never rewritten.
        let missing = dir.path().join("nothing");
        assert_eq!(exe_to_start(&missing), missing);
    }
}

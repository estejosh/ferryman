use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Distinct process exit codes, documented in the README.
#[derive(Debug)]
pub enum Error {
    /// Still time-locked; nothing is wrong. Exit code 3.
    Locked { round: u64, at: SystemTime },
    /// Waiting for the beacon exceeded the allowed budget. Exit code 3.
    WaitTimeout { round: u64 },
    /// Bad user input or missing prerequisites. Exit code 2.
    BadInput(String),
    /// No deadman state in the given repo. Exit code 2.
    NotArmed(PathBuf),
    /// Path is not a git repository. Exit code 2.
    NotAGitRepo(PathBuf),
    /// A git subprocess failed. Exit code 1.
    GitFailed { args: String, stderr: String },
    /// Data on disk is damaged or was modified after sealing.
    Corrupt(String),
    /// Filesystem error. Exit code 1.
    Io(std::io::Error),
    /// Serialization error. Exit code 1.
    Json(serde_json::Error),
    /// Everything else. Exit code 1.
    Other(String),
}

impl Error {
    /// Shorthand for [`Error::Other`] with a formatted message.
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Locked { round, at } => write!(
                f,
                "still time-locked: unlocks at beacon round {round} ({})",
                format_time(*at)
            ),
            Error::WaitTimeout { round } => {
                write!(
                    f,
                    "timed out waiting for beacon round {round} to become available"
                )
            }
            Error::BadInput(msg) => write!(f, "invalid input: {msg}"),
            Error::NotArmed(path) => {
                write!(
                    f,
                    "not armed: no .deadman state found under {}",
                    path.display()
                )
            }
            Error::NotAGitRepo(path) => write!(f, "{} is not a git repository", path.display()),
            Error::GitFailed { args, stderr } => {
                write!(f, "git {args} failed: {stderr}")
            }
            Error::Corrupt(msg) => write!(f, "corrupt data: {msg}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Json(e) => write!(f, "json error: {e}"),
            Error::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Locked { .. } | Error::WaitTimeout { .. } => 3,
            Error::BadInput(_) | Error::NotArmed(_) | Error::NotAGitRepo(_) => 2,
            Error::GitFailed { .. }
            | Error::Corrupt(_)
            | Error::Io(_)
            | Error::Json(_)
            | Error::Other(_) => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Current unix time in whole seconds.
pub fn unix_now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Other(format!("system clock before unix epoch: {e}")))?
        .as_secs() as i64)
}

/// SystemTime from unix seconds (never fails for sane values).
pub fn from_unix(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-secs) as u64)
    }
}

/// Human-readable UTC timestamp, no external time crate.
pub fn format_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Civil-from-days algorithm (Howard Hinnant).
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

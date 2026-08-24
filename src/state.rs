//! Persistent state in `<repo>/.deadman/state.json`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::artifact::write_atomic;
use crate::error::{Error, Result};

pub const STATE_DIR_NAME: &str = ".deadman";
pub const ARTIFACT_NAME: &str = "sealed-archive.tlock";
pub const STATE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Sim,
    Drand,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Sim => write!(f, "simulate"),
            Mode::Drand => write!(f, "drand"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u8,
    pub mode: Mode,
    #[serde(default)]
    pub beacon_url: Option<String>,
    #[serde(default)]
    pub chain_hash: Option<String>,
    pub period_secs: u64,
    /// Chain genesis (drand) or arm-time anchor (sim), unix seconds.
    pub genesis_unix: i64,
    /// When the switch was first armed.
    pub armed_unix: i64,
    pub window_secs: u64,
    /// Round at which the current artifact unlocks.
    pub unlock_round: u64,
    pub successor_fingerprint: String,
    pub include_secrets: bool,
    /// Last re-arm (heartbeat or arm) time.
    pub last_heartbeat_unix: i64,
    /// sha256 of the tar.gz archive sealed into the artifact.
    pub archive_sha256: String,
    /// sha256 of the git bundle inside that archive.
    pub bundle_sha256: String,
    #[serde(default)]
    pub head_sha256: Option<String>,
}

impl State {
    pub fn beacon(&self) -> crate::beacon::Beacon {
        match self.mode {
            Mode::Sim => crate::beacon::Beacon::sim(self.genesis_unix),
            Mode::Drand => crate::beacon::Beacon::Drand(crate::beacon::DrandParams {
                base_url: self
                    .beacon_url
                    .clone()
                    .unwrap_or_else(|| crate::beacon::DEFAULT_BEACON_BASES[0].to_string()),
                chain_hash: self
                    .chain_hash
                    .clone()
                    .unwrap_or_else(|| crate::beacon::QUICKNET_CHAIN_HASH.to_string()),
                // info is refetched when needed; store a stub here.
                info: crate::beacon::ChainInfo {
                    hash: self.chain_hash.clone().unwrap_or_default(),
                    public_key: String::new(),
                    period: self.period_secs,
                    genesis_time: self.genesis_unix,
                    scheme: String::new(),
                    metadata: None,
                },
            }),
        }
    }

    pub fn window_display(&self) -> String {
        crate::duration::format_window(self.window_secs)
    }
}

pub fn state_dir(repo: &Path) -> PathBuf {
    repo.join(STATE_DIR_NAME)
}

pub fn state_path(repo: &Path) -> PathBuf {
    state_dir(repo).join("state.json")
}

pub fn artifact_path(repo: &Path) -> PathBuf {
    state_dir(repo).join(ARTIFACT_NAME)
}

/// Load state; missing file maps to `Error::NotArmed`.
pub fn load(repo: &Path) -> Result<State> {
    let path = state_path(repo);
    if !path.exists() {
        return Err(Error::NotArmed(repo.to_path_buf()));
    }
    let bytes = std::fs::read(&path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Corrupt(format!("{} is corrupt: {e}", path.display())))
}

/// Persist state atomically.
pub fn save(repo: &Path, state: &State) -> Result<()> {
    let json = serde_json::to_vec_pretty(state)?;
    write_atomic(&state_path(repo), &json)
}

/// Best-effort: keep `.deadman/` out of the user's repo without touching any
/// tracked file — append to `.git/info/exclude` (local-only ignore).
pub fn exclude_from_git_index(repo: &Path) {
    if !crate::beacon::is_git_repo(repo) {
        return;
    }
    let Ok(gitdir) = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
    else {
        return;
    };
    if !gitdir.status.success() {
        return;
    }
    let exclude = PathBuf::from(String::from_utf8_lossy(&gitdir.stdout).trim())
        .join("info")
        .join("exclude");
    let already_excluded = std::fs::read_to_string(&exclude)
        .map(|existing| existing.lines().any(|l| l.trim() == STATE_DIR_NAME))
        .unwrap_or(false);
    if already_excluded {
        return;
    }
    let _ = std::fs::create_dir_all(exclude.parent().unwrap_or(Path::new(".")));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&exclude)
    {
        use std::io::Write as _;
        let _ = writeln!(f, "{STATE_DIR_NAME}/");
    }
}

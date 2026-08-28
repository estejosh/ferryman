//! Persistent state in `<repo>/.deadman/state.json`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::artifact::write_atomic;
use crate::error::{Error, Result};

pub const STATE_DIR_NAME: &str = ".deadman";
/// Artifact filename when the config names exactly one successor without an
/// explicit name (the common case; matches v1 layouts).
pub const ARTIFACT_NAME: &str = "sealed-archive.tlock";
pub const STATE_VERSION: u8 = 2;

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

/// A successor as recorded at seal time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuccessorRecord {
    pub name: String,
    /// sha256 commitment of the successor key (or name when no key given).
    pub fingerprint: String,
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
    /// Round at which the current artifacts unlock.
    pub unlock_round: u64,
    /// One record per sealed copy on disk.
    pub successors: Vec<SuccessorRecord>,
    pub include_secrets: bool,
    /// Extra globs archived beside the bundle (recorded verbatim).
    #[serde(default)]
    pub include_globs: Vec<String>,
    /// Replacement archiver argv, when configured.
    #[serde(default)]
    pub archive_argv: Option<Vec<String>>,
    /// When the trigger hook last fired for this armed cycle.
    #[serde(default)]
    pub notified_trigger_unix: Option<i64>,
    /// Last re-arm (heartbeat or arm) time.
    pub last_heartbeat_unix: i64,
    /// sha256 of the tar.gz archive sealed into the artifacts.
    pub archive_sha256: String,
    /// sha256 of the git bundle inside that archive (None for custom archivers).
    #[serde(default)]
    pub bundle_sha256: Option<String>,
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

    /// Filename of the sealed copy belonging to `succ`.
    pub fn artifact_name_for(succ: &SuccessorRecord) -> String {
        if succ.name.is_empty() {
            return ARTIFACT_NAME.to_string();
        }
        format!("sealed-{}.tlock", slug(&succ.name))
    }

    /// All artifact files currently expected from this state.
    pub fn artifact_names(&self) -> Vec<String> {
        self.successors
            .iter()
            .map(Self::artifact_name_for)
            .collect()
    }
}

/// Filesystem-safe identifier: lowercase, [a-z0-9._-] only, non-empty.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches(['-', '.']).to_string();
    if trimmed.is_empty() {
        "successor".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

pub fn state_dir(repo: &Path) -> PathBuf {
    repo.join(STATE_DIR_NAME)
}

pub fn state_path(repo: &Path) -> PathBuf {
    state_dir(repo).join("state.json")
}

pub fn artifact_path(repo: &Path, name: &str) -> PathBuf {
    state_dir(repo).join(name)
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

/// Remove every `.tlock` file in the state dir whose name is not in `keep`.
/// Returns the removed paths (used by heartbeat pruning and tests).
pub fn prune_artifacts(repo: &Path, keep: &[String]) -> Result<Vec<PathBuf>> {
    let dir = state_dir(repo);
    let mut removed = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(removed),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if fname.ends_with(".tlock") && !keep.iter().any(|k| k == fname) {
            std::fs::remove_file(&path)?;
            removed.push(path);
        }
    }
    Ok(removed)
}

/// Best-effort: keep `.deadman/` and `deadman.toml` out of the user's repo
/// without touching any tracked file — append to `.git/info/exclude`.
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
        writeln!(f, "{STATE_DIR_NAME}/").ok();
        writeln!(f, "deadman.toml").ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_safe_and_stable() {
        assert_eq!(slug("Ada Lovelace"), "ada-lovelace");
        assert_eq!(slug("GRACE"), "grace");
        assert_eq!(slug("../evil"), "evil");
        assert_eq!(slug(""), "successor");
        assert_eq!(slug("   "), "successor");
        let long = "x".repeat(100);
        assert_eq!(slug(&long).len(), 64);
    }

    #[test]
    fn artifact_naming_single_unnamed_is_legacy() {
        let unnamed = SuccessorRecord {
            name: String::new(),
            fingerprint: "sha256:x".into(),
        };
        assert_eq!(
            State::artifact_name_for(&unnamed),
            ARTIFACT_NAME.to_string()
        );
        let named = SuccessorRecord {
            name: "ada".into(),
            fingerprint: "sha256:y".into(),
        };
        assert_eq!(
            State::artifact_name_for(&named),
            "sealed-ada.tlock".to_string()
        );
    }
}

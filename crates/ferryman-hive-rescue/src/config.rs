//! `[hive_rescue]` in `ferry.toml`, and the posting credentials (from the environment or a
//! secrets file, never from `ferry.toml`).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::tx::PostingKey;

/// Public API nodes, tried in turn. Reads trust none of them for content: every record is
/// signed.
pub const DEFAULT_NODES: [&str; 4] = [
    "https://api.hive.blog",
    "https://api.deathwing.me",
    "https://hive-api.arcange.eu",
    "https://api.openhive.network",
];

/// The operation id records are posted under.
pub const DEFAULT_OP_ID: &str = "ferryman-rescue";

/// What `[hive_rescue]` says. Off unless `enabled = true`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RescueConfig {
    pub enabled: bool,
    /// The fleet's Hive account: readers read its history, posters post under its
    /// authority. `HIVE_RESCUE_ACCOUNT` overrides.
    pub account: String,
    pub nodes: Vec<String>,
    pub op_id: String,
    /// Minutes cut off from the relay and every peer before the master posts.
    pub cut_off_minutes: u64,
    /// Minutes between a cut-off machine's reads of Hive.
    pub poll_minutes: u64,
    /// How long a record stays valid.
    pub expires_minutes: u64,
    /// While still cut off, post again this often so a fresh record is always there.
    /// 0: post once per cut-off.
    pub repost_minutes: u64,
    /// This machine is the designated backup poster (and not the master).
    pub backup: bool,
    /// A backup posts only when cut off this long AND no master record is this fresh.
    pub backup_after_minutes: u64,
    /// Names whose backup records readers accept.
    pub backup_agents: Vec<String>,
    /// A baseline post every this many hours. 0 (default): none.
    pub routine_hours: u64,
    /// Put direct IP addresses in the record. Off by default: the chain keeps it forever.
    pub include_direct_addresses: bool,
    /// The relay to use when the usual one is what is down.
    pub rescue_relay: Option<String>,
    /// Its certificate, 64 hex digits, when no public CA signs for it.
    pub rescue_relay_cert_sha256: Option<String>,
    /// A `KEY=VALUE` file holding `HIVE_RESCUE_*` (default: the process environment only).
    pub secrets_env: Option<PathBuf>,
}

impl Default for RescueConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            account: String::new(),
            nodes: DEFAULT_NODES.iter().map(|s| (*s).to_owned()).collect(),
            op_id: DEFAULT_OP_ID.to_owned(),
            cut_off_minutes: 15,
            poll_minutes: 3,
            expires_minutes: 60,
            repost_minutes: 45,
            backup: false,
            backup_after_minutes: 60,
            backup_agents: Vec::new(),
            routine_hours: 0,
            include_direct_addresses: false,
            rescue_relay: None,
            rescue_relay_cert_sha256: None,
            secrets_env: None,
        }
    }
}

impl RescueConfig {
    /// Read `[hive_rescue]` from `<root>/ferry.toml`. A missing section or file is the
    /// default (off); a section that does not parse is an error worth showing.
    ///
    /// # Errors
    /// The section exists and is not valid.
    pub fn load(root: &Path) -> anyhow::Result<Self> {
        #[derive(Deserialize, Default)]
        struct File {
            hive_rescue: Option<RescueConfig>,
        }
        let Ok(text) = std::fs::read_to_string(root.join("ferry.toml")) else {
            return Ok(Self::default());
        };
        let file: File =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("ferry.toml: {}", e.message()))?;
        Ok(file.hive_rescue.unwrap_or_default())
    }
}

/// What posting needs. Debug shows no secret.
pub struct Credentials {
    /// The fleet account (from the environment, else the config).
    pub account: String,
    /// This machine's own Hive account, when it posts under delegated authority.
    pub poster: Option<String>,
    pub key: Option<PostingKey>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("account", &self.account)
            .field("poster", &self.poster)
            .field("key", &self.key.as_ref().map(|_| "<set>"))
            .finish()
    }
}

fn from_env_file(path: &Path, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim();
        let (key, value) = line.split_once('=')?;
        (key.trim() == name).then(|| value.trim().trim_matches(['"', '\'']).to_owned())
    })
}

fn lookup(env_file: Option<&Path>, name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| env_file.and_then(|p| from_env_file(p, name)))
        .filter(|v| !v.is_empty())
}

impl Credentials {
    /// Load: `HIVE_RESCUE_ACCOUNT`, `HIVE_RESCUE_POSTER` (optional) and
    /// `HIVE_RESCUE_POSTING_KEY`, from the environment then `secrets_env`.
    ///
    /// # Errors
    /// A key is present and is not a valid WIF key (the text is not repeated).
    pub fn load(config: &RescueConfig) -> anyhow::Result<Self> {
        let file = config.secrets_env.as_deref();
        let key = match lookup(file, "HIVE_RESCUE_POSTING_KEY") {
            Some(wif) => Some(PostingKey::from_wif(&wif)?),
            None => None,
        };
        Ok(Self {
            account: lookup(file, "HIVE_RESCUE_ACCOUNT").unwrap_or_else(|| config.account.clone()),
            poster: lookup(file, "HIVE_RESCUE_POSTER"),
            key,
        })
    }
}

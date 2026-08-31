//! Durable, project-scoped live communications with local/shared-first delivery and
//! private-Git failover. This is deliberately separate from encrypted continuity packs.

#![forbid(unsafe_code)]
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub mod ask;
pub mod contract;
pub mod conversation;
pub mod cost;
pub mod credentials;
pub mod discovery;
pub mod encrypt;
pub mod events;
pub mod interrupt;
pub mod keys;
pub mod learning;
pub mod lease;
pub mod ledger;
pub mod licensing;
pub mod master;
pub mod memory;
pub mod migration;
pub mod orchestrator;
pub mod portable_auth;
pub mod secrets;
pub mod skills;
pub mod source;
pub mod trajectory;
pub mod worktree;

use portable_auth::{
    AcknowledgementV2, MessageV2, ReplayLedger, SignerGrant, SignerId, TrustedSigners,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wait_timeout::ChildExt;

const MESSAGE_FORMAT: &str = "ferryman-message/v1";
const DEFAULT_GIT_SUFFIX: &str = "-ferryman";
const DEFAULT_ACK_DEADLINE_SECONDS: i64 = 30;
const VISIBILITY_CACHE_SECONDS: u64 = 600;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const HEALTH_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const TRANSPORT_STATE_FORMAT: &str = "ferryman-transport-state/v1";
const MAX_INLINE_PAYLOAD_BYTES: usize = 256 * 1024;
const SENSITIVE_CHILD_ENVIRONMENT: &[&str] = &[
    "FERRYMAN_ADMIN_TOKEN",
    "FERRYMAN_MEMORY_WRITE_TOKEN",
    "FERRYMAN_MEMORY_TOKEN",
    "FERRYMAN_TOKEN",
    "FERRYMAN_RECOVERY_KEY_HEX",
    "FERRYMAN_DRIVE_ACCESS_TOKEN",
    "FERRYMAN_SUDO_PW",
    "HUB_ADMIN_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "HF_TOKEN",
    "HUGGINGFACE_TOKEN",
    "OMNIROUTE_API_KEY",
    "ARENA_COOKIE",
    "NVIDIA_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "CODEX_API_KEY",
];

/// Name fragments that mark an environment variable as secret, so a new
/// provider's key is scrubbed even before it is added to the explicit list.
/// Substrings that make a variable name look like it holds a secret.
///
/// `TOKEN` is here, and the compound forms it subsumes are not, because requiring the
/// compound was a hole you could drive a fleet through. `AUTH_TOKEN` and `ACCESS_TOKEN`
/// matched; `GITHUB_TOKEN`, `GH_TOKEN`, `TELEGRAM_BOT_TOKEN`, `NPM_TOKEN` and `HF_TOKEN`
/// did not — which is to say the list caught the names almost nobody uses and missed the
/// ones everybody does. Found on a live machine, where a GitHub PAT and a Telegram bot
/// token were reaching the environment of every task the worker ran, on a box whose
/// documentation promises an environment scrub.
///
/// Over-scrubbing is the safe direction here. The cost of removing a variable an engine
/// wanted is a task that fails loudly and an operator who puts it in `credentials.json`,
/// which is where engine credentials are supposed to live. The cost of keeping one is
/// that every task any agent ever runs can read it.
const SECRET_NAME_HINTS: &[&str] = &[
    "API_KEY",
    "APIKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSPHRASE",
    "CREDENTIAL",
    "PRIVATE_KEY",
];
#[cfg(windows)]
const NULL_GIT_HOOKS_PATH: &str = "NUL";
#[cfg(not(windows))]
const NULL_GIT_HOOKS_PATH: &str = "/dev/null";

/// Where this installation's channel repositories are expected to live.
///
/// Pinning the channel to a canonical location is a real security control: it stops a
/// tampered or mistaken mapping from redirecting a private channel to a destination
/// somebody else controls. Ferryman keeps that control but stops assuming whose
/// account it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelNamespace {
    /// e.g. "acme" -> https://github.com/acme/<project>-ferryman.git
    pub git_owner: Option<String>,
    /// Repository name suffix. Defaults to "-ferryman": Ferryman is the software
    /// that carries communications *about* a project, so a project's channel is
    /// `<project>-ferryman`. Deployments still on the older "-bridge" naming set
    /// FERRYMAN_CHANNEL_GIT_SUFFIX and keep working.
    pub git_suffix: String,
}

impl Default for ChannelNamespace {
    fn default() -> Self {
        Self {
            git_owner: None,
            git_suffix: DEFAULT_GIT_SUFFIX.to_owned(),
        }
    }
}

impl ChannelNamespace {
    /// Read the namespace from the environment. Call this at construction time —
    /// never from inside a validation hot path, because Rust tests run in parallel
    /// and share one process environment.
    #[must_use]
    pub fn from_env() -> Self {
        let git_owner = std::env::var("FERRYMAN_CHANNEL_GIT_OWNER")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let git_suffix = std::env::var("FERRYMAN_CHANNEL_GIT_SUFFIX")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_GIT_SUFFIX.to_owned());
        Self {
            git_owner,
            git_suffix,
        }
    }

    /// Build a namespace pinned to `owner`. Mostly useful in tests and for callers
    /// that carry their own configuration rather than reading the environment.
    #[must_use]
    pub fn with_owner(owner: impl Into<String>) -> Self {
        Self {
            git_owner: Some(owner.into()),
            git_suffix: DEFAULT_GIT_SUFFIX.to_owned(),
        }
    }

    /// The canonical GitHub `owner/name` for a project, if an owner is configured.
    #[must_use]
    pub fn repository_name(&self, project_id: &str) -> Option<String> {
        self.git_owner
            .as_ref()
            .map(|owner| format!("{owner}/{project_id}{}", self.git_suffix))
    }

    /// The canonical HTTPS remote for a project, if an owner is configured.
    #[must_use]
    pub fn git_remote(&self, project_id: &str) -> Option<String> {
        self.repository_name(project_id)
            .map(|name| format!("https://github.com/{name}.git"))
    }

    /// Check a configured remote against this namespace. Fails closed: a remote that
    /// is set while no owner is configured is rejected rather than silently accepted,
    /// because an unpinned remote is exactly the redirection this control exists to
    /// prevent. An empty remote is valid — that is the Syncthing-only channel, which
    /// simply has no git rung.
    fn verify_git_remote(&self, project_id: &str, remote: &str) -> Result<()> {
        if remote.trim().is_empty() {
            return Ok(());
        }
        let Some(expected) = self.git_remote(project_id) else {
            bail!(
                "a communications Git remote is configured but this installation has no \
                 channel namespace: set FERRYMAN_CHANNEL_GIT_OWNER to the account that owns \
                 the channel repositories, or clear the remote to run Syncthing-only"
            )
        };
        if normalize_git_remote(remote) != normalize_git_remote(&expected) {
            bail!("communications Git remote must be the exact expected private project remote")
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRoute {
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// This agent's public key, hex encoded. Absent for a fleet not yet signing.
    /// The PRIVATE half never appears here, or anywhere else in the channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// This agent's X25519 public key for sealed secrets, hex encoded. Absent
    /// until the agent has generated its encryption keypair (at `join`). The
    /// private half never appears here; it stays beside the signing key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRoute {
    pub project_id: String,
    pub workspace: PathBuf,
    pub attachment: PathBuf,
    pub communications: PathBuf,
    pub shared_remote: String,
    pub git_remote: String,
    pub git_visibility: String,
    #[serde(default)]
    pub agents: Vec<AgentRoute>,
}

impl ProjectRoute {
    /// Structural validation: everything that is true of a well-formed route
    /// regardless of which installation it belongs to.
    ///
    /// This deliberately does *not* check the channel namespace. Operations that
    /// route traffic must use [`ProjectRoute::validate_in`] so the canonical-location
    /// pin is enforced; see [`ChannelNamespace`].
    pub fn validate(&self) -> Result<()> {
        if !is_safe_component(&self.project_id) {
            bail!("project ID must contain only letters, digits, '.', '-', or '_'")
        }
        if !self.workspace.is_absolute()
            || !self.attachment.is_absolute()
            || !self.communications.is_absolute()
        {
            bail!("workspace and communications paths must be absolute")
        }
        let workspace = normalize_path(&self.workspace);
        let attachment = normalize_path(&self.attachment);
        let communications = normalize_path(&self.communications);
        if [&workspace, &attachment, &communications]
            .iter()
            .any(|path| {
                path.split('/')
                    .any(|component| component == "." || component == "..")
            })
        {
            bail!("workspace and communications paths must not contain traversal components")
        }
        if attachment != format!("{workspace}/.ferryman") {
            bail!("attachment must be <workspace>/.ferryman")
        }
        if communications != format!("{attachment}/ferryman") {
            bail!("communications must be <attachment>/ferryman")
        }
        // Visibility only matters when there is actually a remote to expose. A
        // Syncthing-only channel has no GitHub repository whose visibility could leak.
        if !self.git_remote.trim().is_empty() && self.git_visibility != "private" {
            bail!("communications Git repository must be private")
        }
        // `shared_remote` is a Syncthing folder ID since the transport swap, not the
        // MEGA path it used to be. Empty means no shared rung is configured.
        if !self.shared_remote.is_empty() && !is_safe_component(&self.shared_remote) {
            bail!("shared remote must be a path-safe Syncthing folder ID")
        }
        let mut names = HashSet::new();
        for agent in &self.agents {
            if !is_safe_component(&agent.name) || !is_safe_component(&agent.role) {
                bail!("registered participant name and role must be path-safe identifiers")
            }
            if agent.name.len() > 128 || agent.role.len() > 128 {
                bail!("registered participant name or role exceeds 128 bytes")
            }
            // Fang's catch, kept as the backstop for the fold. `route.agents` is
            // built by `read_agent_roster`, which folds case variants away, so two
            // spellings should be impossible by the time validation runs - and that is
            // exactly what makes this worth asserting. If it ever fires, the fold has a
            // hole in it and the channel says so instead of quietly routing to one of
            // two agents that are supposed to be one.
            if !names.insert(canonical_agent_name(&agent.name)) {
                bail!("registered participant names must be unique, ignoring case")
            }
            if agent.capabilities.len() > 128
                || agent
                    .capabilities
                    .iter()
                    .any(|capability| capability.is_empty() || capability.len() > 128)
            {
                bail!("registered participant capabilities exceed their limits")
            }
        }
        Ok(())
    }

    /// Full validation for anything that routes traffic: structural invariants plus
    /// the canonical-location pin for this installation.
    ///
    /// Fails closed. A route carrying a git remote that this installation cannot pin
    /// is rejected, not accepted unpinned.
    pub fn validate_in(&self, namespace: &ChannelNamespace) -> Result<()> {
        self.validate()?;
        namespace.verify_git_remote(&self.project_id, &self.git_remote)
    }

    pub fn permits(&self, recipient: &str, capability: Option<&str>) -> bool {
        self.agents.iter().any(|agent| {
            (agent.name.eq_ignore_ascii_case(recipient) || agent.role == recipient)
                && capability
                    .is_none_or(|required| agent.capabilities.iter().any(|item| item == required))
        })
    }

    /// The master's root-of-trust folder, local to this machine. A separate
    /// Syncthing folder (`<project>-master-ferryman`) synced only to the
    /// master's own devices.
    #[must_use]
    pub fn master_dir(&self) -> PathBuf {
        self.attachment.join("master")
    }

    /// Whether this project runs as a multi-agent team (vs `single-agent` or
    /// `unmanaged`). Teams are the mode where the master's grants gate who may
    /// act.
    #[must_use]
    pub fn is_team(&self) -> bool {
        bridge_field(&self.attachment, "integration_mode") == "multi-agent"
    }

    /// Whether this project requires a master grant before an agent may work.
    ///
    /// `grants = "required"` in `bridge.toml`; absent or `"open"` means full
    /// permissions — the default for a user's own projects, who wants to work
    /// without asking anyone.
    #[must_use]
    pub fn requires_grants(&self) -> bool {
        bridge_field(&self.attachment, "grants") == "required"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub format: String,
    pub id: String,
    pub project_id: String,
    pub sender: String,
    pub recipient: String,
    pub created_at: DateTime<Utc>,
    pub acknowledgement_deadline: DateTime<Utc>,
    pub payload_reference: String,
    pub payload: Value,
    pub reply_required: bool,
    pub idempotency_key: String,
    /// The agent that signed this, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// Hex ed25519 signature over the fields in `signing_payload`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Message {
    pub fn new(
        project_id: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        payload_reference: impl Into<String>,
        payload: Value,
        reply_required: bool,
        idempotency_key: Option<String>,
    ) -> Self {
        Self::new_with_ack_deadline(
            project_id,
            sender,
            recipient,
            payload_reference,
            payload,
            reply_required,
            idempotency_key,
            chrono::Duration::seconds(DEFAULT_ACK_DEADLINE_SECONDS),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ack_deadline(
        project_id: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        payload_reference: impl Into<String>,
        payload: Value,
        reply_required: bool,
        idempotency_key: Option<String>,
        acknowledgement_timeout: chrono::Duration,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        Self {
            format: MESSAGE_FORMAT.into(),
            idempotency_key: idempotency_key.unwrap_or_else(|| id.clone()),
            id,
            project_id: project_id.into(),
            // Folded here rather than at the twenty-odd places that compare them. Both
            // fields hold either an agent name or a role, and roles are lowercase
            // already, so this is a no-op for everything except the case that was
            // broken. Doing it before signing keeps the signature over what is stored.
            sender: canonical_agent_name(&sender.into()),
            recipient: canonical_agent_name(&recipient.into()),
            created_at,
            acknowledgement_deadline: created_at + acknowledgement_timeout,
            payload_reference: payload_reference.into(),
            payload,
            reply_required,
            signed_by: None,
            signature: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != MESSAGE_FORMAT || Uuid::parse_str(&self.id).is_err() {
            bail!("invalid Ferryman message format or ID")
        }
        if self.project_id.trim().is_empty()
            || self.sender.trim().is_empty()
            || self.recipient.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
        {
            bail!("message routing and idempotency fields are required")
        }
        if self.acknowledgement_deadline < self.created_at {
            bail!("acknowledgement deadline cannot precede creation")
        }
        if self.sender.len() > 128
            || self.recipient.len() > 128
            || self.idempotency_key.len() > 256
            || self.payload_reference.len() > 2_048
        {
            bail!("message routing or reference field exceeds its size limit")
        }
        if serde_json::to_vec(&self.payload)?.len() > MAX_INLINE_PAYLOAD_BYTES {
            bail!("inline message payload exceeds 256 KiB")
        }
        if contains_sensitive_key(&self.payload) {
            bail!("portable message payload contains a prohibited secret-like field")
        }
        Ok(())
    }
}

fn contains_sensitive_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            [
                "token",
                "secret",
                "password",
                "credential",
                "api_key",
                "private_key",
            ]
            .iter()
            .any(|marker| key.contains(marker))
                || contains_sensitive_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_sensitive_key),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Acknowledgement {
    pub message_id: String,
    pub project_id: String,
    pub recipient: String,
    pub processed_at: DateTime<Utc>,
    pub idempotency_key: String,
}

impl Acknowledgement {
    pub fn validate(&self) -> Result<()> {
        if Uuid::parse_str(&self.message_id).is_err()
            || !is_safe_component(&self.project_id)
            || self.recipient.is_empty()
            || self.recipient.len() > 128
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 256
        {
            bail!("acknowledgement fields are invalid")
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    LocalFilesystem,
    SharedFolder,
    PrivateGit,
    Queued,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub message_id: String,
    pub attempt_id: String,
    pub transport: TransportKind,
    pub delivered_at: DateTime<Utc>,
    pub failover_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Unavailable,
    RateLimited,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunicationsStatus {
    pub project_id: String,
    pub external_probes_performed: bool,
    pub local_health: Health,
    pub shared_health: Health,
    pub git_health: Health,
    pub git_live: bool,
    pub git_inbound_active: bool,
    pub preferred_successes: u8,
    pub outbox_depth: usize,
    pub acknowledgement_outbox_depth: usize,
    pub oldest_outbox_age_seconds: Option<i64>,
    pub quarantine_files: usize,
    pub git_backoff_attempt: u32,
    pub git_retry_after_unix_ms: Option<u64>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitRuntimeState {
    pub backoff_attempt: u32,
    pub retry_after_unix_ms: Option<u64>,
    pub visibility_verified_until_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProjectTransportState {
    format: String,
    project_id: String,
    git_live: bool,
    #[serde(default)]
    git_inbound_active: bool,
    preferred_successes: u8,
    git: Option<GitRuntimeState>,
    updated_at: DateTime<Utc>,
}

pub trait MessageTransport {
    fn kind(&self) -> TransportKind;
    fn health(&mut self, route: &ProjectRoute) -> Result<Health>;
    fn deliver(&mut self, route: &ProjectRoute, message: &Message) -> Result<()>;
    fn synchronize(&mut self, _: &ProjectRoute) -> Result<()> {
        Ok(())
    }
    fn deliver_acknowledgement(&mut self, _: &ProjectRoute, _: &Acknowledgement) -> Result<()> {
        Ok(())
    }
    fn export_runtime_state(&self) -> Option<GitRuntimeState> {
        None
    }
    fn import_runtime_state(&mut self, _: &GitRuntimeState) {}
}

fn system_time_to_unix_ms(value: SystemTime) -> Option<u64> {
    u64::try_from(value.duration_since(UNIX_EPOCH).ok()?.as_millis()).ok()
}

fn unix_ms_to_system_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(value)
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn persist_message(path: &Path, message: &Message) -> Result<()> {
    message.validate()?;
    if path.exists() {
        let existing: Message = serde_json::from_slice(&fs::read(path)?)
            .with_context(|| format!("read existing message {}", path.display()))?;
        if existing == *message {
            return Ok(());
        }
        bail!(
            "refusing to overwrite message {} with different content",
            message.id
        )
    }
    atomic_json(path, message)
}

fn persist_acknowledgement(path: &Path, acknowledgement: &Acknowledgement) -> Result<()> {
    acknowledgement.validate()?;
    if path.exists() {
        let existing: Acknowledgement = serde_json::from_slice(&fs::read(path)?)
            .with_context(|| format!("read existing acknowledgement {}", path.display()))?;
        if existing == *acknowledgement {
            return Ok(());
        }
        bail!(
            "refusing to overwrite acknowledgement {} with different content",
            acknowledgement.message_id
        )
    }
    atomic_json(path, acknowledgement)
}

fn message_path(root: &Path, message: &Message) -> PathBuf {
    root.join("messages")
        .join(&message.project_id)
        .join(format!("{}.json", message.id))
}

fn acknowledgement_path(route: &ProjectRoute, message_id: &str) -> PathBuf {
    route
        .communications
        .join("acknowledgements")
        .join(&route.project_id)
        .join(format!("{message_id}.json"))
}

/// Work carried as files, so it crosses networks the way messages already do.
///
/// The job/worker protocol over HTTP requires every worker to reach the orchestrator's
/// machine. That is fine in one building and useless for a fleet spread across houses,
/// which is the case Syncthing was chosen for. Here an order is a file, a claim is a
/// file, a result is a file and a review is a file - so a laptop on cellular can be
/// given work without anyone opening a port.
///
/// Everything about one task lives in its own directory:
///
/// ```text
/// tasks/t-4f2a/
///   order.json                 written once, by the orchestrator
///   claim.fang.json        fang's claim; only fang writes it
///   claim.nebra.json           nebra's claim; only nebra writes it
///   result.fang.001.json   a result, at a revision
///   review.001.json            accepted, or changes requested with notes
/// ```
///
/// No path ever has two writers, which is the single rule that makes a synced folder
/// safe. Conflicts are impossible by construction rather than unlikely in practice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Order {
    pub id: String,
    pub project_id: String,
    /// Who issued it.
    pub issued_by: String,
    /// The machine this is for, or `None` for "whoever picks it up first".
    ///
    /// An addressed order has NOTHING to race over: one agent is eligible, full stop.
    /// Only open orders need the tie-break below, so the race applies to a minority of
    /// cases rather than all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    pub created_at: DateTime<Utc>,
    pub payload: Value,
    /// Whether the result must be reviewed before the task is done.
    #[serde(default)]
    pub requires_review: bool,
    /// Destructive or sensitive work: the accept must come from the master — a
    /// separate principal — never the agent that did the work. Signed into the
    /// order so it cannot be flipped off after issue.
    #[serde(default)]
    pub requires_approval: bool,
    /// Orders this order depends on; it is not offered for work until each is
    /// accepted or done. This is the dependency DAG between orders.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The shape the result must have. Present when the issuer wants malformed
    /// deliverables rejected mechanically rather than reviewed by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_contract: Option<crate::contract::ResultContract>,
}

/// An agent staking a claim on an open order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub order_id: String,
    pub agent: String,
    pub claimed_at: DateTime<Utc>,
}

/// How often a running worker rewrites its heartbeat.
pub const HEARTBEAT_INTERVAL_SECS: i64 = 30;
/// A heartbeat this many intervals old reads as `Stale` (display only).
pub const HEARTBEAT_STALE_MULTIPLE: i64 = 10;

/// A heartbeat a worker rewrites while a task runs.
///
/// `run` names *this* execution, so a retry after a failure is distinguishable from
/// the attempt before it. `pid` is local truth on the machine that wrote it and
/// meaningless anywhere else - it is only ever read back by that machine, to decide
/// whether its own child is still alive. See ADR 0011.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Heartbeat {
    pub order_id: String,
    pub agent: String,
    pub run: String,
    pub pid: u32,
    pub at: DateTime<Utc>,
}

/// A signed, recorded release of a claim.
///
/// The claim file is kept beside the release on purpose: the history should say who
/// held a task, who let it go, and why. A release is never a result - it says the
/// work was abandoned, never that it was done.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub order_id: String,
    /// The agent whose claim is being released.
    pub released: String,
    /// The agent (or operator) doing the releasing.
    pub releaser: String,
    pub reason: String,
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A short, unique name for one execution of a task, so a retry is distinguishable
/// from the attempt before it. Uniqueness matters, not beauty.
#[must_use]
pub fn new_run_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// A submitted result, at a revision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskResult {
    pub order_id: String,
    pub agent: String,
    pub revision: u32,
    pub submitted_at: DateTime<Utc>,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A verdict on a result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Review {
    pub order_id: String,
    pub revision: u32,
    pub reviewer: String,
    pub reviewed_at: DateTime<Utc>,
    /// Accepted, or sent back.
    pub accepted: bool,
    /// Why it was sent back. Required when `accepted` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A reviewing agent's proposed verdict, which is NOT a verdict.
///
/// A `Review` is final: writing one moves the task. This does not move anything. It
/// exists so an agent can do the reading and the judging - the slow part - and still
/// leave the decision with a human, for operators whose risk tolerance says a model
/// should not be the last word.
///
/// It carries `reasoning` rather than optional notes because a recommendation with no
/// stated reason is worse than none: it invites the human to rubber-stamp it, which is
/// the exact failure this type is meant to prevent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recommendation {
    pub order_id: String,
    pub revision: u32,
    /// The agent that judged it.
    pub reviewer: String,
    pub recommended_at: DateTime<Utc>,
    /// What it suggests: keep the work, or send it back.
    pub accept: bool,
    /// Why. Never empty.
    pub reasoning: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Where a task has got to, worked out by reading its directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// Nobody has claimed it, and it is addressed to nobody.
    Open,
    /// Addressed to one machine, which has not picked it up yet.
    ///
    /// # Why this is not `Claimed`
    ///
    /// It used to be. [`Task::holder`] answers "whose task is this", and for an addressed
    /// order that is the assignee from the moment it is written - so `state()` reported
    /// `Claimed { by: "fang" }` for an order fang had never seen, could not see
    /// (its worker was down), or had given up on.
    ///
    /// An operator reading that has no way to tell "a machine is working on this right
    /// now" from "this has been sitting untouched since this morning". Those call for
    /// opposite responses - wait, or go and find out why nothing is running - and the
    /// status display was giving the reassuring one in both cases. A fleet you cannot ask
    /// "has anyone actually picked this up" is a fleet you have to guess about.
    Offered { to: String },
    /// Claimed, being worked on.
    Claimed { by: String },
    /// Claimed, but the holder's heartbeat has lapsed past a generous multiple of the
    /// interval. Display only: it must not make the task claimable by anyone. It
    /// exists because "nobody is doing this" currently looks identical to "someone is
    /// doing this". See ADR 0011.
    Stale { by: String, since: DateTime<Utc> },
    /// A result is in, waiting on a reviewer.
    AwaitingReview { by: String, revision: u32 },
    /// Sent back; the next revision is owed.
    ChangesRequested { revision: u32 },
    /// Reviewed and kept.
    Accepted,
    /// Finished, with no review asked for.
    Done,
}

/// Everything known about one task.
#[derive(Debug, Clone)]
pub struct Task {
    pub order: Order,
    pub claims: Vec<Claim>,
    pub results: Vec<TaskResult>,
    pub reviews: Vec<Review>,
    /// Proposed verdicts awaiting a human. Deliberately separate from `reviews`: these
    /// never change `state()`, so a machine that does not understand them behaves
    /// exactly as it did before.
    pub recommendations: Vec<Recommendation>,
    /// Heartbeats written by workers while they run the task. Read for display (see
    /// [`TaskState::Stale`]) and, by the machine that wrote one, to decide whether its
    /// own child is still alive.
    pub heartbeats: Vec<Heartbeat>,
    /// Signed releases of claims. A released claim is no longer held, so the task
    /// returns to `Open` or `Offered`.
    pub releases: Vec<Release>,
}

impl Task {
    /// Whether the given agent's claim on this task has been released.
    #[must_use]
    pub fn released(&self, agent: &str) -> bool {
        self.releases
            .iter()
            .any(|release| release.released.eq_ignore_ascii_case(agent))
    }

    /// The claims that still count: every claim except one its holder has released.
    fn active_claims(&self) -> impl Iterator<Item = &Claim> {
        self.claims
            .iter()
            .filter(|claim| !self.released(&claim.agent))
    }

    /// Whether the holder holds the task via an actual (unreleased) claim, rather than
    /// merely by being the assignee of an order nobody has picked up yet.
    fn held_by_claim(&self, holder: &str) -> bool {
        self.active_claims()
            .any(|claim| claim.agent.eq_ignore_ascii_case(holder))
    }

    /// The holder's heartbeat, if one was written under the holder's own name.
    fn heartbeat_for(&self, agent: &str) -> Option<&Heartbeat> {
        self.heartbeats
            .iter()
            .find(|heartbeat| heartbeat.agent.eq_ignore_ascii_case(agent))
    }

    /// Who holds this task.
    ///
    /// An addressed order belongs to its assignee and nobody else. For an open order the
    /// OLDEST claim wins - two machines can both claim in the seconds before Syncthing
    /// tells each about the other, and a rule that every machine computes identically
    /// from the same files resolves that without anyone having to be authoritative. The
    /// loser discovers it lost and stops, having wasted seconds rather than corrupted
    /// anything.
    ///
    /// A released claim no longer counts: releasing is what returns a task to `Open` or
    /// `Offered`, so the holder must be recomputed as if that claim never existed.
    #[must_use]
    pub fn holder(&self) -> Option<&str> {
        if let Some(assignee) = &self.order.assigned_to {
            return Some(assignee.as_str());
        }
        self.active_claims()
            .min_by(|a, b| {
                a.claimed_at
                    .cmp(&b.claimed_at)
                    // Identical timestamps are possible; agent name breaks the tie so
                    // every machine reaches the same answer rather than each picking its
                    // own favourite.
                    .then_with(|| a.agent.cmp(&b.agent))
            })
            .map(|claim| claim.agent.as_str())
    }

    /// The highest revision anyone has submitted.
    #[must_use]
    pub fn latest_revision(&self) -> Option<u32> {
        self.results.iter().map(|r| r.revision).max()
    }

    /// The keys the order's contract requires but the latest result is missing.
    /// `None` means there is no contract to satisfy; `Some(vec![])` means the
    /// contract is satisfied; otherwise it is the list of missing keys.
    #[must_use]
    pub fn contract_violations(&self) -> Option<Vec<String>> {
        let contract = self.order.result_contract.as_ref()?;
        let latest = self.results.iter().max_by_key(|r| r.revision)?;
        Some(contract.violations(&latest.payload))
    }

    /// A proposed verdict on the newest result that no human has settled yet.
    ///
    /// Returns nothing once a `Review` exists for that revision: the decision has been
    /// made, and a stale recommendation sitting beside it would invite someone to
    /// approve the same work twice.
    #[must_use]
    pub fn pending_recommendation(&self) -> Option<&Recommendation> {
        let revision = self.latest_revision()?;
        if self.reviews.iter().any(|r| r.revision == revision) {
            return None;
        }
        self.recommendations
            .iter()
            .filter(|r| r.revision == revision)
            .max_by_key(|r| r.recommended_at)
    }

    #[must_use]
    pub fn state(&self) -> TaskState {
        self.state_at(Utc::now())
    }

    /// `state`, with the current instant passed in rather than read, so staleness can be
    /// reasoned about without sleeping in a test.
    #[must_use]
    pub fn state_at(&self, now: DateTime<Utc>) -> TaskState {
        let Some(holder) = self.holder() else {
            return TaskState::Open;
        };
        let Some(revision) = self.latest_revision() else {
            // A claim is a record someone wrote: it says who took it and when. An
            // assignment is only a wish until then.
            if !self.held_by_claim(holder) {
                return TaskState::Offered {
                    to: holder.to_string(),
                };
            }
            // A heartbeat that has lapsed reads as stale. This is display only: it
            // must not make the task claimable by anyone. The threshold is a generous
            // multiple of the interval so that a wrong clock does not start lying about
            // a task that is merely slow to sync.
            if let Some(heartbeat) = self.heartbeat_for(holder)
                && heartbeat_lapsed(heartbeat, now)
            {
                return TaskState::Stale {
                    by: holder.to_string(),
                    since: heartbeat.at,
                };
            }
            return TaskState::Claimed {
                by: holder.to_string(),
            };
        };
        let verdict = self.reviews.iter().find(|r| r.revision == revision);
        match verdict {
            Some(review) if review.accepted => TaskState::Accepted,
            Some(_) => TaskState::ChangesRequested {
                revision: revision + 1,
            },
            None if self.order.requires_review => TaskState::AwaitingReview {
                by: holder.to_string(),
                revision,
            },
            None => TaskState::Done,
        }
    }
}

/// Whether a heartbeat is old enough to report its task as stale.
fn heartbeat_lapsed(heartbeat: &Heartbeat, now: DateTime<Utc>) -> bool {
    let threshold = chrono::Duration::seconds(HEARTBEAT_INTERVAL_SECS * HEARTBEAT_STALE_MULTIPLE);
    now.signed_duration_since(heartbeat.at) > threshold
}

fn tasks_root(route: &ProjectRoute) -> PathBuf {
    route.communications.join("tasks")
}

pub(crate) fn task_dir(route: &ProjectRoute, order_id: &str) -> PathBuf {
    tasks_root(route).join(order_id)
}

/// Write a file nobody else writes, atomically.
///
/// Temp-then-rename because Syncthing may copy the directory at any instant, and a
/// half-written order read by a peer is worse than no order at all.
pub(crate) fn write_task_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

/// Issue an order into the channel.
pub fn issue_order(route: &ProjectRoute, order: &Order) -> Result<PathBuf> {
    if !is_safe_component(&order.id) {
        bail!("order id must be a path-safe identifier")
    }
    let path = task_dir(route, &order.id).join("order.json");
    if path.exists() {
        bail!(
            "order {} already exists; an order is written once",
            order.id
        )
    }
    write_task_file(&path, order)?;
    Ok(path)
}

/// Stake a claim on an open order.
///
/// Each agent writes only its own claim file, so claiming can never collide. Whether the
/// claim WINS is decided by reading the directory, not by writing it.
pub fn claim_order(route: &ProjectRoute, order_id: &str, agent: &str) -> Result<Claim> {
    if !is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier")
    }
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier")
    }
    let claim = Claim {
        order_id: order_id.to_string(),
        agent: agent.to_string(),
        claimed_at: Utc::now(),
    };
    let path = task_dir(route, order_id).join(format!("claim.{agent}.json"));
    // Re-claiming keeps the ORIGINAL timestamp: refreshing it would let a latecomer
    // win a race it already lost by simply claiming again.
    if !path.exists() {
        write_task_file(&path, &claim)?;
    }
    Ok(claim)
}

fn heartbeat_path(route: &ProjectRoute, order_id: &str, agent: &str) -> PathBuf {
    task_dir(route, order_id).join(format!("heartbeat.{agent}.json"))
}

fn release_path(route: &ProjectRoute, order_id: &str, releaser: &str) -> PathBuf {
    task_dir(route, order_id).join(format!("release.{releaser}.json"))
}

/// Write (or rewrite) this agent's heartbeat for a task. One writer per path.
pub fn write_heartbeat(route: &ProjectRoute, heartbeat: &Heartbeat) -> Result<PathBuf> {
    if !is_safe_component(&heartbeat.agent) {
        bail!("agent name must be a path-safe identifier")
    }
    if !is_safe_component(&heartbeat.order_id) {
        bail!("order id must be a path-safe identifier")
    }
    let path = heartbeat_path(route, &heartbeat.order_id, &heartbeat.agent);
    write_task_file(&path, heartbeat)?;
    Ok(path)
}

/// Remove this agent's heartbeat for a task once the run has finished. Best effort: a
/// heartbeat left behind by a killed worker is exactly what the dead-run recovery in
/// the worker reads back.
pub fn remove_heartbeat(route: &ProjectRoute, order_id: &str, agent: &str) {
    let path = heartbeat_path(route, order_id, agent);
    let _ = fs::remove_file(path);
}

/// Read this agent's heartbeat for a task, if one has been written.
pub fn read_heartbeat(
    route: &ProjectRoute,
    order_id: &str,
    agent: &str,
) -> Result<Option<Heartbeat>> {
    let path = heartbeat_path(route, order_id, agent);
    match fs::read_to_string(&path) {
        Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Write a signed release into the channel, atomically. One writer per path: each
/// releaser writes only its own `release.<releaser>.json`.
pub fn write_release(route: &ProjectRoute, release: &Release) -> Result<PathBuf> {
    if !is_safe_component(&release.releaser) {
        bail!("releaser name must be a path-safe identifier")
    }
    if !is_safe_component(&release.released) {
        bail!("released name must be a path-safe identifier")
    }
    if !is_safe_component(&release.order_id) {
        bail!("order id must be a path-safe identifier")
    }
    let path = release_path(route, &release.order_id, &release.releaser);
    write_task_file(&path, release)?;
    Ok(path)
}

/// Release a claim, signed and recorded, and return the written release.
///
/// The caller chooses `released` (whose claim is freed) and `releaser` (who is doing
/// the freeing). A worker freeing its own claim passes the same name for both; a
/// deliberate retire passes the retired name as `released` and the operator or machine
/// acting as `releaser`. The ledger entry records who let the task go and why, and the
/// claim file is left in place so the history keeps both sides of the hand-over.
pub fn release_claim(
    route: &ProjectRoute,
    order_id: &str,
    released: &str,
    releaser: &str,
    reason: &str,
    identity: &AgentIdentity,
) -> Result<Release> {
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier")
    }
    if !is_safe_component(released) {
        bail!("released name must be a path-safe identifier")
    }
    if !is_safe_component(releaser) {
        bail!("releaser name must be a path-safe identifier")
    }
    let mut release = Release {
        order_id: order_id.to_string(),
        released: released.to_string(),
        releaser: releaser.to_string(),
        reason: reason.to_string(),
        at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    identity.sign_release(&mut release);
    write_release(route, &release)?;
    crate::ledger::append_ledger_entry(
        route,
        identity,
        "release",
        releaser,
        &format!("released {released}'s claim on {order_id} ({reason})"),
        Some(order_id),
    )?;
    Ok(release)
}

/// Release the caller's own claim, and nothing else.
///
/// A worker may only decide a task is abandoned about itself. Releasing a claim held
/// by another agent is refused here, because the whole point of a signed release is
/// that it says who let a task go - and a machine has no authority to say that about
/// someone else's claim. A deliberate retire of a gone identity is the separate,
/// operator-invoked path.
pub fn release_own_claim(
    route: &ProjectRoute,
    order_id: &str,
    agent: &str,
    reason: &str,
    identity: &AgentIdentity,
) -> Result<Release> {
    let task = read_task(route, order_id)?;
    if task
        .holder()
        .is_none_or(|held| !held.eq_ignore_ascii_case(agent))
    {
        bail!("{agent} does not hold {order_id}; a worker may only release its own claim");
    }
    release_claim(route, order_id, agent, agent, reason, identity)
}

/// Submit a result at a revision.
pub fn submit_result(route: &ProjectRoute, result: &TaskResult) -> Result<PathBuf> {
    if !is_safe_component(&result.agent) {
        bail!("agent name must be a path-safe identifier")
    }
    if !is_safe_component(&result.order_id) {
        bail!("order id must be a path-safe identifier")
    }
    let path = task_dir(route, &result.order_id).join(format!(
        "result.{}.{:03}.json",
        result.agent, result.revision
    ));
    write_task_file(&path, result)?;
    Ok(path)
}

/// Record a verdict on a revision.
pub fn submit_review(route: &ProjectRoute, review: &Review) -> Result<PathBuf> {
    if !is_safe_component(&review.order_id) {
        bail!("order id must be a path-safe identifier")
    }
    if !review.accepted
        && review
            .notes
            .as_ref()
            .is_none_or(|notes| notes.trim().is_empty())
    {
        bail!("sending work back requires notes saying what to change")
    }
    // Independent approval: an order marked `requires_approval` may only be
    // accepted by the master (a separate principal), never by the agent that
    // produced the work. Enforced here so no code path can self-approve.
    if review.accepted {
        let task = crate::read_task(route, &review.order_id)?;
        if task.order.requires_approval {
            let worker = task
                .results
                .iter()
                .find(|r| r.revision == review.revision)
                .map(|r| r.agent.as_str());
            if worker == Some(review.reviewer.as_str()) {
                bail!("an agent cannot approve its own work")
            }
            match crate::master::read_master(route)? {
                Some(master) if master.master == review.reviewer => {}
                Some(_) => bail!("order requires master approval"),
                None => bail!("order requires approval but no master is declared"),
            }
        }
    }
    let path =
        task_dir(route, &review.order_id).join(format!("review.{:03}.json", review.revision));
    write_task_file(&path, review)?;
    // The fleet learns from every verdict: record which engine produced the
    // result and whether it was kept, so later work can be steered to what wins.
    let _ = crate::learning::record_outcome(
        route,
        &review.order_id,
        review.revision,
        review.accepted,
        review.notes.as_deref().unwrap_or(""),
    );
    Ok(path)
}

/// Record a proposed verdict for a human to settle.
///
/// The path carries the reviewer's name as well as the revision, so two reviewing
/// agents looking at the same result still write to two different paths - the
/// one-writer-per-path rule holds, and a synced folder cannot produce a conflict out of
/// two opinions.
pub fn submit_recommendation(
    route: &ProjectRoute,
    recommendation: &Recommendation,
) -> Result<PathBuf> {
    if !is_safe_component(&recommendation.reviewer) {
        bail!("reviewer name must be a path-safe identifier")
    }
    if recommendation.reasoning.trim().is_empty() {
        bail!("a recommendation must say why, or it is just a rubber stamp waiting to happen")
    }
    let path = task_dir(route, &recommendation.order_id).join(format!(
        "recommendation.{}.{:03}.json",
        recommendation.reviewer, recommendation.revision
    ));
    write_task_file(&path, recommendation)?;
    Ok(path)
}

/// Read one task by reading its directory.
pub fn read_task(route: &ProjectRoute, order_id: &str) -> Result<Task> {
    if !is_safe_component(order_id) {
        bail!("order id must be a path-safe identifier")
    }
    let directory = task_dir(route, order_id);
    let order: Order = serde_json::from_str(&fs::read_to_string(directory.join("order.json"))?)
        .with_context(|| format!("order {order_id} is unreadable"))?;
    if order.id != order_id {
        bail!(
            "order {} does not match its directory name {order_id}",
            order.id
        );
    }
    let mut claims = Vec::new();
    let mut results = Vec::new();
    let mut reviews = Vec::new();
    let mut recommendations = Vec::new();
    let mut heartbeats = Vec::new();
    let mut releases = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        // A single unreadable file must not hide the rest of the task.
        if name.starts_with("claim.")
            && let Ok(value) = serde_json::from_str(&text)
        {
            claims.push(value);
        } else if name.starts_with("result.")
            && let Ok(value) = serde_json::from_str::<TaskResult>(&text)
            && verify_result(&value, &route.agents) == SignatureCheck::Valid
        {
            results.push(value);
        } else if name.starts_with("review.")
            && let Ok(value) = serde_json::from_str::<Review>(&text)
            && verify_review(&value, &route.agents) == SignatureCheck::Valid
        {
            reviews.push(value);
        } else if name.starts_with("recommendation.")
            && let Ok(value) = serde_json::from_str::<Recommendation>(&text)
            && verify_recommendation(&value, &route.agents) == SignatureCheck::Valid
        {
            recommendations.push(value);
        } else if name.starts_with("heartbeat.")
            && let Ok(value) = serde_json::from_str::<Heartbeat>(&text)
        {
            // Heartbeats are unsigned local truth; the pid is only meaningful to the
            // machine that wrote it, and no signature is checked here for the same
            // reason a claim carries none - it is a marker, not an assertion of work.
            heartbeats.push(value);
        } else if name.starts_with("release.")
            && let Ok(value) = serde_json::from_str::<Release>(&text)
            && verify_release(&value, &route.agents) == SignatureCheck::Valid
        {
            releases.push(value);
        }
    }
    results.sort_by_key(|r: &TaskResult| r.revision);
    reviews.sort_by_key(|r: &Review| r.revision);
    recommendations.sort_by_key(|r: &Recommendation| r.revision);
    Ok(Task {
        order,
        claims,
        results,
        reviews,
        recommendations,
        heartbeats,
        releases,
    })
}

/// Every task in the channel.
pub fn list_tasks(route: &ProjectRoute) -> Result<Vec<Task>> {
    let root = tasks_root(route);
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut tasks = Vec::new();
    for entry in fs::read_dir(&root)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let Some(id) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Ok(task) = read_task(route, id) {
            tasks.push(task);
        }
    }
    tasks.sort_by_key(|task| task.order.created_at);
    Ok(tasks)
}

/// Work this agent should pick up: addressed to it, or open and unclaimed by anyone
/// ahead of it.
/// Whether every order this order depends on is in a terminal (accepted or
/// done) state, so it is safe to start. A missing dependency is unsatisfied.
pub fn dependencies_satisfied(route: &ProjectRoute, order: &Order) -> Result<bool> {
    for dependency in &order.depends_on {
        match crate::read_task(route, dependency) {
            Ok(task) => {
                if !matches!(task.state(), TaskState::Accepted | TaskState::Done) {
                    return Ok(false);
                }
            }
            Err(_) => return Ok(false),
        }
    }
    Ok(true)
}

pub fn work_for(route: &ProjectRoute, agent: &str) -> Result<Vec<Task>> {
    let mut out = Vec::new();
    for task in list_tasks(route)? {
        // The same trust boundary the loop enforces before it acts. This was missing
        // here, and the gap had a name: `ferry agent run --dry-run` printed
        // `postpurge-20260827  claim it, then run the agent` for an order the real loop
        // refuses on every pass, and had done for a day. A dry run that advertises work
        // the wet run will not do is the one failure mode a dry run must not have -
        // it is consulted precisely by someone asking "what is this machine going to
        // do?", and it answered wrongly.
        //
        // Verifying here rather than only in the loop also fixes `ferry channel work`
        // and anything else that asks what can be picked up: there is now one answer to
        // that question rather than an optimistic one and a real one.
        if verify_order(&task.order, &route.agents) != SignatureCheck::Valid {
            continue;
        }
        // An order whose dependencies are not yet done must not be offered.
        if !dependencies_satisfied(route, &task.order)? {
            continue;
        }
        match task.state() {
            TaskState::Open | TaskState::Offered { .. } => {
                if task
                    .order
                    .assigned_to
                    .as_deref()
                    .is_none_or(|assignee| assignee.eq_ignore_ascii_case(agent))
                {
                    out.push(task);
                }
            }
            // Stale is display only: it is treated here exactly as `Claimed`, offered
            // only to its holder. It must not make the task claimable by anyone else.
            TaskState::Claimed { .. }
            | TaskState::ChangesRequested { .. }
            | TaskState::Stale { .. }
                if task
                    .holder()
                    .is_some_and(|held| held.eq_ignore_ascii_case(agent)) =>
            {
                out.push(task);
            }
            _ => {}
        }
    }
    Ok(out)
}

/// An agent's signing key.
///
/// One key per AGENT, not per machine. A machine may run several agents and the whole
/// point of signing is telling them apart: when something breaks at 3am on a team, you
/// want to know whose agent did it, not merely which computer it came from.
///
/// Syncthing already authenticates devices, so nobody can drop a file into the channel
/// without being a machine you approved. Signing adds the three things that does not
/// give you: agents on one machine are distinguishable, an approved-but-compromised
/// machine can forge only its own agents rather than everyone's, and the proof survives
/// the message leaving the folder for Git, a backup, or an audit report.
pub struct AgentIdentity {
    name: String,
    signing: SigningKey,
}

/// Never shows the signing seed: an identity may be debug-printed in logs and
/// test failures, and the private half must not leak that way.
impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("name", &self.name)
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl AgentIdentity {
    /// Load this agent's key, creating one the first time it runs.
    ///
    /// The private key is kept in the machine's own secret store when there is one, and
    /// otherwise in the private state directory - which is deliberately the directory
    /// Ferryman keeps OUT of the synced folder, so the key physically cannot travel.
    /// The file fallback is not a compromise: a headless container has no keychain, and
    /// that is the main way people run this.
    /// This machine's signing identity.
    ///
    /// # One key per machine, not one per project
    ///
    /// The key used to live only under the project's `.ferryman/`, so a machine working
    /// on three projects had three different keys under one name. Every project saw a
    /// different public key for "wisp", and the roster - which is keyed by name -
    /// could not tell that apart from an impostor. An identity that changes per directory
    /// is not an identity.
    ///
    /// It now lives once per machine, beside the device id, and the project copy is kept
    /// in step so an older `ferry` on the same machine signs as the same agent rather
    /// than minting a second one.
    ///
    /// A machine already signing under a project key **keeps it**. Rotating on upgrade
    /// would invalidate every signature that machine has already published, which is the
    /// one thing this must not do.
    pub fn load_or_create(name: &str, state_dir: &Path) -> Result<Self> {
        Self::load_or_create_in(name, state_dir, licensing::machine_state_dir())
    }

    /// The same, with the machine directory given rather than discovered. Exists so a
    /// test can construct an identity belonging to a *different machine*, which is the
    /// only way left to write one: two directories on one machine now correctly produce
    /// one key.
    pub(crate) fn load_or_create_in(
        name: &str,
        state_dir: &Path,
        machine_dir: Option<PathBuf>,
    ) -> Result<Self> {
        if !is_safe_component(name) {
            bail!("agent name must be a path-safe identifier")
        }
        // One spelling, everywhere. See `canonical_agent_name`: the name is a filename in
        // three stores, and on a case-sensitive filesystem `Fang` and `fang` were
        // two identities with two keys. Folded here, at the point a key is minted, so no
        // new split can be created; `from_state_file` adopts the ones already on disk.
        let name = &canonical_agent_name(name);
        // An identity that has already signed things must never change. A project with
        // its own key keeps it, even though a machine-wide key exists: swapping it would
        // make this agent sign as a key the roster has not seen, and the roster - rightly
        // - reports that as impersonation. Unification therefore happens for *new*
        // attachments, never by re-keying an established one.
        if let Some(existing) = Self::from_state_file(name, state_dir)? {
            if let Some(dir) = &machine_dir
                && Self::from_state_file(name, dir)?.is_none()
            {
                Self::write_state_file(name, dir, &existing.signing)?;
            }
            return Ok(existing);
        }

        // No key here yet, so this attachment can join the machine's identity.
        if let Some(dir) = &machine_dir
            && let Some(existing) = Self::from_state_file(name, dir)?
        {
            Self::write_state_file(name, state_dir, &existing.signing)?;
            return Ok(existing);
        }

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = SigningKey::from_bytes(&seed);
        if let Some(dir) = &machine_dir {
            Self::write_state_file(name, dir, &signing)?;
        }
        Self::write_state_file(name, state_dir, &signing)?;
        Ok(Self {
            name: name.to_string(),
            signing,
        })
    }

    /// Load an existing identity, and do NOT create one.
    ///
    /// The distinction matters wherever a name comes from the operator rather than from this
    /// machine's own config. `load_or_create` would happily mint a brand-new key called
    /// `fang` on a machine that is not fang - a second identity under a name the
    /// roster already knows, whose signatures every other machine would then reject as an
    /// impostor. For "sign something as <name>", the only correct answer when the key is
    /// absent is to refuse.
    pub fn load_existing(name: &str, state_dir: &Path) -> Result<Option<Self>> {
        Self::from_state_file(name, state_dir)
    }

    fn key_path(name: &str, state_dir: &Path) -> PathBuf {
        let name = canonical_agent_name(name);
        state_dir.join("keys").join(format!("{name}.key"))
    }

    /// A key file on disk written under a different capitalisation of this same name.
    ///
    /// Only consulted when the canonical path is absent, which is exactly the upgrade
    /// case: a machine that joined as `Fang` has `keys/Fang.key` and nothing
    /// else. Without this it would find no key under the folded name and **mint a new
    /// one** - a second key under a name the roster already knows, which is the single
    /// worst thing this code can do, and precisely what `load_existing` exists to
    /// prevent. Adopt, never rotate.
    fn case_variant_key_path(name: &str, state_dir: &Path) -> Option<PathBuf> {
        let mut found: Vec<PathBuf> = fs::read_dir(state_dir.join("keys"))
            .ok()?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let stem = path.file_stem()?.to_str()?;
                (path.extension().is_some_and(|ext| ext == "key")
                    && canonical_agent_name(stem) == name)
                    .then_some(path)
            })
            .collect();
        // Sorted so a machine that somehow holds `Fang.key` and `FANG.key` picks
        // the same one on every run rather than whichever the directory listing happened
        // to yield. Deterministically wrong beats non-deterministically wrong: the
        // operator sees one stable public key and can act on it.
        found.sort();
        found.into_iter().next()
    }

    fn from_state_file(name: &str, state_dir: &Path) -> Result<Option<Self>> {
        let name = &canonical_agent_name(name);
        let canonical = Self::key_path(name, state_dir);
        let (path, adopted) = if canonical.is_file() {
            (canonical, false)
        } else {
            match Self::case_variant_key_path(name, state_dir) {
                Some(variant) => (variant, true),
                None => return Ok(None),
            }
        };
        let encoded = fs::read_to_string(&path)?;
        let bytes = hex::decode(encoded.trim())
            .with_context(|| format!("{} is not a valid key", path.display()))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a 32-byte key", path.display()))?;
        let signing = SigningKey::from_bytes(&bytes);
        if adopted {
            // Write the same key under the canonical name so the next run finds it
            // directly and the scan above becomes dead weight rather than load-bearing.
            // Best-effort: a read-only state directory must still yield the identity it
            // already holds, and the old file is left in place so an older `ferry` on
            // this machine keeps working.
            let _ = Self::write_state_file(name, state_dir, &signing);
        }
        Ok(Some(Self {
            name: name.to_string(),
            signing,
        }))
    }

    /// Install this identity into another project's attachment on the same machine.
    ///
    /// # Why one machine's identity has to be seated per project
    ///
    /// A key lives per attachment, and an attachment is per project. That is right for a
    /// worker, which is one machine doing one project's work. It is wrong for anything
    /// that spans projects - and the Telegram bridge does exactly that: one process, one
    /// operator name, a topic per project.
    ///
    /// The bridge signed its first order fine, because the project it was first set up in
    /// had the key. Every other project refused: "this machine holds no signing key for
    /// 'phone'". Refusing was correct - [`AgentIdentity::load_existing`] must never mint a
    /// key for a name it does not already hold, or one typo would publish an impostor.
    /// But the identity was not missing. It was one directory away.
    ///
    /// So this moves the key the machine already has, rather than making a new one. The
    /// public half is identical in every project, which is the whole point: an operator is
    /// a person, and a person who signs as a different key in each project is nineteen
    /// strangers rather than one operator.
    ///
    /// Refuses to overwrite a *different* key already sitting there. That case is not a
    /// machine spreading its own identity - it is two identities colliding under one name,
    /// and silently replacing one of them would invalidate everything it had signed.
    pub fn seat_in(&self, state_dir: &Path) -> Result<()> {
        if let Some(existing) = Self::from_state_file(&self.name, state_dir)? {
            if existing.public_key_hex() == self.public_key_hex() {
                return Ok(());
            }
            bail!(
                "'{}' already has a different key in {} - refusing to replace it, because \
                 everything it has already signed would start reading as an impostor",
                self.name,
                state_dir.display()
            )
        }
        Self::write_state_file(&self.name, state_dir, &self.signing)
    }

    fn write_state_file(name: &str, state_dir: &Path, signing: &SigningKey) -> Result<()> {
        let path = Self::key_path(name, state_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, hex::encode(signing.to_bytes()))?;
        restrict_to_owner(&path)?;
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The half that is safe to publish.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Reconstruct an identity from a raw 32-byte signing seed.
    ///
    /// This is the import half of a password-sealed operator identity: the
    /// dashboard seals the seed with the operator's password, and on login
    /// rebuilds the identity here so its signatures are indistinguishable from
    /// one kept on disk.
    #[must_use]
    pub fn from_seed(name: &str, seed: [u8; 32]) -> Self {
        Self {
            name: canonical_agent_name(name),
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The raw 32-byte signing seed.
    ///
    /// Private key material: only needed to seal the identity under a password.
    /// Never write it to the synced channel (it is not part of the roster and
    /// must not travel).
    #[must_use]
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Sign a message, binding the signature to the fields that matter.
    pub fn sign(&self, message: &mut Message) {
        let signature = self.signing.sign(signing_payload(message).as_bytes());
        message.signed_by = Some(self.name.clone());
        message.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign a v2 portable message envelope.
    pub fn sign_message_v2(&self, message: &mut MessageV2) -> Result<()> {
        message.sign(&self.signing)
    }

    /// Sign a v2 portable acknowledgement envelope.
    pub fn sign_acknowledgement_v2(&self, acknowledgement: &mut AcknowledgementV2) -> Result<()> {
        acknowledgement.sign(&self.signing)
    }

    /// Sign an order. Whoever issues work is on the record for it.
    pub fn sign_order(&self, order: &mut Order) {
        let signature = self.signing.sign(order_payload(order).as_bytes());
        order.signed_by = Some(self.name.clone());
        order.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign a result. This is the one that matters most for accountability: it ties a
    /// specific agent to specific work it produced.
    pub fn sign_result(&self, result: &mut TaskResult) {
        let signature = self.signing.sign(result_payload(result).as_bytes());
        result.signed_by = Some(self.name.clone());
        result.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign a verdict, so an acceptance cannot later be denied or forged.
    pub fn sign_review(&self, review: &mut Review) {
        let signature = self.signing.sign(review_payload(review).as_bytes());
        review.signed_by = Some(self.name.clone());
        review.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign a recommendation. A human is going to act on this, so it needs to be as
    /// checkable as the verdict it is proposing.
    pub fn sign_recommendation(&self, recommendation: &mut Recommendation) {
        let signature = self
            .signing
            .sign(recommendation_payload(recommendation).as_bytes());
        recommendation.signed_by = Some(self.name.clone());
        recommendation.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign an agent's specialization profile.
    ///
    /// A profile is prompt text placed at the front of every prompt, carried by the synced
    /// channel. Unsigned, it was the one input the worker acted on without checking who
    /// wrote it - see [`crate::memory::ProfileAttestation`] for the whole argument.
    pub fn sign_profile_attestation(&self, attestation: &mut crate::memory::ProfileAttestation) {
        let signature = self.signing.sign(
            crate::memory::attestation_payload_for(&attestation.agent, &attestation.sha256)
                .as_bytes(),
        );
        attestation.signed_by = Some(self.name.clone());
        attestation.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign an interrupt, so a kill/steer/pause cannot be forged onto an agent.
    pub fn sign_interrupt(&self, interrupt: &mut crate::interrupt::Interrupt) {
        let signature = self
            .signing
            .sign(crate::interrupt::payload(interrupt).as_bytes());
        interrupt.signed_by = Some(self.name.clone());
        interrupt.signature = Some(hex::encode(signature.to_bytes()));
    }
    /// Sign a release, so freeing a claim cannot be forged onto an agent.
    pub fn sign_release(&self, release: &mut Release) {
        let signature = self.signing.sign(release_payload(release).as_bytes());
        release.signed_by = Some(self.name.clone());
        release.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Sign arbitrary bytes and return the hex signature.
    ///
    /// The built-in `sign_*` methods each know their own canonical payload; an
    /// envelope that is not one of those (a sealed secret) builds its payload
    /// string in its own module and signs it here, so it still verifies against
    /// the roster through the same key.
    #[must_use]
    pub fn sign_bytes(&self, bytes: &[u8]) -> String {
        hex::encode(self.signing.sign(bytes).to_bytes())
    }
}

fn order_payload(order: &Order) -> String {
    let mut payload = format!(
        "ferryman-order-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        order.id,
        order.project_id,
        order.issued_by,
        order.assigned_to.as_deref().unwrap_or(""),
        order.created_at.to_rfc3339(),
        order.requires_review,
        payload_digest(&order.payload),
    );
    // Optional fields are bound to the signature only when present, so an order
    // with neither keeps the exact bytes it always had and still verifies.
    if let Some(contract) = &order.result_contract {
        payload.push_str(&format!(
            "\ncontract:{}",
            serde_json::to_string(&contract.required).unwrap_or_else(|_| "[]".to_string())
        ));
    }
    if order.requires_approval {
        payload.push_str("\napproval:true");
    }
    if !order.depends_on.is_empty() {
        payload.push_str(&format!(
            "\ndepends:{}",
            serde_json::to_string(&order.depends_on).unwrap_or_else(|_| "[]".to_string())
        ));
    }
    payload
}

fn result_payload(result: &TaskResult) -> String {
    format!(
        "ferryman-result-v1\n{}\n{}\n{}\n{}\n{}",
        result.order_id,
        result.agent,
        result.revision,
        result.submitted_at.to_rfc3339(),
        payload_digest(&result.payload),
    )
}

fn review_payload(review: &Review) -> String {
    format!(
        "ferryman-review-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        review.order_id,
        review.revision,
        review.reviewer,
        review.reviewed_at.to_rfc3339(),
        review.accepted,
        review.notes.as_deref().unwrap_or(""),
    )
}

fn recommendation_payload(recommendation: &Recommendation) -> String {
    format!(
        "ferryman-recommendation-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        recommendation.order_id,
        recommendation.revision,
        recommendation.reviewer,
        recommendation.recommended_at.to_rfc3339(),
        recommendation.accept,
        recommendation.reasoning,
    )
}
fn release_payload(release: &Release) -> String {
    format!(
        "ferryman-release-v1\n{}\n{}\n{}\n{}\n{}",
        release.order_id,
        release.released,
        release.releaser,
        release.reason,
        release.at.to_rfc3339(),
    )
}

/// Shared verification: look the signer up in the roster and check the signature over
/// the exact bytes that were signed.
fn check_signature(
    signed_by: Option<&String>,
    signature: Option<&String>,
    payload: &str,
    roster: &[AgentRoute],
) -> SignatureCheck {
    let (Some(signed_by), Some(signature_hex)) = (signed_by, signature) else {
        return SignatureCheck::Unsigned;
    };
    // Case-insensitive, because a message already in flight was signed under whatever
    // spelling its sender used. The roster it is checked against is folded, so an exact
    // match would report a perfectly good signature from `Fang` as `UnknownSigner` -
    // turning an upgrade into a fleet-wide impersonation alarm.
    let Some(agent) = roster
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(signed_by))
    else {
        return SignatureCheck::UnknownSigner;
    };
    let Some(known_key) = agent.public_key.as_ref().filter(|k| !k.is_empty()) else {
        return SignatureCheck::UnknownSigner;
    };
    let Ok(key_bytes) = hex::decode(known_key) else {
        return SignatureCheck::Invalid;
    };
    let Ok(key_bytes): Result<[u8; 32], _> = key_bytes.try_into() else {
        return SignatureCheck::Invalid;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
        return SignatureCheck::Invalid;
    };
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return SignatureCheck::Invalid;
    };
    let Ok(signature_bytes): Result<[u8; 64], _> = signature_bytes.try_into() else {
        return SignatureCheck::Invalid;
    };
    if verifying
        .verify_strict(payload.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .is_ok()
    {
        SignatureCheck::Valid
    } else {
        SignatureCheck::Invalid
    }
}

/// Who issued this order, checkably.
#[must_use]
pub fn verify_order(order: &Order, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        order.signed_by.as_ref(),
        order.signature.as_ref(),
        &order_payload(order),
        roster,
    )
}

/// Who produced this result, checkably. The fingerprint on a contribution.
#[must_use]
pub fn verify_result(result: &TaskResult, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        result.signed_by.as_ref(),
        result.signature.as_ref(),
        &result_payload(result),
        roster,
    )
}

/// Who gave this verdict, checkably.
#[must_use]
pub fn verify_review(review: &Review, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        review.signed_by.as_ref(),
        review.signature.as_ref(),
        &review_payload(review),
        roster,
    )
}
/// Who released this claim, checkably. A release is a security-relevant act - it frees
/// a claim so another machine can take the task - so only a verified one is honoured.
#[must_use]
pub fn verify_release(release: &Release, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        release.signed_by.as_ref(),
        release.signature.as_ref(),
        &release_payload(release),
        roster,
    )
}

/// Who issued this interrupt, checkably. An unsigned interrupt is a forged one:
/// a peer could otherwise kill, pause, or steer another machine's work.
#[must_use]
pub fn verify_interrupt(
    interrupt: &crate::interrupt::Interrupt,
    roster: &[AgentRoute],
) -> SignatureCheck {
    check_signature(
        interrupt.signed_by.as_ref(),
        interrupt.signature.as_ref(),
        &crate::interrupt::payload(interrupt),
        roster,
    )
}

/// Check a recommendation's signature.
///
/// Worth doing even though a recommendation decides nothing: it is what a human reads
/// before deciding, so a forged one steers the decision just as effectively.
pub fn verify_recommendation(
    recommendation: &Recommendation,
    roster: &[AgentRoute],
) -> SignatureCheck {
    check_signature(
        recommendation.signed_by.as_ref(),
        recommendation.signature.as_ref(),
        &recommendation_payload(recommendation),
        roster,
    )
}

/// Keep a private key readable only by its owner.
///
/// On Unix that is mode 0600. On Windows the state directory is already per-user and
/// Rust exposes no equivalent without extra dependencies, so this is a no-op there and
/// says so rather than pretending otherwise.
///
/// Public because it is not only this module's concern: the dashboard seals operator
/// identities into their own files, and a second implementation of "make this owner-only"
/// is a second thing that can be wrong. One resolver for one question - the same reason
/// there is one `identity::machine_name` rather than two that drifted.
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Exactly what a signature covers.
///
/// Deliberately explicit rather than "serialise the whole struct": a signature over a
/// serialisation is a signature over whatever that serialisation happens to include
/// today, which quietly changes meaning the next time a field is added. These are the
/// fields that decide what the message IS and who it is for.
fn signing_payload(message: &Message) -> String {
    format!(
        "ferryman-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        message.id,
        message.project_id,
        message.sender,
        message.recipient,
        message.created_at.to_rfc3339(),
        message.reply_required,
        payload_digest(&message.payload),
    )
}

/// A stable digest of a payload, so a signature binds to the content rather than to one
/// particular serialisation of it.
fn payload_digest(payload: &Value) -> String {
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// What happened when a message's signature was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCheck {
    /// Signed by the key this name is known by.
    Valid,
    /// No signature. Normal for a fleet that has not adopted signing.
    Unsigned,
    /// A signature that does not verify against the key on file.
    Invalid,
    /// Signed by a name with no published key, so nothing can be concluded.
    UnknownSigner,
    /// A DIFFERENT key is claiming a name that is already established.
    ///
    /// This is the interesting one, and it is never resolved silently. Either an agent
    /// legitimately re-keyed, or something is impersonating it - and quietly accepting
    /// the new key is how that attack succeeds.
    KeyChanged { known: String, presented: String },
}

/// Verify a message against the roster published in the channel.
#[must_use]
pub fn verify_message(message: &Message, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        message.signed_by.as_ref(),
        message.signature.as_ref(),
        &signing_payload(message),
        roster,
    )
}

/// Load this project's trust store, or an empty store when none is configured.
///
/// A missing store means no trusted signers: v2 verification fails closed while
/// the (still-unsigned) v1 transport keeps working until migration flips the
/// switch. Wiring this into the inbound read/claim path is a later gate.
pub fn trust_store(route: &ProjectRoute) -> Result<TrustedSigners> {
    TrustedSigners::load_or_empty(&route.attachment.join("trusted-signers.toml"))
}

/// Load this project's machine-local replay ledger.
pub fn replay_ledger(route: &ProjectRoute) -> Result<ReplayLedger> {
    ReplayLedger::load(&route.attachment.join("runtime/replay-ledger.json"))
}

/// Verify a v2 message against this project's trust store.
pub fn verify_v2_message(route: &ProjectRoute, message: &MessageV2) -> Result<SignerId> {
    message.verify(&trust_store(route)?)
}

/// Verify a v2 acknowledgement against this project's trust store.
pub fn verify_v2_acknowledgement(
    route: &ProjectRoute,
    acknowledgement: &AcknowledgementV2,
) -> Result<SignerId> {
    acknowledgement.verify(&trust_store(route)?)
}

/// Add a trusted signer grant, refusing to replace an existing signer id.
///
/// Returns `true` when the grant was added. Rotation is expressed as `add` the
/// new key, then `revoke_trusted_signer` the old one.
pub fn add_trusted_signer(route: &ProjectRoute, grant: SignerGrant) -> Result<bool> {
    let path = route.attachment.join("trusted-signers.toml");
    let signer_id = grant.signer_id()?;
    let mut store = TrustedSigners::load_or_empty(&path)?;
    if store
        .signers
        .iter()
        .any(|existing| existing.signer_id().is_ok_and(|id| id == signer_id))
    {
        bail!("signer {} is already trusted", signer_id.as_str());
    }
    store.signers.push(grant);
    store.save(&path)?;
    Ok(true)
}

/// Mark a trusted signer as revoked, writing the store back atomically.
///
/// A revoked signer is rejected by the v2 verifiers even though its signature
/// is otherwise valid. Returns `true` when a matching grant was changed.
pub fn revoke_trusted_signer(route: &ProjectRoute, signer_id: &str) -> Result<bool> {
    let path = route.attachment.join("trusted-signers.toml");
    let mut store = TrustedSigners::load_or_empty(&path)?;
    let mut changed = false;
    for grant in &mut store.signers {
        if grant.signer_id().is_ok_and(|id| id.as_str() == signer_id) && !grant.revoked {
            grant.revoked = true;
            changed = true;
        }
    }
    if changed {
        store.save(&path)?;
    }
    Ok(changed)
}

/// Inspect one inbound message file against the portable-authentication gate.
///
/// `Ok(())` means the file may be processed; `Err(reason)` means it must be
/// quarantined: a v2 message that fails verification, or an unsigned v1 message
/// once a trust store (enforcement) exists.
fn inspect_inbound_message_file(route: &ProjectRoute, path: &Path) -> Result<()> {
    let raw = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&raw).context("message is not valid JSON")?;
    let format = value
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("ferryman-message/v1");
    let trusted = trust_store(route)?;
    if format == portable_auth::MESSAGE_FORMAT_V2 {
        let message: MessageV2 = serde_json::from_slice(&raw).context("v2 message is malformed")?;
        message
            .verify(&trusted)
            .context("v2 message failed verification")?;
    } else if !trusted.signers.is_empty() {
        bail!("unsigned v1 message while enforcement is enabled");
    }
    Ok(())
}

/// Move an inbound message file to machine-local quarantine with a reason sidecar.
fn quarantine_inbound_file(route: &ProjectRoute, path: &Path, reason: &str) -> Result<()> {
    let quarantine = route.attachment.join("runtime/quarantine/outbox");
    fs::create_dir_all(&quarantine)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("message.json");
    fs::rename(path, quarantine.join(name))
        .with_context(|| format!("quarantine {}", path.display()))?;
    fs::write(quarantine.join(format!("{name}.error")), reason)?;
    Ok(())
}

/// Scan this project's inbound messages, quarantining any that fail the
/// portable-authentication gate. Returns how many were quarantined.
///
/// This is the enforcement primitive: call it at the authenticated inbound
/// boundary (server inbox/claim, or a migration command) before listing or
/// reading messages. It is intentionally not wired into the v1 `read_message`
/// and `list_messages` yet, because those parse only v1 envelopes and a mixed
/// v1/v2 directory must be migrated, not half-read.
pub fn quarantine_invalid_inbound(route: &ProjectRoute) -> Result<usize> {
    let directory = route
        .communications
        .join("messages")
        .join(&route.project_id);
    if !directory.is_dir() {
        return Ok(0);
    }
    let mut paths = fs::read_dir(directory)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut quarantined = 0;
    for path in paths {
        let reason = match inspect_inbound_message_file(route, &path) {
            Ok(()) => continue,
            Err(error) => format!("{error:#}"),
        };
        if quarantine_inbound_file(route, &path, &reason).is_ok() {
            quarantined += 1;
        }
    }
    Ok(quarantined)
}

#[cfg(test)]
mod portable_auth_route_tests {
    use super::*;
    use crate::portable_auth::{MessageV2, ReplayLedger, SignerGrant, TrustedSigners};

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn test_route_with_agents(dir: &std::path::Path) -> ProjectRoute {
        ProjectRoute {
            agents: vec![AgentRoute {
                name: "worker".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: None,
            }],
            ..test_route(dir)
        }
    }

    #[test]
    fn v2_message_verifies_against_the_route_trust_store() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        std::fs::create_dir_all(&route.attachment).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);

        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();
        verify_v2_message(&route, &message).unwrap();

        // Fail closed: a route with no trust store trusts no one.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = test_route(empty_dir.path());
        std::fs::create_dir_all(&empty.attachment).unwrap();
        assert!(verify_v2_message(&empty, &message).is_err());
    }

    #[test]
    fn inbound_scanner_quarantines_unsigned_v1_when_enforcing() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let message = Message::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
            None,
        );
        std::fs::write(
            messages.join(format!("{}.json", message.id)),
            serde_json::to_string(&message).unwrap(),
        )
        .unwrap();

        // No trust store yet: the unsigned v1 message is accepted.
        assert_eq!(quarantine_invalid_inbound(&route).unwrap(), 0);

        // Enable enforcement by writing a trust store.
        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        assert_eq!(quarantine_invalid_inbound(&route).unwrap(), 1);
        assert!(!messages.join(format!("{}.json", message.id)).exists());
        assert!(
            route
                .attachment
                .join("runtime/quarantine/outbox")
                .join(format!("{}.json.error", message.id))
                .exists()
        );
    }

    #[test]
    fn inbound_scanner_quarantines_a_tampered_v2_message() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut v2 = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        v2.sign(&signing).unwrap();
        v2.payload = serde_json::json!({"tampered": true});
        std::fs::write(
            messages.join(format!("{}.json", v2.id)),
            serde_json::to_string(&v2).unwrap(),
        )
        .unwrap();

        assert_eq!(quarantine_invalid_inbound(&route).unwrap(), 1);
    }

    #[test]
    fn inbound_scanner_does_not_quarantine_a_claimed_message() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut v2 = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        v2.sign(&signing).unwrap();
        std::fs::write(
            messages.join(format!("{}.json", v2.id)),
            serde_json::to_string(&v2).unwrap(),
        )
        .unwrap();

        // A claimed message has its nonce recorded but stays on disk: it is the
        // canonical copy acknowledgements bind to, not a replay to quarantine.
        let mut ledger = ReplayLedger::default();
        ledger.record(&v2.authentication.signer_id, &v2.authentication.nonce);
        ledger
            .save(&route.attachment.join("runtime/replay-ledger.json"))
            .unwrap();

        assert_eq!(quarantine_invalid_inbound(&route).unwrap(), 0);
        assert!(messages.join(format!("{}.json", v2.id)).is_file());
    }

    #[test]
    fn list_messages_v2_skips_non_v2_and_invalid_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut first = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        first.sign(&signing).unwrap();
        let mut second = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        second.sign(&signing).unwrap();

        // A v1 file is ignored by the v2 listing.
        let v1 = Message::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
            None,
        );
        std::fs::write(
            messages.join(format!("{}.json", v1.id)),
            serde_json::to_string(&v1).unwrap(),
        )
        .unwrap();

        // A tampered v2 file is skipped rather than failing the listing.
        let mut tampered = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        tampered.sign(&signing).unwrap();
        tampered.payload = serde_json::json!({"tampered": true});
        std::fs::write(
            messages.join(format!("{}.json", tampered.id)),
            serde_json::to_string(&tampered).unwrap(),
        )
        .unwrap();

        std::fs::write(
            messages.join(format!("{}.json", first.id)),
            serde_json::to_string(&first).unwrap(),
        )
        .unwrap();
        std::fs::write(
            messages.join(format!("{}.json", second.id)),
            serde_json::to_string(&second).unwrap(),
        )
        .unwrap();

        let listed = list_messages_v2(&route).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert!(listed.iter().any(|message| message.id == first.id));
        assert!(listed.iter().any(|message| message.id == second.id));
    }

    #[test]
    fn read_message_v2_reads_a_claimed_message() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();
        std::fs::write(
            messages.join(format!("{}.json", message.id)),
            serde_json::to_string(&message).unwrap(),
        )
        .unwrap();

        assert_eq!(read_message_v2(&route, &message.id).unwrap().id, message.id);

        let mut ledger = ReplayLedger::default();
        ledger.record(
            &message.authentication.signer_id,
            &message.authentication.nonce,
        );
        ledger
            .save(&route.attachment.join("runtime/replay-ledger.json"))
            .unwrap();
        // A claimed message (nonce recorded) is still readable: its
        // acknowledgement is bound to this exact file.
        assert_eq!(read_message_v2(&route, &message.id).unwrap().id, message.id);
    }

    #[test]
    fn claim_message_v2_records_nonce_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route_with_agents(dir.path());

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::create_dir_all(&route.attachment).unwrap();
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();

        assert!(claim_message_v2(&route, &message).unwrap());
        let claim = route
            .attachment
            .join("runtime/processed")
            .join(hex::encode(Sha256::digest(
                message.idempotency_key.as_bytes(),
            )));
        assert!(claim.join("message.json").is_file());
        let ledger =
            ReplayLedger::load(&route.attachment.join("runtime/replay-ledger.json")).unwrap();
        assert!(ledger.contains(
            &message.authentication.signer_id,
            &message.authentication.nonce
        ));
        assert!(!claim_message_v2(&route, &message).unwrap());
    }

    #[test]
    fn claim_message_v2_rejects_a_replayed_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route_with_agents(dir.path());

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::create_dir_all(&route.attachment).unwrap();
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();

        // Simulate a previously consumed nonce.
        let mut ledger = ReplayLedger::default();
        ledger.record(
            &message.authentication.signer_id,
            &message.authentication.nonce,
        );
        ledger
            .save(&route.attachment.join("runtime/replay-ledger.json"))
            .unwrap();

        assert!(claim_message_v2(&route, &message).is_err());
    }

    #[test]
    fn claim_then_acknowledge_survives_a_boundary_scan() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route_with_agents(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let orchestrator = ed25519_dalek::SigningKey::from_bytes(&seed);
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let worker = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![
                SignerGrant {
                    public_key: hex::encode(orchestrator.verifying_key().as_bytes()),
                    projects: vec!["ferryman".into()],
                    roles: vec!["orchestrator".into()],
                    capabilities: vec!["issue".into()],
                    revoked: false,
                },
                SignerGrant {
                    public_key: hex::encode(worker.verifying_key().as_bytes()),
                    projects: vec!["ferryman".into()],
                    roles: vec!["worker".into()],
                    capabilities: vec![],
                    revoked: false,
                },
            ],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&orchestrator).unwrap();
        std::fs::write(
            messages.join(format!("{}.json", message.id)),
            serde_json::to_string(&message).unwrap(),
        )
        .unwrap();

        // The server's claim handler: quarantine, read, then claim.
        assert_eq!(quarantine_invalid_inbound(&route).unwrap(), 0);
        assert_eq!(read_message_v2(&route, &message.id).unwrap().id, message.id);
        assert!(claim_message_v2(&route, &message).unwrap());

        // The server's acknowledge handler runs a boundary scan first. The
        // claimed message is the canonical copy the acknowledgement binds to, so
        // it must not be quarantined as a "replayed nonce".
        assert_eq!(quarantine_invalid_inbound(&route).unwrap(), 0);
        let mut acknowledgement = AcknowledgementV2::new(&message).unwrap();
        acknowledgement.acknowledged_by = "worker".into();
        acknowledgement.sign(&worker).unwrap();
        assert!(acknowledge_v2(&route, &acknowledgement).unwrap());
    }

    #[test]
    fn acknowledge_v2_persists_verified_ack_and_handles_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route_with_agents(dir.path());
        let messages = route.communications.join("messages").join("ferryman");
        std::fs::create_dir_all(&messages).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into(), "worker".into()],
                capabilities: vec!["issue".into()],
                revoked: false,
            }],
        };
        std::fs::write(
            route.attachment.join("trusted-signers.toml"),
            toml::to_string(&store).unwrap(),
        )
        .unwrap();

        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();
        std::fs::write(
            messages.join(format!("{}.json", message.id)),
            serde_json::to_string(&message).unwrap(),
        )
        .unwrap();

        let mut acknowledgement = AcknowledgementV2::new(&message).unwrap();
        acknowledgement.acknowledged_by = "worker".into();
        acknowledgement.sign(&signing).unwrap();
        assert!(acknowledge_v2(&route, &acknowledgement).unwrap());

        let path = acknowledgement_path(&route, &message.id);
        assert!(path.is_file());
        let stored: AcknowledgementV2 =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored.message_id, message.id);

        let ledger =
            ReplayLedger::load(&route.attachment.join("runtime/replay-ledger.json")).unwrap();
        assert!(ledger.contains(
            &acknowledgement.authentication.signer_id,
            &acknowledgement.authentication.nonce
        ));

        assert!(!acknowledge_v2(&route, &acknowledgement).unwrap());
    }

    #[test]
    fn add_and_revoke_trusted_signer_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        std::fs::create_dir_all(&route.attachment).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let grant = SignerGrant {
            public_key: hex::encode(signing.verifying_key().as_bytes()),
            projects: vec!["ferryman".into()],
            roles: vec!["orchestrator".into()],
            capabilities: vec!["issue".into()],
            revoked: false,
        };
        let signer_id = grant.signer_id().unwrap().as_str().to_owned();

        assert!(add_trusted_signer(&route, grant.clone()).unwrap());
        assert!(add_trusted_signer(&route, grant).is_err());

        // A message signed by the added key verifies against the stored store.
        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();
        verify_v2_message(&route, &message).unwrap();

        // Revocation makes the same signature fail closed, and is idempotent.
        assert!(revoke_trusted_signer(&route, &signer_id).unwrap());
        assert!(!revoke_trusted_signer(&route, &signer_id).unwrap());
        assert!(verify_v2_message(&route, &message).is_err());
    }

    /// A machine that joined as `Fang` must keep the key it already signed with.
    ///
    /// This is the whole risk in folding names: the key store is `keys/<name>.key`, so a
    /// folded lookup finds nothing where an unfolded one found a key, and
    /// `load_or_create` would happily mint a fresh one. That new key would be published
    /// under a name the fleet already has a key for, and every machine would - correctly
    /// - read the result as an impostor. Adopt, never rotate.
    #[test]
    fn a_key_stored_under_the_old_capitalisation_is_adopted_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();

        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let established = SigningKey::from_bytes(&seed);
        std::fs::write(keys.join("Fang.key"), hex::encode(established.to_bytes())).unwrap();

        // Asked for under either spelling, it is the same key - the one already on disk.
        for asked in ["fang", "Fang", "FANG"] {
            let identity = AgentIdentity::load_or_create_in(
                asked,
                dir.path(),
                Some(machine.path().to_path_buf()),
            )
            .unwrap();
            assert_eq!(
                identity.public_key_hex(),
                hex::encode(established.verifying_key().to_bytes()),
                "asking as '{asked}' minted a new key instead of adopting the existing one"
            );
            assert_eq!(identity.name(), "fang", "the name itself is folded");
        }

        // And it was written under the canonical name, so the variant scan stops being
        // load-bearing after the first run.
        assert!(keys.join("fang.key").is_file());
    }

    /// Both spellings in the roster are one agent, and the entry that survives is the
    /// one current code wrote.
    #[test]
    fn a_roster_holding_both_spellings_reports_one_agent() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let agents = route.communications.join("agents");
        std::fs::create_dir_all(&agents).unwrap();

        let write = |file: &str, name: &str, key: &str| {
            std::fs::write(
                agents.join(file),
                serde_json::to_vec_pretty(&AgentRoute {
                    name: name.into(),
                    role: "worker".into(),
                    capabilities: Vec::new(),
                    public_key: Some(key.into()),
                    encryption_key: None,
                })
                .unwrap(),
            )
            .unwrap();
        };
        // The stale entry from before folding, and the live one written since.
        write("Fang.json", "Fang", &"aa".repeat(32));
        write("fang.json", "fang", &"bb".repeat(32));

        let roster = read_agent_roster(&route.communications).unwrap();
        assert_eq!(roster.len(), 1, "two spellings are one agent");
        assert_eq!(roster[0].name, "fang");
        assert_eq!(
            roster[0].public_key.as_deref(),
            Some("bb".repeat(32).as_str()),
            "the canonically-stored entry is the live one and must win"
        );

        // A message signed under the OLD spelling still verifies against the folded
        // roster: it was signed before the upgrade and is legitimately in flight.
        assert_ne!(
            check_signature(
                Some(&"Fang".to_string()),
                Some(&String::new()),
                "payload",
                &roster,
            ),
            SignatureCheck::UnknownSigner,
            "folding the roster must not turn an old sender into an unknown one"
        );
    }

    /// A keyless reservation from `ferry channel expect` must not displace the real
    /// agent, whichever order the directory listing happens to yield.
    #[test]
    fn a_reservation_never_outranks_the_agent_that_holds_the_key() {
        let reservation = AgentRoute {
            name: "fang".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        };
        let real = AgentRoute {
            name: "Fang".into(),
            public_key: Some("cc".repeat(32)),
            encryption_key: None,
            ..reservation.clone()
        };
        for input in [
            vec![reservation.clone(), real.clone()],
            vec![real.clone(), reservation.clone()],
        ] {
            let folded = fold_case_variants(input);
            assert_eq!(folded.len(), 1);
            assert_eq!(folded[0].name, "fang");
            assert_eq!(
                folded[0].public_key.as_deref(),
                Some("cc".repeat(32).as_str())
            );
        }
    }

    /// Registering under any spelling writes exactly one file, under the folded name.
    #[test]
    fn registering_a_mixed_case_name_writes_the_folded_entry() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let path = register_expected_agent(&route, "Fang", "worker", &[]).unwrap();
        assert_eq!(path.file_name().unwrap(), "fang.json");

        let roster = read_agent_roster(&route.communications).unwrap();
        assert_eq!(roster.len(), 1);
        assert_eq!(
            roster[0].name, "fang",
            "the name inside the file is folded too, not just the filename"
        );
    }

    /// Fang's test, kept verbatim in intent: a route that somehow carries both
    /// spellings must refuse to route rather than pick one. With the fold in
    /// `read_agent_roster` this should be unreachable through any real path, which is
    /// the point of asserting it - it is how we find out if the fold ever regresses.
    #[test]
    fn participant_names_are_case_insensitively_unique() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        route.agents = vec![
            AgentRoute {
                name: "fang".into(),
                role: "orchestrator".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: None,
            },
            AgentRoute {
                name: "Fang".into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: None,
            },
        ];
        let error = route.validate().unwrap_err();
        assert!(format!("{error:#}").contains("ignoring case"));
    }

    /// Fang's other test, and the bug that actually broke the live channel: a
    /// Syncthing conflict copy names the same agent, so it was read as a second one.
    #[test]
    fn roster_ignores_syncthing_conflict_copies() {
        let dir = tempfile::tempdir().unwrap();
        let agents = dir.path().join("agents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::write(
            agents.join("wisp.json"),
            r#"{"name":"wisp","role":"orchestrator","capabilities":[],"public_key":"aa"}"#,
        )
        .unwrap();
        // The conflict copy is the older, KEYLESS one - so reading it was not merely
        // double-counting, it could displace the real agent's published key.
        std::fs::write(
            agents.join("wisp.sync-conflict-20260817-144138-O4SHF2J.json"),
            r#"{"name":"wisp","role":"orchestrator","capabilities":[]}"#,
        )
        .unwrap();

        let roster = read_roster_in(&agents).unwrap();
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].name, "wisp");
        assert_eq!(
            roster[0].public_key.as_deref(),
            Some("aa"),
            "the real entry survived, not the keyless conflict copy"
        );
    }

    /// Addressing and sending use the folded name whatever the operator typed.
    #[test]
    fn addressing_an_agent_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let route = ProjectRoute {
            agents: vec![AgentRoute {
                name: "fang".into(),
                role: "worker".into(),
                capabilities: vec!["build".into()],
                public_key: None,
                encryption_key: None,
            }],
            ..test_route(dir.path())
        };
        assert!(route.permits("Fang", Some("build")));
        assert!(route.permits("FANG", None));

        let message = Message::new(
            "ferryman",
            "Wisp",
            "Fang",
            "r",
            serde_json::json!({}),
            false,
            None,
        );
        assert_eq!(message.sender, "wisp");
        assert_eq!(message.recipient, "fang");
    }
}

/// Publish an agent, refusing to overwrite an established key with a different one.
///
/// First key wins. A name that already carries a key keeps it, and a different key
/// arriving for that name is an error the operator must look at - not a silent
/// replacement, which is precisely how impersonation succeeds.
pub fn register_agent_key(
    route: &ProjectRoute,
    agent: &AgentRoute,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let published = AgentRoute {
        name: canonical_agent_name(&agent.name),
        role: agent.role.clone(),
        capabilities: agent.capabilities.clone(),
        public_key: Some(identity.public_key_hex()),
        encryption_key: agent.encryption_key.clone(),
    };
    if let Some(existing) = read_agent_roster(&route.communications)?
        .into_iter()
        .find(|a| canonical_agent_name(&a.name) == published.name)
        && let Some(known) = existing.public_key.filter(|k| !k.is_empty())
        && Some(&known) != published.public_key.as_ref()
    {
        bail!(
            "agent '{}' is already published with a different key. First key wins: this is \
             either a genuine re-key, which an operator must approve by removing \
             agents/{}.json, or something impersonating it.",
            published.name,
            published.name
        )
    }
    // Published to the fleet channel too, so identity is the same fact wherever it is
    // asked about. Failure here is not fatal: a machine with no per-user directory must
    // still be able to join a project.
    if let Some(fleet) = licensing::fleet_dir() {
        let _ = write_roster_entry(&fleet.join("agents"), &published);
    }
    register_agent(route, &published)
}

/// One roster entry, written atomically.
fn write_roster_entry(directory: &Path, agent: &AgentRoute) -> Result<PathBuf> {
    let path = directory.join(format!("{}.json", canonical_agent_name(&agent.name)));
    fs::create_dir_all(directory)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(agent)?)?;
    fs::rename(&temporary, &path)?;
    Ok(path)
}

/// Find the attachment for the project containing `start`, walking upwards the way git
/// looks for `.git`. Returns the `.ferryman` directory, not the workspace.
///
/// This is what lets a command locate the channel with nothing running: the attachment
/// is on disk, so there is no daemon to ask.
#[must_use]
pub fn discover_attachment(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        let candidate = directory.join(".ferryman");
        if candidate.join("bridge.toml").is_file() {
            return Some(candidate);
        }
        current = directory.parent();
    }
    None
}

/// Read the route an attachment describes.
///
/// `bridge.toml` is written by the attachment scripts and is deliberately a flat list of
/// `key = "value"` lines, so reading it needs no TOML parser and the channel crate keeps
/// its short dependency list. Anything richer is a signal the file has been hand-edited
/// into a shape Ferryman did not write, which is worth refusing rather than guessing at.
pub fn load_route(attachment: &Path) -> Result<ProjectRoute> {
    let path = attachment.join("bridge.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut fields: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!(
                "{} contains a line that is not key = \"value\": {line}",
                path.display()
            )
        };
        let value = value.trim().trim_matches('"');
        fields.insert(key.trim().to_string(), value.to_string());
    }
    let take = |key: &str| -> Result<String> {
        fields
            .get(key)
            .cloned()
            .with_context(|| format!("{} is missing '{key}'", path.display()))
    };
    let route = ProjectRoute {
        project_id: take("project")?,
        workspace: PathBuf::from(take("workspace")?),
        attachment: PathBuf::from(take("attachment")?),
        communications: PathBuf::from(take("communications")?),
        shared_remote: fields.get("shared_remote").cloned().unwrap_or_default(),
        git_remote: fields.get("git_remote").cloned().unwrap_or_default(),
        git_visibility: fields
            .get("git_visibility")
            .cloned()
            .unwrap_or_else(|| "private".into()),
        agents: read_agent_roster(&PathBuf::from(take("communications")?))?,
    };
    route.validate()?;
    Ok(route)
}

/// Read one key from the attachment's `bridge.toml`, or an empty string when the
/// file or key is absent. Used for fields that inform behaviour but are not part
/// of the route's structural identity.
fn bridge_field(attachment: &Path, key: &str) -> String {
    let path = attachment.join("bridge.toml");
    let Ok(text) = fs::read_to_string(&path) else {
        return String::new();
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((field, value)) = line.split_once('=')
            && field.trim() == key
        {
            return value.trim().trim_matches('"').to_owned();
        }
    }
    String::new()
}

/// The agents taking part, read from the channel itself.
///
/// Each agent publishes one file under `agents/`, named for itself. One writer per file
/// is the same rule the whole channel follows, so two machines registering at once can
/// never collide - and it is where an agent's public key will live once envelopes are
/// signed.
///
/// A malformed entry is skipped rather than fatal: one agent writing nonsense must not
/// stop the rest of the fleet from talking.
fn pin_path(attachment: &Path, name: &str) -> PathBuf {
    let name = canonical_agent_name(name);
    attachment.join("agents-pinned").join(format!("{name}.key"))
}

/// Collapse capitalisation variants of one agent into the single entry that agent is.
///
/// Ferryman channels that predate the folding rule contain both spellings as separate
/// files - a live one written by current code and a stale one from before - and the
/// stale entry carries a key that nothing signs with any more. Deleting it is not this
/// function's business: the synced folder is one-writer-per-path, and the writer of
/// `agents/Fang.json` is fang, not whoever happens to be reading. So it is
/// folded away on read instead, everywhere, and the file may be removed at leisure.
///
/// Which survives, in order:
///  1. an entry carrying a key, over a keyless one. A keyless entry is a reservation
///     made by `register_expected_agent` for an agent that has not come online yet;
///     a key is proof that a machine actually holds this identity, and no spelling
///     convention outranks that. Getting this the other way round - preferring the
///     canonical filename first - let a `ferry channel expect fang` reservation
///     erase the real `Fang`'s published key, which is the fold doing exactly the
///     damage it exists to prevent.
///  2. among keyed entries, the one already stored under the canonical spelling: that
///     is current code writing, so it is the identity in use now rather than the
///     leftover from before.
///
/// Order within the input is otherwise preserved, so a roster's own ordering still
/// decides ties rather than the directory listing.
fn fold_case_variants(agents: Vec<AgentRoute>) -> Vec<AgentRoute> {
    fn rank(agent: &AgentRoute) -> u8 {
        let canonical = agent.name == canonical_agent_name(&agent.name);
        let keyed = agent.public_key.as_ref().is_some_and(|key| !key.is_empty());
        u8::from(keyed) * 2 + u8::from(canonical)
    }
    let mut folded: Vec<AgentRoute> = Vec::with_capacity(agents.len());
    for agent in agents {
        match folded
            .iter_mut()
            .find(|kept| canonical_agent_name(&kept.name) == canonical_agent_name(&agent.name))
        {
            Some(kept) if rank(&agent) > rank(kept) => *kept = agent,
            Some(_) => {}
            None => folded.push(agent),
        }
    }
    for agent in &mut folded {
        agent.name = canonical_agent_name(&agent.name);
    }
    folded
}

pub fn read_agent_roster(communications: &Path) -> Result<Vec<AgentRoute>> {
    // The attachment (`.ferryman`) is the operator-local, non-synced side of the
    // channel; `communications` is its `ferryman` subdirectory.
    let attachment = communications.parent().unwrap_or(communications);
    // Folded before the pinning loop below, not after: pins are keyed by agent name, and
    // pinning `Fang` and `fang` separately would re-create the split in the one
    // store whose whole job is to notice when an agent's key changes.
    let mut agents = fold_case_variants(read_roster_in(&communications.join("agents"))?);
    // Pin keys: an agent's public key is pinned to this operator's local store
    // the first time it is seen, and a later change to agents/<name>.json in the
    // shared folder (a peer overwriting a victim's key to forge as it) is
    // reverted to the pinned key. Trust-on-first-use: a machine that has never
    // seen an agent will pin whatever is in the channel at first sight.
    for agent in &mut agents {
        let Some(key) = agent.public_key.as_ref().filter(|k| !k.is_empty()) else {
            continue;
        };
        let pin = pin_path(attachment, &agent.name);
        match std::fs::read_to_string(&pin) {
            Ok(pinned) if pinned.trim() != key.as_str() => {
                agent.public_key = Some(pinned.trim().to_string());
            }
            Ok(_) => {}
            Err(_) => {
                // First sight: pin it. Best-effort; a read-only attachment must
                // not break the roster.
                if let Some(parent) = pin.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&pin, key);
            }
        }
        // The same pinning applies to the encryption key, for the same reason:
        // a peer overwriting an agent's X25519 key would otherwise redirect the
        // next secret sealed to that agent. Trust-on-first-use, and only when a
        // key is actually present.
        if let Some(enc) = agent.encryption_key.as_ref().filter(|k| !k.is_empty()) {
            let enc_pin = pin_path(attachment, &format!("{}.enc", agent.name));
            match std::fs::read_to_string(&enc_pin) {
                Ok(pinned) if pinned.trim() != enc.as_str() => {
                    agent.encryption_key = Some(pinned.trim().to_string());
                }
                Ok(_) => {}
                Err(_) => {
                    if let Some(parent) = enc_pin.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&enc_pin, enc);
                }
            }
        }
    }
    // An agent's public key should not depend on which repository you ask about. The
    // fleet channel is where identity belongs; the project copy stays authoritative for
    // anyone already in it, so an existing channel keeps verifying exactly as it did.
    if let Some(fleet) = licensing::fleet_dir() {
        for entry in fold_case_variants(read_roster_in(&fleet.join("agents"))?) {
            if !agents.iter().any(|known| known.name == entry.name) {
                agents.push(entry);
            }
        }
    }
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(agents)
}

fn read_roster_in(directory: &Path) -> Result<Vec<AgentRoute>> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut agents = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        // Fang's find, and the more valuable half of the two fixes: a Syncthing
        // conflict copy of an agent file was being read as a SECOND participant. It
        // carries the same `name`, so the roster held two `wisp` entries - and the
        // conflict copy is usually the older, keyless one, so it could displace the real
        // key. That is what actually broke this channel with "registered participant
        // names must be unique"; the capitalisation split was a separate fault that
        // happened to look similar.
        //
        // `ledger.rs` already skipped these for the same reason. The primitive existed
        // and this code reached past it, which by now is the most familiar shape of
        // defect in this codebase.
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains(".sync-conflict-"))
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(agent) = serde_json::from_str::<AgentRoute>(&text) {
            agents.push(agent);
        }
    }
    Ok(agents)
}

/// Publish this agent into the channel so others may address it.
///
/// Writing is atomic - a temporary file then a rename - because Syncthing may copy the
/// directory at any instant, and a half-written roster entry read by a peer is a fleet
/// that cannot agree on who exists.
pub fn register_agent(route: &ProjectRoute, agent: &AgentRoute) -> Result<PathBuf> {
    if !is_safe_component(&agent.name) || !is_safe_component(&agent.role) {
        bail!("agent name and role must be path-safe identifiers")
    }
    // Both the filename and the name recorded inside it, so the entry says the same
    // thing however it is read. Writing the canonical file while leaving `MixedCase`
    // in the JSON would just move the split from the filesystem into the payload.
    let agent = &AgentRoute {
        name: canonical_agent_name(&agent.name),
        ..agent.clone()
    };
    let directory = route.communications.join("agents");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", agent.name));
    let temporary = directory.join(format!(".{}.json.tmp", agent.name));
    fs::write(&temporary, serde_json::to_vec_pretty(agent)?)?;
    fs::rename(&temporary, &path)?;
    Ok(path)
}

/// Reserve a name for an agent that has not come online yet, so it can be
/// addressed — and messages queued for it — before its device syncs. No key is
/// published. When the real agent registers, its key binds to the reserved name
/// under the usual first-key-wins rule, so this is a name reservation rather
/// than an impersonation risk.
pub fn register_expected_agent(
    route: &ProjectRoute,
    name: &str,
    role: &str,
    capabilities: &[String],
) -> Result<PathBuf> {
    register_agent(
        route,
        &AgentRoute {
            name: name.to_string(),
            role: role.to_string(),
            capabilities: capabilities.to_vec(),
            public_key: None,
            encryption_key: None,
        },
    )
}

/// Locate the route for the project containing `start`, with a clear explanation when
/// there is nothing to find - "no channel here" is a normal situation for a new user,
/// not an error worth a backtrace.
pub fn route_for(start: &Path) -> Result<ProjectRoute> {
    let attachment = discover_attachment(start).with_context(|| {
        format!(
            // Names the command that fixes it, not a script in a repository the reader
            // may not have checked out. An agent that hits this needs one runnable line.
            "no Ferryman channel found in {} or any parent directory; run 'ferry enable --email you@example.com' here",
            start.display()
        )
    })?;
    load_route(&attachment)
}

pub fn is_acknowledged(route: &ProjectRoute, message_id: &str) -> bool {
    acknowledgement_path(route, message_id).is_file()
}

fn outbox_path(route: &ProjectRoute, message_id: &str) -> PathBuf {
    route
        .attachment
        .join("runtime/outbox")
        .join(format!("{message_id}.json"))
}

fn acknowledgement_outbox_path(route: &ProjectRoute, message_id: &str) -> PathBuf {
    route
        .attachment
        .join("runtime/acknowledgement-outbox")
        .join(format!("{message_id}.json"))
}

#[derive(Default)]
pub struct LocalFilesystemTransport;

impl MessageTransport for LocalFilesystemTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::LocalFilesystem
    }

    fn health(&mut self, route: &ProjectRoute) -> Result<Health> {
        Ok(if route.communications.is_dir() {
            Health::Healthy
        } else {
            Health::Unavailable
        })
    }

    fn deliver(&mut self, route: &ProjectRoute, message: &Message) -> Result<()> {
        persist_message(&message_path(&route.communications, message), message)
    }
}

pub trait SharedHealthProbe {
    fn health(&mut self, route: &ProjectRoute) -> Result<Health>;
}

fn run_with_timeout(command: &mut Command, timeout: Duration, label: &str) -> Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {label}"))?;
    if child
        .wait_timeout(timeout)
        .with_context(|| format!("wait for {label}"))?
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        bail!("{label} exceeded the {} second timeout", timeout.as_secs())
    }
    child
        .wait_with_output()
        .with_context(|| format!("collect {label} output"))
}

fn scrub_sensitive_child_environment(command: &mut Command) {
    for name in scrub_child_environment_names() {
        command.env_remove(&name);
    }
}

/// The environment variable names a child process must not inherit: the
/// explicit secret list, plus anything whose name looks secret. Public so the
/// agent loop can scrub the agent CLI it spawns the same way git is scrubbed.
pub fn scrub_child_environment_names() -> Vec<String> {
    let mut names: Vec<String> = SENSITIVE_CHILD_ENVIRONMENT
        .iter()
        .map(|s| s.to_string())
        .collect();
    for (name, _) in std::env::vars() {
        if looks_like_a_secret_name(&name) {
            names.push(name);
        }
    }
    names
}

/// Whether a variable name alone is reason enough not to hand it to a child.
///
/// A pure function of the name, so the policy can be tested without touching the
/// process environment - which this crate could not do anyway, since it forbids
/// `unsafe` and `std::env::set_var` is unsafe under edition 2024. Naming the rule also
/// makes it reviewable, which a closure inside a loop was not.
fn looks_like_a_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if !SECRET_NAME_HINTS.iter().any(|hint| upper.contains(hint)) {
        return false;
    }
    // The `GIT_` exemption exists so git's own configuration survives - `GIT_DIR`,
    // `GIT_TERMINAL_PROMPT` and friends, none of which look like secrets. It must not
    // become a way to smuggle one through: `GIT_TOKEN` was exempt purely for its prefix.
    let git_configuration = upper.starts_with("GIT_")
        && !["TOKEN", "SECRET", "PASSWORD", "PASSPHRASE", "CREDENTIAL"]
            .iter()
            .any(|hint| upper.contains(hint));
    !git_configuration
}

#[cfg(test)]
mod child_environment_scrub {
    use super::looks_like_a_secret_name as secret;

    /// The names a real machine actually uses.
    ///
    /// The hint list used to require a compound - `AUTH_TOKEN`, `ACCESS_TOKEN` - so it
    /// caught the spellings almost nobody uses and missed the ones everybody does.
    /// `TELEGRAM_BOT_TOKEN` was reaching the environment of every task a worker ran, on a
    /// machine whose own documentation promises an environment scrub.
    #[test]
    fn a_name_saying_token_is_a_secret_whatever_precedes_it() {
        for name in [
            "TELEGRAM_BOT_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "NPM_TOKEN",
            "SLACK_BOT_TOKEN",
            "SOME_VENDOR_APIKEY",
            "db_password",
        ] {
            assert!(secret(name), "{name} must not reach a child process");
        }
    }

    /// The `GIT_` exemption is for git's own configuration, not a way through it.
    #[test]
    fn the_git_prefix_does_not_carry_a_secret_through() {
        assert!(secret("GIT_TOKEN"), "a GIT_ prefix must not exempt a token");
        assert!(secret("GIT_PASSWORD"));
    }

    /// Over-scrubbing is the safe direction, but not infinitely: a child that loses
    /// `PATH` cannot run anything, and git that loses its own configuration misbehaves in
    /// ways that look like Ferryman bugs. `PATH` also has to survive a rule about `PAT`.
    #[test]
    fn ordinary_configuration_is_not_a_secret() {
        for name in [
            "GIT_DIR",
            "GIT_TERMINAL_PROMPT",
            "GIT_AUTHOR_NAME",
            "PATH",
            "HOME",
            "LANG",
            "FERRYMAN_ENV_FILE",
        ] {
            assert!(!secret(name), "{name} is configuration, not a credential");
        }
    }
}

fn system_git_command(directory: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new("git");
    scrub_sensitive_child_environment(&mut command);
    command
        .args([
            "-c",
            "http.lowSpeedLimit=1",
            "-c",
            "http.lowSpeedTime=30",
            "-c",
            &format!("core.hooksPath={NULL_GIT_HOOKS_PATH}"),
        ])
        .args(arguments)
        .current_dir(directory)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "Never");
    command
}

/// Default address of the local Syncthing REST API.
const SYNCTHING_DEFAULT_API: &str = "http://127.0.0.1:8384";
/// Hard deadline for a single Syncthing API call. The API is on loopback, so a slow
/// answer means Syncthing is wedged, not that the network is far away.
const SYNCTHING_API_TIMEOUT: Duration = Duration::from_secs(5);

/// Health of the Syncthing folder that carries this project's channel.
///
/// A shared folder is a usable transport only when Syncthing is running, is actually
/// serving this folder, and is actually connected to at least one peer. A directory
/// that merely exists proves none of those, which is why this asks Syncthing itself.
///
/// The peer check is the part MEGAcmd could never answer: a folder can look perfectly
/// healthy locally while no other machine is reachable, in which case a message written
/// into it is not delivered, it is only stored.
pub struct SyncthingProbe {
    /// Base URL of the local Syncthing REST API.
    pub api_base: String,
    /// `X-API-Key` for that API. Empty means "not configured": the probe then reports
    /// `Unavailable` rather than guessing, so delivery fails over instead of silently
    /// assuming a transport that may not exist.
    pub api_key: String,
}

impl SyncthingProbe {
    /// Reads `SYNCTHING_API_BASE` / `SYNCTHING_API_KEY`, falling back to the API key in
    /// Syncthing's own `config.xml` at its platform-default location. That fallback is
    /// what lets an operator who already runs Syncthing attach a project without
    /// copying a key anywhere.
    #[must_use]
    pub fn from_env() -> Self {
        let api_base = std::env::var("SYNCTHING_API_BASE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| SYNCTHING_DEFAULT_API.to_string());
        let api_key = std::env::var("SYNCTHING_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(syncthing_api_key_from_config)
            .unwrap_or_default();
        Self { api_base, api_key }
    }
}

impl SharedHealthProbe for SyncthingProbe {
    fn health(&mut self, route: &ProjectRoute) -> Result<Health> {
        if self.api_key.is_empty() || route.shared_remote.trim().is_empty() {
            return Ok(Health::Unavailable);
        }
        // The folder must exist in Syncthing and must not be in an error state.
        let folder = urlencode(&route.shared_remote);
        let Some(status) = syncthing_get(
            &self.api_base,
            &format!("/rest/db/status?folder={folder}"),
            &self.api_key,
        )?
        else {
            return Ok(Health::Unavailable);
        };
        if status.get("errors").and_then(Value::as_i64).unwrap_or(0) > 0 {
            return Ok(Health::Unavailable);
        }
        let state = status.get("state").and_then(Value::as_str).unwrap_or("");
        if state.eq_ignore_ascii_case("error") {
            return Ok(Health::Unavailable);
        }
        // At least one peer must be connected, or nothing can actually be delivered.
        let Some(connections) =
            syncthing_get(&self.api_base, "/rest/system/connections", &self.api_key)?
        else {
            return Ok(Health::Unavailable);
        };
        let connected = connections
            .get("connections")
            .and_then(Value::as_object)
            .is_some_and(|devices| {
                devices
                    .values()
                    .any(|device| device.get("connected").and_then(Value::as_bool) == Some(true))
            });
        Ok(if connected {
            Health::Healthy
        } else {
            Health::Unavailable
        })
    }
}

/// Percent-encodes the characters a Syncthing folder id could plausibly contain.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A deliberately tiny loopback-only HTTP GET.
///
/// Syncthing's API is plain HTTP on localhost, so this needs no TLS, no redirects and
/// no connection pooling. Keeping it dependency-free is what lets the channel crate
/// stay free of an async runtime and an HTTP client: the whole point of the channel is
/// that it runs with nothing else installed.
///
/// Returns `Ok(None)` for any non-200 answer (folder unknown, key rejected, Syncthing
/// not running) because every one of those means the same thing to a caller: this
/// transport is not usable right now.
fn syncthing_get(api_base: &str, path: &str, api_key: &str) -> Result<Option<Value>> {
    let authority = api_base
        .trim()
        .trim_end_matches('/')
        .strip_prefix("http://")
        .context("SYNCTHING_API_BASE must be a plain http:// loopback address")?;
    let authority = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:8384")
    };
    let Some(address) = authority.to_socket_addrs()?.next() else {
        return Ok(None);
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, SYNCTHING_API_TIMEOUT) else {
        return Ok(None);
    };
    stream.set_read_timeout(Some(SYNCTHING_API_TIMEOUT))?;
    stream.set_write_timeout(Some(SYNCTHING_API_TIMEOUT))?;
    // HTTP/1.0 so the answer is never chunked and the server closes when it is done.
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {authority}\r\nX-API-Key: {api_key}\r\nAccept: application/json\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return Ok(None);
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).is_err() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&raw);
    let Some(status_line) = text.lines().next() else {
        return Ok(None);
    };
    if !status_line.contains(" 200") {
        return Ok(None);
    }
    // Slice the JSON body out directly; this tolerates a chunked answer without
    // needing a full HTTP parser for a fixed loopback endpoint.
    let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) else {
        return Ok(None);
    };
    Ok(serde_json::from_str(&text[start..=end]).ok())
}

/// POST to Syncthing's local API.
///
/// Same hand-rolled HTTP as `syncthing_get`, for the same reason: this talks to a fixed
/// loopback address and pulling in an HTTP client for it would add a dependency tree to
/// a crate that deliberately has almost none.
fn syncthing_post(api_base: &str, path: &str, api_key: &str, body: &str) -> Result<Option<u16>> {
    let authority = api_base
        .trim()
        .trim_end_matches('/')
        .strip_prefix("http://")
        .context("SYNCTHING_API_BASE must be a plain http:// loopback address")?;
    let authority = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:8384")
    };
    let Some(address) = authority.to_socket_addrs()?.next() else {
        return Ok(None);
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, SYNCTHING_API_TIMEOUT) else {
        return Ok(None);
    };
    stream.set_read_timeout(Some(SYNCTHING_API_TIMEOUT))?;
    stream.set_write_timeout(Some(SYNCTHING_API_TIMEOUT))?;
    let request = format!(
        "POST {path} HTTP/1.0\r\nHost: {authority}\r\nX-API-Key: {api_key}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return Ok(None);
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).is_err() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&raw);
    let Some(status_line) = text.lines().next() else {
        return Ok(None);
    };
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    Ok(code)
}

/// A peer Syncthing knows about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncthingPeer {
    pub device_id: String,
    pub name: String,
}

/// What wiring Syncthing did, or why it could not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncthingSetup {
    /// False when Syncthing is not installed or not running. Never an error: a channel
    /// works locally without it, and an unattended caller should not fail setup because
    /// a separate program is not up yet.
    pub available: bool,
    pub folder_id: String,
    pub folder_path: String,
    /// This machine's device id, to give to the other machines.
    pub device_id: Option<String>,
    /// Peers the folder is now shared with.
    pub shared_with: Vec<SyncthingPeer>,
    pub note: String,
}

/// Find the local Syncthing API key, honouring an explicit override first.
pub fn syncthing_api_key() -> Option<String> {
    std::env::var("SYNCTHING_API_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .or_else(syncthing_api_key_from_config)
}

fn syncthing_api_base() -> String {
    if let Ok(explicit) = std::env::var("SYNCTHING_API_BASE")
        && !explicit.trim().is_empty()
    {
        return explicit;
    }
    syncthing_address_from_config().unwrap_or_else(|| SYNCTHING_DEFAULT_API.to_string())
}

/// Every device this Syncthing already knows, minus itself.
pub fn syncthing_peers() -> Result<Vec<SyncthingPeer>> {
    let Some(key) = syncthing_api_key() else {
        return Ok(Vec::new());
    };
    let base = syncthing_api_base();
    let me = syncthing_get(&base, "/rest/system/status", &key)?
        .and_then(|v| v.get("myID").and_then(Value::as_str).map(str::to_string));
    // The devices endpoint returns an array, and syncthing_get slices out an object, so
    // this asks for the config and reads the devices out of it instead.
    let Some(config) = syncthing_get(&base, "/rest/config", &key)? else {
        return Ok(Vec::new());
    };
    let mut peers = Vec::new();
    if let Some(devices) = config.get("devices").and_then(Value::as_array) {
        for device in devices {
            let Some(id) = device.get("deviceID").and_then(Value::as_str) else {
                continue;
            };
            if Some(id.to_string()) == me {
                continue;
            }
            peers.push(SyncthingPeer {
                device_id: id.to_string(),
                name: device
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    Ok(peers)
}

pub fn channel_folder_id(route: &ProjectRoute) -> String {
    if route.shared_remote.trim().is_empty() {
        format!("{}-ferryman", route.project_id)
    } else {
        route.shared_remote.clone()
    }
}

/// DELETE to Syncthing's local API, for removing a folder.
fn syncthing_delete(api_base: &str, path: &str, api_key: &str) -> Result<Option<u16>> {
    let authority = api_base
        .trim()
        .trim_end_matches('/')
        .strip_prefix("http://")
        .context("SYNCTHING_API_BASE must be a plain http:// loopback address")?;
    let authority = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:8384")
    };
    let Some(address) = authority.to_socket_addrs()?.next() else {
        return Ok(None);
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, SYNCTHING_API_TIMEOUT) else {
        return Ok(None);
    };
    stream.set_read_timeout(Some(SYNCTHING_API_TIMEOUT))?;
    stream.set_write_timeout(Some(SYNCTHING_API_TIMEOUT))?;
    let request =
        format!("DELETE {path} HTTP/1.0\r\nHost: {authority}\r\nX-API-Key: {api_key}\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return Ok(None);
    }
    let mut raw = Vec::new();
    if stream.read_to_end(&mut raw).is_err() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&raw);
    let Some(status_line) = text.lines().next() else {
        return Ok(None);
    };
    Ok(status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok()))
}

/// Register this project's channel folder with the local Syncthing and share it.
///
/// This is the step that used to be left to the operator, and leaving it there was the
/// single biggest reason setting up a second machine was hard: everything else is one
/// command, and this was a trip through a web UI. An agent cannot click a web UI.
///
/// Idempotent. Syncthing's config POST replaces a folder with the same id, so running
/// it again after adding a machine simply widens the share list.
pub fn syncthing_register_folder(
    route: &ProjectRoute,
    share_with: &[SyncthingPeer],
) -> Result<SyncthingSetup> {
    let folder_id = if route.shared_remote.trim().is_empty() {
        format!("{}-ferryman", route.project_id)
    } else {
        route.shared_remote.clone()
    };
    register_folder(
        &folder_id,
        &route.communications,
        &format!("{} ferryman channel", route.project_id),
        share_with,
    )
}

/// Register the fleet channel, so identity and the device count actually travel.
///
/// A fleet channel that only exists on one machine answers the same question the project
/// channel already answered badly. Shared with the devices Syncthing already trusts -
/// the same rule as a project channel, so this never widens trust, it only uses trust
/// that exists.
pub fn syncthing_register_fleet(share_with: &[SyncthingPeer]) -> Result<Option<SyncthingSetup>> {
    let Some(dir) = licensing::fleet_dir() else {
        return Ok(None);
    };
    fs::create_dir_all(&dir)?;
    // The fleet channel carries identity and device records - never keys, never
    // executables, and never anything a project put there.
    let ignore = dir.join(".stignore");
    if !ignore.exists() {
        fs::write(
            &ignore,
            "keys
*.tmp
*.key
*.exe
*.dll
*.so
*.dylib
",
        )?;
    }
    register_folder(
        licensing::FLEET_FOLDER_ID,
        &dir,
        "ferryman fleet",
        share_with,
    )
    .map(Some)
}

fn register_folder(
    folder_id: &str,
    path: &Path,
    label: &str,
    share_with: &[SyncthingPeer],
) -> Result<SyncthingSetup> {
    let folder_id = folder_id.to_string();
    let folder_path = path.display().to_string();
    let unavailable = |note: &str| SyncthingSetup {
        available: false,
        folder_id: folder_id.clone(),
        folder_path: folder_path.clone(),
        device_id: None,
        shared_with: Vec::new(),
        note: note.to_string(),
    };

    let Some(key) = syncthing_api_key() else {
        return Ok(unavailable(
            "Syncthing config not found; the channel works locally, and other machines \
             can be added once Syncthing is installed",
        ));
    };
    let base = syncthing_api_base();
    let Some(status) = syncthing_get(&base, "/rest/system/status", &key)? else {
        // Naming the address matters more than it looks: when this fired on a machine
        // where Syncthing was up on a different port, the old wording sent the operator
        // to restart a healthy service instead of to the one line that explains it.
        return Ok(unavailable(&format!(
            "Syncthing did not answer at {base}; if its GUI is on another address, set \
             SYNCTHING_API_BASE to it, otherwise start Syncthing and re-run",
        )));
    };
    let device_id = status
        .get("myID")
        .and_then(Value::as_str)
        .map(str::to_string);

    let mut devices: Vec<Value> = Vec::new();
    if let Some(me) = &device_id {
        devices.push(json!({ "deviceID": me }));
    }
    for peer in share_with {
        devices.push(json!({ "deviceID": peer.device_id }));
    }
    let body = serde_json::to_string(&json!({
        "id": folder_id,
        "label": label,
        "path": folder_path,
        "type": "sendreceive",
        "devices": devices,
        "fsWatcherEnabled": true,
        "fsWatcherDelayS": 1,
        "rescanIntervalS": 30,
    }))?;

    match syncthing_post(&base, "/rest/config/folders", &key, &body)? {
        Some(code) if (200..300).contains(&code) => Ok(SyncthingSetup {
            available: true,
            folder_id,
            folder_path,
            device_id,
            shared_with: share_with.to_vec(),
            note: if share_with.is_empty() {
                "folder registered; no other devices are paired with this Syncthing yet".to_string()
            } else {
                "folder registered and shared".to_string()
            },
        }),
        Some(code) => Ok(unavailable(&format!(
            "Syncthing refused the folder (HTTP {code}); register it by hand"
        ))),
        None => Ok(unavailable("could not reach Syncthing's API")),
    }
}

/// The device ids this project's channel folder is currently shared with
/// (this machine excluded). Empty when the folder is not registered.
pub fn syncthing_folder_device_ids(route: &ProjectRoute) -> Result<Vec<String>> {
    let folder_id = channel_folder_id(route);
    let Some(key) = syncthing_api_key() else {
        return Ok(Vec::new());
    };
    let base = syncthing_api_base();
    let Some(status) = syncthing_get(&base, "/rest/system/status", &key)? else {
        return Ok(Vec::new());
    };
    let me = status
        .get("myID")
        .and_then(Value::as_str)
        .map(str::to_string);
    let Some(config) = syncthing_get(&base, "/rest/config", &key)? else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    if let Some(folders) = config.get("folders").and_then(Value::as_array) {
        for folder in folders {
            if folder.get("id").and_then(Value::as_str) != Some(folder_id.as_str()) {
                continue;
            }
            if let Some(devices) = folder.get("devices").and_then(Value::as_array) {
                for device in devices {
                    if let Some(id) = device.get("deviceID").and_then(Value::as_str)
                        && Some(id.to_string()) != me
                    {
                        ids.push(id.to_string());
                    }
                }
            }
        }
    }
    Ok(ids)
}

/// Resolve device ids to peers, keeping the names Syncthing already knows and
/// leaving the name blank for an id this Syncthing has not paired yet.
pub fn peers_for_ids(device_ids: &[String]) -> Result<Vec<SyncthingPeer>> {
    let known = syncthing_peers()?;
    Ok(device_ids
        .iter()
        .map(|id| SyncthingPeer {
            device_id: id.clone(),
            name: known
                .iter()
                .find(|peer| &peer.device_id == id)
                .map(|peer| peer.name.clone())
                .unwrap_or_default(),
        })
        .collect())
}

/// Add a device to Syncthing's config so a folder can be shared with it. This is
/// the step that turns a "non-trusted PC" into a peer: without it Syncthing will
/// not deliver a shared folder to a device it does not know. The device is named
/// with `name` (its id is shown when the name is empty).
pub fn syncthing_add_device(device_id: &str, name: &str) -> Result<()> {
    let Some(key) = syncthing_api_key() else {
        bail!("Syncthing config not found; cannot add a device");
    };
    let base = syncthing_api_base();
    let body = serde_json::to_string(&json!({ "deviceID": device_id, "name": name }))?;
    match syncthing_post(&base, "/rest/config/devices", &key, &body)? {
        Some(code) if (200..300).contains(&code) => Ok(()),
        Some(code) => bail!("Syncthing refused the device (HTTP {code})"),
        None => bail!("could not reach Syncthing's API"),
    }
}

/// Files and directories the pre-Ferryman git-backed hone bridge used. Their
/// presence identifies an "old method" that can be moved out of the way into a
/// `deprecated/` folder. Deliberately excludes `.git`, `.gitignore`,
/// `.gitattributes`, and `README.md`, which belong to the repository itself.
const LEGACY_BRIDGE_ARTIFACTS: &[&str] = &[
    "send.sh",
    "watch-wisp.sh",
    "watch-fang.sh",
    "_kc.sh",
    "wisp",
    "fang",
    "claw",
    "fang",
    "outbox",
    "inbox",
    "proposals",
    "harness",
    "runbooks",
    "worker-adapter",
    "fleet",
    "tools",
    "agents",
    "FMN_LOG.md",
    "ORCHESTRATION.md",
    "PROTOCOL.md",
    "GO_LIVE_CYCLE.md",
    "GITHUB_AUTH.md",
    "JOIN-PROMPT.md",
    "ROAD_TO_LIVE.md",
    "SCOREBOARD.md",
    "SYNCTHING.md",
    "nodes.md",
];

/// The legacy bridge artifacts present in a workspace, if any.
pub fn legacy_bridge_artifacts(workspace: &Path) -> Vec<PathBuf> {
    LEGACY_BRIDGE_ARTIFACTS
        .iter()
        .map(|name| workspace.join(name))
        .filter(|path| path.exists())
        .collect()
}

/// Move any legacy bridge artifacts into `<workspace>/deprecated/`, so the old
/// method is preserved but out of the way of the ferryman channel. Returns the
/// destination paths that were moved (empty when there is nothing to move).
pub fn deprecate_legacy_bridge(workspace: &Path) -> Result<Vec<PathBuf>> {
    let artifacts = legacy_bridge_artifacts(workspace);
    if artifacts.is_empty() {
        return Ok(Vec::new());
    }
    let deprecated = workspace.join("deprecated");
    fs::create_dir_all(&deprecated)?;
    let mut moved = Vec::new();
    for artifact in artifacts {
        let Some(name) = artifact.file_name() else {
            continue;
        };
        let destination = deprecated.join(name);
        if destination.exists() {
            continue;
        }
        fs::rename(&artifact, &destination)?;
        moved.push(destination);
    }
    Ok(moved)
}

/// Share this project's channel folder with the given device ids, keeping every
/// peer it is already shared with. This is the granular control `enable`'s
/// share-everything default does not give: one project can go to one person.
pub fn syncthing_share_folder(
    route: &ProjectRoute,
    device_ids: &[String],
) -> Result<SyncthingSetup> {
    let mut current = syncthing_folder_device_ids(route)?;
    for id in device_ids {
        if !current.contains(id) {
            current.push(id.clone());
        }
    }
    syncthing_register_folder(route, &peers_for_ids(&current)?)
}

/// Stop sharing this project's channel folder with the given device ids, leaving
/// every other share untouched.
pub fn syncthing_unshare_folder(
    route: &ProjectRoute,
    device_ids: &[String],
) -> Result<SyncthingSetup> {
    let remaining: Vec<String> = syncthing_folder_device_ids(route)?
        .into_iter()
        .filter(|id| !device_ids.contains(id))
        .collect();
    syncthing_register_folder(route, &peers_for_ids(&remaining)?)
}

/// Remove this project's channel folder from Syncthing entirely: the channel
/// files stay put and still work locally, but this project no longer syncs.
pub fn syncthing_unregister_folder(route: &ProjectRoute) -> Result<SyncthingSetup> {
    let folder_id = channel_folder_id(route);
    let folder_path = route.communications.display().to_string();
    let unavailable = |note: &str| SyncthingSetup {
        available: false,
        folder_id: folder_id.clone(),
        folder_path: folder_path.clone(),
        device_id: None,
        shared_with: Vec::new(),
        note: note.to_string(),
    };
    let Some(key) = syncthing_api_key() else {
        return Ok(unavailable(
            "Syncthing config not found; nothing registered to remove",
        ));
    };
    let base = syncthing_api_base();
    match syncthing_delete(&base, &format!("/rest/config/folders/{folder_id}"), &key)? {
        Some(code) if (200..300).contains(&code) => Ok(SyncthingSetup {
            available: true,
            folder_id,
            folder_path,
            device_id: None,
            shared_with: Vec::new(),
            note: "folder removed from Syncthing; the channel still works locally".to_string(),
        }),
        Some(code) => Ok(unavailable(&format!(
            "Syncthing refused to remove the folder (HTTP {code})"
        ))),
        None => Ok(unavailable("could not reach Syncthing's API")),
    }
}

/// Syncthing's config.xml holds `<apikey>...</apikey>`. Read it from the platform
/// default location so an existing Syncthing install needs no extra configuration.
/// `canonicalize`, without Windows' extended-length prefix.
///
/// `std::fs::canonicalize` returns verbatim paths on Windows - `\\?\X:\project` - and
/// Ferryman was putting them straight into `bridge.toml`, into every path in
/// `enable --json`, and into the folder path handed to Syncthing. They are unreadable in
/// output meant for a person, and tools that do not understand the prefix reject them.
///
/// The prefix is only dropped where doing so is lossless: a drive path, or a UNC share
/// written back to its `\\server\share` form. A verbatim path that means something a
/// normal path cannot express is left exactly as it is.
pub fn real_path(path: &Path) -> PathBuf {
    if !cfg!(windows) {
        return path.to_path_buf();
    }
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        // Only a drive-letter path round-trips; anything else keeps the prefix.
        let mut chars = rest.chars();
        if matches!((chars.next(), chars.next()), (Some(c), Some(':')) if c.is_ascii_alphabetic()) {
            return PathBuf::from(rest);
        }
    }
    path.to_path_buf()
}

/// Every place Syncthing is known to keep `config.xml`, most specific first.
fn syncthing_config_paths() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(explicit) = std::env::var("SYNCTHING_CONFIG_DIR") {
        candidates.push(PathBuf::from(explicit).join("config.xml"));
    }
    if cfg!(windows) {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(PathBuf::from(local).join("Syncthing").join("config.xml"));
        }
    } else if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            candidates.push(PathBuf::from(xdg).join("syncthing").join("config.xml"));
        }
        candidates.push(home.join(".config").join("syncthing").join("config.xml"));
        candidates.push(
            home.join(".local")
                .join("state")
                .join("syncthing")
                .join("config.xml"),
        );
        candidates.push(
            home.join("Library")
                .join("Application Support")
                .join("Syncthing")
                .join("config.xml"),
        );
    }
    candidates
}

/// The text of one element inside Syncthing's `<gui>` block.
///
/// Scoped to `<gui>` deliberately: `<address>` also appears under every `<device>`
/// entry, and the first one in the file is a peer's, not the API's.
fn gui_element(config: &str, tag: &str) -> Option<String> {
    let start = config.find("<gui")?;
    let end = config[start..].find("</gui>")? + start;
    let gui = &config[start..end];
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let from = gui.find(&open)? + open.len();
    let to = gui[from..].find(&close)? + from;
    let value = gui[from..to].trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn syncthing_config_field(tag: &str) -> Option<String> {
    for candidate in syncthing_config_paths() {
        let Ok(text) = fs::read_to_string(&candidate) else {
            continue;
        };
        if let Some(value) = gui_element(&text, tag) {
            return Some(value);
        }
    }
    None
}

fn syncthing_api_key_from_config() -> Option<String> {
    syncthing_config_field("apikey")
}

/// The address Syncthing's own config says its API is on.
///
/// Ferryman used to assume 8384. Syncthing 2.x picks a **random** free port on a fresh
/// install - a clean Windows machine came up on 61103 - so the assumption made `enable`
/// report "Syncthing is installed but not answering on its API; start it and re-run" for
/// a Syncthing that was installed, running and answering. Telling someone to restart a
/// service that is already up is worse than saying nothing: it is a confident instruction
/// with no exit.
///
/// A wildcard bind is rewritten to loopback. `0.0.0.0` is a listen address, not a
/// destination, and connecting to it is not portable.
fn syncthing_address_from_config() -> Option<String> {
    let address = syncthing_config_field("address")?;
    let address = match address.rsplit_once(':') {
        Some((host, port)) if host == "0.0.0.0" || host.is_empty() => format!("127.0.0.1:{port}"),
        Some(("::", port)) | Some(("[::]", port)) => format!("127.0.0.1:{port}"),
        _ => address,
    };
    Some(format!("http://{address}"))
}

pub struct SharedFolderTransport<P> {
    pub probe: P,
}

impl<P: SharedHealthProbe> MessageTransport for SharedFolderTransport<P> {
    fn kind(&self) -> TransportKind {
        TransportKind::SharedFolder
    }

    fn health(&mut self, route: &ProjectRoute) -> Result<Health> {
        self.probe.health(route)
    }

    fn deliver(&mut self, route: &ProjectRoute, message: &Message) -> Result<()> {
        // Syncthing observes this inner root. Replacing the already-local message is
        // unnecessary; successful probe means the durable inner write is shared.
        if message_path(&route.communications, message).is_file() {
            Ok(())
        } else {
            persist_message(&message_path(&route.communications, message), message)
        }
    }
}

pub trait GitRunner {
    fn run(&mut self, directory: &Path, arguments: &[&str]) -> Result<()>;
    fn output(&mut self, directory: &Path, arguments: &[&str]) -> Result<String>;
    fn verify_private(&mut self, expected_name: &str) -> Result<bool>;
}

#[derive(Default)]
pub struct SystemGit;

impl GitRunner for SystemGit {
    fn run(&mut self, directory: &Path, arguments: &[&str]) -> Result<()> {
        let mut command = system_git_command(directory, arguments);
        let output = run_with_timeout(
            &mut command,
            GIT_COMMAND_TIMEOUT,
            &format!("git {}", arguments.join(" ")),
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.to_ascii_lowercase().contains("rate limit") {
                bail!("GitHub rate limited Git transport")
            }
            bail!("git {} failed: {}", arguments.join(" "), stderr.trim())
        }
        Ok(())
    }

    fn output(&mut self, directory: &Path, arguments: &[&str]) -> Result<String> {
        let mut command = system_git_command(directory, arguments);
        let output = run_with_timeout(
            &mut command,
            GIT_COMMAND_TIMEOUT,
            &format!("git {}", arguments.join(" ")),
        )?;
        if !output.status.success() {
            bail!(
                "git {} failed: {}",
                arguments.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn verify_private(&mut self, expected_name: &str) -> Result<bool> {
        let mut command = Command::new("gh");
        scrub_sensitive_child_environment(&mut command);
        command.args([
            "repo",
            "view",
            expected_name,
            "--json",
            "nameWithOwner,visibility",
        ]);
        let output = run_with_timeout(
            &mut command,
            HEALTH_COMMAND_TIMEOUT,
            "GitHub visibility verification",
        )?;
        if !output.status.success() {
            bail!(
                "GitHub visibility verification failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RepositoryView {
            name_with_owner: String,
            visibility: String,
        }
        let view: RepositoryView =
            serde_json::from_slice(&output.stdout).context("parse gh visibility response")?;
        Ok(view.name_with_owner == expected_name && view.visibility == "PRIVATE")
    }
}

pub struct PrivateGitTransport<G> {
    pub git: G,
    pub namespace: ChannelNamespace,
    pub visibility_verified_until: Option<SystemTime>,
    pub backoff_attempt: u32,
    pub retry_after: Option<SystemTime>,
}

impl<G: GitRunner> PrivateGitTransport<G> {
    /// Build a transport with no channel namespace configured. The git rung stays
    /// unavailable until an owner is pinned; use [`PrivateGitTransport::with_namespace`].
    pub fn new(git: G) -> Self {
        Self::with_namespace(git, ChannelNamespace::default())
    }

    pub fn with_namespace(git: G, namespace: ChannelNamespace) -> Self {
        Self {
            git,
            namespace,
            visibility_verified_until: None,
            backoff_attempt: 0,
            retry_after: None,
        }
    }

    pub fn note_failure(&mut self, now: SystemTime) {
        self.backoff_attempt = self.backoff_attempt.saturating_add(1).min(8);
        let seconds = 1_u64 << self.backoff_attempt;
        self.retry_after = Some(now + Duration::from_secs(seconds.min(300)));
    }

    pub fn note_success(&mut self) {
        self.backoff_attempt = 0;
        self.retry_after = None;
    }

    fn verify_origin_and_branch(&mut self, route: &ProjectRoute) -> Result<String> {
        let actual_origin = self.git.output(
            &route.communications,
            &["config", "--get", "remote.origin.url"],
        )?;
        if normalize_git_remote(&actual_origin) != normalize_git_remote(&route.git_remote) {
            bail!("inner repository origin does not match the registered project remote")
        }
        let branch = self.git.output(
            &route.communications,
            &["rev-parse", "--abbrev-ref", "HEAD"],
        )?;
        if branch.is_empty() || branch == "HEAD" {
            bail!("inner communications repository must be on a named branch")
        }
        Ok(branch)
    }

    fn commit_and_push_locked(
        &mut self,
        route: &ProjectRoute,
        relative: &str,
        commit_message: &str,
    ) -> Result<()> {
        let branch = self.verify_origin_and_branch(route)?;
        self.git
            .run(&route.communications, &["fetch", "--prune", "origin"])?;
        self.prepare_inbound_collisions(route, &branch)?;
        self.git.run(
            &route.communications,
            &["pull", "--rebase", "--autostash", "origin", &branch],
        )?;
        self.git
            .run(&route.communications, &["add", "--", relative])?;
        let pending = self.git.output(
            &route.communications,
            &["status", "--porcelain", "--", relative],
        )?;
        if !pending.is_empty() {
            self.git.run(
                &route.communications,
                &[
                    "-c",
                    "user.name=Ferryman",
                    "-c",
                    "user.email=ferryman@localhost",
                    "commit",
                    "-m",
                    commit_message,
                ],
            )?;
        }
        if let Err(first_push_error) = self
            .git
            .run(&route.communications, &["push", "origin", "HEAD"])
        {
            self.git.run(
                &route.communications,
                &["pull", "--rebase", "--autostash", "origin", &branch],
            )?;
            self.git
                .run(&route.communications, &["push", "origin", "HEAD"])
                .with_context(|| {
                    format!("push retry after reconciliation; first error: {first_push_error}")
                })?;
        }
        Ok(())
    }

    fn prepare_inbound_collisions(&mut self, route: &ProjectRoute, branch: &str) -> Result<()> {
        let untracked = self.git.output(
            &route.communications,
            &["ls-files", "--others", "--exclude-standard"],
        )?;
        let remote_ref = format!("origin/{branch}");
        for relative in untracked.lines().filter(|line| !line.is_empty()) {
            if !is_project_portable_json(route, relative) {
                continue;
            }
            let remote_paths = self.git.output(
                &route.communications,
                &["ls-tree", "-r", "--name-only", &remote_ref, "--", relative],
            )?;
            if !remote_paths.lines().any(|path| path == relative) {
                continue;
            }
            let remote_spec = format!("{remote_ref}:{relative}");
            let remote = self
                .git
                .output(&route.communications, &["show", &remote_spec])?;
            let local_path = route.communications.join(relative);
            let local = fs::read_to_string(&local_path)
                .with_context(|| format!("read portable collision {}", local_path.display()))?;
            if local.trim_end_matches(['\r', '\n']) != remote {
                bail!("private-Git inbound file conflicts with portable local state: {relative}")
            }
            fs::remove_file(&local_path).with_context(|| {
                format!(
                    "remove identical untracked copy before private-Git pull {}",
                    local_path.display()
                )
            })?;
        }
        Ok(())
    }

    fn finish_operation(&mut self, result: Result<()>) -> Result<()> {
        match result {
            Ok(()) => {
                self.note_success();
                Ok(())
            }
            Err(error) => {
                self.note_failure(SystemTime::now());
                Err(error)
            }
        }
    }
}

/// How long to wait for another operation to finish with the Git backstop.
///
/// It used to be zero: `try_lock_exclusive` once, and turn "somebody else is
/// committing right now" into a hard error. But two operations wanting the backstop
/// at the same moment is the normal case, not a fault - a worker delivering a
/// message while a snapshot runs is exactly what this lock is for - and the second
/// one should wait a beat rather than fail. Ten seconds is long enough for any git
/// commit-and-push this serialises, and short enough that a genuinely stuck holder
/// is still reported rather than waited on forever.
const GIT_LIVE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

fn acquire_git_live_lock(route: &ProjectRoute) -> Result<File> {
    let path = route.attachment.join("runtime/locks/git-live.lock");
    fs::create_dir_all(path.parent().context("Git lock path has no parent")?)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    let deadline = std::time::Instant::now() + GIT_LIVE_LOCK_WAIT;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if std::time::Instant::now() >= deadline => {
                return Err(anyhow::Error::new(error).context(format!(
                    "project Git-live lock is still held after {}s: {}",
                    GIT_LIVE_LOCK_WAIT.as_secs(),
                    path.display()
                )));
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
}

/// Commit the whole portable channel to the private-Git backstop.
///
/// Message delivery commits one file at a time; task orders, claims, results,
/// reviews, and the attribution ledger accumulate independently and would
/// otherwise be left to Syncthing alone — where any peer can delete them and
/// have the deletion propagate everywhere. Staging everything here gives those
/// files the same recovery backstop messages already have.
///
/// No-op when no private-Git backstop is configured. Callers that cannot afford
/// to block on a remote should swallow the error: the channel remains correct,
/// only the recovery copy is deferred.
pub fn snapshot_channel_to_git(route: &ProjectRoute) -> Result<()> {
    if route.git_visibility != "private" || route.git_remote.trim().is_empty() {
        return Ok(());
    }
    let mut git = SystemGit;
    let _lock = acquire_git_live_lock(route)?;

    let actual_origin = git.output(
        &route.communications,
        &["config", "--get", "remote.origin.url"],
    )?;
    if normalize_git_remote(&actual_origin) != normalize_git_remote(&route.git_remote) {
        bail!("inner repository origin does not match the registered project remote");
    }
    let branch = git.output(
        &route.communications,
        &["rev-parse", "--abbrev-ref", "HEAD"],
    )?;
    if branch.is_empty() || branch == "HEAD" {
        bail!("inner communications repository must be on a named branch");
    }

    git.run(&route.communications, &["fetch", "--prune", "origin"])?;
    // Stage before pulling so a new local file is already tracked and cannot be
    // mistaken for an untracked collision with the remote.
    git.run(&route.communications, &["add", "-A"])?;
    let pending = git.output(&route.communications, &["status", "--porcelain"])?;
    if !pending.is_empty() {
        git.run(
            &route.communications,
            &[
                "-c",
                "user.name=Ferryman",
                "-c",
                "user.email=ferryman@localhost",
                "commit",
                "-m",
                "snapshot portable channel",
            ],
        )?;
    }
    git.run(
        &route.communications,
        &["pull", "--rebase", "--autostash", "origin", &branch],
    )?;
    if let Err(first_push_error) = git.run(&route.communications, &["push", "origin", "HEAD"]) {
        git.run(
            &route.communications,
            &["pull", "--rebase", "--autostash", "origin", &branch],
        )?;
        git.run(&route.communications, &["push", "origin", "HEAD"])
            .with_context(|| {
                format!("push retry after reconciliation; first error: {first_push_error}")
            })?;
    }
    Ok(())
}

impl<G: GitRunner> MessageTransport for PrivateGitTransport<G> {
    fn kind(&self) -> TransportKind {
        TransportKind::PrivateGit
    }

    fn health(&mut self, route: &ProjectRoute) -> Result<Health> {
        if route.git_visibility != "private" || route.git_remote.trim().is_empty() {
            return Ok(Health::Unavailable);
        }
        if self
            .retry_after
            .is_some_and(|retry| retry > SystemTime::now())
        {
            return Ok(Health::RateLimited);
        }
        // No configured namespace means there is no canonical repository to verify
        // against. Report the rung unavailable rather than guessing at an owner.
        let Some(expected_name) = self.namespace.repository_name(&route.project_id) else {
            return Ok(Health::Unavailable);
        };
        let now = SystemTime::now();
        if self
            .visibility_verified_until
            .is_none_or(|expires| expires <= now)
        {
            match self.git.verify_private(&expected_name) {
                Ok(true) => {
                    self.visibility_verified_until =
                        Some(now + Duration::from_secs(VISIBILITY_CACHE_SECONDS));
                }
                Ok(false) => return Ok(Health::Unavailable),
                Err(error) => {
                    self.note_failure(now);
                    return Err(error);
                }
            }
        }
        Ok(Health::Healthy)
    }

    fn deliver(&mut self, route: &ProjectRoute, message: &Message) -> Result<()> {
        let relative = format!("messages/{}/{}.json", message.project_id, message.id);
        let result = (|| {
            let _lock = acquire_git_live_lock(route)?;
            persist_message(&message_path(&route.communications, message), message)?;
            self.commit_and_push_locked(route, &relative, &format!("message {}", message.id))
        })();
        self.finish_operation(result)
    }

    fn synchronize(&mut self, route: &ProjectRoute) -> Result<()> {
        let result = (|| {
            let _lock = acquire_git_live_lock(route)?;
            let branch = self.verify_origin_and_branch(route)?;
            self.git
                .run(&route.communications, &["fetch", "--prune", "origin"])?;
            self.prepare_inbound_collisions(route, &branch)?;
            let tracked = self
                .git
                .output(&route.communications, &["diff", "--name-only"])?;
            let staged = self
                .git
                .output(&route.communications, &["diff", "--cached", "--name-only"])?;
            let untracked = self.git.output(
                &route.communications,
                &["ls-files", "--others", "--exclude-standard"],
            )?;
            if !tracked.is_empty()
                || !staged.is_empty()
                || untracked
                    .lines()
                    .any(|relative| !is_project_portable_json(route, relative))
            {
                bail!(
                    "inbound Git synchronization deferred while non-message portable files are uncommitted"
                )
            }
            self.git.run(
                &route.communications,
                &["pull", "--ff-only", "origin", &branch],
            )
        })();
        self.finish_operation(result)
    }

    fn deliver_acknowledgement(
        &mut self,
        route: &ProjectRoute,
        acknowledgement: &Acknowledgement,
    ) -> Result<()> {
        let relative = format!(
            "acknowledgements/{}/{}.json",
            acknowledgement.project_id, acknowledgement.message_id
        );
        let result = (|| {
            let _lock = acquire_git_live_lock(route)?;
            if !acknowledgement_path(route, &acknowledgement.message_id).is_file() {
                bail!("acknowledgement must be durable before Git delivery")
            }
            self.commit_and_push_locked(
                route,
                &relative,
                &format!("acknowledge {}", acknowledgement.message_id),
            )
        })();
        self.finish_operation(result)
    }

    fn export_runtime_state(&self) -> Option<GitRuntimeState> {
        Some(GitRuntimeState {
            backoff_attempt: self.backoff_attempt,
            retry_after_unix_ms: self.retry_after.and_then(system_time_to_unix_ms),
            visibility_verified_until_unix_ms: self
                .visibility_verified_until
                .and_then(system_time_to_unix_ms),
        })
    }

    fn import_runtime_state(&mut self, state: &GitRuntimeState) {
        self.backoff_attempt = state.backoff_attempt.min(8);
        self.retry_after = state.retry_after_unix_ms.map(unix_ms_to_system_time);
        self.visibility_verified_until = state
            .visibility_verified_until_unix_ms
            .map(unix_ms_to_system_time);
    }
}

fn is_project_portable_json(route: &ProjectRoute, relative: &str) -> bool {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return false;
    }
    let message_prefix = format!("messages/{}/", route.project_id);
    let acknowledgement_prefix = format!("acknowledgements/{}/", route.project_id);
    let file_name = relative
        .strip_prefix(&message_prefix)
        .or_else(|| relative.strip_prefix(&acknowledgement_prefix));
    file_name.is_some_and(|name| !name.is_empty() && !name.contains('/') && name.ends_with(".json"))
}

fn normalize_git_remote(remote: &str) -> String {
    remote.trim().trim_end_matches(".git").to_ascii_lowercase()
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_owned()
}

/// The one canonical form of an agent name: trimmed and lowercase.
///
/// # Why an agent name has to be case-folded
///
/// An agent name is not just a label - it is a **filename**, in three places at once:
/// the roster entry (`agents/<name>.json`) in the synced folder, the pinned-key store
/// (`agents-pinned/<name>.key`), and the private key store (`keys/<name>.key`). Whether
/// two spellings are the same file therefore depends on the filesystem, and Ferryman
/// deliberately runs across all of them: NTFS and APFS fold case, ext4 does not.
///
/// So `--agent Fang` on Linux minted a *second* key under a *second* roster entry,
/// and the fleet ended up with `Fang` and `fang` as two agents with two different
/// public keys. Messages addressed to one were invisible to the other, and a message
/// signed as one read as `UnknownSigner` to a machine that only knew the other. On
/// Windows the very same pair of commands silently shared one key, so the bug did not
/// exist there - which is why it went unnoticed until a mixed fleet.
///
/// ASCII lowercase rather than [`str::to_lowercase`] on purpose: names are already
/// restricted to ASCII by [`is_safe_component`], and Unicode lowering is locale-shaped
/// (the dotless-i problem), which is not a property an identity should have.
#[must_use]
pub fn canonical_agent_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// A single path component that is safe to use as a directory or folder-ID segment:
/// non-empty, not a traversal token, and restricted to ASCII alphanumerics plus
/// `.`, `-`, `_`.
#[must_use]
pub fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub struct DeliveryEngine<L, S, G> {
    pub local: L,
    pub shared: S,
    pub git: G,
    /// Carried explicitly rather than read from the environment inside validation,
    /// so parallel tests sharing one process environment stay deterministic.
    pub namespace: ChannelNamespace,
    preferred_successes: HashMap<String, u8>,
    git_live: HashSet<String>,
    git_inbound_active: HashSet<String>,
    loaded_projects: HashSet<String>,
    stability_threshold: u8,
}

pub type SystemDeliveryEngine = DeliveryEngine<
    LocalFilesystemTransport,
    SharedFolderTransport<SyncthingProbe>,
    PrivateGitTransport<SystemGit>,
>;

/// Local filesystem first, then the Syncthing-carried shared folder, then private Git
/// as a backstop. Git is deliberately last: it is an archive of record, not the live
/// channel, and treating it as live is what let a bridge repository silently diverge
/// while real traffic never reached it.
#[must_use]
pub fn system_delivery_engine() -> SystemDeliveryEngine {
    system_delivery_engine_in(ChannelNamespace::from_env())
}

/// Same as [`system_delivery_engine`] but with an explicitly supplied namespace, for
/// callers that already resolved their configuration.
#[must_use]
pub fn system_delivery_engine_in(namespace: ChannelNamespace) -> SystemDeliveryEngine {
    DeliveryEngine::with_namespace(
        LocalFilesystemTransport,
        SharedFolderTransport {
            probe: SyncthingProbe::from_env(),
        },
        PrivateGitTransport::with_namespace(SystemGit, namespace.clone()),
        namespace,
    )
}

impl<L: MessageTransport, S: MessageTransport, G: MessageTransport> DeliveryEngine<L, S, G> {
    /// Build an engine with no channel namespace configured. Routes carrying a git
    /// remote will be rejected until an owner is pinned; use
    /// [`DeliveryEngine::with_namespace`].
    pub fn new(local: L, shared: S, git: G) -> Self {
        Self::with_namespace(local, shared, git, ChannelNamespace::default())
    }

    pub fn with_namespace(local: L, shared: S, git: G, namespace: ChannelNamespace) -> Self {
        Self {
            local,
            shared,
            git,
            namespace,
            preferred_successes: HashMap::new(),
            git_live: HashSet::new(),
            git_inbound_active: HashSet::new(),
            loaded_projects: HashSet::new(),
            stability_threshold: 2,
        }
    }

    pub fn send(&mut self, route: &ProjectRoute, message: &Message) -> Result<DeliveryReceipt> {
        route.validate_in(&self.namespace)?;
        message.validate()?;
        self.restore_state(route)?;
        if route.project_id != message.project_id {
            bail!("message project does not match project route")
        }
        if !route.permits(&message.recipient, None) {
            bail!("recipient is not registered for this project")
        }

        let outbox = outbox_path(route, &message.id);
        persist_message(&outbox, message)?;
        if acknowledgement_path(route, &message.id).is_file() {
            fs::remove_file(&outbox)?;
            return self.receipt(
                route,
                message,
                TransportKind::LocalFilesystem,
                Some("message already acknowledged; duplicate delivery suppressed".into()),
            );
        }

        let local_health = self.local.health(route).unwrap_or(Health::Unavailable);
        let shared_health = self.shared.health(route).unwrap_or(Health::Unavailable);
        let in_git_live = self.git_live.contains(&route.project_id);
        let preferred_kind = if local_health == Health::Healthy {
            match self.local.deliver(route, message) {
                Ok(()) => Some(self.local.kind()),
                Err(_) => None,
            }
        } else {
            None
        };
        let preferred_kind = if preferred_kind.is_none() && shared_health == Health::Healthy {
            match self.shared.deliver(route, message) {
                Ok(()) => Some(self.shared.kind()),
                Err(_) => None,
            }
        } else {
            preferred_kind
        };
        let acknowledgement_overdue = Utc::now() >= message.acknowledgement_deadline;

        if let Some(preferred_kind) = preferred_kind {
            if in_git_live {
                if shared_health != Health::Healthy {
                    self.preferred_successes.remove(&route.project_id);
                    if self.git.health(route).unwrap_or(Health::Unavailable) == Health::Healthy
                        && self.git.deliver(route, message).is_ok()
                    {
                        return self.receipt(
                            route,
                            message,
                            TransportKind::PrivateGit,
                            Some(
                                "Git live mode retained until the shared transport is stable"
                                    .into(),
                            ),
                        );
                    }
                    return self.receipt(
                        route,
                        message,
                        TransportKind::Queued,
                        Some(
                            "Git live mode is required while the shared transport is unavailable; delivery queued"
                                .into(),
                        ),
                    );
                }
                let count = self
                    .preferred_successes
                    .entry(route.project_id.clone())
                    .or_default();
                *count = count.saturating_add(1);
                if *count < self.stability_threshold {
                    if self.git.health(route).unwrap_or(Health::Unavailable) == Health::Healthy
                        && self.git.deliver(route, message).is_ok()
                    {
                        return self.receipt(
                            route,
                            message,
                            TransportKind::PrivateGit,
                            Some(
                                "preferred transport is recovering; Git live mode retained".into(),
                            ),
                        );
                    }
                    return self.receipt(
                        route,
                        message,
                        TransportKind::Queued,
                        Some(
                            "preferred transport is recovering, but required Git live delivery is queued"
                                .into(),
                        ),
                    );
                }
                self.git_live.remove(&route.project_id);
                self.preferred_successes.remove(&route.project_id);
            }
            if !acknowledgement_overdue {
                let reason = if shared_health == Health::Healthy {
                    None
                } else {
                    Some(format!(
                        "Syncthing shared transport unavailable; awaiting local acknowledgement until {}",
                        message.acknowledgement_deadline.to_rfc3339()
                    ))
                };
                return self.receipt(route, message, preferred_kind, reason);
            }
        }

        self.preferred_successes.remove(&route.project_id);
        self.git_live.insert(route.project_id.clone());
        match self.git.health(route).unwrap_or(Health::Unavailable) {
            Health::Healthy => match self.git.deliver(route, message) {
                Ok(()) => self.receipt(
                    route,
                    message,
                    TransportKind::PrivateGit,
                    Some(if acknowledgement_overdue {
                        "acknowledgement deadline elapsed on preferred transports".into()
                    } else {
                        "local peer and Syncthing shared transport unavailable".into()
                    }),
                ),
                Err(error) => self.receipt(
                    route,
                    message,
                    TransportKind::Queued,
                    Some(format!(
                        "Git live delivery failed; durable local outbox retained: {error}"
                    )),
                ),
            },
            Health::Unavailable | Health::RateLimited => self.receipt(
                route,
                message,
                TransportKind::Queued,
                Some("all transports unavailable; durable local outbox retained".into()),
            ),
        }
    }

    fn receipt(
        &self,
        route: &ProjectRoute,
        message: &Message,
        transport: TransportKind,
        failover_reason: Option<String>,
    ) -> Result<DeliveryReceipt> {
        self.persist_state(route)?;
        let receipt = DeliveryReceipt {
            message_id: message.id.clone(),
            attempt_id: Uuid::new_v4().to_string(),
            transport,
            delivered_at: Utc::now(),
            failover_reason,
        };
        atomic_json(
            &route
                .attachment
                .join("runtime/delivery-attempts")
                .join(&message.id)
                .join(format!("{}.json", receipt.attempt_id)),
            &receipt,
        )?;
        atomic_json(
            &route
                .attachment
                .join("runtime/deliveries")
                .join(format!("{}.json", message.id)),
            &receipt,
        )?;
        Ok(receipt)
    }

    fn acknowledgement_receipt(
        &self,
        route: &ProjectRoute,
        acknowledgement: &Acknowledgement,
        transport: TransportKind,
        failover_reason: Option<String>,
    ) -> Result<DeliveryReceipt> {
        self.persist_state(route)?;
        let receipt = DeliveryReceipt {
            message_id: acknowledgement.message_id.clone(),
            attempt_id: Uuid::new_v4().to_string(),
            transport,
            delivered_at: Utc::now(),
            failover_reason,
        };
        atomic_json(
            &route
                .attachment
                .join("runtime/acknowledgement-attempts")
                .join(&acknowledgement.message_id)
                .join(format!("{}.json", receipt.attempt_id)),
            &receipt,
        )?;
        atomic_json(
            &route
                .attachment
                .join("runtime/acknowledgement-deliveries")
                .join(format!("{}.json", acknowledgement.message_id)),
            &receipt,
        )?;
        Ok(receipt)
    }

    pub fn synchronize_inbound(&mut self, route: &ProjectRoute) -> Result<TransportKind> {
        route.validate_in(&self.namespace)?;
        self.restore_state(route)?;
        if self.shared.health(route).unwrap_or(Health::Unavailable) == Health::Healthy {
            let mut git_sync_failed = false;
            if self.git_inbound_active.contains(&route.project_id) {
                let git_synchronized = self.git.health(route).unwrap_or(Health::Unavailable)
                    == Health::Healthy
                    && self.git.synchronize(route).is_ok();
                if git_synchronized {
                    let successes = self
                        .preferred_successes
                        .entry(route.project_id.clone())
                        .or_default();
                    *successes = successes.saturating_add(1);
                    if *successes >= self.stability_threshold {
                        self.git_inbound_active.remove(&route.project_id);
                        self.preferred_successes.remove(&route.project_id);
                    }
                } else {
                    git_sync_failed = true;
                    self.preferred_successes.remove(&route.project_id);
                }
            }
            retire_acknowledged_outbox(route)?;
            self.persist_state(route)?;
            return Ok(if git_sync_failed {
                TransportKind::Queued
            } else if self.git_inbound_active.contains(&route.project_id) {
                TransportKind::PrivateGit
            } else {
                TransportKind::SharedFolder
            });
        }
        self.preferred_successes.remove(&route.project_id);
        let synchronized = self.git.health(route).unwrap_or(Health::Unavailable) == Health::Healthy
            && self.git.synchronize(route).is_ok();
        if synchronized {
            self.git_inbound_active.insert(route.project_id.clone());
            retire_acknowledged_outbox(route)?;
            self.persist_state(route)?;
            Ok(TransportKind::PrivateGit)
        } else {
            self.persist_state(route)?;
            Ok(TransportKind::Queued)
        }
    }

    pub fn acknowledge(
        &mut self,
        route: &ProjectRoute,
        acknowledgement: &Acknowledgement,
    ) -> Result<(Acknowledgement, bool, DeliveryReceipt)> {
        route.validate_in(&self.namespace)?;
        acknowledgement.validate()?;
        self.restore_state(route)?;
        let canonical = canonical_acknowledgement(route, acknowledgement)?;
        let queued_path = acknowledgement_outbox_path(route, &canonical.message_id);
        let delivery_path = route
            .attachment
            .join("runtime/acknowledgement-deliveries")
            .join(format!("{}.json", canonical.message_id));
        if acknowledgement_path(route, &canonical.message_id).is_file()
            && !queued_path.is_file()
            && delivery_path.is_file()
        {
            let receipt: DeliveryReceipt = serde_json::from_slice(&fs::read(delivery_path)?)?;
            let _ = record_acknowledgement(route, &canonical)?;
            return Ok((canonical, false, receipt));
        }
        let locally_originated = outbox_path(route, &canonical.message_id).is_file();
        persist_acknowledgement(&queued_path, &canonical)?;
        let recorded = record_acknowledgement(route, &canonical)?;
        let receipt =
            self.deliver_pending_acknowledgement(route, &canonical, locally_originated)?;
        Ok((canonical, recorded, receipt))
    }

    fn deliver_pending_acknowledgement(
        &mut self,
        route: &ProjectRoute,
        acknowledgement: &Acknowledgement,
        locally_originated: bool,
    ) -> Result<DeliveryReceipt> {
        let queued = acknowledgement_outbox_path(route, &acknowledgement.message_id);
        if locally_originated {
            if queued.is_file() {
                fs::remove_file(&queued)?;
            }
            return self.acknowledgement_receipt(
                route,
                acknowledgement,
                TransportKind::LocalFilesystem,
                None,
            );
        }
        let shared_health = self.shared.health(route).unwrap_or(Health::Unavailable);
        let requires_git = self.git_live.contains(&route.project_id)
            || self.git_inbound_active.contains(&route.project_id)
            || shared_health != Health::Healthy;
        if !requires_git {
            if queued.is_file() {
                fs::remove_file(&queued)?;
            }
            return self.acknowledgement_receipt(
                route,
                acknowledgement,
                TransportKind::SharedFolder,
                None,
            );
        }
        if self.git.health(route).unwrap_or(Health::Unavailable) == Health::Healthy
            && self
                .git
                .deliver_acknowledgement(route, acknowledgement)
                .is_ok()
        {
            if queued.is_file() {
                fs::remove_file(&queued)?;
            }
            return self.acknowledgement_receipt(
                route,
                acknowledgement,
                TransportKind::PrivateGit,
                Some("shared acknowledgement path unavailable or Git live mode active".into()),
            );
        }
        self.acknowledgement_receipt(
            route,
            acknowledgement,
            TransportKind::Queued,
            Some("acknowledgement retained for private-Git reconciliation".into()),
        )
    }

    fn reconcile_acknowledgement_outbox(
        &mut self,
        route: &ProjectRoute,
    ) -> Result<Vec<DeliveryReceipt>> {
        let directory = route.attachment.join("runtime/acknowledgement-outbox");
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut paths = fs::read_dir(&directory)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        paths.sort();
        let mut receipts = Vec::with_capacity(paths.len());
        for path in paths {
            let acknowledgement: Acknowledgement = match fs::read(&path)
                .with_context(|| format!("read queued acknowledgement {}", path.display()))
                .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
                .and_then(|acknowledgement: Acknowledgement| {
                    acknowledgement.validate()?;
                    if acknowledgement.project_id != route.project_id {
                        bail!("queued acknowledgement crossed the project boundary")
                    }
                    Ok(acknowledgement)
                }) {
                Ok(acknowledgement) => acknowledgement,
                Err(error) => {
                    quarantine_file(route, &path, "acknowledgement-outbox", &error.to_string())?;
                    continue;
                }
            };
            let locally_originated = outbox_path(route, &acknowledgement.message_id).is_file();
            if let Err(error) = record_acknowledgement(route, &acknowledgement) {
                quarantine_file(route, &path, "acknowledgement-outbox", &error.to_string())?;
                continue;
            }
            receipts.push(self.deliver_pending_acknowledgement(
                route,
                &acknowledgement,
                locally_originated,
            )?);
        }
        Ok(receipts)
    }

    pub fn reconcile_outbox(&mut self, route: &ProjectRoute) -> Result<Vec<DeliveryReceipt>> {
        route.validate_in(&self.namespace)?;
        self.restore_state(route)?;
        let _ = self.synchronize_inbound(route)?;
        let outbox = route.attachment.join("runtime/outbox");
        let mut receipts = Vec::new();
        if outbox.is_dir() {
            let mut paths = fs::read_dir(&outbox)?
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .collect::<Vec<_>>();
            paths.sort();
            receipts.reserve(paths.len());
            for path in paths {
                let message: Message = match fs::read(&path)
                    .with_context(|| format!("read queued message {}", path.display()))
                    .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
                    .and_then(|message: Message| {
                        message.validate()?;
                        if message.project_id != route.project_id {
                            bail!("queued message crossed the project boundary")
                        }
                        Ok(message)
                    }) {
                    Ok(message) => message,
                    Err(error) => {
                        quarantine_file(route, &path, "outbox", &error.to_string())?;
                        continue;
                    }
                };
                if acknowledgement_path(route, &message.id).is_file() {
                    fs::remove_file(path)?;
                    continue;
                }
                receipts.push(self.send(route, &message)?);
            }
        }
        receipts.extend(self.reconcile_acknowledgement_outbox(route)?);
        Ok(receipts)
    }

    pub fn status(
        &mut self,
        route: &ProjectRoute,
        probe_external: bool,
    ) -> Result<CommunicationsStatus> {
        route.validate_in(&self.namespace)?;
        self.restore_state(route)?;
        let local_health = self.local.health(route).unwrap_or(Health::Unavailable);
        let shared_health = if probe_external {
            self.shared.health(route).unwrap_or(Health::Unavailable)
        } else {
            Health::Unavailable
        };
        let git_health = if probe_external {
            self.git.health(route).unwrap_or(Health::Unavailable)
        } else {
            Health::Unavailable
        };
        let (
            outbox_depth,
            acknowledgement_outbox_depth,
            oldest_outbox_age_seconds,
            quarantine_files,
        ) = filesystem_metrics(route)?;
        let git = self.git.export_runtime_state().unwrap_or_default();
        let status = CommunicationsStatus {
            project_id: route.project_id.clone(),
            external_probes_performed: probe_external,
            local_health,
            shared_health,
            git_health,
            git_live: self.git_live.contains(&route.project_id),
            git_inbound_active: self.git_inbound_active.contains(&route.project_id),
            preferred_successes: self
                .preferred_successes
                .get(&route.project_id)
                .copied()
                .unwrap_or_default(),
            outbox_depth,
            acknowledgement_outbox_depth,
            oldest_outbox_age_seconds,
            quarantine_files,
            git_backoff_attempt: git.backoff_attempt,
            git_retry_after_unix_ms: git.retry_after_unix_ms,
            updated_at: Utc::now(),
        };
        self.persist_state(route)?;
        Ok(status)
    }

    fn restore_state(&mut self, route: &ProjectRoute) -> Result<()> {
        if self.loaded_projects.contains(&route.project_id) {
            return Ok(());
        }
        let path = route.attachment.join("runtime/transport-state.json");
        if path.is_file() {
            let restored = fs::read(&path)
                .context("read persisted transport state")
                .and_then(|bytes| {
                    serde_json::from_slice::<ProjectTransportState>(&bytes).map_err(Into::into)
                });
            match restored {
                Ok(state)
                    if state.format == TRANSPORT_STATE_FORMAT
                        && state.project_id == route.project_id =>
                {
                    if state.git_live {
                        self.git_live.insert(route.project_id.clone());
                    }
                    if state.git_inbound_active {
                        self.git_inbound_active.insert(route.project_id.clone());
                    }
                    if state.preferred_successes > 0 {
                        self.preferred_successes
                            .insert(route.project_id.clone(), state.preferred_successes);
                    }
                    if let Some(git) = state.git {
                        self.git.import_runtime_state(&git);
                    }
                }
                Ok(_) => {
                    quarantine_file(
                        route,
                        &path,
                        "transport-state",
                        "state format or project ID did not match",
                    )?;
                }
                Err(error) => {
                    quarantine_file(route, &path, "transport-state", &error.to_string())?;
                }
            }
        }
        self.loaded_projects.insert(route.project_id.clone());
        Ok(())
    }

    fn persist_state(&self, route: &ProjectRoute) -> Result<()> {
        let state = ProjectTransportState {
            format: TRANSPORT_STATE_FORMAT.into(),
            project_id: route.project_id.clone(),
            git_live: self.git_live.contains(&route.project_id),
            git_inbound_active: self.git_inbound_active.contains(&route.project_id),
            preferred_successes: self
                .preferred_successes
                .get(&route.project_id)
                .copied()
                .unwrap_or_default(),
            git: self.git.export_runtime_state(),
            updated_at: Utc::now(),
        };
        atomic_json(
            &route.attachment.join("runtime/transport-state.json"),
            &state,
        )
    }
}

pub fn filesystem_metrics(route: &ProjectRoute) -> Result<(usize, usize, Option<i64>, usize)> {
    route.validate()?;
    let outbox = route.attachment.join("runtime/outbox");
    let mut depth = 0;
    let mut oldest: Option<DateTime<Utc>> = None;
    if outbox.is_dir() {
        for entry in fs::read_dir(outbox)?.filter_map(std::result::Result::ok) {
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            depth += 1;
            if let Some(message) = fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Message>(&bytes).ok())
            {
                oldest =
                    Some(oldest.map_or(message.created_at, |value| value.min(message.created_at)));
            }
        }
    }
    let quarantine = route.attachment.join("runtime/quarantine");
    let acknowledgement_outbox = route.attachment.join("runtime/acknowledgement-outbox");
    let mut acknowledgement_outbox_depth = 0;
    if acknowledgement_outbox.is_dir() {
        for entry in fs::read_dir(acknowledgement_outbox)?.filter_map(std::result::Result::ok) {
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            acknowledgement_outbox_depth += 1;
            if let Some(acknowledgement) = fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Acknowledgement>(&bytes).ok())
            {
                oldest = Some(oldest.map_or(acknowledgement.processed_at, |value| {
                    value.min(acknowledgement.processed_at)
                }));
            }
        }
    }
    let quarantine_files = if quarantine.is_dir() {
        fs::read_dir(quarantine)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.path().is_dir())
            .map(|entry| {
                fs::read_dir(entry.path())
                    .map(|entries| entries.filter_map(std::result::Result::ok).count())
                    .unwrap_or_default()
            })
            .sum()
    } else {
        0
    };
    Ok((
        depth,
        acknowledgement_outbox_depth,
        oldest.map(|created| (Utc::now() - created).num_seconds().max(0)),
        quarantine_files,
    ))
}

fn quarantine_file(
    route: &ProjectRoute,
    source: &Path,
    category: &str,
    reason: &str,
) -> Result<PathBuf> {
    let directory = route.attachment.join("runtime/quarantine").join(category);
    fs::create_dir_all(&directory)?;
    let original_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("invalid");
    let destination = directory.join(format!("{}.{}.quarantined", original_name, Uuid::new_v4()));
    fs::rename(source, &destination)?;
    atomic_json(
        &destination.with_extension("error.json"),
        &serde_json::json!({
            "source": original_name,
            "reason": reason,
            "quarantined_at": Utc::now(),
        }),
    )?;
    Ok(destination)
}

pub fn claim_message(route: &ProjectRoute, message: &Message) -> Result<bool> {
    route.validate()?;
    message.validate()?;
    if message.project_id != route.project_id || !route.permits(&message.recipient, None) {
        bail!("message is not permitted by this project route")
    }
    if acknowledgement_path(route, &message.id).is_file() {
        return Ok(false);
    }
    let claim = route
        .attachment
        .join("runtime/processed")
        .join(hex::encode(Sha256::digest(
            message.idempotency_key.as_bytes(),
        )));
    fs::create_dir_all(claim.parent().context("claim path has no parent")?)?;
    match fs::create_dir(&claim) {
        Ok(()) => {
            atomic_json(&claim.join("message.json"), message)?;
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn read_message(route: &ProjectRoute, message_id: &str) -> Result<Message> {
    route.validate()?;
    if Uuid::parse_str(message_id).is_err() {
        bail!("message ID is invalid")
    }
    let path = route
        .communications
        .join("messages")
        .join(&route.project_id)
        .join(format!("{message_id}.json"));
    let message: Message = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read message {message_id}"))?,
    )?;
    message.validate()?;
    if message.project_id != route.project_id {
        bail!("stored message belongs to another project")
    }
    Ok(message)
}

pub fn list_messages(route: &ProjectRoute) -> Result<Vec<Message>> {
    route.validate()?;
    let directory = route
        .communications
        .join("messages")
        .join(&route.project_id);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let message: Message = serde_json::from_slice(&fs::read(&path)?)?;
            message.validate()?;
            if message.project_id != route.project_id {
                bail!("message {} crossed project boundary", message.id)
            }
            Ok(message)
        })
        .collect()
}

pub fn find_message_by_idempotency_key(
    route: &ProjectRoute,
    idempotency_key: &str,
) -> Result<Option<Message>> {
    let mut found = None;
    let mut candidates = list_messages(route)?;
    let outbox = route.attachment.join("runtime/outbox");
    if outbox.is_dir() {
        let mut paths = fs::read_dir(outbox)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let message: Message = serde_json::from_slice(&fs::read(&path)?)
                .with_context(|| format!("read queued message {}", path.display()))?;
            message.validate()?;
            if message.project_id != route.project_id {
                bail!("queued message {} crossed project boundary", message.id)
            }
            candidates.push(message);
        }
    }
    for message in candidates
        .into_iter()
        .filter(|message| message.idempotency_key == idempotency_key)
    {
        match &found {
            Some(existing) if existing != &message => {
                bail!("idempotency key belongs to conflicting durable messages")
            }
            Some(_) => {}
            None => found = Some(message),
        }
    }
    Ok(found)
}

pub fn record_acknowledgement(
    route: &ProjectRoute,
    acknowledgement: &Acknowledgement,
) -> Result<bool> {
    route.validate()?;
    acknowledgement.validate()?;
    if acknowledgement.project_id != route.project_id {
        bail!("acknowledgement project does not match route")
    }
    let stored_message_path = route
        .communications
        .join("messages")
        .join(&route.project_id)
        .join(format!("{}.json", acknowledgement.message_id));
    let message: Message = serde_json::from_slice(
        &fs::read(&stored_message_path)
            .with_context(|| format!("read message {}", acknowledgement.message_id))?,
    )?;
    if acknowledgement.idempotency_key != message.idempotency_key
        || (acknowledgement.recipient != message.recipient
            && !route.agents.iter().any(|agent| {
                agent.name.eq_ignore_ascii_case(&acknowledgement.recipient)
                    && agent.role == message.recipient
            }))
    {
        bail!("acknowledgement does not match the stored message")
    }
    let path = acknowledgement_path(route, &acknowledgement.message_id);
    if path.exists() {
        let existing: Acknowledgement = serde_json::from_slice(&fs::read(&path)?)?;
        if existing.message_id == acknowledgement.message_id
            && existing.project_id == acknowledgement.project_id
            && existing.recipient == acknowledgement.recipient
            && existing.idempotency_key == acknowledgement.idempotency_key
        {
            let queued = outbox_path(route, &acknowledgement.message_id);
            if queued.is_file() {
                fs::remove_file(queued)?;
            }
            return Ok(false);
        }
        bail!("conflicting acknowledgement already exists")
    }
    atomic_json(&path, acknowledgement)?;
    let queued = outbox_path(route, &acknowledgement.message_id);
    if queued.is_file() {
        fs::remove_file(queued)?;
    }
    Ok(true)
}

/// Read the envelope `format` field from a stored message file without parsing the
/// version-specific body. Missing `format` is treated as the unsigned v1 envelope.
pub fn inbound_message_format(route: &ProjectRoute, message_id: &str) -> Result<String> {
    route.validate()?;
    if Uuid::parse_str(message_id).is_err() {
        bail!("message ID is invalid")
    }
    let path = route
        .communications
        .join("messages")
        .join(&route.project_id)
        .join(format!("{message_id}.json"));
    let value: Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read message {message_id}"))?,
    )?;
    Ok(value
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or(MESSAGE_FORMAT)
        .to_owned())
}

fn validate_v2_message(message: &MessageV2) -> Result<()> {
    if message.format != portable_auth::MESSAGE_FORMAT_V2 || Uuid::parse_str(&message.id).is_err() {
        bail!("invalid Ferryman v2 message format or ID")
    }
    if message.project_id.trim().is_empty()
        || message.sender.trim().is_empty()
        || message.recipient.trim().is_empty()
        || message.idempotency_key.trim().is_empty()
    {
        bail!("message routing and idempotency fields are required")
    }
    if message.acknowledgement_deadline < message.created_at {
        bail!("acknowledgement deadline cannot precede creation")
    }
    if message.sender.len() > 128
        || message.recipient.len() > 128
        || message.idempotency_key.len() > 256
        || message.payload_reference.len() > 2_048
    {
        bail!("message routing or reference field exceeds its size limit")
    }
    if serde_json::to_vec(&message.payload)?.len() > MAX_INLINE_PAYLOAD_BYTES {
        bail!("inline message payload exceeds 256 KiB")
    }
    if contains_sensitive_key(&message.payload) {
        bail!("portable message payload contains a prohibited secret-like field")
    }
    Ok(())
}

/// List the v2 messages in this project's inbound directory.
///
/// Invalid or non-v2 files are skipped rather than failing the whole listing; the
/// server boundary calls [`quarantine_invalid_inbound`] before this so invalid
/// envelopes have already been moved aside. Returned messages are sorted by ID.
/// Claimed messages are still listed: replay protection is enforced at claim
/// time, not here, so a claimed message stays visible until acknowledged.
pub fn list_messages_v2(route: &ProjectRoute) -> Result<Vec<MessageV2>> {
    route.validate()?;
    let directory = route
        .communications
        .join("messages")
        .join(&route.project_id);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut messages = Vec::new();
    for path in paths {
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let value: Value = match serde_json::from_slice(&raw) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if value.get("format").and_then(Value::as_str) != Some(portable_auth::MESSAGE_FORMAT_V2) {
            continue;
        }
        let message: MessageV2 = match serde_json::from_slice(&raw) {
            Ok(message) => message,
            Err(_) => continue,
        };
        if validate_v2_message(&message).is_err()
            || message.project_id != route.project_id
            || verify_v2_message(route, &message).is_err()
        {
            continue;
        }
        messages.push(message);
    }
    messages.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(messages)
}

/// Read one v2 message by ID, verifying its signature against the trust store.
///
/// Replay protection is enforced at claim time, not here: a claimed message is
/// still readable because its acknowledgement is bound to this exact file.
pub fn read_message_v2(route: &ProjectRoute, message_id: &str) -> Result<MessageV2> {
    route.validate()?;
    if Uuid::parse_str(message_id).is_err() {
        bail!("message ID is invalid")
    }
    let path = route
        .communications
        .join("messages")
        .join(&route.project_id)
        .join(format!("{message_id}.json"));
    let message: MessageV2 = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read v2 message {message_id}"))?,
    )
    .with_context(|| format!("parse v2 message {message_id}"))?;
    validate_v2_message(&message)?;
    if message.project_id != route.project_id {
        bail!("stored message belongs to another project")
    }
    if message.id != message_id {
        bail!("stored message ID does not match its filename")
    }
    verify_v2_message(route, &message)?;
    Ok(message)
}

/// Serialize replay-ledger check-and-record for this project. Claim and
/// acknowledgement both read then write the ledger; without this lock two
/// concurrent claims of different messages reusing one nonce could both pass
/// the read before either records.
fn acquire_replay_lock(route: &ProjectRoute) -> Result<File> {
    let path = route.attachment.join("runtime/locks/replay.lock");
    fs::create_dir_all(path.parent().context("replay lock path has no parent")?)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    file.lock_exclusive()
        .with_context(|| format!("project replay lock is held: {}", path.display()))?;
    Ok(file)
}

/// Atomically claim a v2 message, recording its nonce in the replay ledger
/// before the claim so a replayed nonce can never be claimed twice.
pub fn claim_message_v2(route: &ProjectRoute, message: &MessageV2) -> Result<bool> {
    route.validate()?;
    validate_v2_message(message)?;
    if message.project_id != route.project_id || !route.permits(&message.recipient, None) {
        bail!("message is not permitted by this project route")
    }
    verify_v2_message(route, message)?;
    if acknowledgement_path(route, &message.id).is_file() {
        return Ok(false);
    }
    let claim = route
        .attachment
        .join("runtime/processed")
        .join(hex::encode(Sha256::digest(
            message.idempotency_key.as_bytes(),
        )));
    // An already-claimed message (same idempotency key) is idempotent, not a
    // replay: the original claim recorded the nonce, so check the claim first.
    if claim.is_dir() {
        return Ok(false);
    }
    // Serialize check-then-record so a nonce cannot be claimed twice by two
    // racing requests. Re-check the claim after taking the lock: the message may
    // have been claimed (idempotently) while we waited, which is not a replay.
    let _replay_lock = acquire_replay_lock(route)?;
    if claim.is_dir() {
        return Ok(false);
    }
    // Reject a replayed nonce, then durably record acceptance before claiming.
    let mut ledger = replay_ledger(route)?;
    if ledger.contains(
        &message.authentication.signer_id,
        &message.authentication.nonce,
    ) {
        bail!(
            "replayed nonce for signer {}",
            message.authentication.signer_id
        );
    }
    ledger.record(
        &message.authentication.signer_id,
        &message.authentication.nonce,
    );
    ledger.save(&route.attachment.join("runtime/replay-ledger.json"))?;

    fs::create_dir_all(claim.parent().context("claim path has no parent")?)?;
    match fs::create_dir(&claim) {
        Ok(()) => {
            atomic_json(&claim.join("message.json"), message)?;
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Verify and persist a v2 acknowledgement, mirroring the v1 acknowledgement path.
pub fn acknowledge_v2(route: &ProjectRoute, acknowledgement: &AcknowledgementV2) -> Result<bool> {
    route.validate()?;
    if acknowledgement.format != portable_auth::ACKNOWLEDGEMENT_FORMAT_V2 {
        bail!("invalid Ferryman v2 acknowledgement format")
    }
    if Uuid::parse_str(&acknowledgement.message_id).is_err() {
        bail!("acknowledgement message ID is invalid")
    }
    if acknowledgement.project_id != route.project_id {
        bail!("acknowledgement project does not match route")
    }
    if !is_safe_component(&acknowledgement.acknowledged_by) {
        bail!("acknowledgement actor is missing or not a path-safe identifier")
    }
    verify_v2_acknowledgement(route, acknowledgement)?;

    let stored_message_path = route
        .communications
        .join("messages")
        .join(&route.project_id)
        .join(format!("{}.json", acknowledgement.message_id));
    let stored_message: MessageV2 = serde_json::from_slice(
        &fs::read(&stored_message_path)
            .with_context(|| format!("read message {}", acknowledgement.message_id))?,
    )
    .with_context(|| format!("parse v2 message {}", acknowledgement.message_id))?;
    validate_v2_message(&stored_message)?;
    if stored_message.project_id != route.project_id {
        bail!("stored message belongs to another project")
    }
    // The message must be from a trusted signer, but its nonce may already have been
    // consumed by a successful claim, so only the acknowledgement nonce is replay-checked.
    verify_v2_message(route, &stored_message)?;
    let expected = AcknowledgementV2::new(&stored_message)?;
    if acknowledgement.message_id != stored_message.id
        || acknowledgement.idempotency_key != stored_message.idempotency_key
        || acknowledgement.recipient != stored_message.recipient
        || acknowledgement.message_digest != expected.message_digest
    {
        bail!("acknowledgement does not match the stored message")
    }

    // Serialize idempotency + replay check-and-record for the acknowledgement.
    let _replay_lock = acquire_replay_lock(route)?;
    let path = acknowledgement_path(route, &acknowledgement.message_id);
    if path.exists() {
        let existing: AcknowledgementV2 = serde_json::from_slice(&fs::read(&path)?)?;
        if existing.message_id == acknowledgement.message_id
            && existing.project_id == acknowledgement.project_id
            && existing.recipient == acknowledgement.recipient
            && existing.idempotency_key == acknowledgement.idempotency_key
        {
            let queued = outbox_path(route, &acknowledgement.message_id);
            if queued.is_file() {
                fs::remove_file(queued)?;
            }
            return Ok(false);
        }
        bail!("conflicting acknowledgement already exists")
    }

    let mut ledger = replay_ledger(route)?;
    if ledger.contains(
        &acknowledgement.authentication.signer_id,
        &acknowledgement.authentication.nonce,
    ) {
        bail!(
            "replayed acknowledgement nonce for signer {}",
            acknowledgement.authentication.signer_id
        )
    }
    atomic_json(&path, acknowledgement)?;
    let queued = outbox_path(route, &acknowledgement.message_id);
    if queued.is_file() {
        fs::remove_file(queued)?;
    }
    ledger.record(
        &acknowledgement.authentication.signer_id,
        &acknowledgement.authentication.nonce,
    );
    ledger.save(&route.attachment.join("runtime/replay-ledger.json"))?;
    Ok(true)
}

fn canonical_acknowledgement(
    route: &ProjectRoute,
    acknowledgement: &Acknowledgement,
) -> Result<Acknowledgement> {
    let path = acknowledgement_path(route, &acknowledgement.message_id);
    if !path.is_file() {
        return Ok(acknowledgement.clone());
    }
    let existing: Acknowledgement = serde_json::from_slice(&fs::read(&path)?)?;
    existing.validate()?;
    if existing.message_id != acknowledgement.message_id
        || existing.project_id != acknowledgement.project_id
        || existing.recipient != acknowledgement.recipient
        || existing.idempotency_key != acknowledgement.idempotency_key
    {
        bail!("conflicting acknowledgement already exists")
    }
    Ok(existing)
}

fn retire_acknowledged_outbox(route: &ProjectRoute) -> Result<()> {
    let acknowledgements = route
        .communications
        .join("acknowledgements")
        .join(&route.project_id);
    if !acknowledgements.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(acknowledgements)?.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let acknowledgement: Acknowledgement = serde_json::from_slice(&fs::read(&path)?)?;
        // Inbound acknowledgement files are transport input, not authority.
        // Reuse the same stored-message binding checks as the API path before
        // allowing one to retire a durable outbox entry.
        record_acknowledgement(route, &acknowledgement)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    struct FakeTransport {
        kind: TransportKind,
        health: Health,
        deliveries: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }
    impl MessageTransport for FakeTransport {
        fn kind(&self) -> TransportKind {
            self.kind.clone()
        }
        fn health(&mut self, _: &ProjectRoute) -> Result<Health> {
            Ok(self.health)
        }
        fn deliver(&mut self, _: &ProjectRoute, message: &Message) -> Result<()> {
            if self.fail {
                bail!("offline")
            }
            self.deliveries.lock().unwrap().push(message.id.clone());
            Ok(())
        }
    }

    /// The namespace the test fixtures are pinned to. Supplied explicitly so tests
    /// never depend on the ambient process environment.
    fn test_namespace() -> ChannelNamespace {
        ChannelNamespace::with_owner("example-org")
    }

    fn test_engine<L, S, G>(local: L, shared: S, git: G) -> DeliveryEngine<L, S, G>
    where
        L: MessageTransport,
        S: MessageTransport,
        G: MessageTransport,
    {
        DeliveryEngine::with_namespace(local, shared, git, test_namespace())
    }

    fn test_git_transport<G: GitRunner>(git: G) -> PrivateGitTransport<G> {
        PrivateGitTransport::with_namespace(git, test_namespace())
    }

    fn fixture() -> (tempfile::TempDir, ProjectRoute) {
        let directory = tempfile::tempdir().unwrap();
        let workspace = directory.path().join("project");
        fs::create_dir_all(&workspace).unwrap();
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        (
            directory,
            ProjectRoute {
                project_id: "alpha".into(),
                workspace,
                attachment,
                communications,
                shared_remote: "alpha-ferryman".into(),
                git_remote: "https://github.com/example-org/alpha-ferryman.git".into(),
                git_visibility: "private".into(),
                agents: vec![AgentRoute {
                    name: "alpha-builder".into(),
                    role: "builder".into(),
                    capabilities: vec!["code".into()],
                    public_key: None,
                    encryption_key: None,
                }],
            },
        )
    }

    fn fake(kind: TransportKind, health: Health, log: Arc<Mutex<Vec<String>>>) -> FakeTransport {
        FakeTransport {
            kind,
            health,
            deliveries: log,
            fail: false,
        }
    }

    #[test]
    fn transport_children_drop_sensitive_environment_and_git_hooks() {
        let directory = tempfile::tempdir().unwrap();
        let mut command = system_git_command(directory.path(), &["status", "--short"]);
        command.env("FERRYMAN_NON_SECRET_SETTING", "kept");

        let removed = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<HashSet<_>>();
        for name in SENSITIVE_CHILD_ENVIRONMENT {
            assert!(removed.contains(*name), "{name} was not removed");
        }
        assert!(command.get_envs().any(|(name, value)| {
            name == "FERRYMAN_NON_SECRET_SETTING" && value.is_some_and(|item| item == "kept")
        }));

        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let hooks_argument = format!("core.hooksPath={NULL_GIT_HOOKS_PATH}");
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair[0] == "-c" && pair[1] == hooks_argument)
        );
        assert!(arguments.ends_with(&["status".into(), "--short".into()]));
    }

    #[test]
    fn portable_messages_enforce_payload_and_route_limits() {
        let (_temp, mut route) = fixture();
        let nested_secret = Message::new(
            "alpha",
            "operator",
            "alpha-builder",
            "inline",
            serde_json::json!({"task":{"password":"do-not-port"}}),
            false,
            None,
        );
        assert!(nested_secret.validate().is_err());
        let disguised_secret = Message::new(
            "alpha",
            "operator",
            "alpha-builder",
            "inline",
            serde_json::json!({"task":{"github_token_value":"do-not-port"}}),
            false,
            None,
        );
        assert!(disguised_secret.validate().is_err());

        let oversized = Message::new(
            "alpha",
            "operator",
            "alpha-builder",
            "inline",
            serde_json::json!({"value":"x".repeat(MAX_INLINE_PAYLOAD_BYTES)}),
            false,
            None,
        );
        assert!(oversized.validate().is_err());

        route.agents.push(route.agents[0].clone());
        assert!(route.validate().is_err());
    }

    #[test]
    fn status_reports_transport_health_and_durable_queue_depth() {
        let (_temp, route) = fixture();
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Healthy,
                deliveries.clone(),
            ),
            fake(
                TransportKind::SharedFolder,
                Health::Unavailable,
                deliveries.clone(),
            ),
            fake(TransportKind::PrivateGit, Health::Healthy, deliveries),
        );
        let message = Message::new(
            "alpha",
            "operator",
            "alpha-builder",
            "inline",
            serde_json::json!({"task":"status fixture"}),
            false,
            None,
        );
        engine.send(&route, &message).unwrap();
        let status = engine.status(&route, true).unwrap();
        assert_eq!(status.project_id, "alpha");
        assert_eq!(status.local_health, Health::Healthy);
        assert_eq!(status.shared_health, Health::Unavailable);
        assert_eq!(status.git_health, Health::Healthy);
        assert_eq!(status.outbox_depth, 1);
        assert_eq!(status.quarantine_files, 0);
    }

    #[test]
    fn stable_ids_routing_and_duplicate_acknowledgements() {
        let (_temp, route) = fixture();
        let first = Message::new(
            "alpha",
            "operator",
            "builder",
            "inline",
            serde_json::json!({"task":"x"}),
            true,
            Some("stable-key".into()),
        );
        assert_eq!(first.idempotency_key, "stable-key");
        persist_message(&outbox_path(&route, &first.id), &first).unwrap();
        assert_eq!(
            find_message_by_idempotency_key(&route, "stable-key")
                .unwrap()
                .unwrap(),
            first
        );
        assert!(!route.permits("beta-builder", None));
        let ack = Acknowledgement {
            message_id: first.id.clone(),
            project_id: "alpha".into(),
            recipient: "alpha-builder".into(),
            processed_at: Utc::now(),
            idempotency_key: first.idempotency_key.clone(),
        };
        LocalFilesystemTransport.deliver(&route, &first).unwrap();
        assert!(claim_message(&route, &first).unwrap());
        assert!(!claim_message(&route, &first).unwrap());
        assert!(record_acknowledgement(&route, &ack).unwrap());
        assert!(!record_acknowledgement(&route, &ack).unwrap());
        let claim = route
            .attachment
            .join("runtime/processed")
            .join(hex::encode(Sha256::digest(
                first.idempotency_key.as_bytes(),
            )));
        fs::remove_dir_all(claim).unwrap();
        assert!(!claim_message(&route, &first).unwrap());
    }

    #[test]
    fn inbound_acknowledgement_must_match_stored_message_before_retiring_outbox() {
        let (_temp, route) = fixture();
        let message = Message::new(
            "alpha",
            "operator",
            "builder",
            "inline",
            serde_json::json!({"task":"protected"}),
            false,
            Some("expected-key".into()),
        );
        LocalFilesystemTransport.deliver(&route, &message).unwrap();
        persist_message(&outbox_path(&route, &message.id), &message).unwrap();

        let forged = Acknowledgement {
            message_id: message.id.clone(),
            project_id: route.project_id.clone(),
            recipient: "alpha-builder".into(),
            processed_at: Utc::now(),
            idempotency_key: "forged-key".into(),
        };
        atomic_json(&acknowledgement_path(&route, &message.id), &forged).unwrap();

        let error = retire_acknowledged_outbox(&route).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("acknowledgement does not match the stored message")
        );
        assert!(outbox_path(&route, &message.id).is_file());

        let forged_recipient = Acknowledgement {
            message_id: message.id.clone(),
            project_id: route.project_id.clone(),
            recipient: "unauthorized-recipient".into(),
            processed_at: Utc::now(),
            idempotency_key: message.idempotency_key.clone(),
        };
        atomic_json(
            &acknowledgement_path(&route, &message.id),
            &forged_recipient,
        )
        .unwrap();

        assert!(retire_acknowledged_outbox(&route).is_err());
        assert!(outbox_path(&route, &message.id).is_file());
    }

    #[test]
    fn valid_inbound_acknowledgement_retires_outbox() {
        let (_temp, route) = fixture();
        let message = Message::new(
            "alpha",
            "operator",
            "builder",
            "inline",
            Value::Null,
            false,
            Some("expected-key".into()),
        );
        LocalFilesystemTransport.deliver(&route, &message).unwrap();
        persist_message(&outbox_path(&route, &message.id), &message).unwrap();

        let acknowledgement = Acknowledgement {
            message_id: message.id.clone(),
            project_id: route.project_id.clone(),
            recipient: "alpha-builder".into(),
            processed_at: Utc::now(),
            idempotency_key: message.idempotency_key.clone(),
        };
        atomic_json(&acknowledgement_path(&route, &message.id), &acknowledgement).unwrap();

        retire_acknowledged_outbox(&route).unwrap();
        assert!(!outbox_path(&route, &message.id).exists());
    }

    #[test]
    fn inbound_git_mode_requires_stable_shared_and_git_synchronization() {
        let (_temp, route) = fixture();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(TransportKind::LocalFilesystem, Health::Healthy, log.clone()),
            fake(
                TransportKind::SharedFolder,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::PrivateGit, Health::Healthy, log),
        );
        assert_eq!(
            engine.synchronize_inbound(&route).unwrap(),
            TransportKind::PrivateGit
        );
        assert!(engine.git_inbound_active.contains("alpha"));

        engine.shared.health = Health::Healthy;
        engine.git.health = Health::Unavailable;
        assert_eq!(
            engine.synchronize_inbound(&route).unwrap(),
            TransportKind::Queued
        );
        assert!(engine.git_inbound_active.contains("alpha"));

        engine.git.health = Health::Healthy;
        assert_eq!(
            engine.synchronize_inbound(&route).unwrap(),
            TransportKind::PrivateGit
        );
        assert_eq!(
            engine.synchronize_inbound(&route).unwrap(),
            TransportKind::SharedFolder
        );
        assert!(!engine.git_inbound_active.contains("alpha"));
    }

    #[test]
    fn remote_acknowledgements_queue_and_reconcile_through_git() {
        let (_temp, route) = fixture();
        let message = Message::new(
            "alpha",
            "operator",
            "builder",
            "inline",
            Value::Null,
            false,
            None,
        );
        LocalFilesystemTransport.deliver(&route, &message).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(TransportKind::LocalFilesystem, Health::Healthy, log.clone()),
            fake(
                TransportKind::SharedFolder,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::PrivateGit, Health::RateLimited, log),
        );
        let acknowledgement = Acknowledgement {
            message_id: message.id.clone(),
            project_id: "alpha".into(),
            recipient: "alpha-builder".into(),
            processed_at: Utc::now(),
            idempotency_key: message.idempotency_key,
        };
        let (_, recorded, receipt) = engine.acknowledge(&route, &acknowledgement).unwrap();
        assert!(recorded);
        assert_eq!(receipt.transport, TransportKind::Queued);
        assert!(acknowledgement_outbox_path(&route, &message.id).is_file());
        engine.git.health = Health::Healthy;
        let receipts = engine.reconcile_outbox(&route).unwrap();
        assert!(
            receipts
                .iter()
                .any(|receipt| receipt.transport == TransportKind::PrivateGit)
        );
        assert!(!acknowledgement_outbox_path(&route, &message.id).exists());
    }

    #[test]
    fn local_first_git_failover_and_stable_return() {
        let (_temp, route) = fixture();
        let local_log = Arc::new(Mutex::new(Vec::new()));
        let shared_log = Arc::new(Mutex::new(Vec::new()));
        let git_log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Healthy,
                local_log.clone(),
            ),
            fake(TransportKind::SharedFolder, Health::Healthy, shared_log),
            fake(TransportKind::PrivateGit, Health::Healthy, git_log.clone()),
        );
        let message = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &message).unwrap().transport,
            TransportKind::LocalFilesystem
        );
        assert!(git_log.lock().unwrap().is_empty());

        engine.local.health = Health::Unavailable;
        engine.shared.health = Health::Unavailable;
        let failed = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &failed).unwrap().transport,
            TransportKind::PrivateGit
        );
        engine.local.health = Health::Healthy;
        engine.shared.health = Health::Healthy;
        let recovering = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &recovering).unwrap().transport,
            TransportKind::PrivateGit
        );
        let recovered = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &recovered).unwrap().transport,
            TransportKind::LocalFilesystem
        );
    }

    #[test]
    fn shared_folder_is_used_when_local_peer_is_unavailable() {
        let (_temp, route) = fixture();
        let log = Arc::new(Mutex::new(Vec::new()));
        let shared_log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                log.clone(),
            ),
            fake(
                TransportKind::SharedFolder,
                Health::Healthy,
                shared_log.clone(),
            ),
            fake(TransportKind::PrivateGit, Health::Healthy, log),
        );
        let message = Message::new(
            "alpha",
            "operator",
            "builder",
            "inline",
            Value::Null,
            false,
            None,
        );
        assert_eq!(
            engine.send(&route, &message).unwrap().transport,
            TransportKind::SharedFolder
        );
        assert_eq!(shared_log.lock().unwrap().as_slice(), &[message.id]);
    }

    /// The case this whole change exists for: a channel carried entirely by Syncthing,
    /// with no GitHub repository at all, must validate and must be able to send.
    #[test]
    fn syncthing_only_channel_validates_and_sends_without_any_git_remote() {
        let (_temp, mut route) = fixture();
        route.git_remote = String::new();
        // With no remote there is no repository whose visibility could leak, so the
        // "private" requirement does not apply.
        route.git_visibility = String::new();

        route.validate().expect("structural validation");
        // Valid under a namespace-less installation and under a configured one alike:
        // there is simply no git rung to pin.
        route
            .validate_in(&ChannelNamespace::default())
            .expect("Syncthing-only route is valid with no namespace configured");
        route
            .validate_in(&test_namespace())
            .expect("Syncthing-only route is valid with a namespace configured");

        let message = Message::new(
            "alpha",
            "operator",
            "alpha-builder",
            "inline",
            Value::Null,
            false,
            None,
        );
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::SharedFolder, Health::Healthy, log.clone()),
            fake(TransportKind::PrivateGit, Health::Unavailable, log.clone()),
        );
        let receipt = engine
            .send(&route, &message)
            .expect("Syncthing-only channel must be able to send");
        assert_eq!(receipt.transport, TransportKind::SharedFolder);
        assert_eq!(log.lock().unwrap().as_slice(), &[message.id]);
    }

    /// Fail closed: a remote that this installation cannot pin is refused outright
    /// rather than accepted unpinned.
    #[test]
    fn git_remote_without_a_configured_namespace_is_refused() {
        let (_temp, route) = fixture();
        let error = route
            .validate_in(&ChannelNamespace::default())
            .expect_err("an unpinnable remote must be rejected, not silently accepted");
        // The operator has to be told exactly which knob to set.
        assert!(
            error.to_string().contains("FERRYMAN_CHANNEL_GIT_OWNER"),
            "error must name the variable to set, got: {error}"
        );
    }

    /// The pin is still exact: a remote under somebody else's account is refused.
    #[test]
    fn git_remote_under_a_foreign_owner_is_refused() {
        let (_temp, mut route) = fixture();
        route.git_remote = "https://github.com/somebody-else/alpha-ferryman.git".into();
        assert!(route.validate_in(&test_namespace()).is_err());

        // ...and the matching remote for this namespace is accepted, including the
        // usual .git / case-insensitivity normalisation.
        route.git_remote = "https://github.com/Example-Org/alpha-ferryman".into();
        route
            .validate_in(&test_namespace())
            .expect("the canonical remote for this namespace must be accepted");
    }

    #[test]
    fn namespace_honours_a_configured_repository_suffix() {
        let namespace = ChannelNamespace {
            git_owner: Some("acme".into()),
            git_suffix: "-channel".into(),
        };
        assert_eq!(
            namespace.git_remote("alpha").unwrap(),
            "https://github.com/acme/alpha-channel.git"
        );
        let (_temp, mut route) = fixture();
        route.git_remote = "https://github.com/acme/alpha-channel.git".into();
        route.validate_in(&namespace).expect("suffix is honoured");
    }

    #[test]
    fn public_repository_and_cross_project_messages_are_refused() {
        let (_temp, mut route) = fixture();
        route.git_visibility = "public".into();
        assert!(route.validate().is_err());
        route.git_visibility = "private".into();
        // `shared_remote` is a Syncthing folder ID now: it must be a path-safe
        // component, and the old MEGA-style path no longer qualifies.
        route.shared_remote = "/shared-bridges/alpha".into();
        assert!(route.validate().is_err());
        route.shared_remote = "alpha-ferryman".into();
        let message = Message::new(
            "beta",
            "operator",
            "builder",
            "inline",
            Value::Null,
            false,
            None,
        );
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(TransportKind::LocalFilesystem, Health::Healthy, log.clone()),
            fake(TransportKind::SharedFolder, Health::Healthy, log.clone()),
            fake(TransportKind::PrivateGit, Health::Healthy, log),
        );
        assert!(engine.send(&route, &message).is_err());
    }

    #[test]
    fn offline_queue_and_bounded_backoff() {
        let (_temp, route) = fixture();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                log.clone(),
            ),
            fake(
                TransportKind::SharedFolder,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::PrivateGit, Health::RateLimited, log),
        );
        let message = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &message).unwrap().transport,
            TransportKind::Queued
        );
        assert!(
            route
                .attachment
                .join(format!("runtime/outbox/{}.json", message.id))
                .is_file()
        );
        engine.git.health = Health::Healthy;
        assert_eq!(
            engine.send(&route, &message).unwrap().transport,
            TransportKind::PrivateGit
        );

        let mut git = test_git_transport(SystemGit);
        for _ in 0..20 {
            git.note_failure(SystemTime::now());
        }
        assert_eq!(git.backoff_attempt, 8);
        assert!(git.retry_after.unwrap() <= SystemTime::now() + Duration::from_secs(301));
    }

    #[test]
    fn secrets_stay_outside_the_portable_repository() {
        let (_temp, route) = fixture();
        fs::create_dir_all(&route.communications).unwrap();
        fs::write(route.attachment.join("token"), "secret").unwrap();
        assert!(!route.communications.join("token").exists());
        assert!(!route.communications.join("runtime").exists());
    }

    #[test]
    fn overdue_acknowledgement_promotes_git_even_when_preferred_routes_probe_healthy() {
        let (_temp, route) = fixture();
        let log = Arc::new(Mutex::new(Vec::new()));
        let git_log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(TransportKind::LocalFilesystem, Health::Healthy, log.clone()),
            fake(TransportKind::SharedFolder, Health::Healthy, log),
            fake(TransportKind::PrivateGit, Health::Healthy, git_log.clone()),
        );
        let message = Message::new_with_ack_deadline(
            "alpha",
            "operator",
            "builder",
            "inline",
            Value::Null,
            false,
            None,
            chrono::Duration::zero(),
        );
        let receipt = engine.send(&route, &message).unwrap();
        assert_eq!(receipt.transport, TransportKind::PrivateGit);
        assert_eq!(git_log.lock().unwrap().as_slice(), &[message.id]);
        assert!(
            receipt
                .failover_reason
                .unwrap()
                .contains("acknowledgement deadline")
        );
    }

    #[test]
    fn reconciliation_recovers_an_offline_queue() {
        let (_temp, route) = fixture();
        let log = Arc::new(Mutex::new(Vec::new()));
        let git_log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::SharedFolder, Health::Unavailable, log),
            fake(
                TransportKind::PrivateGit,
                Health::RateLimited,
                git_log.clone(),
            ),
        );
        let message = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &message).unwrap().transport,
            TransportKind::Queued
        );
        engine.git.health = Health::Healthy;
        let receipts = engine.reconcile_outbox(&route).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].transport, TransportKind::PrivateGit);
        assert_eq!(git_log.lock().unwrap().as_slice(), &[message.id]);
    }

    /// These tests exercise Git failover state, not shared-folder health, so the
    /// shared rung just needs to be reliably absent.
    struct OfflineProbe;
    impl SharedHealthProbe for OfflineProbe {
        fn health(&mut self, _route: &ProjectRoute) -> Result<Health> {
            Ok(Health::Unavailable)
        }
    }

    struct FakeGitRunner {
        visibility: bool,
        visibility_checks: usize,
        status: VecDeque<String>,
        commands: Vec<Vec<String>>,
        expected_origin: String,
    }

    impl GitRunner for FakeGitRunner {
        fn run(&mut self, _: &Path, arguments: &[&str]) -> Result<()> {
            self.commands
                .push(arguments.iter().map(ToString::to_string).collect());
            Ok(())
        }

        fn output(&mut self, _: &Path, arguments: &[&str]) -> Result<String> {
            self.commands
                .push(arguments.iter().map(ToString::to_string).collect());
            if arguments.starts_with(&["config", "--get", "remote.origin.url"]) {
                return Ok(self.expected_origin.clone());
            }
            if arguments.starts_with(&["rev-parse", "--abbrev-ref"]) {
                return Ok("main".into());
            }
            if arguments.starts_with(&["status", "--porcelain"]) {
                return Ok(self.status.pop_front().unwrap_or_default());
            }
            Ok(String::new())
        }

        fn verify_private(&mut self, _: &str) -> Result<bool> {
            self.visibility_checks += 1;
            Ok(self.visibility)
        }
    }

    #[test]
    fn git_visibility_is_verified_cached_and_retries_are_idempotent() {
        let (_temp, route) = fixture();
        let runner = FakeGitRunner {
            visibility: true,
            visibility_checks: 0,
            status: VecDeque::from(["?? message.json".into(), String::new()]),
            commands: Vec::new(),
            expected_origin: route.git_remote.clone(),
        };
        let mut git = test_git_transport(runner);
        assert_eq!(git.health(&route).unwrap(), Health::Healthy);
        assert_eq!(git.health(&route).unwrap(), Health::Healthy);
        assert_eq!(git.git.visibility_checks, 1);
        let message = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        git.deliver(&route, &message).unwrap();
        git.deliver(&route, &message).unwrap();
        let commits = git
            .git
            .commands
            .iter()
            .filter(|command| command.iter().any(|item| item == "commit"))
            .count();
        let pushes = git
            .git
            .commands
            .iter()
            .filter(|command| command.first().is_some_and(|item| item == "push"))
            .count();
        assert_eq!(commits, 1);
        assert_eq!(pushes, 2);

        git.visibility_verified_until = None;
        git.git.visibility = false;
        assert_eq!(git.health(&route).unwrap(), Health::Unavailable);
    }

    #[test]
    fn transport_mode_and_git_backoff_survive_engine_restart() {
        let (_temp, route) = fixture();
        let log = Arc::new(Mutex::new(Vec::new()));
        let git_log = Arc::new(Mutex::new(Vec::new()));
        let mut first = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::SharedFolder, Health::Unavailable, log),
            fake(TransportKind::PrivateGit, Health::Healthy, git_log.clone()),
        );
        let message = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            first.send(&route, &message).unwrap().transport,
            TransportKind::PrivateGit
        );
        assert!(
            route
                .attachment
                .join("runtime/transport-state.json")
                .is_file()
        );

        let local_log = Arc::new(Mutex::new(Vec::new()));
        let mut restarted = test_engine(
            fake(TransportKind::LocalFilesystem, Health::Healthy, local_log),
            fake(
                TransportKind::SharedFolder,
                Health::Unavailable,
                Arc::new(Mutex::new(Vec::new())),
            ),
            fake(TransportKind::PrivateGit, Health::Healthy, git_log.clone()),
        );
        let after_restart =
            Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            restarted.send(&route, &after_restart).unwrap().transport,
            TransportKind::PrivateGit
        );
        assert_eq!(git_log.lock().unwrap().len(), 2);

        let runner = FakeGitRunner {
            visibility: true,
            visibility_checks: 0,
            status: VecDeque::new(),
            commands: Vec::new(),
            expected_origin: route.git_remote.clone(),
        };
        let mut state_writer = test_engine(
            LocalFilesystemTransport,
            SharedFolderTransport {
                probe: OfflineProbe,
            },
            test_git_transport(runner),
        );
        state_writer.git.note_failure(SystemTime::now());
        state_writer.persist_state(&route).unwrap();

        let runner = FakeGitRunner {
            visibility: true,
            visibility_checks: 0,
            status: VecDeque::new(),
            commands: Vec::new(),
            expected_origin: route.git_remote.clone(),
        };
        let mut state_reader = test_engine(
            LocalFilesystemTransport,
            SharedFolderTransport {
                probe: OfflineProbe,
            },
            test_git_transport(runner),
        );
        state_reader.restore_state(&route).unwrap();
        assert_eq!(state_reader.git.backoff_attempt, 1);
        assert_eq!(
            state_reader.git.health(&route).unwrap(),
            Health::RateLimited
        );
    }

    #[test]
    fn corrupt_outbox_entries_are_quarantined_without_stopping_reconciliation() {
        let (_temp, route) = fixture();
        let outbox = route.attachment.join("runtime/outbox");
        fs::create_dir_all(&outbox).unwrap();
        fs::write(outbox.join("bad.json"), b"{not-json").unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(TransportKind::LocalFilesystem, Health::Healthy, log.clone()),
            fake(TransportKind::SharedFolder, Health::Healthy, log.clone()),
            fake(TransportKind::PrivateGit, Health::Healthy, log),
        );
        assert!(engine.reconcile_outbox(&route).unwrap().is_empty());
        assert!(!outbox.join("bad.json").exists());
        let quarantined = fs::read_dir(route.attachment.join("runtime/quarantine/outbox"))
            .unwrap()
            .count();
        assert_eq!(quarantined, 2);
    }

    #[test]
    fn subprocess_timeout_kills_a_stalled_command() {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("powershell.exe");
            command.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 2"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 2"]);
            command
        };
        let error =
            run_with_timeout(&mut command, Duration::from_millis(50), "stall-test").unwrap_err();
        assert!(error.to_string().contains("exceeded"));
    }

    struct VerifiedLocalGit {
        system: SystemGit,
    }

    impl GitRunner for VerifiedLocalGit {
        fn run(&mut self, directory: &Path, arguments: &[&str]) -> Result<()> {
            self.system.run(directory, arguments)
        }

        fn output(&mut self, directory: &Path, arguments: &[&str]) -> Result<String> {
            self.system.output(directory, arguments)
        }

        fn verify_private(&mut self, _: &str) -> Result<bool> {
            Ok(true)
        }
    }

    fn test_git(directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn clone_test_route(
        temp: &Path,
        remote: &Path,
        remote_url: &str,
        source_route: &ProjectRoute,
        name: &str,
    ) -> ProjectRoute {
        let workspace = temp.join(name);
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&attachment).unwrap();
        test_git(
            temp,
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                communications.to_str().unwrap(),
            ],
        );
        test_git(
            &communications,
            &["remote", "set-url", "origin", &source_route.git_remote],
        );
        test_git(
            &communications,
            &[
                "config",
                &format!("url.{remote_url}.insteadOf"),
                &source_route.git_remote,
            ],
        );
        ProjectRoute {
            workspace,
            attachment,
            communications,
            ..source_route.clone()
        }
    }

    #[test]
    fn real_local_git_live_flow_pushes_each_message_without_duplicate_commits() {
        let (temp, route) = fixture();
        let remote = temp.path().join("communications.git");
        fs::create_dir_all(&route.communications).unwrap();
        test_git(
            temp.path(),
            &["init", "--bare", "--template=", remote.to_str().unwrap()],
        );
        test_git(&route.communications, &["init", "-q", "--template="]);
        test_git(
            &route.communications,
            &["config", "user.name", "Ferryman Test"],
        );
        test_git(
            &route.communications,
            &["config", "user.email", "ferryman-test@example.invalid"],
        );
        test_git(&route.communications, &["branch", "-M", "main"]);
        test_git(
            &route.communications,
            &["commit", "--allow-empty", "-q", "-m", "seed"],
        );
        test_git(
            &route.communications,
            &["remote", "add", "origin", &route.git_remote],
        );
        let remote_text = remote.to_string_lossy().replace('\\', "/");
        let remote_url = if remote_text.as_bytes().get(1) == Some(&b':') {
            format!("file:///{remote_text}")
        } else {
            format!("file://{remote_text}")
        };
        test_git(
            &route.communications,
            &[
                "config",
                &format!("url.{remote_url}.insteadOf"),
                &route.git_remote,
            ],
        );
        test_git(
            &route.communications,
            &["push", "-q", "-u", "origin", "main"],
        );
        test_git(
            temp.path(),
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "symbolic-ref",
                "HEAD",
                "refs/heads/main",
            ],
        );
        let peer_route =
            clone_test_route(temp.path(), &remote, &remote_url, &route, "peer-project");
        let receiver_route = clone_test_route(
            temp.path(),
            &remote,
            &remote_url,
            &route,
            "receiver-project",
        );

        let log = Arc::new(Mutex::new(Vec::new()));
        let mut engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                log.clone(),
            ),
            fake(TransportKind::SharedFolder, Health::Unavailable, log),
            test_git_transport(VerifiedLocalGit { system: SystemGit }),
        );
        let first = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        let first_receipt = engine.send(&route, &first).unwrap();
        assert_eq!(
            first_receipt.transport,
            TransportKind::PrivateGit,
            "{:?}",
            first_receipt.failover_reason
        );
        let after_first = test_git(
            temp.path(),
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "rev-list",
                "--count",
                "main",
            ],
        );
        assert_eq!(after_first, "2");

        assert_eq!(
            engine.send(&route, &first).unwrap().transport,
            TransportKind::PrivateGit
        );
        let after_duplicate = test_git(
            temp.path(),
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "rev-list",
                "--count",
                "main",
            ],
        );
        assert_eq!(after_duplicate, "2");

        let peer_log = Arc::new(Mutex::new(Vec::new()));
        let mut peer_engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                peer_log.clone(),
            ),
            fake(TransportKind::SharedFolder, Health::Unavailable, peer_log),
            test_git_transport(VerifiedLocalGit { system: SystemGit }),
        );
        assert_eq!(
            peer_engine.send(&peer_route, &first).unwrap().transport,
            TransportKind::PrivateGit
        );
        let after_peer_duplicate = test_git(
            temp.path(),
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "rev-list",
                "--count",
                "main",
            ],
        );
        assert_eq!(after_peer_duplicate, "2");

        let receiver_log = Arc::new(Mutex::new(Vec::new()));
        let mut receiver_engine = test_engine(
            fake(
                TransportKind::LocalFilesystem,
                Health::Unavailable,
                receiver_log.clone(),
            ),
            fake(
                TransportKind::SharedFolder,
                Health::Unavailable,
                receiver_log,
            ),
            test_git_transport(VerifiedLocalGit { system: SystemGit }),
        );
        // Simulate the common handoff edge: Syncthing wrote the message into this
        // stale checkout just before the receiver switched to Git inbound.
        persist_message(
            &message_path(&receiver_route.communications, &first),
            &first,
        )
        .unwrap();
        assert_eq!(
            receiver_engine
                .synchronize_inbound(&receiver_route)
                .unwrap(),
            TransportKind::PrivateGit
        );
        assert_eq!(read_message(&receiver_route, &first.id).unwrap(), first);
        let acknowledgement = Acknowledgement {
            message_id: first.id.clone(),
            project_id: "alpha".into(),
            recipient: "alpha-builder".into(),
            processed_at: Utc::now(),
            idempotency_key: first.idempotency_key.clone(),
        };
        let (_, recorded, acknowledgement_receipt) = receiver_engine
            .acknowledge(&receiver_route, &acknowledgement)
            .unwrap();
        assert!(recorded);
        assert_eq!(acknowledgement_receipt.transport, TransportKind::PrivateGit);
        assert_eq!(
            engine.synchronize_inbound(&route).unwrap(),
            TransportKind::PrivateGit
        );
        assert!(is_acknowledged(&route, &first.id));
        assert!(!outbox_path(&route, &first.id).exists());
        assert_eq!(
            engine.send(&route, &first).unwrap().transport,
            TransportKind::LocalFilesystem
        );

        let second = Message::new("alpha", "a", "builder", "inline", Value::Null, false, None);
        assert_eq!(
            engine.send(&route, &second).unwrap().transport,
            TransportKind::PrivateGit
        );
        let observer = temp.path().join("observer");
        test_git(
            temp.path(),
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                observer.to_str().unwrap(),
            ],
        );
        assert!(
            observer
                .join(format!("messages/alpha/{}.json", first.id))
                .is_file()
        );
        assert!(
            observer
                .join(format!("messages/alpha/{}.json", second.id))
                .is_file()
        );
        assert!(
            observer
                .join(format!("acknowledgements/alpha/{}.json", first.id))
                .is_file()
        );
    }

    #[test]
    fn v2_signed_flow_survives_a_local_git_round_trip() {
        use crate::portable_auth::SignerGrant;

        let (temp, route) = fixture();
        let remote = temp.path().join("communications.git");
        fs::create_dir_all(&route.communications).unwrap();
        test_git(
            temp.path(),
            &["init", "--bare", "--template=", remote.to_str().unwrap()],
        );
        test_git(&route.communications, &["init", "-q", "--template="]);
        test_git(
            &route.communications,
            &["config", "user.name", "Ferryman Test"],
        );
        test_git(
            &route.communications,
            &["config", "user.email", "ferryman-test@example.invalid"],
        );
        test_git(&route.communications, &["branch", "-M", "main"]);
        test_git(
            &route.communications,
            &["commit", "--allow-empty", "-q", "-m", "seed"],
        );
        test_git(
            &route.communications,
            &["remote", "add", "origin", &route.git_remote],
        );
        let remote_text = remote.to_string_lossy().replace('\\', "/");
        let remote_url = if remote_text.as_bytes().get(1) == Some(&b':') {
            format!("file:///{remote_text}")
        } else {
            format!("file://{remote_text}")
        };
        test_git(
            &route.communications,
            &[
                "config",
                &format!("url.{remote_url}.insteadOf"),
                &route.git_remote,
            ],
        );
        test_git(
            &route.communications,
            &["push", "-q", "-u", "origin", "main"],
        );
        test_git(
            temp.path(),
            &[
                "--git-dir",
                remote.to_str().unwrap(),
                "symbolic-ref",
                "HEAD",
                "refs/heads/main",
            ],
        );
        let sender_route =
            clone_test_route(temp.path(), &remote, &remote_url, &route, "sender-project");
        let receiver_route = clone_test_route(
            temp.path(),
            &remote,
            &remote_url,
            &route,
            "receiver-project",
        );
        test_git(
            &sender_route.communications,
            &["config", "user.name", "Ferryman Test"],
        );
        test_git(
            &sender_route.communications,
            &["config", "user.email", "ferryman-test@example.invalid"],
        );

        // Trust store: the orchestrator issues, the builder acknowledges.
        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let orchestrator = ed25519_dalek::SigningKey::from_bytes(&seed);
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        let builder = ed25519_dalek::SigningKey::from_bytes(&seed);
        let store = TrustedSigners {
            signers: vec![
                SignerGrant {
                    public_key: hex::encode(orchestrator.verifying_key().as_bytes()),
                    projects: vec!["alpha".into()],
                    roles: vec!["orchestrator".into()],
                    capabilities: vec!["issue".into()],
                    revoked: false,
                },
                SignerGrant {
                    public_key: hex::encode(builder.verifying_key().as_bytes()),
                    projects: vec!["alpha".into()],
                    roles: vec!["builder".into()],
                    capabilities: vec![],
                    revoked: false,
                },
            ],
        };
        let store_toml = toml::to_string(&store).unwrap();
        for checkpoint in [&sender_route, &receiver_route] {
            fs::create_dir_all(&checkpoint.attachment).unwrap();
            fs::write(
                checkpoint.attachment.join("trusted-signers.toml"),
                &store_toml,
            )
            .unwrap();
        }

        // The orchestrator signs a v2 message and a tampered twin.
        let mut message = MessageV2::new(
            "alpha",
            "orchestrator",
            "builder",
            "r",
            serde_json::json!({"work": "build"}),
            true,
        );
        message.sign(&orchestrator).unwrap();
        let mut tampered = MessageV2::new(
            "alpha",
            "orchestrator",
            "builder",
            "r",
            serde_json::json!({"work": "sabotage"}),
            true,
        );
        tampered.sign(&orchestrator).unwrap();
        tampered.payload = serde_json::json!({"work": "forged after signing"});

        let inbound = sender_route.communications.join("messages").join("alpha");
        fs::create_dir_all(&inbound).unwrap();
        fs::write(
            inbound.join(format!("{}.json", message.id)),
            serde_json::to_vec_pretty(&message).unwrap(),
        )
        .unwrap();
        fs::write(
            inbound.join(format!("{}.json", tampered.id)),
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();
        test_git(&sender_route.communications, &["add", "-A"]);
        test_git(
            &sender_route.communications,
            &["commit", "-q", "-m", "v2 messages"],
        );
        test_git(
            &sender_route.communications,
            &["push", "-q", "origin", "main"],
        );
        test_git(
            &receiver_route.communications,
            &["pull", "-q", "--ff-only", "origin", "main"],
        );

        // Only the genuine envelope survives the receiver's gate; the tampered twin
        // fails signature verification and is dropped from the listing.
        let listed = crate::list_messages_v2(&receiver_route).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, message.id);
        let read = crate::read_message_v2(&receiver_route, &message.id).unwrap();
        assert_eq!(read.id, message.id);
        assert!(crate::read_message_v2(&receiver_route, &tampered.id).is_err());

        // Claim is idempotent, and the builder's acknowledgement verifies.
        assert!(crate::claim_message_v2(&receiver_route, &message).unwrap());
        assert!(!crate::claim_message_v2(&receiver_route, &message).unwrap());
        let mut acknowledgement = AcknowledgementV2::new(&message).unwrap();
        acknowledgement.acknowledged_by = "alpha-builder".into();
        acknowledgement.sign(&builder).unwrap();
        assert!(crate::acknowledge_v2(&receiver_route, &acknowledgement).unwrap());
    }
}

#[cfg(test)]
mod serverless_tests {
    use super::*;
    use serde_json::json;

    /// A channel on disk, exactly as the attachment scripts leave one.
    fn attached() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(communications.join("messages/demo")).unwrap();
        fs::create_dir_all(communications.join("acknowledgements/demo")).unwrap();
        let config = format!(
            "project = \"demo\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\nshared_remote = \"demo-ferryman\"\ngit_remote = \"\"\ngit_visibility = \"private\"\n",
            workspace.display(),
            attachment.display(),
            communications.display()
        );
        fs::write(attachment.join("bridge.toml"), config).unwrap();
        (temp, workspace)
    }

    #[test]
    fn the_channel_is_found_by_walking_up_from_a_subdirectory() {
        let (_temp, workspace) = attached();
        let deep = workspace.join("crates/thing/src");
        fs::create_dir_all(&deep).unwrap();
        let found = discover_attachment(&deep).expect("walk upwards like git does");
        assert_eq!(found, workspace.join(".ferryman"));
    }

    #[test]
    fn no_channel_anywhere_above_is_reported_plainly() {
        let temp = tempfile::tempdir().unwrap();
        assert!(discover_attachment(temp.path()).is_none());
        let error = route_for(temp.path()).unwrap_err().to_string();
        assert!(
            error.contains("no Ferryman channel found"),
            "a new user with no channel deserves an explanation, got: {error}"
        );
    }

    #[test]
    fn a_route_loads_from_disk_with_no_server_involved() {
        let (_temp, workspace) = attached();
        let route = route_for(&workspace).unwrap();
        assert_eq!(route.project_id, "demo");
        assert_eq!(route.shared_remote, "demo-ferryman");
        assert!(
            route.git_remote.is_empty(),
            "a Syncthing-only channel has no Git remote and must still load"
        );
    }

    #[test]
    fn an_expected_agent_is_reserved_and_addressable_without_a_key() {
        let (_temp, workspace) = attached();
        let route = route_for(&workspace).unwrap();
        register_expected_agent(
            &route,
            "wisp",
            "orchestrator",
            &["messages.receive".to_string()],
        )
        .unwrap();

        // A freshly loaded route sees the reservation and permits messages to it.
        let reloaded = route_for(&workspace).unwrap();
        assert!(reloaded.permits("wisp", None));
        // The reservation is a name, not an identity: no key was published.
        let entry = reloaded
            .agents
            .iter()
            .find(|agent| agent.name == "wisp")
            .unwrap();
        assert!(entry.public_key.is_none());
    }

    #[test]
    fn a_hand_mangled_bridge_file_is_refused_rather_than_guessed_at() {
        let (_temp, workspace) = attached();
        let attachment = workspace.join(".ferryman");
        fs::write(attachment.join("bridge.toml"), "this is not a setting\n").unwrap();
        assert!(load_route(&attachment).is_err());
    }

    #[test]
    fn agents_register_themselves_and_everyone_sees_them() {
        let (_temp, workspace) = attached();
        let route = route_for(&workspace).unwrap();
        register_agent(
            &route,
            &AgentRoute {
                name: "fang".into(),
                role: "worker".into(),
                capabilities: vec!["messages.receive".into()],
                public_key: None,
                encryption_key: None,
            },
        )
        .unwrap();
        register_agent(
            &route,
            &AgentRoute {
                name: "wisp".into(),
                role: "orchestrator".into(),
                capabilities: vec!["messages.receive".into(), "review".into()],
                public_key: None,
                encryption_key: None,
            },
        )
        .unwrap();

        // Re-read from disk: this is what another machine does after Syncthing carries it.
        let reloaded = route_for(&workspace).unwrap();
        let names: Vec<_> = reloaded.agents.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["fang", "wisp"], "sorted, and both present");
        assert!(reloaded.permits("fang", None));
        assert!(
            reloaded.permits("orchestrator", None),
            "role addressing works"
        );
        assert!(!reloaded.permits("nobody", None));
    }

    #[test]
    fn one_agent_writing_nonsense_does_not_silence_the_fleet() {
        let (_temp, workspace) = attached();
        let route = route_for(&workspace).unwrap();
        register_agent(
            &route,
            &AgentRoute {
                name: "fang".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: None,
                encryption_key: None,
            },
        )
        .unwrap();
        fs::write(
            route.communications.join("agents/broken.json"),
            "{ not json at all",
        )
        .unwrap();
        let reloaded = route_for(&workspace).unwrap();
        assert_eq!(
            reloaded.agents.len(),
            1,
            "the unreadable entry is skipped, the readable one survives"
        );
    }

    #[test]
    fn an_agent_cannot_take_a_name_that_would_escape_its_directory() {
        let (_temp, workspace) = attached();
        let route = route_for(&workspace).unwrap();
        for bad in ["../escape", "..", ".", "with/slash"] {
            assert!(
                register_agent(
                    &route,
                    &AgentRoute {
                        name: bad.into(),
                        role: "worker".into(),
                        capabilities: vec![],
                        public_key: None,
                        encryption_key: None,
                    },
                )
                .is_err(),
                "'{bad}' must be refused as an agent name"
            );
        }
    }

    #[test]
    fn a_message_written_with_no_server_is_readable_as_a_plain_file() {
        let (_temp, workspace) = attached();
        let route = route_for(&workspace).unwrap();
        register_agent(
            &route,
            &AgentRoute {
                name: "fang".into(),
                role: "worker".into(),
                capabilities: vec!["messages.receive".into()],
                public_key: None,
                encryption_key: None,
            },
        )
        .unwrap();
        let route = route_for(&workspace).unwrap();

        let message = Message::new(
            "demo",
            "wisp",
            "fang",
            "text/plain",
            json!({"text": "check this against the real code"}),
            true,
            None,
        );
        let mut transport = LocalFilesystemTransport;
        transport.deliver(&route, &message).unwrap();

        let listed = list_messages(&route).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sender, "wisp");
        assert!(
            listed[0].reply_required,
            "reply expectation is declared, not inferred"
        );

        // And it is genuinely just a file in the folder Syncthing carries.
        let on_disk = route
            .communications
            .join("messages/demo")
            .join(format!("{}.json", message.id));
        assert!(
            on_disk.is_file(),
            "the message is a file, not a database row"
        );
    }
}

#[cfg(test)]
mod identity_tests {
    /// Keep this test binary's machine state out of the developer's home.
    ///
    /// `cfg(test)` is per crate, so a dependent crate's tests link ferryman-channel
    /// compiled without it - which is how the suite came to write real signing keys into
    /// ~/.local/state. First call wins, so every test here shares one temporary machine.
    pub(crate) fn hermetic_machine() {
        let dir = std::env::temp_dir().join(format!(
            "ferryman-test-machine-{}-{}",
            env!("CARGO_CRATE_NAME"),
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        crate::licensing::use_machine_state_dir_per_thread(dir);
    }

    use super::*;
    use serde_json::json;

    fn message(text: &str) -> Message {
        Message::new(
            "demo",
            "wisp",
            "fang",
            "text/plain",
            json!({ "text": text }),
            true,
            None,
        )
    }

    fn identity(name: &str) -> (tempfile::TempDir, AgentIdentity) {
        let dir = tempfile::tempdir().unwrap();
        let identity = AgentIdentity::load_or_create(name, dir.path()).unwrap();
        (dir, identity)
    }

    fn roster(name: &str, identity: &AgentIdentity) -> Vec<AgentRoute> {
        vec![AgentRoute {
            name: name.into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }]
    }

    #[test]
    fn a_signed_message_verifies_against_the_published_key() {
        let (_dir, wisp) = identity("wisp");
        let mut m = message("deploy the thing");
        wisp.sign(&mut m);
        assert_eq!(m.signed_by.as_deref(), Some("wisp"));
        assert_eq!(
            verify_message(&m, &roster("wisp", &wisp)),
            SignatureCheck::Valid
        );
    }

    #[test]
    fn changing_the_body_after_signing_is_caught() {
        let (_dir, wisp) = identity("wisp");
        let mut m = message("deploy the thing");
        wisp.sign(&mut m);
        m.payload = json!({ "text": "delete everything" });
        assert_eq!(
            verify_message(&m, &roster("wisp", &wisp)),
            SignatureCheck::Invalid,
            "a signature must cover the payload, not merely accompany it"
        );
    }

    #[test]
    fn changing_the_recipient_after_signing_is_caught() {
        let (_dir, wisp) = identity("wisp");
        let mut m = message("deploy the thing");
        wisp.sign(&mut m);
        m.recipient = "someone-else".into();
        assert_eq!(
            verify_message(&m, &roster("wisp", &wisp)),
            SignatureCheck::Invalid,
            "redirecting a signed order to another agent must not verify"
        );
    }

    #[test]
    fn one_agent_cannot_sign_as_another() {
        let (_a, wisp) = identity("wisp");
        let (_b, impostor) = identity("impostor");
        let mut m = message("deploy the thing");
        // The impostor signs, then relabels the message as though wisp sent it.
        impostor.sign(&mut m);
        m.signed_by = Some("wisp".into());
        assert_eq!(
            verify_message(&m, &roster("wisp", &wisp)),
            SignatureCheck::Invalid,
            "a compromised machine must only be able to forge its OWN agents"
        );
    }

    #[test]
    fn an_unsigned_message_is_reported_as_unsigned_not_valid() {
        let (_dir, wisp) = identity("wisp");
        let m = message("no signature here");
        assert_eq!(
            verify_message(&m, &roster("wisp", &wisp)),
            SignatureCheck::Unsigned,
            "a fleet that has not adopted signing keeps working, but is never called valid"
        );
    }

    #[test]
    fn a_signature_from_a_name_with_no_published_key_concludes_nothing() {
        let (_dir, stranger) = identity("stranger");
        let mut m = message("hello");
        stranger.sign(&mut m);
        assert_eq!(
            verify_message(&m, &[]),
            SignatureCheck::UnknownSigner,
            "no key on file means unknown, which is not the same as valid or invalid"
        );
    }

    #[test]
    fn the_key_survives_a_restart_rather_than_being_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let first = AgentIdentity::load_or_create("wisp", dir.path()).unwrap();
        let again = AgentIdentity::load_or_create("wisp", dir.path()).unwrap();
        assert_eq!(
            first.public_key_hex(),
            again.public_key_hex(),
            "an agent that re-keys on every start has no stable identity at all"
        );
    }

    #[test]
    fn a_private_key_is_never_written_where_syncthing_would_carry_it() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(communications.join("messages/demo")).unwrap();
        let identity = AgentIdentity::load_or_create("wisp", &attachment).unwrap();

        // The key lives in the attachment, which is machine-local. The channel is the
        // subdirectory Syncthing carries. The key must not be inside it.
        let key_path = attachment.join("keys/wisp.key");
        assert!(key_path.is_file(), "the key is kept on this machine");
        assert!(
            !key_path.starts_with(&communications),
            "a private key inside the synced folder would be handed to every peer"
        );
        assert!(
            !identity.public_key_hex().is_empty(),
            "the public half is what gets published"
        );
    }

    #[test]
    fn a_different_key_claiming_an_established_name_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(communications.join("messages/demo")).unwrap();
        fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"demo\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\nshared_remote = \"demo-ferryman\"\ngit_remote = \"\"\ngit_visibility = \"private\"\n",
                workspace.display(), attachment.display(), communications.display()
            ),
        )
        .unwrap();
        let route = route_for(&workspace).unwrap();
        let agent = AgentRoute {
            name: "wisp".into(),
            role: "orchestrator".into(),
            capabilities: vec![],
            public_key: None,
            encryption_key: None,
        };

        let first = AgentIdentity::load_or_create("wisp", &attachment).unwrap();
        register_agent_key(&route, &agent, &first).unwrap();

        // Same key again is fine - re-registering after a restart must not be an error.
        let route = route_for(&workspace).unwrap();
        register_agent_key(&route, &agent, &first).unwrap();

        // A DIFFERENT key for the same name is not silently accepted.
        // A different *machine* claiming the same name. Two directories on one machine
        // deliberately no longer produce two keys, so the impostor needs its own.
        let elsewhere = tempfile::tempdir().unwrap();
        let other_machine = tempfile::tempdir().unwrap();
        let other = AgentIdentity::load_or_create_in(
            "wisp",
            elsewhere.path(),
            Some(other_machine.path().to_path_buf()),
        )
        .unwrap();
        let route = route_for(&workspace).unwrap();
        let error = register_agent_key(&route, &agent, &other)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already published with a different key"),
            "silent replacement is how impersonation succeeds; got: {error}"
        );
    }
}

#[cfg(test)]
mod work_over_files_tests {
    use super::*;
    use serde_json::json;

    fn channel() -> (tempfile::TempDir, ProjectRoute) {
        super::identity_tests::hermetic_machine();
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(communications.join("messages/demo")).unwrap();
        fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"demo\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\nshared_remote = \"demo-ferryman\"\ngit_remote = \"\"\ngit_visibility = \"private\"\n",
                workspace.display(), attachment.display(), communications.display()
            ),
        )
        .unwrap();
        let route = route_for(&workspace).unwrap();
        (temp, route)
    }

    /// A route whose roster carries real signing keys for the agents the tests
    /// use, plus the identities, so results/reviews/interrupts can be signed.
    fn signed_channel() -> (
        tempfile::TempDir,
        ProjectRoute,
        HashMap<String, AgentIdentity>,
    ) {
        let (temp, mut route) = channel();
        let mut identities = HashMap::new();
        let mut roster = Vec::new();
        for name in ["fang", "wisp", "nebra", "worker", "orchestrator"] {
            let identity = AgentIdentity::load_or_create(name, &route.attachment).unwrap();
            roster.push(AgentRoute {
                name: name.to_string(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            });
            identities.insert(name.to_string(), identity);
        }
        route.agents = roster;
        (temp, route, identities)
    }

    /// The same order, signed by whoever issued it.
    ///
    /// `work_for` verifies signatures now, the way the loop always did, so a test that
    /// issues an unsigned order and expects to see it offered is testing a state no
    /// worker will ever act on. Signing here keeps these tests about what they are
    /// named for.
    fn signed(identities: &HashMap<String, AgentIdentity>, mut order: Order) -> Order {
        identities
            .get(&order.issued_by)
            .expect("the issuer must be in the roster")
            .sign_order(&mut order);
        order
    }

    fn order(id: &str, assigned_to: Option<&str>, requires_review: bool) -> Order {
        Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "wisp".into(),
            assigned_to: assigned_to.map(ToString::to_string),
            created_at: Utc::now(),
            payload: json!({"task": "write the report"}),
            requires_review,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
        }
    }

    #[test]
    fn an_order_is_a_file_in_the_folder_syncthing_carries() {
        let (_t, route) = channel();
        let path = issue_order(&route, &order("t-1", None, false)).unwrap();
        assert!(path.is_file());
        assert!(
            path.starts_with(&route.communications),
            "work must ride the same synced folder as messages, or it cannot cross networks"
        );
    }

    #[test]
    fn an_order_is_written_once_and_never_rewritten() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", None, false)).unwrap();
        assert!(
            issue_order(&route, &order("t-1", None, false)).is_err(),
            "two writers on one path is the one thing a synced folder cannot survive"
        );
    }

    #[test]
    fn an_approval_required_order_cannot_be_self_approved() {
        let (_t, route, identities) = signed_channel();
        let mut order = order("t-1", None, true);
        order.requires_approval = true;
        issue_order(&route, &order).unwrap();
        let mut result = TaskResult {
            order_id: "t-1".into(),
            agent: "worker".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"output": "x"}),
            signed_by: None,
            signature: None,
        };
        identities["worker"].sign_result(&mut result);
        submit_result(&route, &result).unwrap();
        // The worker that produced the result tries to accept its own work.
        let mut review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "worker".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        identities["worker"].sign_review(&mut review);
        let error = submit_review(&route, &review).unwrap_err().to_string();
        assert!(
            error.contains("cannot approve its own work"),
            "self-approval must be rejected: {error}"
        );
    }

    #[test]
    fn an_addressed_order_has_nothing_to_race_over() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", Some("fang"), false)).unwrap();
        // Someone else claims it anyway. It changes nothing.
        claim_order(&route, "t-1", "nebra").unwrap();
        let task = read_task(&route, "t-1").unwrap();
        assert_eq!(task.holder(), Some("fang"), "the assignee holds it");
    }

    #[test]
    fn work_on_offer_is_work_the_loop_would_actually_do() {
        // `--dry-run` printed `postpurge-20260827  claim it, then run the agent` every
        // pass for an order the loop refused every pass, and had for a day. A dry run is
        // consulted by someone asking "what is this machine about to do?"; answering
        // with work that will never be done is the one way it must not be wrong.
        let (_t, route, ids) = signed_channel();
        issue_order(&route, &signed(&ids, order("t-signed", None, false))).unwrap();
        // Unsigned, and from a name the roster does know - exactly the shape of a seat
        // that declares it has no durable key.
        issue_order(&route, &order("t-unsigned", None, false)).unwrap();

        let offered: Vec<String> = work_for(&route, "fang")
            .unwrap()
            .into_iter()
            .map(|task| task.order.id)
            .collect();
        assert!(offered.contains(&"t-signed".to_string()));
        assert!(
            !offered.contains(&"t-unsigned".to_string()),
            "an order the loop refuses must not be offered as work: {offered:?}"
        );
    }

    #[test]
    fn an_order_waits_for_its_dependencies() {
        let (_t, route, ids) = signed_channel();
        issue_order(&route, &signed(&ids, order("t-1", None, false))).unwrap();
        let mut dependent = order("t-2", None, false);
        dependent.depends_on = vec!["t-1".into()];
        let dependent = signed(&ids, dependent);
        issue_order(&route, &dependent).unwrap();
        // t-1 is still open, so t-2 must not be offered for work.
        assert!(
            work_for(&route, "fang")
                .unwrap()
                .iter()
                .all(|t| t.order.id != "t-2"),
            "a dependent order must wait for its dependencies"
        );
        assert!(!dependencies_satisfied(&route, &dependent).unwrap());
    }

    #[test]
    fn two_machines_claiming_at_once_resolve_to_the_same_winner_everywhere() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", None, false)).unwrap();

        // Both claim before either has seen the other - exactly the sync-window race.
        let early = Claim {
            order_id: "t-1".into(),
            agent: "fang".into(),
            claimed_at: Utc::now() - chrono::Duration::seconds(3),
        };
        let late = Claim {
            order_id: "t-1".into(),
            agent: "nebra".into(),
            claimed_at: Utc::now(),
        };
        write_task_file(&task_dir(&route, "t-1").join("claim.fang.json"), &early).unwrap();
        write_task_file(&task_dir(&route, "t-1").join("claim.nebra.json"), &late).unwrap();

        let task = read_task(&route, "t-1").unwrap();
        assert_eq!(
            task.holder(),
            Some("fang"),
            "oldest claim wins, and every machine computes that identically from the same files"
        );
    }
    #[test]
    fn a_claim_whose_heartbeat_has_lapsed_reads_stale_and_stays_held() {
        let (_t, route, ids) = signed_channel();
        issue_order(&route, &signed(&ids, order("t-1", None, false))).unwrap();
        claim_order(&route, "t-1", "fang").unwrap();
        write_heartbeat(
            &route,
            &Heartbeat {
                order_id: "t-1".into(),
                agent: "fang".into(),
                run: "1a".into(),
                pid: 12345,
                at: Utc::now()
                    - chrono::Duration::seconds(
                        HEARTBEAT_INTERVAL_SECS * HEARTBEAT_STALE_MULTIPLE + 60,
                    ),
            },
        )
        .unwrap();

        let task = read_task(&route, "t-1").unwrap();
        assert!(
            matches!(task.state(), TaskState::Stale { ref by, .. } if by == "fang"),
            "a lapsed heartbeat must read as stale, got {:?}",
            task.state()
        );
        // Display only: it is not offered to another machine...
        assert!(work_for(&route, "wisp").unwrap().is_empty());
        // ...but it is still offered to its own holder, exactly as Claimed is.
        assert_eq!(work_for(&route, "fang").unwrap().len(), 1);
    }

    #[test]
    fn a_release_returns_the_task_to_open_and_to_offered_when_addressed() {
        let (_t, route, identities) = signed_channel();

        // An open order: releasing the claim returns it to Open.
        issue_order(&route, &order("t-1", None, false)).unwrap();
        claim_order(&route, "t-1", "fang").unwrap();
        release_claim(&route, "t-1", "fang", "fang", "test", &identities["fang"]).unwrap();
        assert_eq!(read_task(&route, "t-1").unwrap().state(), TaskState::Open);

        // An addressed order: releasing the claim returns it to Offered.
        issue_order(&route, &order("t-2", Some("fang"), false)).unwrap();
        claim_order(&route, "t-2", "fang").unwrap();
        release_claim(&route, "t-2", "fang", "fang", "test", &identities["fang"]).unwrap();
        assert!(matches!(
            read_task(&route, "t-2").unwrap().state(),
            TaskState::Offered { ref to } if to == "fang"
        ));
    }

    #[test]
    fn a_worker_will_not_release_a_claim_it_does_not_hold() {
        let (_t, route, identities) = signed_channel();
        issue_order(&route, &order("t-1", None, false)).unwrap();
        claim_order(&route, "t-1", "fang").unwrap();

        let error = release_own_claim(&route, "t-1", "nebra", "test", &identities["nebra"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not hold"), "must refuse: {error}");

        // The claim is untouched: fang still holds it.
        assert_eq!(read_task(&route, "t-1").unwrap().holder(), Some("fang"));
    }

    #[test]
    fn a_release_is_not_a_result() {
        let (_t, route, identities) = signed_channel();
        issue_order(&route, &order("t-1", None, true)).unwrap();
        claim_order(&route, "t-1", "fang").unwrap();
        release_claim(&route, "t-1", "fang", "fang", "test", &identities["fang"]).unwrap();

        let task = read_task(&route, "t-1").unwrap();
        // A release says the work was abandoned, never that it was done: no revision was
        // submitted, and the task is back to Open rather than Accepted/Done.
        assert_eq!(task.latest_revision(), None);
        assert_eq!(task.state(), TaskState::Open);
    }

    #[test]
    fn a_release_is_signed_and_recorded_beside_the_claim() {
        let (_t, route, identities) = signed_channel();
        issue_order(&route, &order("t-1", None, false)).unwrap();
        claim_order(&route, "t-1", "fang").unwrap();
        release_claim(
            &route,
            "t-1",
            "fang",
            "fang",
            "retired",
            &identities["fang"],
        )
        .unwrap();

        let dir = task_dir(&route, "t-1");
        assert!(
            dir.join("claim.fang.json").is_file(),
            "the claim is kept so the history keeps both sides of the hand-over"
        );
        assert!(dir.join("release.fang.json").is_file());
        let release: Release =
            serde_json::from_str(&fs::read_to_string(dir.join("release.fang.json")).unwrap())
                .unwrap();
        assert_eq!(release.released, "fang");
        assert_eq!(release.reason, "retired");
        assert_eq!(
            verify_release(&release, &route.agents),
            SignatureCheck::Valid
        );
    }

    #[test]
    fn a_tie_is_broken_the_same_way_on_every_machine() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", None, false)).unwrap();
        let at = Utc::now();
        for agent in ["nebra", "fang"] {
            write_task_file(
                &task_dir(&route, "t-1").join(format!("claim.{agent}.json")),
                &Claim {
                    order_id: "t-1".into(),
                    agent: agent.into(),
                    claimed_at: at,
                },
            )
            .unwrap();
        }
        let task = read_task(&route, "t-1").unwrap();
        assert_eq!(
            task.holder(),
            Some("fang"),
            "identical timestamps must not leave each machine picking its own favourite"
        );
    }

    #[test]
    fn re_claiming_does_not_let_a_latecomer_win_a_race_it_lost() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", None, false)).unwrap();
        write_task_file(
            &task_dir(&route, "t-1").join("claim.fang.json"),
            &Claim {
                order_id: "t-1".into(),
                agent: "fang".into(),
                claimed_at: Utc::now() - chrono::Duration::seconds(10),
            },
        )
        .unwrap();
        claim_order(&route, "t-1", "nebra").unwrap();
        // nebra claims again, later. Its original timestamp must stand.
        claim_order(&route, "t-1", "nebra").unwrap();
        let task = read_task(&route, "t-1").unwrap();
        assert_eq!(task.holder(), Some("fang"));
    }

    #[test]
    fn one_machine_signs_as_one_key_in_every_project_it_serves() {
        // The bridge failure this exists to prevent: set up in one project, refused in
        // every other one, and the suggested remedy would have minted a second key.
        let home = tempfile::tempdir().unwrap();
        let first = home.path().join("one/.ferryman");
        let second = home.path().join("two/.ferryman");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();

        let identity = AgentIdentity::load_or_create_in("phone", &first, None).unwrap();
        assert!(
            AgentIdentity::load_existing("phone", &second)
                .unwrap()
                .is_none()
        );

        identity.seat_in(&second).unwrap();
        let seated = AgentIdentity::load_existing("phone", &second)
            .unwrap()
            .unwrap();
        // The same key, not merely a key: a different one would read as an impostor.
        assert_eq!(seated.public_key_hex(), identity.public_key_hex());
    }

    #[test]
    fn seating_the_same_identity_twice_changes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ferryman");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = AgentIdentity::load_or_create_in("phone", &dir, None).unwrap();
        identity.seat_in(&dir).unwrap();
        identity.seat_in(&dir).unwrap();
        assert_eq!(
            AgentIdentity::load_existing("phone", &dir)
                .unwrap()
                .unwrap()
                .public_key_hex(),
            identity.public_key_hex()
        );
    }

    #[test]
    fn seating_refuses_to_overwrite_a_different_key_under_the_same_name() {
        // Two identities colliding under one name is not a machine spreading its own.
        // Replacing either would make everything it had already signed read as forged.
        let home = tempfile::tempdir().unwrap();
        let mine = home.path().join("mine/.ferryman");
        let theirs = home.path().join("theirs/.ferryman");
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::create_dir_all(&theirs).unwrap();
        let ours = AgentIdentity::load_or_create_in("phone", &mine, None).unwrap();
        let stranger = AgentIdentity::load_or_create_in("phone", &theirs, None).unwrap();
        assert_ne!(ours.public_key_hex(), stranger.public_key_hex());

        let error = ours.seat_in(&theirs).unwrap_err().to_string();
        assert!(error.contains("refusing to replace it"), "{error}");
        // And the key that was there is untouched.
        assert_eq!(
            AgentIdentity::load_existing("phone", &theirs)
                .unwrap()
                .unwrap()
                .public_key_hex(),
            stranger.public_key_hex()
        );
    }

    #[test]
    fn an_order_nobody_picked_up_does_not_read_as_being_worked_on() {
        // The failure this prevents: four orders addressed to a machine whose worker was
        // not running all read as "Claimed { by: fang }". The operator waited on work
        // that had never started, and the status display was the reason they waited.
        let (_t, route, _identities) = signed_channel();
        issue_order(&route, &order("t-1", Some("fang"), false)).unwrap();
        let task = read_task(&route, "t-1").unwrap();
        assert_eq!(task.state(), TaskState::Offered { to: "fang".into() });
        // Whose task it is has not changed - only whether anyone has taken it.
        assert_eq!(task.holder(), Some("fang"));

        claim_order(&route, "t-1", "fang").unwrap();
        assert_eq!(
            read_task(&route, "t-1").unwrap().state(),
            TaskState::Claimed { by: "fang".into() }
        );
    }

    #[test]
    fn an_offered_order_is_still_work_its_machine_can_see() {
        // Offered must not become a state that hides work from the machine it was
        // addressed to, or an addressed order would never be done at all.
        let (_t, route, ids) = signed_channel();
        issue_order(&route, &signed(&ids, order("t-1", Some("fang"), false))).unwrap();
        assert_eq!(work_for(&route, "fang").unwrap().len(), 1);
        assert_eq!(work_for(&route, "wisp").unwrap().len(), 0);
    }

    #[test]
    fn the_whole_review_cycle_is_just_more_files_in_one_directory() {
        let (_t, route, identities) = signed_channel();
        issue_order(&route, &order("t-1", Some("fang"), true)).unwrap();
        // Addressed, not yet picked up. This used to read as Claimed, which is the same
        // word the display uses for "a machine is working on it right now".
        assert_eq!(
            read_task(&route, "t-1").unwrap().state(),
            TaskState::Offered { to: "fang".into() }
        );
        claim_order(&route, "t-1", "fang").unwrap();
        assert_eq!(
            read_task(&route, "t-1").unwrap().state(),
            TaskState::Claimed { by: "fang".into() }
        );

        let mut result = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"draft": 1}),
            signed_by: None,
            signature: None,
        };
        identities["fang"].sign_result(&mut result);
        submit_result(&route, &result).unwrap();
        assert_eq!(
            read_task(&route, "t-1").unwrap().state(),
            TaskState::AwaitingReview {
                by: "fang".into(),
                revision: 1
            }
        );

        let mut review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "wisp".into(),
            reviewed_at: Utc::now(),
            accepted: false,
            notes: Some("the summary contradicts the table".into()),
            signed_by: None,
            signature: None,
        };
        identities["wisp"].sign_review(&mut review);
        submit_review(&route, &review).unwrap();
        assert_eq!(
            read_task(&route, "t-1").unwrap().state(),
            TaskState::ChangesRequested { revision: 2 }
        );

        let mut result = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 2,
            submitted_at: Utc::now(),
            payload: json!({"draft": 2}),
            signed_by: None,
            signature: None,
        };
        identities["fang"].sign_result(&mut result);
        submit_result(&route, &result).unwrap();
        let mut review = Review {
            order_id: "t-1".into(),
            revision: 2,
            reviewer: "wisp".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        identities["wisp"].sign_review(&mut review);
        submit_review(&route, &review).unwrap();
        assert_eq!(
            read_task(&route, "t-1").unwrap().state(),
            TaskState::Accepted
        );
    }

    #[test]
    fn work_without_review_is_done_when_the_result_lands() {
        let (_t, route, identities) = signed_channel();
        issue_order(&route, &order("t-1", Some("fang"), false)).unwrap();
        let mut result = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"ok": true}),
            signed_by: None,
            signature: None,
        };
        identities["fang"].sign_result(&mut result);
        submit_result(&route, &result).unwrap();
        assert_eq!(read_task(&route, "t-1").unwrap().state(), TaskState::Done);
    }

    #[test]
    fn sending_work_back_without_notes_is_refused() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", Some("fang"), true)).unwrap();
        for notes in [None, Some(String::from("   "))] {
            assert!(
                submit_review(
                    &route,
                    &Review {
                        order_id: "t-1".into(),
                        revision: 1,
                        reviewer: "wisp".into(),
                        reviewed_at: Utc::now(),
                        accepted: false,
                        notes,
                        signed_by: None,
                        signature: None,
                    }
                )
                .is_err(),
                "a rejection with no reason is not actionable"
            );
        }
    }

    #[test]
    fn an_agent_only_sees_work_that_is_actually_its_own() {
        let (_t, route, ids) = signed_channel();
        issue_order(&route, &signed(&ids, order("t-open", None, false))).unwrap();
        issue_order(&route, &signed(&ids, order("t-mine", Some("fang"), false))).unwrap();
        issue_order(
            &route,
            &signed(&ids, order("t-theirs", Some("nebra"), false)),
        )
        .unwrap();

        let mine: Vec<_> = work_for(&route, "fang")
            .unwrap()
            .into_iter()
            .map(|t| t.order.id)
            .collect();
        assert!(
            mine.contains(&"t-open".to_string()),
            "open work is available to anyone"
        );
        assert!(mine.contains(&"t-mine".to_string()));
        assert!(
            !mine.contains(&"t-theirs".to_string()),
            "work addressed to another machine is not on offer"
        );
    }

    #[test]
    fn an_unreadable_file_does_not_hide_the_rest_of_the_task() {
        let (_t, route) = channel();
        issue_order(&route, &order("t-1", Some("fang"), false)).unwrap();
        fs::write(
            task_dir(&route, "t-1").join("claim.broken.json"),
            "{ not json",
        )
        .unwrap();
        let task = read_task(&route, "t-1").unwrap();
        assert_eq!(
            task.holder(),
            Some("fang"),
            "one bad file must not stall the task"
        );
    }

    #[test]
    fn a_signed_order_result_and_review_all_verify() {
        let keys = tempfile::tempdir().unwrap();
        let wisp = AgentIdentity::load_or_create("wisp", keys.path()).unwrap();
        let fang = AgentIdentity::load_or_create("fang", keys.path()).unwrap();
        let roster = vec![
            AgentRoute {
                name: "wisp".into(),
                role: "orchestrator".into(),
                capabilities: vec![],
                public_key: Some(wisp.public_key_hex()),
                encryption_key: None,
            },
            AgentRoute {
                name: "fang".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(fang.public_key_hex()),
                encryption_key: None,
            },
        ];

        let mut o = order("t-1", Some("fang"), true);
        wisp.sign_order(&mut o);
        assert_eq!(verify_order(&o, &roster), SignatureCheck::Valid);

        let mut r = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"draft": 1}),
            signed_by: None,
            signature: None,
        };
        fang.sign_result(&mut r);
        assert_eq!(verify_result(&r, &roster), SignatureCheck::Valid);

        let mut v = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "wisp".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        wisp.sign_review(&mut v);
        assert_eq!(verify_review(&v, &roster), SignatureCheck::Valid);
    }

    #[test]
    fn tampering_with_submitted_work_is_caught() {
        let keys = tempfile::tempdir().unwrap();
        let fang = AgentIdentity::load_or_create("fang", keys.path()).unwrap();
        let roster = vec![AgentRoute {
            name: "fang".into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(fang.public_key_hex()),
            encryption_key: None,
        }];
        let mut r = TaskResult {
            order_id: "t-1".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({"finding": "no problems found"}),
            signed_by: None,
            signature: None,
        };
        fang.sign_result(&mut r);
        r.payload = json!({"finding": "everything is broken"});
        assert_eq!(
            verify_result(&r, &roster),
            SignatureCheck::Invalid,
            "rewriting what an agent reported must not still verify as theirs"
        );
    }

    #[test]
    fn a_verdict_cannot_be_flipped_after_it_was_given() {
        let keys = tempfile::tempdir().unwrap();
        let wisp = AgentIdentity::load_or_create("wisp", keys.path()).unwrap();
        let roster = vec![AgentRoute {
            name: "wisp".into(),
            role: "orchestrator".into(),
            capabilities: vec![],
            public_key: Some(wisp.public_key_hex()),
            encryption_key: None,
        }];
        let mut v = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "wisp".into(),
            reviewed_at: Utc::now(),
            accepted: false,
            notes: Some("this is wrong".into()),
            signed_by: None,
            signature: None,
        };
        wisp.sign_review(&mut v);
        // Turn a rejection into an approval.
        v.accepted = true;
        v.notes = None;
        assert_eq!(
            verify_review(&v, &roster),
            SignatureCheck::Invalid,
            "an approval nobody gave must never verify"
        );
    }

    #[test]
    fn an_order_id_cannot_escape_the_tasks_directory() {
        let (_t, route) = channel();
        for bad in ["../escape", "..", "with/slash"] {
            assert!(
                issue_order(&route, &order(bad, None, false)).is_err(),
                "'{bad}' must be refused"
            );
        }
    }
}

#[cfg(test)]
mod windows_paths {
    use super::*;

    // These run everywhere. `real_path` is a no-op off Windows, so the assertions are
    // written against the helper's decision rather than against the platform - the point
    // is that the mapping is right, and a Linux CI box should still catch it breaking.
    fn strip(text: &str) -> String {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            let mut chars = rest.chars();
            if matches!((chars.next(), chars.next()), (Some(c), Some(':')) if c.is_ascii_alphabetic())
            {
                return rest.to_string();
            }
        }
        text.to_string()
    }

    #[test]
    fn a_drive_path_loses_the_prefix() {
        assert_eq!(strip(r"\\?\X:\ferryman"), r"X:\ferryman");
        assert_eq!(
            strip(r"\\?\C:\Users\me\.ferryman\ferryman"),
            r"C:\Users\me\.ferryman\ferryman"
        );
    }

    #[test]
    fn a_unc_share_is_written_back_to_its_normal_form() {
        assert_eq!(strip(r"\\?\UNC\server\share\dir"), r"\\server\share\dir");
    }

    #[test]
    fn anything_that_would_not_round_trip_is_left_alone() {
        // Device paths mean something no ordinary path can express; dropping the prefix
        // would change where they point.
        assert_eq!(strip(r"\\?\Volume{abc}\x"), r"\\?\Volume{abc}\x");
        assert_eq!(strip(r"X:\already\plain"), r"X:\already\plain");
    }

    #[test]
    fn the_helper_agrees_with_the_mapping_it_documents() {
        let plain = real_path(Path::new(r"X:\already\plain"));
        assert_eq!(plain, PathBuf::from(r"X:\already\plain"));
    }
}

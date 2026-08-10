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

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
            if !names.insert(&agent.name) {
                bail!("registered participant names must be unique")
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
            (agent.name == recipient || agent.role == recipient)
                && capability
                    .is_none_or(|required| agent.capabilities.iter().any(|item| item == required))
        })
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
            sender: sender.into(),
            recipient: recipient.into(),
            created_at,
            acknowledgement_deadline: created_at + acknowledgement_timeout,
            payload_reference: payload_reference.into(),
            payload,
            reply_required,
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
    for name in SENSITIVE_CHILD_ENVIRONMENT {
        command.env_remove(name);
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

/// Syncthing's config.xml holds `<apikey>...</apikey>`. Read it from the platform
/// default location so an existing Syncthing install needs no extra configuration.
fn syncthing_api_key_from_config() -> Option<String> {
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
    for candidate in candidates {
        let Ok(text) = fs::read_to_string(&candidate) else {
            continue;
        };
        if let Some(start) = text.find("<apikey>")
            && let Some(end) = text[start..].find("</apikey>")
        {
            let key = text[start + "<apikey>".len()..start + end]
                .trim()
                .to_string();
            if !key.is_empty() {
                return Some(key);
            }
        }
    }
    None
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

fn acquire_git_live_lock(route: &ProjectRoute) -> Result<File> {
    let path = route.attachment.join("runtime/locks/git-live.lock");
    fs::create_dir_all(path.parent().context("Git lock path has no parent")?)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    file.try_lock_exclusive()
        .with_context(|| format!("project Git-live lock is held: {}", path.display()))?;
    Ok(file)
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
                agent.name == acknowledgement.recipient && agent.role == message.recipient
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
        test_git(temp.path(), &["init", "--bare", remote.to_str().unwrap()]);
        test_git(&route.communications, &["init", "-q"]);
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
}

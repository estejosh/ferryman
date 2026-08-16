//! The agentic half: a machine that picks work up, runs an agent CLI on it, and
//! optionally judges what comes back.
//!
//! Everything here reads and writes the synced folder directly. There is no server to
//! start, no port to open and no token to mint - which is the whole reason this exists
//! rather than the older HTTP worker, whose lease/heartbeat protocol required every
//! machine to be reachable from every other one.
//!
//! # Ferryman does not choose your risk level
//!
//! A reviewing agent can be given the last word, or it can be made to hand its verdict
//! to a human. That is [`ReviewMode`], it comes from the operator's config file, and
//! there is no clever default that decides it for them: how much a model is trusted to
//! approve unsupervised is a property of the work and the team, not of this program.
//!
//! # Isolation - read before pointing this at a real agent
//!
//! The agent CLI spawned here runs with the FULL privileges of the OS user that started
//! the loop, in its working directory, with no sandbox from Ferryman. Ferryman
//! coordinates agents; it does not contain them. Give each worker its own
//! least-privilege account and its own disposable directory, and prefer the agent's own
//! sandbox flags over trusting this process to hold it back.

use crate::Progress;
use anyhow::{Context, Result, anyhow, bail};
use ferryman_channel::{
    AgentIdentity, ProjectRoute, Recommendation, Review, Task, TaskResult, TaskState,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// How much authority the operator has given the reviewing agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMode {
    /// The agent's verdict stands. The loop runs unattended.
    Auto,
    /// The agent judges and explains, and a human settles it. The reasoning is written
    /// into the channel so whoever settles it can see the case rather than a verdict.
    Confirm,
    /// No agent judgement at all. Results wait for a person.
    Off,
}

impl ReviewMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "auto" => Ok(Self::Auto),
            "confirm" => Ok(Self::Confirm),
            "off" => Ok(Self::Off),
            other => bail!("review must be 'auto', 'confirm' or 'off', not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Confirm => "confirm",
            Self::Off => "off",
        }
    }
}

/// Where the agent CLI runs. The sandbox idea, generalised into a pluggable
/// runner: today that is bare or one of two container runtimes, but a native
/// per-platform sandbox (like groundcrew's Safehouse) can be added here later
/// without touching the agent core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runner {
    /// Run directly on the host, with this user's full privileges.
    Bare,
    /// Run inside a podman container built from the given image.
    Podman(String),
    /// Run inside a docker container built from the given image.
    Docker(String),
}

impl Runner {
    /// Parse the `sandbox = "..."` config value.
    ///
    /// `""` and `"none"` mean bare; `podman:IMAGE` and `docker:IMAGE` pick a
    /// runtime; a bare `IMAGE` means podman, the behaviour this field always had
    /// before the prefix existed, so old configs keep working.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("none") {
            return Ok(Self::Bare);
        }
        if let Some(image) = value.strip_prefix("podman:") {
            return Ok(Self::Podman(image.trim().to_string()));
        }
        if let Some(image) = value.strip_prefix("docker:") {
            return Ok(Self::Docker(image.trim().to_string()));
        }
        if !value.is_empty() {
            return Ok(Self::Podman(value.to_string()));
        }
        Ok(Self::Bare)
    }

    /// Whether the agent CLI runs inside a sandbox at all.
    #[must_use]
    pub fn is_sandboxed(&self) -> bool {
        !matches!(self, Self::Bare)
    }

    /// The container runtime binary, if any. Empty when bare.
    #[must_use]
    pub fn runtime(&self) -> &'static str {
        match self {
            Self::Bare => "",
            Self::Podman(_) => "podman",
            Self::Docker(_) => "docker",
        }
    }
}

/// How much network the sandboxed agent gets. Borrowed from OpenSandbox's
/// egress-control idea, in the smallest form a container flag can express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Full network - the historical default; a cloud agent needs its API.
    Open,
    /// No network at all - for local/offline models or hermetic work.
    None,
    /// A named, operator-configured network, e.g. one whose firewall already
    /// enforces an egress allowlist, or Docker's `internal` network.
    Named(String),
}

impl NetworkPolicy {
    /// Parse the `net = "..."` config value: `open`, `none`, or a network name.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("open") {
            return Ok(Self::Open);
        }
        if value.eq_ignore_ascii_case("none") {
            return Ok(Self::None);
        }
        Ok(Self::Named(value.to_string()))
    }

    /// The `--network` argument for podman/docker, or `None` for full access.
    #[must_use]
    pub fn network_arg(&self) -> Option<&str> {
        match self {
            Self::Open => None,
            Self::None => Some("none"),
            Self::Named(name) => Some(name.as_str()),
        }
    }
}

/// What this machine runs, and how far it is trusted.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The name this agent joined the channel under. Its signing key is filed under it.
    pub agent: String,
    /// Kept so the roster entry and the config cannot drift apart, even though the
    /// loops themselves do not branch on it.
    #[allow(dead_code)]
    pub role: String,
    /// The agent binary. Ferryman runs no models itself and is not tied to one vendor.
    pub command: String,
    /// Passed to the binary verbatim. The literal token `{prompt}` is replaced with the
    /// prompt; everything else is untouched, so a different CLI's flags need a config
    /// edit rather than a new build.
    pub args: Vec<String>,
    /// A container image to run the agent CLI inside, if any. Empty means the
    /// agent runs directly on the host with this user's full privileges.
    pub runner: Runner,
    /// Run each task in its own git worktree (branch derived from the signed
    /// order + agent) when the workspace is a git repo. Off by default.
    pub worktree: bool,
    /// How much network the sandboxed agent gets. Only applies to the podman /
    /// docker runners; the bare runner is unaffected.
    pub network: NetworkPolicy,
    pub timeout: Duration,
    /// How long the agent CLI may run without printing anything to stdout or stderr
    /// before it is considered frozen and killed. A healthy CLI streams progress; a
    /// frozen one is silent, and left alone it holds the claim while the machine stays
    /// busy for nothing. 0 turns the watchdog off (timeout_secs still bounds the run).
    pub stall: Duration,
    pub review: ReviewMode,
    /// Megabytes of memory to leave available on this machine. Below this the agent
    /// does not claim a new task - it stays open for a machine with room - and a task
    /// already running is killed before the OS has to kill something itself. 0 turns
    /// both checks off.
    pub min_free_ram_mb: u64,
    /// Stop taking work while someone is using this machine.
    pub pause_while_active: bool,
    /// How long the machine must be untouched before work resumes.
    pub idle_after: Duration,
    /// Hours during which this machine picks work up. `None` means any hour.
    pub claim_window: Option<crate::governor::Window>,
    pub poll: Duration,
    /// The preamble file as the operator wrote it, resolved relative to the attachment.
    /// Kept separate from its contents so [`Self::parse`] stays a pure string function.
    pub preamble_file: Option<String>,
    /// Standing context placed at the very front of every prompt, unchanged between runs.
    ///
    /// Read once at startup rather than per task, so the bytes cannot change under the
    /// cache mid-run, and so a file that has been moved or deleted is a loud failure
    /// before any work is claimed rather than a quiet degradation forty tasks in.
    pub preamble: Option<String>,
}

impl AgentConfig {
    /// Where the config lives: beside the attachment, never inside the synced folder.
    #[must_use]
    pub fn path(attachment: &Path) -> PathBuf {
        attachment.join("agent.toml")
    }

    /// The file written by `ferry enable`.
    ///
    /// Parsed by hand in the same flat `key = "value"` shape as `bridge.toml`, which
    /// keeps this crate free of a TOML dependency it would otherwise pull in for six
    /// keys. `args` is a JSON array because a list does not fit that shape.
    pub fn load(attachment: &Path) -> Result<Self> {
        let path = Self::path(attachment);
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "read {}; run 'ferry enable' in this project first",
                path.display()
            )
        })?;
        let mut config =
            Self::parse(&text).with_context(|| format!("{} is not valid", path.display()))?;
        config.load_preamble(attachment)?;
        Ok(config)
    }

    /// Read the configured preamble, and refuse to start without it.
    ///
    /// A missing preamble is an error, not an empty string. The whole value of this file
    /// is that its bytes are identical on every prompt: a machine that silently carried
    /// on without it would produce work that is subtly less informed and prompts that
    /// miss every cache, and nothing about either would look wrong. Failing here means
    /// the operator finds out at startup, once, instead of from a bill.
    fn load_preamble(&mut self, attachment: &Path) -> Result<()> {
        let Some(configured) = &self.preamble_file else {
            return Ok(());
        };
        // Relative paths resolve against the attachment, so the config and the file it
        // names travel together and the loop does not depend on its working directory.
        let path = {
            let named = Path::new(configured);
            if named.is_absolute() {
                named.to_path_buf()
            } else {
                attachment.join(named)
            }
        };
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "read the preamble at {}, named by preamble_file in {}",
                path.display(),
                Self::path(attachment).display()
            )
        })?;
        self.preamble = Some(text);
        Ok(())
    }

    fn parse(text: &str) -> Result<Self> {
        let mut fields: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("line is not key = value: {line}")
            };
            fields.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
        let take = |key: &str| -> Result<String> {
            fields
                .get(key)
                .cloned()
                .with_context(|| format!("missing '{key}'"))
        };
        let args_raw = fields
            .get("args")
            .cloned()
            .unwrap_or_else(|| r#"["-p","{prompt}"]"#.to_string());
        let args: Vec<String> = serde_json::from_str(&args_raw)
            .context("args must be a JSON array of strings, e.g. [\"-p\",\"{prompt}\"]")?;
        let number = |key: &str, default: u64| -> Result<u64> {
            match fields.get(key) {
                None => Ok(default),
                Some(value) => value
                    .parse()
                    .with_context(|| format!("{key} must be a whole number of seconds")),
            }
        };
        Ok(Self {
            agent: take("agent")?,
            role: fields
                .get("role")
                .cloned()
                .unwrap_or_else(|| "worker".to_string()),
            command: take("command")?,
            args,
            runner: Runner::parse(&fields.get("sandbox").cloned().unwrap_or_default())?,
            worktree: match fields.get("worktree").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                Some(other) => bail!("worktree must be true or false, not '{other}'"),
            },
            network: NetworkPolicy::parse(&fields.get("net").cloned().unwrap_or_default())?,
            timeout: Duration::from_secs(number("timeout_secs", 900)?),
            stall: Duration::from_secs(number("stall_secs", 600)?),
            review: ReviewMode::parse(
                &fields
                    .get("review")
                    .cloned()
                    .unwrap_or_else(|| "confirm".to_string()),
            )?,
            poll: Duration::from_secs(number("poll_secs", 10)?),
            min_free_ram_mb: number("min_free_ram_mb", 1024)?,
            pause_while_active: match fields.get("pause_while_active").map(String::as_str) {
                None | Some("true") => true,
                Some("false") => false,
                Some(other) => bail!("pause_while_active must be true or false, not '{other}'"),
            },
            idle_after: Duration::from_secs(number("idle_after_secs", 300)?),
            claim_window: match fields.get("claim_window").map(String::as_str) {
                None | Some("") => None,
                Some(value) => Some(crate::governor::Window::parse(value)?),
            },
            preamble_file: fields
                .get("preamble_file")
                .cloned()
                .filter(|p| !p.is_empty()),
            preamble: None,
        })
    }

    /// Render the file. Used by `ferry enable`, and the comments are the documentation
    /// most operators will actually read.
    #[must_use]
    pub fn render(
        agent: &str,
        role: &str,
        command: &str,
        args: &[String],
        review: ReviewMode,
        sandbox: Option<&str>,
        worktree: bool,
    ) -> String {
        let args = serde_json::to_string(args).unwrap_or_else(|_| "[]".into());
        format!(
            r#"# Written by 'ferry enable'. Safe to edit; re-running enable will not
# overwrite it.

# The name this agent signs as. Its private key lives beside this file and is
# never synced.
agent = "{agent}"
role = "{role}"

# What actually does the work. Ferryman runs no models itself - point this at
# whichever agent CLI you use. {{prompt}} is replaced with the task; every other
# argument is passed through untouched.
command = "{command}"
args = {args}

# Where the agent CLI runs. Empty (the default) or "none" runs it directly on
# the host, with your full privileges. Otherwise it runs inside a container
# built from an image that contains the command above:
#   podman:IMAGE   sandbox with podman
#   docker:IMAGE   sandbox with docker
#   IMAGE          shorthand for podman:IMAGE (the historical behaviour)
#
# Overhead, so you can decide knowingly: on Linux the container costs roughly
# 10-50 MB of RAM and a 1-2 second start per task. On macOS (podman machine) or
# Windows (WSL2 / Docker Desktop) a Linux VM runs underneath and reserves about
# 1-2 GB, shared across all containers.
sandbox = "{sandbox}"
timeout_secs = "900"

# The agent CLI is killed if it prints nothing for this many seconds - frozen,
# not slow: the machine is busy, the claim is held, and nothing is happening. A
# healthy agent streams progress; a frozen one goes silent. Set 0 to turn the
# watchdog off. timeout_secs still bounds the whole run either way.
stall_secs = "600"

# Run each task in its own git worktree when this workspace is a git repo, so
# parallel agents never collide in the same checkout. The branch name derives
# from the signed order and this agent, and its head commit is signed into the
# result, so the work is attributable and a re-dispatched task lands in the same
# worktree rather than a fresh one. Off by default; harmless on a non-git
# workspace.
worktree = "{worktree}"

# How much network the sandboxed agent gets (podman/docker runners only):
#   open      full network - the default, and what a cloud agent needs
#   none      no network at all - for local/offline models or hermetic work
#   <name>    a named, operator-configured network, e.g. one whose firewall
#             already enforces an egress allowlist, or Docker's "internal"
# A per-host domain allowlist is a firewall concern, not a flag - point this at
# a network that your firewall has already restricted.
# net = "open"

# How much authority the reviewing agent has. This is YOUR call, not Ferryman's:
#   auto    - the agent's verdict stands, and the loop runs unattended
#   confirm - the agent judges and explains; a human settles it
#   off     - no agent judgement; results wait for a person
review = "{review}"

# How often to look for new work, in seconds.
poll_secs = "10"

# Megabytes of memory to leave available on this machine. If less than this is
# free, this agent does not claim - the task simply stays open, so another
# machine can take it and nothing is failed or lost. And if memory runs out
# while a task is already running, that task is killed before the OS has to
# kill something itself - a machine you had to hard-reset is the worst failure
# of all. Lowering the agent's priority stops it fighting you for CPU; this
# stops it taking the last of your memory. Set to 0 to turn the check off.
min_free_ram_mb = "1024"

# Stop taking new work while you are using this machine, and start again once it
# has been untouched for idle_after_secs. Work already running is never
# interrupted - only the decision to pick up something new waits. On a machine
# with no desktop session, such as a server, there is nobody to get in the way
# and this does nothing.
pause_while_active = "true"
idle_after_secs = "300"

# Hours during which this machine picks work up, as HH:MM-HH:MM. Unset means
# any hour, which is the default and what you want unless you have a reason.
#
# The reasons people do have: electricity that is cheaper overnight, a metered
# connection with a free window, a desktop in the same room as someone asleep, an
# inference provider that discounts off-peak hours. Ferryman does not need to
# know which; they are all "take work between these times".
#
# Times are this machine's LOCAL time unless you append UTC. Say which you mean:
# a window that is off by your offset still looks like a working window, and you
# find out from the fact that nothing happened last night.
#
# A window crossing midnight is fine and is the usual case. Work already running
# when the window closes is never interrupted - only the decision to pick up
# something new waits, so nothing part-finished is thrown away.
# claim_window = "22:00-06:00"
# claim_window = "16:30-00:30 UTC"

# A file of standing context - the repo map, the conventions, whatever every task
# on this project needs to know. Its contents go at the very front of every
# prompt this machine sends, before anything task-specific, and do not change
# between runs.
#
# That position is the point. Inference providers charge far less for a prefix
# they have already seen: on some the cached rate is under a fiftieth of the
# uncached one. The discount applies to the longest run of leading bytes that is
# identical to last time, so context that would be useful anywhere in the prompt
# is worth real money specifically at the front of it.
#
# It is also just better prompting, and it costs nothing when unset. Relative
# paths resolve against this directory. If the file is named but cannot be read,
# the agent refuses to start rather than quietly working without it.
# preamble_file = "preamble.md"
"#,
            review = review.as_str(),
            sandbox = sandbox.unwrap_or(""),
            worktree = if worktree { "true" } else { "false" }
        )
    }
}

/// What the agent CLI printed, and whether it got to finish.
#[derive(Debug)]
struct AgentRun {
    stdout: String,
    stderr: String,
    ok: bool,
}

/// The bind-mount argument for the container runner, computed per platform so
/// the workspace mounts correctly everywhere.
fn workspace_mount(workspace: &Path) -> String {
    mount_arg(workspace, selinux_enforcing())
}

/// The pure form of [`workspace_mount`], so the flag logic is testable without
/// reading the host's SELinux state.
///
/// Linux with SELinux enforcing adds `:z` (shared relabel) so both the host and
/// the container keep access to the workspace. `:Z` (private) would relabel the
/// workspace so only the container could read it — breaking the host's own git
/// and result-collection access. Non-SELinux hosts (Ubuntu, macOS, WSL) need no
/// flag at all.
fn mount_arg(workspace: &Path, selinux_enforcing: bool) -> String {
    let flag = if selinux_enforcing { ":z" } else { "" };
    format!("{}:/workspace{flag}", workspace.display())
}

/// Whether this host enforces SELinux. Reads the kernel's enforce flag; the
/// path is absent on hosts without SELinux, which is the common case.
fn selinux_enforcing() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|enforce| enforce.trim() == "1")
        .unwrap_or(false)
}

/// Bind-mount warnings for a workspace path, returned for the caller to log.
///
/// - **macOS**: podman/docker run containers in a Linux VM that only mounts a
///   few host directories (`/Users`, `/Volumes`, `/tmp`, `/private`). A
///   workspace outside those mounts empty inside the container.
/// - **WSL**: a workspace on a Windows drive (`/mnt/<letter>/…`) is re-exported
///   through the VM with degraded permissions and performance. A normal Linux
///   `/mnt` (e.g. `/mnt/nvme-storage`) has a multi-character first component
///   and must not warn, so only a single ASCII drive letter counts.
fn mount_warnings(workspace: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let path = workspace.to_string_lossy();

    #[cfg(target_os = "macos")]
    {
        const SHARED_ROOTS: [&str; 5] = ["/Users", "/Volumes", "/tmp", "/private", "/var/folders"];
        if !SHARED_ROOTS.iter().any(|root| path.starts_with(root)) {
            warnings.push(format!(
                "workspace {path} is outside the directories podman/docker share into the macOS VM \
                 (/Users, /Volumes, /tmp, /private); the container may see an empty mount"
            ));
        }
    }

    if let Some(rest) = path.strip_prefix("/mnt/") {
        let drive = rest.split('/').next().unwrap_or("");
        if drive.len() == 1 && drive.chars().all(|c| c.is_ascii_alphabetic()) {
            warnings.push(format!(
                "workspace {path} is on a Windows drive (/mnt/<letter>); container mounts from \
                 Windows drives are slower and report Unix permissions loosely"
            ));
        }
    }

    warnings
}

/// Run the configured agent CLI over a prompt.
///
/// Compute the runtime binary and full argument list for a prompt, without
/// spawning anything. Pure so it can be tested without a container runtime.
fn run_command(
    config: &AgentConfig,
    workspace: &Path,
    prompt: &str,
    credentials: &[(String, String)],
) -> (String, Vec<String>) {
    let args: Vec<String> = config
        .args
        .iter()
        .map(|arg| arg.replace("{prompt}", prompt))
        .collect();
    match &config.runner {
        Runner::Bare => (config.command.clone(), args),
        Runner::Podman(image) | Runner::Docker(image) => {
            let mut full = vec!["run".to_string(), "--rm".to_string()];
            if let Some(network) = config.network.network_arg() {
                full.push("--network".to_string());
                full.push(network.to_string());
            }
            // Inject only the operator-listed credentials; the container gets
            // nothing else of the host environment.
            for (key, value) in credentials {
                full.push("--env".to_string());
                full.push(format!("{key}={value}"));
            }
            full.push("-v".to_string());
            full.push(workspace_mount(workspace));
            full.push("-w".to_string());
            full.push("/workspace".to_string());
            full.push(image.clone());
            full.push(config.command.clone());
            full.extend(args);
            (config.runner.runtime().to_string(), full)
        }
    }
}

/// stdout is the result. stderr is kept because a failed run's only explanation is
/// usually there, and discarding it turns a diagnosable problem into a silent retry.
async fn run_agent(
    config: &AgentConfig,
    workspace: &Path,
    prompt: &str,
    credentials: &[(String, String)],
) -> Result<AgentRun> {
    let (binary, args) = run_command(config, workspace, prompt, credentials);
    for warning in mount_warnings(workspace) {
        tracing::warn!("{warning}");
    }
    let mut command = Command::new(&binary);
    command.args(&args);
    // Run in the workspace (or its per-task worktree) so the agent's files land
    // in the right checkout, not wherever the loop happened to be started.
    command.current_dir(workspace);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The agent CLI is an untrusted, model-driven process. It must not inherit
    // the operator's secret environment (tokens, keys) even in the bare runner;
    // the containerized runner does not receive host env anyway.
    for name in ferryman_channel::scrub_child_environment_names() {
        command.env_remove(&name);
    }
    // Put back only the credentials the operator listed; the container got them
    // via --env, the bare runner needs them set directly.
    if matches!(config.runner, Runner::Bare) {
        for (key, value) in credentials {
            command.env(key, value);
        }
    }
    // The agent CLI, not Ferryman, is what makes a machine unusable: the loop idles at
    // about 5 MB, the thing it starts is measured in hundreds. Below-normal is set at
    // spawn on Windows, where the API is safe to use, so there is no window at full
    // priority.
    #[cfg(windows)]
    // tokio's Command carries its own inherent `creation_flags` on Windows, so the
    // std CommandExt trait is deliberately not imported - doing so is an unused import
    // that only a Windows build reports, which is exactly the kind of warning a
    // Linux-only clippy run cannot catch.
    command.creation_flags(crate::priority::BELOW_NORMAL_PRIORITY_CLASS);
    let mut child = command
        .spawn()
        .with_context(|| format!("start '{binary}'; is it installed and on PATH?"))?;
    // Elsewhere it is done just after spawn, which needs no unsafe and leaves the spawn
    // itself - and so its error message - exactly as it was.
    if let Some(pid) = child.id() {
        crate::priority::lower(pid);
    }
    let stdout_pipe = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let stderr_pipe = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

    // Two readers pull both streams concurrently and stamp a shared clock on every
    // byte. A frozen agent - alive, but silent - is then distinguishable from one that
    // is merely slow, because "slow" keeps the clock moving.
    let clock_start = Instant::now();
    let last_output = Arc::new(AtomicU64::new(0));
    let stdout_task = drain_pipe(stdout_pipe, Arc::clone(&last_output), clock_start);
    let stderr_task = drain_pipe(stderr_pipe, Arc::clone(&last_output), clock_start);

    // The watchdog poll. A few times a second is invisible while a task runs - and this
    // function only runs while a task runs - but bounds how long a freeze can last.
    let mut poll = tokio::time::interval(Duration::from_millis(500));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let deadline = Instant::now() + config.timeout;
    // Memory is the one check that is not free (sysinfo re-reads the system), so it is
    // sampled at most every five seconds.
    let mut memory_checked_at = Instant::now() - Duration::from_secs(5);

    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_task.await??;
            let stderr = stderr_task.await??;
            return Ok(AgentRun {
                stdout,
                stderr,
                ok: status.success(),
            });
        }
        poll.tick().await;

        // A frozen agent holds the claim forever while the machine stays busy for
        // nothing. Kill it; the task fails and can be retried by someone else.
        if !config.stall.is_zero() {
            let silent_ms =
                clock_start.elapsed().as_millis() as u64 - last_output.load(Ordering::Relaxed);
            if silent_ms >= config.stall.as_millis() as u64 {
                kill_child(&mut child).await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                bail!(
                    "'{}' printed nothing for {}s and was killed as frozen",
                    config.command,
                    config.stall.as_secs()
                );
            }
        }

        // An agent that keeps printing but never finishes must not hold the claim
        // forever either. This is the overall bound, distinct from the stall guard.
        if Instant::now() >= deadline {
            kill_child(&mut child).await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            bail!(
                "'{}' ran past {}s and was killed",
                config.command,
                config.timeout.as_secs()
            );
        }

        // The operator asked to keep this much memory free. Declining to claim only
        // protects the *next* task; a running one can still eat the machine alive, and a
        // machine the operator had to hard-reset is the worst failure of all. Kill the
        // child before the OS has to kill something itself.
        if config.min_free_ram_mb > 0 && memory_checked_at.elapsed() >= Duration::from_secs(5) {
            memory_checked_at = Instant::now();
            if let Some(free) = crate::governor::available_memory_mb()
                && free < config.min_free_ram_mb
            {
                kill_child(&mut child).await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                bail!(
                    "'{}' was killed: {free} MB free, below min_free_ram_mb {}",
                    config.command,
                    config.min_free_ram_mb
                );
            }
        }
    }
}

/// Kill a child and wait for it to be reaped, so no zombie is left behind.
async fn kill_child(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Read a pipe to EOF into a string, stamping `last_output` (milliseconds since
/// `clock_start`, monotonic) on every chunk so the watchdog can tell a silent child
/// from a slow one.
fn drain_pipe<R>(
    mut pipe: R,
    last_output: Arc<AtomicU64>,
    clock_start: Instant,
) -> tokio::task::JoinHandle<std::io::Result<String>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        let mut out = String::new();
        loop {
            match pipe.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    last_output.store(clock_start.elapsed().as_millis() as u64, Ordering::Relaxed);
                    out.push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
                Err(_) => break,
            }
        }
        Ok(out)
    })
}

/// Run any engine (agent CLI) over a prompt and return what it printed.
///
/// This is `run_agent` generalised past this machine's `agent.toml`, so a
/// benchmark can drive several engines - deepseek, codex, claude, a local model
/// - and compare them. Reuses the same runner/sandbox and timeout handling.
#[tracing::instrument(name = "run_engine", skip_all, fields(command = %command, engine = %command))]
pub async fn run_engine_prompt(
    runner: &Runner,
    command: &str,
    args: &[String],
    workspace: &Path,
    prompt: &str,
    timeout: Duration,
) -> Result<String> {
    // A benchmark compares raw engines, so only the overall timeout applies: the
    // stall and memory guards are worker protections, and a benchmark must be able
    // to watch a long, quiet inference without being killed for it.
    let config = AgentConfig::parse(&format!(
        "agent = \"bench\"\ncommand = \"{}\"\nargs = {}\ntimeout_secs = \"{}\"\nstall_secs = \"0\"\nmin_free_ram_mb = \"0\"\n",
        command,
        serde_json::to_string(args)?,
        timeout.as_secs(),
    ))?;
    let mut config = config;
    config.runner = runner.clone();
    let run = run_agent(&config, workspace, prompt, &[]).await?;
    if !run.ok {
        bail!(
            "'{}' failed: {}",
            command,
            run.stderr.trim().lines().next().unwrap_or("no output")
        );
    }
    Ok(run.stdout)
}

/// The prompt for a first attempt, or for a revision.
///
/// A revision deliberately repeats the original task, the rejected attempt and the
/// reviewer's notes. Sending only the notes is the tempting shortcut and it is how you
/// get an agent that fixes the complaint and quietly loses the requirement.
/// Told to the agent on every task, before the work itself.
///
/// The first outside user ran a task, wrote its answer to stdout, and closed by saying
/// "I have not submitted this, since that would be an outward-facing write." It had
/// already been submitted - the loop captures stdout and publishes it. The agent was
/// being careful about a boundary it could not see, and reported a state that was not
/// true, into a signed artefact carrying its name.
///
/// An agent that does not know it is publishing will also write deliberation, ask
/// clarifying questions, or hedge - all of which become the result. Saying so costs two
/// sentences.
const PUBLISHING_NOTICE: &str = "\
Everything you print to stdout becomes your submitted result, signed with your name and \
carried to the other machines on this channel. You do not need to submit it yourself and \
you cannot take it back. Print the deliverable and nothing else - no preamble, no \
commentary on whether you should submit, no questions.\n\n";

/// The standing context, if there is any, followed by whatever comes next.
///
/// Every prompt this machine sends goes through here, so the preamble occupies the same
/// leading bytes in all of them - a work prompt and a review prompt share a prefix even
/// though nothing else about them is alike.
///
/// Order matters and is not arbitrary. The preamble goes before the publishing notice,
/// not after it, because the preamble is the large stable block and a cache discount is
/// measured from the first byte: putting sixty tokens of notice in front of a
/// four-thousand-token repo map would cost nothing on a work prompt and throw the entire
/// shared prefix away on a review prompt, which has no notice.
fn with_preamble(config: &AgentConfig, rest: String) -> String {
    match &config.preamble {
        // Two newlines whatever the file ends with, so a preamble saved with or without
        // a trailing newline produces the same bytes. A prefix cache is a byte
        // comparison; an editor's habits should not decide whether it hits.
        Some(preamble) => format!("{}\n\n{rest}", preamble.trim_end()),
        None => rest,
    }
}

/// The notice that frames an agent's own specialization profile in its prompt.
const PROFILE_NOTICE: &str = "\
The following is your own specialization profile for this project - what you have \
become good at and the conventions you have established. It is yours, accumulated \
across your own sessions. Lean on it, and add to it after the task.\n";

/// This agent's specialization profile, framed for injection, or empty when it has
/// not written one. Keeping the empty case byte-identical means specialization is
/// opt-in by writing a profile, never a tax on every agent's prompt.
fn profile_block(route: &ProjectRoute, agent: &str) -> String {
    let bank = ferryman_channel::memory::memory_bank_dir(route);
    match ferryman_channel::memory::load_agent_profile(&bank, agent) {
        Some(profile) if !profile.trim().is_empty() => {
            format!("{PROFILE_NOTICE}\n\n{}\n\n", profile.trim_end())
        }
        _ => String::new(),
    }
}

/// The roster of the OTHER agents on this project, each with what they are
/// practiced at, plus the instruction to say so when one of them is a better fit.
/// This is what lets an agent hand work to a specialist instead of doing a worse
/// job itself, and what lets the operator see the routing suggestion in a result.
fn peer_roster_block(route: &ProjectRoute, agent: &str) -> String {
    let bank = ferryman_channel::memory::memory_bank_dir(route);
    let peers = ferryman_channel::memory::list_peer_profiles(&bank, agent);
    if peers.is_empty() {
        return String::new();
    }
    let mut out = String::from("Other agents on this project, and what they are practiced at:\n\n");
    for (peer, summary) in &peers {
        if summary.is_empty() {
            out.push_str(&format!("- {peer}\n"));
        } else {
            out.push_str(&format!("- {peer} — {summary}\n"));
        }
    }
    out.push_str(
        "\nIf a task is squarely in one of these agents' listed specialty and outside \
         yours, say so plainly in your result (for example: \"agent 'claw' is better \
         suited to this than I am\") so the operator can route it there.\n\n",
    );
    out
}

/// The prompt for a first attempt or revision, without task-matched skills.
/// Kept as the test-facing entry point; the worker uses
/// [`work_prompt_with_skills`].
#[cfg(test)]
fn work_prompt(config: &AgentConfig, task: &Task) -> String {
    work_prompt_with_skills(config, task, "")
}

/// `work_prompt`, with task-matched skills injected after the preamble and
/// before the publishing notice, so the standing context still leads and the
/// task-specific expertise sits just ahead of the work.
fn work_prompt_with_skills(config: &AgentConfig, task: &Task, skills_text: &str) -> String {
    let request = format!(
        "{skills_text}{PUBLISHING_NOTICE}{}",
        task.order
            .payload
            .get("task")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| task.order.payload.to_string())
    );
    let Some(revision) = task.latest_revision() else {
        return with_preamble(config, request);
    };
    // Only a rejection asks for more work. Matching on "a review exists" would rewrite
    // an accepted task's prompt into "fix this", which is how an agent gets told to
    // improve work that was already signed off.
    let Some(sent_back) = task
        .reviews
        .iter()
        .find(|r| r.revision == revision && !r.accepted)
    else {
        return with_preamble(config, request);
    };
    let previous = task
        .results
        .iter()
        .find(|r| r.revision == revision)
        .map(|r| r.payload.to_string())
        .unwrap_or_default();
    with_preamble(
        config,
        format!(
            "{request}\n\n\
             Your previous attempt was sent back for revision.\n\n\
             What you submitted:\n{previous}\n\n\
             What the reviewer said to change:\n{}\n\n\
             Produce a corrected version. Keep everything that was already right.",
            sent_back.notes.as_deref().unwrap_or("(no notes given)")
        ),
    )
}

/// Ask for a verdict in a shape that can be parsed without guessing.
fn review_prompt(config: &AgentConfig, task: &Task, revision: u32) -> String {
    let request = task
        .order
        .payload
        .get("task")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| task.order.payload.to_string());
    let submitted = task
        .results
        .iter()
        .find(|r| r.revision == revision)
        .map(|r| r.payload.to_string())
        .unwrap_or_default();
    with_preamble(
        config,
        format!(
            "You are reviewing another agent's work.\n\n\
             The task was:\n{request}\n\n\
             What was submitted:\n{submitted}\n\n\
             Decide whether this should be accepted or sent back for another revision. \
             Judge it against the task as stated, not against what you would have done.\n\n\
             Reply with exactly one JSON object and nothing else:\n\
             {{\"accept\": true|false, \"reasoning\": \"one or two sentences\"}}\n\
             If you send it back, the reasoning must say specifically what to change."
        ),
    )
}

/// A verdict as the reviewing agent gave it.
#[derive(Debug)]
struct Verdict {
    accept: bool,
    reasoning: String,
}

/// Pull the verdict out of whatever the agent printed.
///
/// Agents wrap JSON in prose and fences no matter how firmly they are asked not to, so
/// the last balanced object in the output is used. A run that cannot be parsed is an
/// error rather than a default: defaulting to accept approves unread work, and
/// defaulting to reject silently burns revisions.
fn parse_verdict(output: &str) -> Result<Verdict> {
    let start = output.rfind('{').context("no JSON object in the reply")?;
    let end = output[start..]
        .rfind('}')
        .context("no closing brace in the reply")?;
    let value: Value = serde_json::from_str(&output[start..=start + end])
        .context("the reply was not the JSON object the prompt asked for")?;
    let accept = value
        .get("accept")
        .and_then(Value::as_bool)
        .context("the reply has no boolean 'accept'")?;
    let reasoning = value
        .get("reasoning")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if !accept && reasoning.is_empty() {
        bail!("work was rejected with no reason, which a worker cannot act on")
    }
    Ok(Verdict {
        accept,
        reasoning: if reasoning.is_empty() {
            "accepted without comment".to_string()
        } else {
            reasoning
        },
    })
}

/// Do one pass of available work. Returns how many tasks were acted on.
///
/// Separate from the loop so it can be run once (`--once`) in a cron job or a test,
/// rather than only as a daemon.
/// What `work_once` would do, without doing any of it.
///
/// The first outside user stopped here: having just found identity resolution broken,
/// they had no way to check *which name the loop would claim as* without letting it
/// claim. A loop that cannot be asked what it is about to do can only be trusted or
/// avoided, and they reasonably chose to avoid it.
///
/// This resolves exactly what the real pass resolves and touches nothing.
pub struct Plan {
    /// The name this machine would sign and claim as.
    pub agent: String,
    /// Whether the machine has room to start, and why not if it does not.
    pub gate: crate::governor::Decision,
    /// Each task that would be acted on, and what would happen to it.
    pub would_do: Vec<(String, String)>,
}

/// Resolve the same things the worker resolves, and report them.
pub fn plan(route: &ProjectRoute, config: &AgentConfig) -> Result<Plan> {
    let waiting = ferryman_channel::work_for(route, &config.agent)?;
    let would_do = waiting
        .iter()
        .filter_map(|task| {
            let id = task.order.id.clone();
            match task.state() {
                TaskState::Open => Some((id, "claim it, then run the agent".to_string())),
                TaskState::Claimed { .. } => {
                    Some((id, "already claimed here; run the agent".to_string()))
                }
                TaskState::ChangesRequested { revision, .. } => Some((
                    id,
                    format!("revision {revision} was rejected; run the agent again"),
                )),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    Ok(Plan {
        agent: config.agent.clone(),
        gate: if would_do.is_empty() {
            crate::governor::Decision::Go
        } else {
            crate::governor::may_claim(config)
        },
        would_do,
    })
}

#[tracing::instrument(name = "work_once", skip(route, config, report), fields(agent = %config.agent, project = %route.project_id))]
pub async fn work_once(
    route: &ProjectRoute,
    config: &AgentConfig,
    report: &dyn Progress,
) -> Result<usize> {
    let identity = AgentIdentity::load_or_create(&config.agent, &route.attachment)?;
    // Always-on imports: any running worker re-polls the project's configured
    // sources and turns new external tickets into signed orders. This is what
    // makes an idle-but-running fleet pick work up without a human issuing it.
    for trigger in ferryman_channel::source::load_triggers(route)? {
        match ferryman_channel::source::poll_if_due(route, &trigger, &config.agent, &identity) {
            Ok(0) => {}
            Ok(n) => report.info(&format!("imported {n} order(s) from {}", trigger.name)),
            Err(e) => report.warn(&format!("source '{}' failed: {e:#}", trigger.name)),
        }
    }
    let mut acted = 0;
    let waiting = ferryman_channel::work_for(route, &config.agent)?;
    // Checked here rather than at the top of the loop so an idle machine stays quiet:
    // with nothing to claim there is nothing to decline, and repeating "not enough
    // memory" every poll would be noise about a non-event.
    if !waiting.is_empty()
        && let crate::governor::Decision::Wait(reason) = crate::governor::may_claim(config)
    {
        report.warn(&format!("holding off: {reason}"));
        return Ok(0);
    }
    // In a grant-gated team, an agent may not work unless the master granted it
    // its role. Full-permissions projects (`grants = "open"`) skip this.
    if !waiting.is_empty() && route.requires_grants() {
        let granted = ferryman_channel::master::is_granted(route, &config.agent, &config.role)?;
        if !granted {
            report.warn(&format!(
                "holding off: {} is not granted the '{}' role in this team (ask the master)",
                config.agent, config.role
            ));
            return Ok(0);
        }
    }
    for task in waiting {
        let id = task.order.id.clone();
        // Trust boundary: never act on an order whose signature does not verify.
        // Any peer can write to the synced folder, so an unsigned or forged
        // order must be skipped, not executed.
        if ferryman_channel::verify_order(&task.order, &route.agents)
            != ferryman_channel::SignatureCheck::Valid
        {
            report.warn(&format!("  {id}: order signature invalid, skipping"));
            continue;
        }
        match task.state() {
            TaskState::Open => {
                ferryman_channel::claim_order(route, &id, &config.agent)?;
                ferryman_channel::ledger::append_ledger_entry(
                    route,
                    &identity,
                    "claim",
                    &config.agent,
                    &format!("claimed order {id}"),
                    Some(&id),
                )?;
                // Re-read: another machine's claim may have arrived while this one was
                // being written, and the older claim wins. Acting on a stale read is
                // how two agents end up doing the same task.
                let task = ferryman_channel::read_task(route, &id)?;
                if task.holder() != Some(config.agent.as_str()) {
                    report.info(&format!(
                        "  {id}: {} claimed it first, backing off",
                        task.holder().unwrap_or("someone")
                    ));
                    continue;
                }
                do_work(route, config, &identity, &task, report).await?;
                acted += 1;
            }
            TaskState::Claimed { .. } | TaskState::ChangesRequested { .. } => {
                do_work(route, config, &identity, &task, report).await?;
                acted += 1;
            }
            _ => {}
        }
    }
    Ok(acted)
}

#[tracing::instrument(name = "do_work", skip(route, config, identity, task, report), fields(order = %task.order.id, agent = %config.agent))]
async fn do_work(
    route: &ProjectRoute,
    config: &AgentConfig,
    identity: &AgentIdentity,
    task: &Task,
    report: &dyn Progress,
) -> Result<()> {
    use ferryman_channel::interrupt::InterruptAction;

    let id = &task.order.id;
    let revision = task.latest_revision().unwrap_or(0) + 1;
    report.info(&format!(
        "  {id}: running {} (revision {revision})",
        config.command
    ));

    // An operator may interrupt a running task mid-flight. This is Ferryman's
    // answer to groundcrew's live-terminal takeover: a signed order the worker
    // honours between ticks, and recorded in the ledger.
    let mut steer: Option<String> = None;
    for interrupt in ferryman_channel::interrupt::pending_interrupts(route, id, &config.agent)? {
        ferryman_channel::interrupt::acknowledge(route, id, &interrupt.issued_by, &config.agent)?;
        report.warn(&format!(
            "  {id}: {} interrupt from {}: {}",
            interrupt.action.as_str(),
            interrupt.issued_by,
            interrupt.note
        ));
        match interrupt.action {
            InterruptAction::Kill => {
                ferryman_channel::interrupt::abandon_claim(route, id, &config.agent)?;
                ferryman_channel::ledger::append_ledger_entry(
                    route,
                    identity,
                    "interrupt",
                    &config.agent,
                    &format!("killed {id} on interrupt from {}", interrupt.issued_by),
                    Some(id),
                )?;
                return Ok(());
            }
            InterruptAction::Pause => {
                ferryman_channel::interrupt::abandon_claim(route, id, &config.agent)?;
                ferryman_channel::ledger::append_ledger_entry(
                    route,
                    identity,
                    "interrupt",
                    &config.agent,
                    &format!("paused {id} on interrupt from {}", interrupt.issued_by),
                    Some(id),
                )?;
                return Ok(());
            }
            InterruptAction::Steer => steer = Some(interrupt.note),
        }
    }

    // One git worktree per task when enabled and the workspace is a git repo, so
    // parallel agents never collide in the same checkout. The branch derives from
    // the signed order + agent and is signed into the result below.
    let branch = ferryman_channel::worktree::branch_name(id, &config.agent);
    let mut workdir = route.workspace.clone();
    let mut used_worktree = false;
    if config.worktree && ferryman_channel::worktree::is_git_repo(&route.workspace) {
        match ferryman_channel::worktree::create_worktree(&route.workspace, id, &config.agent) {
            Ok((dir, _)) => {
                workdir = dir;
                used_worktree = true;
            }
            Err(e) => report.warn(&format!("  {id}: worktree unavailable, running in place: {e}")),
        }
    }

    // Task-matched skills: load the team's shared SKILL.md expertise and inject
    // only the skills whose description overlaps this task.
    let skills = ferryman_channel::skills::load_skills(route).unwrap_or_default();
    let matched = ferryman_channel::skills::route(&skills, &task.order.payload.to_string());
    let skills_text = ferryman_channel::skills::render(&matched);
    // This agent's own specialization profile rides in front of the task-matched
    // skills: what it has become good at, so an agent that sharpened itself on Rust
    // keeps its Rust memory instead of loading someone else's unrelated one.
    let profile_text = profile_block(route, &config.agent);
    // And the roster of the other agents, so it knows who else is available, what
    // they are practiced at, and can say so when one of them is a better fit.
    let roster_text = peer_roster_block(route, &config.agent);
    let mut prompt =
        work_prompt_with_skills(config, task, &format!("{profile_text}{roster_text}{skills_text}"));
    if let Some(note) = steer {
        prompt = format!(
            "The operator has sent a new instruction that takes precedence over your previous plan.\n\n{note}\n\n---\n\n{prompt}"
        );
    }
    // Operator-listed credentials are the only secrets the agent CLI receives.
    let credentials: Vec<(String, String)> =
        ferryman_channel::credentials::load_credentials(&route.attachment)
            .unwrap_or_default()
            .into_iter()
            .collect();
    let run = run_agent(config, &workdir, &prompt, &credentials).await?;
    // Record the full trajectory (prompt digest + output) for replayable review
    // and as a corpus for the benchmark. Best-effort: a trajectory write must
    // never fail the run itself.
    let _ = ferryman_channel::trajectory::record_trajectory(
        route,
        &ferryman_channel::trajectory::Trajectory {
            order_id: id.clone(),
            agent: config.agent.clone(),
            engine: config.command.clone(),
            revision,
            at: chrono::Utc::now(),
            ok: run.ok,
            prompt_digest: ferryman_channel::trajectory::digest(&prompt),
            output: ferryman_channel::trajectory::truncate(&run.stdout),
        },
    );

    let mut payload = json!({
        "output": run.stdout.trim(),
        "produced_by": config.command,
        "worktree_branch": branch,
    });
    if used_worktree {
        if let Ok(head) = ferryman_channel::worktree::worktree_head(&route.workspace, &branch) {
            payload["worktree_head"] = json!(head);
        }
        let _ = ferryman_channel::worktree::remove_worktree(&route.workspace, &branch);
    }
    if !run.ok {
        // Left claimed on purpose. Marking it failed would need a state this protocol
        // does not have, and inventing one here would be a worse lie than silence.
        bail!(
            "'{}' failed on {id}: {}",
            config.command,
            run.stderr.trim().lines().next().unwrap_or("no output")
        )
    }
    let mut result = TaskResult {
        order_id: id.clone(),
        agent: config.agent.clone(),
        revision,
        submitted_at: chrono::Utc::now(),
        payload,
        signed_by: None,
        signature: None,
    };
    identity.sign_result(&mut result);
    ferryman_channel::submit_result(route, &result)?;
    ferryman_channel::ledger::append_ledger_entry(
        route,
        identity,
        "result",
        &config.agent,
        &format!("submitted revision {revision} for {id}"),
        Some(id),
    )?;
    report.info(&format!(
        "  {id}: submitted revision {revision}, signed by {}",
        config.agent
    ));
    Ok(())
}

/// Judge whatever is waiting, according to the authority the operator granted.
pub async fn review_once(
    route: &ProjectRoute,
    config: &AgentConfig,
    report: &dyn Progress,
) -> Result<usize> {
    if config.review == ReviewMode::Off {
        report.info("review is off; results wait for a person");
        return Ok(0);
    }
    let identity = AgentIdentity::load_or_create(&config.agent, &route.attachment)?;
    let mut acted = 0;
    let mut skipped_own = 0;
    for task in ferryman_channel::list_tasks(route)? {
        let TaskState::AwaitingReview { by, revision } = task.state() else {
            continue;
        };
        // Trust boundary: judge only work whose order and result signatures
        // verify. A forged order or result must not be reviewed as if real.
        if ferryman_channel::verify_order(&task.order, &route.agents)
            != ferryman_channel::SignatureCheck::Valid
        {
            report.warn(&format!(
                "  {}: order signature invalid, skipping",
                task.order.id
            ));
            continue;
        }
        if !task
            .results
            .iter()
            .any(|r| {
                r.revision == revision
                    && ferryman_channel::verify_result(r, &route.agents)
                        == ferryman_channel::SignatureCheck::Valid
            })
        {
            report.warn(&format!(
                "  {}: result signature invalid, skipping",
                task.order.id
            ));
            continue;
        }
        // Reviewing your own work is not review. Saying so out loud matters: a single
        // machine configured as both worker and reviewer would otherwise look like a
        // reviewer that silently does nothing, and the operator would go hunting for a
        // bug instead of starting a second agent.
        if by == config.agent {
            skipped_own += 1;
            continue;
        }
        // Do not re-judge something already sitting in front of a human.
        if task.pending_recommendation().is_some() {
            continue;
        }
        let id = task.order.id.clone();
        report.info(&format!("  {id}: judging revision {revision}"));
        let credentials: Vec<(String, String)> =
            ferryman_channel::credentials::load_credentials(&route.attachment)
                .unwrap_or_default()
                .into_iter()
                .collect();
        let run = run_agent(
            config,
            &route.workspace,
            &review_prompt(config, &task, revision),
            &credentials,
        )
        .await?;
        if !run.ok {
            bail!(
                "'{}' failed reviewing {id}: {}",
                config.command,
                run.stderr.trim().lines().next().unwrap_or("no output")
            )
        }
        let verdict = parse_verdict(&run.stdout)
            .with_context(|| format!("could not read a verdict for {id}"))?;
        match config.review {
            ReviewMode::Auto => {
                let mut review = Review {
                    order_id: id.clone(),
                    revision,
                    reviewer: config.agent.clone(),
                    reviewed_at: chrono::Utc::now(),
                    accepted: verdict.accept,
                    notes: Some(verdict.reasoning.clone()),
                    signed_by: None,
                    signature: None,
                };
                identity.sign_review(&mut review);
                ferryman_channel::submit_review(route, &review)?;
                report.info(&format!(
                    "  {id}: {} - {}",
                    if verdict.accept {
                        "accepted"
                    } else {
                        "sent back"
                    },
                    verdict.reasoning
                ));
            }
            ReviewMode::Confirm => {
                let mut recommendation = Recommendation {
                    order_id: id.clone(),
                    revision,
                    reviewer: config.agent.clone(),
                    recommended_at: chrono::Utc::now(),
                    accept: verdict.accept,
                    reasoning: verdict.reasoning.clone(),
                    signed_by: None,
                    signature: None,
                };
                identity.sign_recommendation(&mut recommendation);
                ferryman_channel::submit_recommendation(route, &recommendation)?;
                report.info(&format!(
                    "  {id}: recommends {} - {}",
                    if verdict.accept { "accept" } else { "changes" },
                    verdict.reasoning
                ));
                report.info(&format!(
                    "  {id}: waiting for a human; settle it with 'ferry channel review'"
                ));
            }
            ReviewMode::Off => unreachable!("returned above"),
        }
        acted += 1;
    }
    if acted == 0 && skipped_own > 0 {
        report.info(&format!(
            "  {skipped_own} result(s) waiting, but all of them are '{}'s own work - \
             an agent does not review itself. Run the reviewer as a different agent.",
            config.agent
        ));
    }
    Ok(acted)
}

/// Everything a human has been asked to settle.
pub fn pending(route: &ProjectRoute) -> Result<Vec<(String, Recommendation)>> {
    let roster = ferryman_channel::read_agent_roster(&route.communications)?;
    let mut waiting = Vec::new();
    for task in ferryman_channel::list_tasks(route)? {
        if let Some(recommendation) = task.pending_recommendation() {
            // Show the signature check beside the advice: a recommendation is read by a
            // human who is about to act on it, so a forged one is as good as a verdict.
            let check = ferryman_channel::verify_recommendation(recommendation, &roster);
            waiting.push((format!("{check:?}"), recommendation.clone()));
        }
    }
    Ok(waiting)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runner_parses_the_new_syntax_and_keeps_the_old() {
        use Runner::*;
        assert_eq!(Runner::parse("").unwrap(), Bare);
        assert_eq!(Runner::parse("none").unwrap(), Bare);
        assert_eq!(Runner::parse("  NONE  ").unwrap(), Bare);
        assert_eq!(Runner::parse("podman:ubuntu").unwrap(), Podman("ubuntu".into()));
        assert_eq!(Runner::parse("docker:alpine:3").unwrap(), Docker("alpine:3".into()));
        // A bare image name still means podman, so an existing config keeps working.
        assert_eq!(Runner::parse("ghcr.io/x/y").unwrap(), Podman("ghcr.io/x/y".into()));
        assert!(!Bare.is_sandboxed());
        assert!(Podman("x".into()).is_sandboxed());
        assert_eq!(Podman("x".into()).runtime(), "podman");
        assert_eq!(Docker("x".into()).runtime(), "docker");
    }

    #[test]
    fn a_bare_runner_spawns_the_command_directly() {
        let config = AgentConfig::parse("agent = \"w\"\ncommand = \"claude\"\n").unwrap();
        let (binary, args) = run_command(&config, Path::new("/ws"), "hello", &[]);
        assert_eq!(binary, "claude");
        assert_eq!(args, vec!["-p", "hello"]);
    }

    #[test]
    fn a_docker_runner_wraps_the_command_in_the_container() {
        let config =
            AgentConfig::parse("agent = \"w\"\ncommand = \"codex\"\nsandbox = \"docker:node:22\"\n")
                .unwrap();
        let (binary, args) = run_command(&config, Path::new("/ws"), "hello", &[]);
        assert_eq!(binary, "docker");
        let mount = workspace_mount(Path::new("/ws"));
        assert_eq!(
            args,
            vec![
                "run",
                "--rm",
                "-v",
                mount.as_str(),
                "-w",
                "/workspace",
                "node:22",
                "codex",
                "-p",
                "hello"
            ]
        );
    }

    #[test]
    fn the_mount_arg_adds_the_selinux_flag_only_when_enforcing() {
        assert_eq!(mount_arg(Path::new("/ws"), false), "/ws:/workspace");
        assert_eq!(mount_arg(Path::new("/ws"), true), "/ws:/workspace:z");
    }

    #[test]
    fn mount_warnings_flag_windows_drives_but_not_normal_mnt() {
        assert!(
            mount_warnings(Path::new("/mnt/c/project"))
                .iter()
                .any(|w| w.contains("Windows drive"))
        );
        assert!(mount_warnings(Path::new("/mnt/nvme-storage/repos")).is_empty());
        assert!(mount_warnings(Path::new("/home/you/project")).is_empty());
    }

    #[test]
    fn a_none_network_policy_blocks_egress_in_the_container() {
        let config = AgentConfig::parse(
            "agent = \"w\"\ncommand = \"codex\"\nsandbox = \"podman:local\"\nnet = \"none\"\n",
        )
        .unwrap();
        let (binary, args) = run_command(&config, Path::new("/ws"), "hello", &[]);
        assert_eq!(binary, "podman");
        assert_eq!(args[..4], ["run", "--rm", "--network", "none"]);
    }

    #[test]
    fn a_named_network_is_passed_through() {
        let config = AgentConfig::parse(
            "agent = \"w\"\ncommand = \"codex\"\nsandbox = \"docker:img\"\nnet = \"restricted\"\n",
        )
        .unwrap();
        let (_, args) = run_command(&config, Path::new("/ws"), "hello", &[]);
        assert_eq!(args[..4], ["run", "--rm", "--network", "restricted"]);
    }

    #[test]
    fn the_network_policy_parses_open_none_and_named() {
        use NetworkPolicy::*;
        assert_eq!(NetworkPolicy::parse("").unwrap(), Open);
        assert_eq!(NetworkPolicy::parse("open").unwrap(), Open);
        assert_eq!(NetworkPolicy::parse("NONE").unwrap(), NetworkPolicy::None);
        assert_eq!(
            NetworkPolicy::parse("restricted").unwrap(),
            Named("restricted".into())
        );
        assert_eq!(Open.network_arg(), Option::None);
        assert_eq!(NetworkPolicy::None.network_arg(), Option::Some("none"));
    }


    use ferryman_channel::{Claim, Order, Review};

    /// A config with no preamble, which is what every prompt test but the preamble ones
    /// wants: they are asserting on the task text, not on what precedes it.
    fn bare_config() -> AgentConfig {
        AgentConfig::parse("agent = \"worker\"\ncommand = \"claude\"\n").unwrap()
    }

    fn order(id: &str) -> Order {
        Order {
            id: id.into(),
            project_id: "p".into(),
            issued_by: "orchestrator".into(),
            assigned_to: None,
            created_at: chrono::Utc::now(),
            payload: json!({ "task": "write the report" }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
        }
    }

    fn task_with(results: Vec<TaskResult>, reviews: Vec<Review>) -> Task {
        Task {
            order: order("t-1"),
            claims: vec![Claim {
                order_id: "t-1".into(),
                agent: "worker".into(),
                claimed_at: chrono::Utc::now(),
            }],
            results,
            reviews,
            recommendations: Vec::new(),
        }
    }

    fn result(revision: u32, body: &str) -> TaskResult {
        TaskResult {
            order_id: "t-1".into(),
            agent: "worker".into(),
            revision,
            submitted_at: chrono::Utc::now(),
            payload: json!({ "output": body }),
            signed_by: None,
            signature: None,
        }
    }

    #[test]
    fn a_first_attempt_is_the_task_plus_the_publishing_notice() {
        let prompt = work_prompt(&bare_config(), &task_with(Vec::new(), Vec::new()));
        assert!(prompt.ends_with("write the report"));
        // The notice is not decoration: without it an agent reported that it had not
        // submitted work that had already been published under its own signature.
        assert!(prompt.contains("becomes your submitted result"));
    }

    #[test]
    fn a_revision_still_tells_the_agent_it_is_publishing() {
        let review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: false,
            notes: Some("wrong totals".into()),
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(
            &bare_config(),
            &task_with(vec![result(1, "first go")], vec![review]),
        );
        assert!(prompt.contains("becomes your submitted result"));
    }

    #[test]
    fn a_revision_carries_the_task_the_attempt_and_the_notes() {
        let review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: false,
            notes: Some("the summary contradicts the table".into()),
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(
            &bare_config(),
            &task_with(vec![result(1, "first go")], vec![review]),
        );
        // All three, because notes alone produce an agent that fixes the complaint and
        // drops the original requirement.
        assert!(prompt.contains("write the report"));
        assert!(prompt.contains("first go"));
        assert!(prompt.contains("the summary contradicts the table"));
    }

    #[test]
    fn an_accepted_revision_does_not_ask_for_more_work() {
        let review = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(
            &bare_config(),
            &task_with(vec![result(1, "first go")], vec![review]),
        );
        assert!(!prompt.contains("sent back for revision"));
    }

    fn config_with_preamble(preamble: &str) -> AgentConfig {
        let mut config = bare_config();
        config.preamble = Some(preamble.to_string());
        config
    }

    #[test]
    fn the_preamble_leads_every_prompt_and_is_byte_identical_across_them() {
        // The property the whole feature rests on. A provider's cache discount is
        // measured from the first byte of the prompt, so what matters is not that the
        // preamble is present but that it is in front and the same every time.
        let config = config_with_preamble("REPO MAP\nsrc/ is the code.");
        let work = work_prompt(&config, &task_with(Vec::new(), Vec::new()));
        let review = review_prompt(&config, &task_with(vec![result(1, "a")], Vec::new()), 1);

        let expected = "REPO MAP\nsrc/ is the code.\n\n";
        assert!(work.starts_with(expected), "work prompt: {work}");
        assert!(review.starts_with(expected), "review prompt: {review}");

        // Not merely "both contain it": a work prompt and a review prompt have nothing
        // else in common, so this shared run of leading bytes is the entire cache hit.
        let shared = work
            .bytes()
            .zip(review.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        assert!(
            shared >= expected.len(),
            "the two prompts must share the whole preamble, shared {shared} bytes"
        );
    }

    #[test]
    fn a_revision_prompt_also_leads_with_the_preamble() {
        // The path most likely to be missed: the revision branch builds its prompt
        // somewhere else entirely, and an agent doing the second attempt needs the
        // standing context at least as much as one doing the first.
        let sent_back = Review {
            order_id: "t-1".into(),
            revision: 1,
            reviewer: "orchestrator".into(),
            reviewed_at: chrono::Utc::now(),
            accepted: false,
            notes: Some("wrong totals".into()),
            signed_by: None,
            signature: None,
        };
        let prompt = work_prompt(
            &config_with_preamble("REPO MAP"),
            &task_with(vec![result(1, "first go")], vec![sent_back]),
        );
        assert!(prompt.starts_with("REPO MAP\n\n"));
        assert!(prompt.contains("sent back for revision"));
    }

    #[test]
    fn a_trailing_newline_in_the_preamble_file_does_not_change_the_prompt() {
        // Whether an editor saved a final newline must not decide whether every prompt
        // for the next month misses the cache.
        let task = task_with(Vec::new(), Vec::new());
        assert_eq!(
            work_prompt(&config_with_preamble("REPO MAP"), &task),
            work_prompt(&config_with_preamble("REPO MAP\n"), &task)
        );
    }

    #[test]
    fn no_preamble_leaves_the_prompt_exactly_as_it_was() {
        // The feature must cost nothing when unset: this is the prompt every existing
        // deployment is already sending.
        let prompt = work_prompt(&bare_config(), &task_with(Vec::new(), Vec::new()));
        assert!(prompt.starts_with("Everything you print to stdout"));
    }

    #[test]
    fn a_named_preamble_that_cannot_be_read_stops_the_agent_starting() {
        // Loud at startup beats a machine that quietly works without the context it was
        // configured to have, producing worse results and paying full price for them.
        let dir = std::env::temp_dir().join(format!("ferryman-preamble-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        fs::write(
            AgentConfig::path(&dir),
            "agent = \"a\"\ncommand = \"c\"\npreamble_file = \"nope.md\"\n",
        )
        .unwrap();

        let error = AgentConfig::load(&dir).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("nope.md"), "must name the file: {text}");
        assert!(
            text.contains("preamble_file"),
            "must name the setting that caused it: {text}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_preamble_is_read_from_beside_the_config() {
        let dir = std::env::temp_dir().join(format!("ferryman-preamble-ok-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        fs::write(
            AgentConfig::path(&dir),
            "agent = \"a\"\ncommand = \"c\"\npreamble_file = \"preamble.md\"\n",
        )
        .unwrap();
        fs::write(dir.join("preamble.md"), "STANDING CONTEXT").unwrap();

        let config = AgentConfig::load(&dir).unwrap();
        assert_eq!(config.preamble.as_deref(), Some("STANDING CONTEXT"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_verdict_survives_the_prose_agents_wrap_it_in() {
        let verdict = parse_verdict(
            "Sure! Here's my assessment:\n```json\n{\"accept\": false, \
             \"reasoning\": \"the totals do not add up\"}\n```\nHope that helps.",
        )
        .unwrap();
        assert!(!verdict.accept);
        assert_eq!(verdict.reasoning, "the totals do not add up");
    }

    #[test]
    fn a_rejection_with_no_reason_is_refused() {
        // Not a default-to-something case: a worker cannot act on "no", and silently
        // accepting instead would approve unread work.
        let error = parse_verdict(r#"{"accept": false, "reasoning": "  "}"#).unwrap_err();
        assert!(error.to_string().contains("no reason"));
    }

    #[test]
    fn unparseable_output_is_an_error_not_a_guess() {
        assert!(parse_verdict("I think it looks fine to me").is_err());
    }

    #[test]
    fn config_round_trips_through_the_file_enable_writes() {
        let rendered = AgentConfig::render(
            "beastly",
            "worker",
            "claude",
            &["-p".into(), "{prompt}".into()],
            ReviewMode::Confirm,
            None,
            false,
        );
        let config = AgentConfig::parse(&rendered).unwrap();
        assert_eq!(config.agent, "beastly");
        assert_eq!(config.command, "claude");
        assert_eq!(config.args, vec!["-p", "{prompt}"]);
        assert_eq!(config.review, ReviewMode::Confirm);
        assert_eq!(config.timeout, Duration::from_secs(900));
        assert_eq!(config.stall, Duration::from_secs(600));
        assert!(!config.worktree);
    }

    #[test]
    fn the_stall_watchdog_defaults_on_and_can_be_turned_off() {
        let config = AgentConfig::parse("agent = \"a\"\ncommand = \"c\"\n").unwrap();
        assert_eq!(config.stall, Duration::from_secs(600));
        let config =
            AgentConfig::parse("agent = \"a\"\ncommand = \"c\"\nstall_secs = \"0\"\n").unwrap();
        assert!(config.stall.is_zero());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_silent_agent_is_killed_as_frozen() {
        // `sleep` prints nothing, so a one-second stall window must kill it long before
        // the thirty seconds it would otherwise run. Skips where there is no `sleep`.
        if std::process::Command::new("sleep")
            .arg("0")
            .status()
            .is_err()
        {
            return;
        }
        let dir = std::env::temp_dir().join(format!("ferryman-stall-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let config = AgentConfig::parse(
            "agent = \"w\"\ncommand = \"sleep\"\nargs = [\"30\"]\nstall_secs = \"1\"\ntimeout_secs = \"60\"\n",
        )
        .unwrap();
        let error = run_agent(&config, &dir, "hello", &[]).await.unwrap_err();
        assert!(
            format!("{error}").contains("frozen"),
            "expected the stall watchdog, got: {error:#}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn review_mode_defaults_to_asking_a_human() {
        // The safe end of the scale. An operator who wants unattended approval has to
        // say so, rather than discovering they had it.
        let config = AgentConfig::parse("agent = \"a\"\ncommand = \"claude\"\n").unwrap();
        assert_eq!(config.review, ReviewMode::Confirm);
    }

    #[test]
    fn an_unknown_review_mode_is_refused_rather_than_assumed() {
        let error =
            AgentConfig::parse("agent=\"a\"\ncommand=\"c\"\nreview=\"yolo\"\n").unwrap_err();
        assert!(format!("{error:#}").contains("auto"));
    }
}

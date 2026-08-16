#![forbid(unsafe_code)]
mod license;

use ferryman_ops::Progress;
use ferryman_ops::agent;
use ferryman_ops::enable;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Parser, Clone)]
#[command(version, about = "Private coordination for a fleet of AI agents")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    endpoint: String,
    /// Required only by commands that talk to a server. The `channel` commands read
    /// and write the synced folder directly and never need one.
    #[arg(long, env = "FERRYMAN_TOKEN")]
    token: Option<String>,
    #[arg(long, env = "FERRYMAN_MEMORY_TOKEN")]
    memory_token: Option<String>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Clone)]
enum Command {
    /// Point a project at Ferryman. Run it once, in the project directory.
    ///
    /// Idempotent: it never overwrites a config you have edited, so re-running it after
    /// a version bump is safe and is the intended way to repair a half-finished setup.
    Enable {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Project id. Defaults to the directory's name.
        #[arg(long)]
        project: Option<String>,
        /// This agent's name. Defaults to this machine's name.
        #[arg(long)]
        agent: Option<String>,
        /// Contact email for this deployment. Required: free production use is
        /// conditioned on registering one (LICENSE section 3). Nothing about your
        /// code or your work is ever sent - see PRIVACY.md.
        #[arg(long, env = "FERRYMAN_EMAIL")]
        email: String,
        /// What this agent is here to do. Shown to every other machine in the roster.
        #[arg(long, default_value = "worker")]
        role: String,
        /// The agent CLI that does the work.
        #[arg(long, default_value = "claude")]
        command: String,
        /// How much authority a reviewing agent has: auto, confirm or off.
        ///
        /// Defaults to `confirm`, which is the cautious end. Ferryman does not decide
        /// how much you trust a model to approve work unsupervised.
        #[arg(long, default_value = "confirm")]
        review: String,
        /// Do not touch the local Syncthing. By default `enable` registers the channel
        /// folder and shares it with the devices Syncthing already trusts, because that
        /// step is otherwise a trip through a web UI that an agent cannot make.
        #[arg(long)]
        no_syncthing: bool,
        /// Share the channel folder with only these Syncthing device ids, instead of
        /// every device Syncthing already trusts. Repeatable. Use this when one project
        /// should reach one person and not the whole fleet.
        #[arg(long)]
        share_with: Vec<String>,
        /// Become this project's master. Ask the user first; this is an explicit choice.
        #[arg(long)]
        master: bool,
        /// Container image to sandbox the agent CLI in; empty runs it bare.
        /// Overhead: ~10-50 MB + 1-2s per task on Linux; ~1-2 GB VM on macOS/Windows.
        #[arg(long)]
        sandbox: Option<String>,
        /// Run each task in its own git worktree when the workspace is a git repo.
        #[arg(long)]
        worktree: bool,
        /// Emit one JSON object describing the result, for a caller that is a program.
        #[arg(long)]
        json: bool,
        /// Also set up the web dashboard. Interactively, `enable` asks for the
        /// operator name and password here (typed privately, never echoed). An
        /// agent (`--json`) never sees or handles the password: it reports that
        /// a human should run `ferry dashboard` and create the operator in the
        /// browser instead.
        #[arg(long)]
        dashboard: bool,
        /// The dashboard operator's username. Used by the interactive prompt.
        #[arg(long)]
        dashboard_operator: Option<String>,
    },
    /// Stop this machine taking on new work, until you resume it.
    ///
    /// Affects every project on this computer, not just this one, because "stop working
    /// on this machine" is the thing people mean. Work already running is left alone.
    Pause {
        /// Why, shown wherever the pause is reported.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Start taking work again after `ferry pause`.
    Resume,
    /// What this machine's worker has been doing.
    ///
    /// The local diagnostic record - attempts, errors, and the reasons the loop declined
    /// to claim. `ferry channel log` is the other half: what the *fleet* did, signed.
    /// This one never leaves the machine, because it carries local paths and whatever
    /// the agent CLI printed.
    Log {
        #[arg(long, default_value_t = 40)]
        lines: usize,
    },
    /// Run the agentic loop: pick work up, do it, and judge what comes back.
    Agent {
        #[command(subcommand)]
        command: Agent,
    },
    /// Benchmark the engines in bench.json against each other, and record the
    /// results in the learning database.
    Bench {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Seconds per engine-task run before it is killed.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
    /// What this deployment counts as under the licence.
    License {
        #[command(subcommand)]
        command: License,
    },
    /// Write an `orchestrator.toml` for SERVER mode. Almost nobody wants this.
    ///
    /// `ferry enable` is the command for the synced channel, which needs no server, no
    /// token and no port. This one writes a config pointing at a server you would have
    /// to run yourself, and it is the command people try first by mistake.
    Init {
        #[arg(default_value = "orchestrator.toml")]
        path: PathBuf,
    },
    /// Server mode: projects on a running ferryman-server.
    Projects {
        #[command(subcommand)]
        command: Projects,
    },
    /// Server mode: jobs on a running ferryman-server.
    Jobs {
        #[command(subcommand)]
        command: Jobs,
    },
    /// Server mode: workers registered with a running ferryman-server.
    Workers {
        #[command(subcommand)]
        command: Workers,
    },
    /// Server mode: agents registered with a running ferryman-server.
    Agents {
        #[command(subcommand)]
        command: Agents,
    },
    /// Server mode: the shared memory store.
    Memory {
        #[command(subcommand)]
        command: Memory,
    },
    /// Server mode: artifacts produced by jobs.
    Artifacts {
        #[command(subcommand)]
        command: Artifacts,
    },
    /// Server mode: consent records.
    Consents {
        #[command(subcommand)]
        command: Consents,
    },
    /// Server mode: continuity packs.
    Continuity {
        #[command(subcommand)]
        command: Continuity,
    },
    /// Talk to the channel directly, with nothing running.
    ///
    /// `communications` does the same things through a server. These do not: they read
    /// and write the synced folder themselves, which is all the server was doing for a
    /// local file write anyway. Syncthing carries it either way.
    Channel {
        #[command(subcommand)]
        command: Channel,
    },
    /// Server mode: messaging through a server. `channel` does the same with none.
    Communications {
        #[command(subcommand)]
        command: Communications,
    },
    /// Serve a web dashboard over this project's channel: tasks, engine stats,
    /// the ledger, and learnings, live. Operators sign in with a
    /// password-protected identity and approve or send back work from the
    /// browser. Binds loopback only.
    Dashboard {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Loopback port to bind. Defaults to 8788.
        #[arg(long, default_value_t = 8788)]
        port: u16,
        /// Minutes of inactivity before an operator is signed out.
        #[arg(long, default_value_t = 15)]
        timeout: u64,
        /// Serve views only; disable sign-in and the approve/send-back action.
        #[arg(long)]
        read_only: bool,
    },
    /// Print this project's persistent memory — the synced memory bank and the
    /// durable append-only log — so an agent that has lost its context (or a
    /// human) can reload the whole picture in one command. Works from the
    /// checkout or the channel folder; no channel is required.
    Loadmem {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Project slug, when the directory name is not the slug.
        #[arg(long)]
        project: Option<String>,
        /// Load one agent's specialization profile on top of the shared memory.
        #[arg(long)]
        agent: Option<String>,
        /// List the agents that have memory, with a one-line summary each — the
        /// chooser for deciding whose memory to load.
        #[arg(long)]
        list_agents: bool,
        /// Append a note to an agent's specialization profile (requires --agent), so
        /// an agent that gets better at a task keeps that sharpened memory.
        #[arg(long)]
        record: Option<String>,
    },
}
#[derive(Subcommand, Clone)]
enum Projects {
    /// Create a project. FERRYMAN_TOKEN must be the admin token when the server runs with --production.
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        token: String,
    },
    /// List projects (admin token when the server runs with --production).
    List,
    /// Delete a project and all of its jobs/events/artifacts (admin token in --production).
    Delete {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Clone)]
enum Communications {
    Send {
        #[arg(long)]
        project: String,
        #[arg(long)]
        sender: String,
        #[arg(long)]
        recipient: String,
        #[arg(long, default_value = "null")]
        payload: String,
        #[arg(long)]
        reply_required: bool,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long, default_value_t = 30)]
        acknowledgement_timeout_seconds: u64,
    },
    List {
        #[arg(long)]
        project: String,
    },
    Inbox {
        #[arg(long)]
        project: String,
        #[arg(long)]
        actor: String,
        /// Read only the local portable inbox without MEGA or Git synchronization.
        #[arg(long)]
        local_only: bool,
    },
    Claim {
        #[arg(long)]
        project: String,
        message: String,
        #[arg(long)]
        recipient: String,
    },
    Acknowledge {
        #[arg(long)]
        project: String,
        message: String,
        #[arg(long)]
        recipient: String,
    },
    Reconcile {
        #[arg(long)]
        project: String,
    },
    Status {
        #[arg(long)]
        project: String,
        /// Report filesystem/cached state without running MEGA or Git probes.
        #[arg(long)]
        local_only: bool,
    },
    MintActorToken {
        #[arg(long)]
        project: String,
        #[arg(long)]
        actor: String,
    },
    /// Inventory and convert local v1 messages into signed v2 envelopes.
    ///
    /// This works directly against the synced channel, not the server. It
    /// defaults to `--dry-run true`; pass `--dry-run false` after reviewing the
    /// classification to rewrite convertible v1 messages in place.
    Migrate {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The signing agent name. Defaults to this machine's name.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        dry_run: bool,
    },
    /// Unregister the hub mapping and actor tokens; portable/local files are preserved.
    Unregister {
        #[arg(long)]
        project: String,
    },
}

#[derive(Subcommand, Clone)]
enum Channel {
    /// Where the channel for this directory lives, and what state it is in.
    Status {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Write a message into the channel. No server, no token.
    Send {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who it is from. Defaults to this machine's name.
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: String,
        /// The message body. Plain text, or JSON if it starts with '{'.
        #[arg(long)]
        body: String,
        /// Say plainly whether an answer is expected, rather than leaving the
        /// receiver to infer it from the message type - inference is what caused a
        /// silent stall in this project's own history.
        #[arg(long)]
        reply_expected: bool,
    },
    /// Messages addressed to an agent.
    Inbox {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        agent: String,
        /// Include messages that have already been acknowledged.
        #[arg(long)]
        all: bool,
    },
    /// Announce this agent to the fleet so others can address it.
    Join {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Defaults to this machine's name, so two agents cannot collide by accident.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "worker")]
        role: String,
        /// Comma-separated, e.g. "messages.receive,code".
        #[arg(long, default_value = "messages.receive")]
        capabilities: String,
    },
    /// Who is taking part in this channel.
    Agents {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Issue work into the channel. Addressed to a machine, or open to anyone.
    Order {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is issuing it. Defaults to this machine's name. Give the name this
        /// agent joined under, or the order is signed by an identity the roster
        /// does not know and every reader reports it as UnknownSigner.
        #[arg(long)]
        agent: Option<String>,
        /// Task id, e.g. t-4f2a.
        #[arg(long)]
        id: String,
        /// The machine to do it. Omit for "whoever picks it up first".
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        task: String,
        /// Hold the result for review before the task counts as done.
        #[arg(long)]
        requires_review: bool,
        /// Require this key in the submitted result, e.g. --require output.
        /// Repeatable; results missing any of these are flagged as malformed.
        #[arg(long)]
        require: Vec<String>,
        /// Destructive/sensitive work: only the master may accept the result.
        #[arg(long)]
        requires_approval: bool,
        /// Order ids this order depends on; repeatable. It is not offered for
        /// work until each dependency is accepted or done.
        #[arg(long)]
        depends_on: Vec<String>,
    },
    /// Import external work - an issue tracker export, a script's output - into
    /// signed orders. Each ticket becomes a signed order with a ledger entry.
    Source {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is importing. Defaults to this machine's name.
        #[arg(long)]
        agent: Option<String>,
        /// A name for the source, e.g. "linear". Becomes part of each order id.
        #[arg(long)]
        name: String,
        /// A shell command that prints one JSON ticket per line to stdout:
        /// {"id": "...", "task": "...", "assigned_to": "..."} (the last is optional).
        #[arg(long)]
        command: String,
    },
    /// List the configured always-on sources (from sources.toml).
    Sources {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Re-poll the configured sources forever, importing anything new. This is
    /// the standalone "always-on" process; a running `ferry agent` already does
    /// the same on its own poll loop.
    Watch {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is importing. Defaults to this machine's name.
        #[arg(long)]
        agent: Option<String>,
        /// Seconds between polls when a source has no interval of its own.
        #[arg(long, default_value_t = 60)]
        interval: u64,
        /// Do one poll and exit, instead of looping.
        #[arg(long)]
        once: bool,
    },
    /// Manage the per-task git worktrees.
    Worktree {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(subcommand)]
        action: WorktreeAction,
    },
    /// Pause, steer or kill a running task from outside the loop.
    Interrupt {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is interrupting. Defaults to this machine's name.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        order: String,
        /// kill, pause or steer.
        #[arg(long)]
        action: String,
        /// Why; folded into the next prompt for a steer.
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Work this agent can pick up.
    Work {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        agent: Option<String>,
    },
    /// Stake a claim on an open order.
    Claim {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        agent: Option<String>,
        id: String,
    },
    /// Submit a result for an order.
    Submit {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        result: String,
        id: String,
    },
    /// Accept a result, or send it back with notes.
    Review {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is settling it. Defaults to this machine, not to a shared name: a
        /// verdict signed "orchestrator" on every machine cannot be told apart from
        /// any other machine's, which defeats the point of signing it.
        #[arg(long)]
        reviewer: Option<String>,
        /// Keep it. Without this, the work is sent back and --notes is required.
        #[arg(long)]
        accept: bool,
        #[arg(long)]
        notes: Option<String>,
        id: String,
    },
    /// Every task and where it has got to.
    Tasks {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// How each engine is doing: aggregate the learning database into per-engine
    /// totals, so the fleet knows which CLI wins on this project.
    Stats {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// List the team's shared skills, and which would load for a task.
    Skills {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Show which skills would match this task text.
        #[arg(long)]
        task: Option<String>,
    },
    /// Everything that has happened in this channel, oldest last.
    ///
    /// Orders, claims, results, reviews and messages, merged into one timeline with
    /// each artifact's signer. This used to list messages only, so a channel full of
    /// signed work printed nothing at all.
    Log {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Manage the trusted signers that may sign v2 portable messages.
    ///
    /// Works directly against the synced channel. `list` shows signers;
    /// `revoke` marks one revoked; `add` grants a new key. Rotation is `add`
    /// the new key, then `revoke` the old.
    Trust {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Choose or inspect this project's master.
    ///
    /// The master is the root of trust for a team: their signed declaration
    /// lives in a separate folder (`<project>-master-ferryman`) synced only to
    /// their own devices.
    Master {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(subcommand)]
        action: MasterAction,
    },
    /// Export a signed audit report of the attribution ledger.
    ///
    /// A standalone, verifiable record of who did what and when — signed by the
    /// exporter, each entry carrying its own verification status. Usable by a
    /// client or regulator without running Ferryman.
    Report {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is exporting. Defaults to this machine's name.
        #[arg(long)]
        agent: Option<String>,
        /// Emit JSON instead of a human-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Manage this project's Syncthing folder: choose which devices it syncs
    /// with, per project. Each project has its own folder, so one project can be
    /// shared with one person without sharing the rest.
    Syncthing {
        #[command(subcommand)]
        action: SyncthingAction,
    },
    /// Move any pre-Ferryman git-backed bridge files in this workspace into a
    /// `deprecated/` folder, out of the way of the channel. Preserves the old
    /// method rather than deleting it.
    Deprecate {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Mint or check short-lived, master-signed lease tokens for workers.
    Lease {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(subcommand)]
        action: LeaseAction,
    },
}

#[derive(Subcommand, Clone)]
enum SyncthingAction {
    /// Every device this Syncthing already trusts (the device ids to share with).
    Devices,
    /// This project's folder, and which devices it is currently shared with.
    Status {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Share this project's folder with the given device ids (adds to existing).
    /// A device id that Syncthing does not already trust is added first, so one
    /// project can be shared with a brand-new PC without sharing the rest.
    Share {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        with: Vec<String>,
        /// Name for a device being added for the first time.
        #[arg(long)]
        name: Option<String>,
    },
    /// Stop sharing this project's folder with the given device ids.
    Unshare {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        with: Vec<String>,
    },
    /// Register this project's folder with Syncthing (start syncing), shared
    /// with no one yet — share explicitly afterwards.
    On {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Remove this project's folder from Syncthing (stop syncing). The channel
    /// files stay in place and still work locally.
    Off {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Record whether a device is one of your own machines or a different
    /// person, so the share list stays auditable.
    Mark {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        with: String,
        /// self = one of your own machines; other = a different person.
        #[arg(long, value_parser = ["self", "other"])]
        owner: String,
    },
}

#[derive(Subcommand, Clone)]
enum Jobs {
    Submit {
        #[arg(long)]
        project: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        requires_approval: bool,
        /// Hold the result for review: it is not done until accepted or sent back.
        #[arg(long)]
        requires_review: bool,
        #[arg(long, default_value_t = 3)]
        max_attempts: u32,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Get {
        #[arg(long)]
        project: String,
        job: String,
    },
    Approve {
        #[arg(long)]
        project: String,
        job: String,
    },
    Reject {
        #[arg(long)]
        project: String,
        job: String,
    },
    Tail {
        #[arg(long)]
        project: String,
        job: String,
    },
    /// Finished work waiting on a reviewer.
    AwaitingReview {
        #[arg(long)]
        project: String,
    },
    /// Keep the result. Terminal.
    Accept {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "orchestrator")]
        reviewer: String,
        job: String,
    },
    /// Send the work back for another revision, saying what to change.
    RequestChanges {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "orchestrator")]
        reviewer: String,
        /// What needs to change. Required: a rejection without a reason is not actionable.
        #[arg(long)]
        notes: String,
        job: String,
    },
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
}

/// Subcommands for [`Channel::Trust`].
#[derive(Subcommand, Clone)]
enum TrustAction {
    /// List trusted signers and their grants.
    List,
    /// Revoke a signer by `sha256:<hex>` signer id.
    Revoke {
        #[arg(long)]
        signer: String,
    },
    /// Grant a new signer key (hex Ed25519 public key).
    Add {
        #[arg(long)]
        public_key: String,
        /// Comma-separated project ids; empty means any project.
        #[arg(long)]
        projects: Option<String>,
        /// Comma-separated roles; empty means any role.
        #[arg(long)]
        roles: Option<String>,
        /// Comma-separated capabilities; empty means none required.
        #[arg(long)]
        capabilities: Option<String>,
    },
}

/// Subcommands for [`Channel::Worktree`].
#[derive(Subcommand, Clone)]
enum WorktreeAction {
    /// Show the branch name an (order, agent) pair would use.
    Branch {
        #[arg(long)]
        order: String,
        #[arg(long)]
        agent: String,
    },
    /// Create the worktree for an (order, agent) pair.
    Create {
        #[arg(long)]
        order: String,
        #[arg(long)]
        agent: String,
    },
    /// Remove the worktree (and its branch) for an (order, agent) pair.
    Cleanup {
        #[arg(long)]
        order: String,
        #[arg(long)]
        agent: String,
    },
}

/// Subcommands for [`Channel::Master`].
#[derive(Subcommand, Clone)]
enum MasterAction {
    /// Become this project's master: write the signed master declaration.
    Init {
        /// The master's name. Defaults to this machine's name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Show this project's master declaration, verifying its signature.
    Status,
    /// Disclaim the master role to another user. Signed by the current master.
    Transfer {
        /// The name of the new master.
        name: String,
    },
    /// Grant roles/capabilities to a member. Signed by the master.
    Grant {
        /// The member's name.
        name: String,
        /// The member's hex Ed25519 public key.
        #[arg(long)]
        public_key: String,
        /// Comma-separated roles; empty means any role.
        #[arg(long)]
        roles: Option<String>,
        /// Comma-separated capabilities; empty means none required.
        #[arg(long)]
        capabilities: Option<String>,
    },
    /// List the master's grants and whether each verifies.
    Grants,
}
/// Subcommands for [`Channel::Lease`].
#[derive(Subcommand, Clone)]
enum LeaseAction {
    /// Mint a short-lived, scoped lease for a worker. Signed by the master.
    Mint {
        /// The worker (agent) the lease is issued to.
        to: String,
        /// Comma-separated capabilities the lease confers. Empty means the
        /// worker's membership roles decide.
        #[arg(long)]
        scope: Option<String>,
        /// Lease lifetime in minutes.
        #[arg(long, default_value_t = 60)]
        minutes: i64,
    },
    /// Verify a worker's lease and report its remaining lifetime.
    Verify {
        /// The worker whose lease to check.
        to: String,
    },
}
#[derive(Subcommand, Clone)]
/// The agentic loop. Every one of these runs unattended and needs no terminal.
enum Agent {
    /// Pick up work, run the configured agent CLI on it, submit a signed result.
    Run {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Do one pass and exit, instead of looping. For cron, or for a caller that
        /// wants to own the scheduling.
        #[arg(long)]
        once: bool,
        /// Say what would be claimed, and as whom, without claiming anything.
        ///
        /// Resolves exactly what a real pass resolves - the agent name, the memory gate,
        /// each task and what would happen to it - and then stops.
        #[arg(long)]
        dry_run: bool,
    },
    /// Judge results that are waiting, as far as the config lets you.
    Review {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        once: bool,
    },
    /// What a human has been asked to settle, and whether each is properly signed.
    Pending {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Clone)]
enum License {
    /// Seats, computers and phones on this channel, and whether that is within the
    /// free tier.
    Status {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Register this machine, or change the address it is registered under.
    Register {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, env = "FERRYMAN_EMAIL")]
        email: String,
        /// computer (runs agents) or mobile (approves only).
        #[arg(long, default_value = "computer")]
        device: String,
    },
    /// Report the counts to the Licensor.
    Checkin {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Print the exact payload and send nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Clone)]
enum Workers {
    Register {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "mock")]
        capability: String,
    },
}
#[derive(Subcommand, Clone)]
enum Agents {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        description: String,
        #[arg(long, default_value = "temporal")]
        persistence: String,
    },
    List {
        #[arg(long)]
        project: String,
    },
}
#[derive(Subcommand, Clone)]
enum Memory {
    Add {
        #[arg(long)]
        project: String,
        #[arg(long)]
        category: String,
        #[arg(long)]
        content: String,
        #[arg(long, default_value = "operator")]
        source: String,
    },
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        limit: Option<u32>,
    },
}
#[derive(Subcommand, Clone)]
enum Artifacts {
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        job: String,
    },
    Download {
        #[arg(long)]
        project: String,
        artifact: String,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand, Clone)]
enum Consents {
    List {
        #[arg(long)]
        project: String,
    },
    Approve {
        #[arg(long)]
        project: String,
        consent: String,
        #[arg(long, default_value = "local-operator")]
        approver: String,
    },
    Reject {
        #[arg(long)]
        project: String,
        consent: String,
        #[arg(long, default_value = "local-operator")]
        approver: String,
    },
}
#[derive(Subcommand, Clone)]
enum Continuity {
    Pack {
        #[arg(long)]
        project: String,
    },
    Recover {
        #[arg(long)]
        project: String,
        pack_hash: String,
    },
    Drill {
        #[arg(long)]
        project: String,
    },
    /// Create the consent that authorizes one exact encrypted pack to private Git.
    GitConsent {
        #[arg(long)]
        project: String,
        pack_hash: String,
    },
    /// Deliver one consent-approved encrypted pack to the configured private Git branch.
    DeliverGit {
        #[arg(long)]
        project: String,
        pack_hash: String,
        #[arg(long)]
        consent: String,
    },
    Timeline {
        #[arg(long)]
        project: String,
        #[arg(long)]
        after: Option<i64>,
        #[arg(long)]
        category: Option<String>,
    },
    Simulate {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "{}")]
        policy: String,
        #[arg(long, default_value_t = 0)]
        artifact_bytes: u64,
        #[arg(long)]
        outbound: bool,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    // OTLP export, when an endpoint is configured: spans from the agent loop go
    // to a collector so a fleet can be observed from one place. No-op otherwise.
    ferryman_ops::telemetry::init();
    let cli = Cli::parse();
    match cli.command.clone() {
        Command::Init { path } => {
            std::fs::write(
                &path,
                "# Keep tokens in FERRYMAN_TOKEN, not this file\nendpoint = \"http://127.0.0.1:8787\"\nproject = \"demo\"\n",
            )?;
            println!("wrote {}", path.display());
        }
        Command::Enable {
            workspace,
            project,
            agent: agent_name,
            role,
            email,
            command,
            review,
            no_syncthing,
            share_with,
            master,
            sandbox,
            worktree,
            json: as_json,
            dashboard,
            dashboard_operator,
        } => {
            let outcome = enable::perform(enable::Request {
                workspace,
                project,
                agent: agent_name,
                role,
                email: email.clone(),
                command,
                review,
                no_syncthing,
                share_with,
                as_json,
                master,
                sandbox,
                worktree,
            })?;
            // A human at a terminal types the operator password here, privately.
            // An agent never sees or supplies it: it is told to hand the human a
            // browser, where the operator identity is created out of the agent's
            // sight.
            let setup = resolve_dashboard_setup(dashboard, dashboard_operator, &email, as_json)?;
            let dashboard = match setup {
                Some(DashboardSetup::Create { name, password }) => {
                    let identity = ferryman_server::operators::create_operator_identity(
                        &outcome.route,
                        &name,
                        &password,
                    )?;
                    Some(DashboardOutcome::Created {
                        operator: identity.name().to_string(),
                        public_key: identity.public_key_hex(),
                    })
                }
                Some(DashboardSetup::DeferToBrowser) => Some(DashboardOutcome::Deferred),
                None => None,
            };
            if as_json {
                report_enable_json(&outcome, dashboard.as_ref())?;
            } else {
                report_enable_human(&outcome, dashboard.as_ref());
            }
        }
        Command::Pause { reason } => {
            let Some(path) = ferryman_ops::governor::pause_marker() else {
                bail!("this machine has no per-user directory, so a pause cannot be recorded")
            };
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let note = reason.unwrap_or_else(|| "paused by hand".to_string());
            std::fs::write(&path, &note).with_context(|| format!("write {}", path.display()))?;
            println!("paused: {note}");
            println!("  no new work will be claimed on this machine until 'ferry resume'");
            println!("  anything already running is unaffected");
        }
        Command::Resume => {
            let Some(path) = ferryman_ops::governor::pause_marker() else {
                bail!("this machine has no per-user directory, so there is no pause to lift")
            };
            match std::fs::remove_file(&path) {
                Ok(()) => println!("resumed; this machine will take work again"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    println!("not paused; nothing to do");
                }
                Err(error) => return Err(error).context(format!("remove {}", path.display())),
            }
        }
        Command::Log { lines } => {
            let entries = ferryman_ops::runlog::tail(lines);
            if entries.is_empty() {
                println!("this machine's worker has not recorded anything yet");
                match ferryman_ops::runlog::path() {
                    Some(path) => println!("  it would be written to {}", path.display()),
                    None => println!("  and there is no per-user directory to write it to"),
                }
            } else {
                for entry in entries {
                    println!("{entry}");
                }
            }
        }
        Command::Agent { command } => agent_command(command).await?,
        Command::Bench {
            workspace,
            timeout_secs,
        } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = ferryman_channel::route_for(&start)?;
            let bench = ferryman_ops::eval::load_bench(&route.attachment)?;
            if bench.engines.is_empty() || bench.tasks.is_empty() {
                bail!("bench.json needs at least one engine and one task");
            }
            // The benchmark is single-shot; the timeout flag is accepted so a caller
            // can tune it, and run_bench uses its own per-run bound.
            let _ = timeout_secs;
            let results = ferryman_ops::eval::run_bench(&route, &bench, &route.workspace).await?;
            let mut by_engine: std::collections::BTreeMap<&str, (usize, usize)> =
                std::collections::BTreeMap::new();
            for result in &results {
                let entry = by_engine.entry(&result.engine).or_insert((0, 0));
                entry.0 += 1;
                if result.accepted {
                    entry.1 += 1;
                }
                println!(
                    "  {:<12} {:<12} {}  {}",
                    result.engine,
                    result.task,
                    if result.accepted { "PASS" } else { "FAIL" },
                    result.note
                );
            }
            println!();
            for (engine, (total, passed)) in &by_engine {
                let rate = if *total == 0 {
                    0.0
                } else {
                    *passed as f64 / *total as f64
                };
                println!("  {engine:<12} {passed}/{total} ({:.0}%)", rate * 100.0);
            }
        }
        Command::License { command } => license_command(command).await?,
        Command::Jobs { command } => jobs(&cli, command).await?,
        Command::Projects { command } => match command {
            Projects::Create { id, name, token } => {
                call(
                    &cli,
                    "POST",
                    "/v1/projects".to_string(),
                    Some(json!({"id":id,"name":name,"token":token})),
                )
                .await?
            }
            Projects::List => call(&cli, "GET", "/v1/projects".to_string(), None).await?,
            Projects::Delete { id } => {
                call(&cli, "DELETE", format!("/v1/projects/{id}"), None).await?
            }
        },
        Command::Channel { command } => channel(command)?,
        Command::Dashboard {
            workspace,
            port,
            timeout,
            read_only,
        } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = std::sync::Arc::new(ferryman_channel::route_for(&start)?);
            // Operators sign in over the web with a password-sealed identity; the
            // signing key is only unlocked in memory for the lifetime of a session.
            let operators = ferryman_server::operators::OperatorStore::new(&route.attachment);
            let state = ferryman_server::dashboard::DashboardState::new(
                route,
                operators,
                read_only,
                std::time::Duration::from_secs(timeout.saturating_mul(60)),
            );
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            println!(
                "dashboard → http://{addr}  (project {})",
                state.route.project_id
            );
            if read_only {
                println!("read-only; ctrl-c to stop");
            } else {
                println!("sign in (or create an operator identity) in the browser; ctrl-c to stop");
            }
            ferryman_server::dashboard::serve(state, addr).await?;
        }
        Command::Loadmem {
            workspace,
            project,
            agent,
            list_agents,
            record,
        } => loadmem(workspace, project, agent, list_agents, record)?,
        Command::Communications { command } => match command {
            Communications::Send {
                project,
                sender,
                recipient,
                payload,
                reply_required,
                idempotency_key,
                acknowledgement_timeout_seconds,
            } => {
                let payload: Value =
                    serde_json::from_str(&payload).context("payload must be valid JSON")?;
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/communications/messages"),
                    Some(json!({
                        "sender":sender,
                        "recipient":recipient,
                        "payload_reference":"inline",
                        "payload":payload,
                        "reply_required":reply_required,
                        "idempotency_key":idempotency_key,
                        "acknowledgement_timeout_seconds":acknowledgement_timeout_seconds
                    })),
                )
                .await?
            }
            Communications::List { project } => {
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/communications/messages"),
                    None,
                )
                .await?
            }
            Communications::Inbox {
                project,
                actor,
                local_only,
            } => {
                let query = if local_only { "?synchronize=false" } else { "" };
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/communications/actors/{actor}/messages{query}"),
                    None,
                )
                .await?
            }
            Communications::Claim {
                project,
                message,
                recipient,
            } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/communications/messages/{message}/claim"),
                    Some(json!({"recipient":recipient})),
                )
                .await?
            }
            Communications::Acknowledge {
                project,
                message,
                recipient,
            } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/communications/messages/{message}/acknowledge"),
                    Some(json!({"recipient":recipient})),
                )
                .await?
            }
            Communications::Reconcile { project } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/communications/reconcile"),
                    None,
                )
                .await?
            }
            Communications::Status {
                project,
                local_only,
            } => {
                let query = if local_only {
                    "?probe_external=false"
                } else {
                    ""
                };
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/communications/status{query}"),
                    None,
                )
                .await?
            }
            Communications::MintActorToken { project, actor } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/communications/actors/{actor}/token"),
                    None,
                )
                .await?
            }
            Communications::Migrate {
                workspace,
                agent,
                dry_run,
            } => {
                let start = match workspace {
                    Some(path) => path,
                    None => std::env::current_dir().context("resolve current directory")?,
                };
                let route = ferryman_channel::route_for(&start)?;

                let entries = ferryman_channel::migration::inventory_v1(&route)?;
                let mut convertible = 0usize;
                for entry in &entries {
                    let message = entry.message();
                    match entry {
                        ferryman_channel::migration::MigrationEntry::Convertible { .. } => {
                            convertible += 1;
                            println!(
                                "convertible    {}  recipient={}",
                                message.id, message.recipient
                            )
                        }
                        ferryman_channel::migration::MigrationEntry::OperatorReview {
                            reason,
                            ..
                        } => println!(
                            "operator-review  {}  recipient={}  reason={reason}",
                            message.id, message.recipient
                        ),
                    }
                }
                println!(
                    "{} v1 message(s), {} convertible",
                    entries.len(),
                    convertible
                );

                if dry_run {
                    println!("dry-run: no files were written");
                    return Ok(());
                }
                if convertible == 0 {
                    println!("nothing to convert");
                    return Ok(());
                }

                let agent = ferryman_ops::identity::resolve(agent, &route.attachment)?;
                let identity =
                    ferryman_channel::AgentIdentity::load_or_create(&agent, &route.attachment)?;

                for entry in entries {
                    if let ferryman_channel::migration::MigrationEntry::Convertible { message } =
                        entry
                    {
                        let outcome = ferryman_channel::migration::convert_v1_to_v2_with_identity(
                            &route, &message, &identity, false,
                        )?;
                        println!(
                            "converted {}  old={}  new={}",
                            outcome.message_id, outcome.old_digest, outcome.new_digest
                        );
                    }
                }
            }
            Communications::Unregister { project } => {
                call(
                    &cli,
                    "DELETE",
                    format!("/v1/projects/{project}/communications"),
                    None,
                )
                .await?
            }
        },
        Command::Workers { command } => match command {
            Workers::Register {
                project,
                capability,
            } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/workers"),
                    Some(json!({"capabilities":[capability]})),
                )
                .await?
            }
        },
        Command::Agents { command } => {
            match command {
                Agents::Create {
                    project,
                    role,
                    description,
                    persistence,
                } => call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/agents"),
                    Some(json!({"role":role,"description":description,"persistence":persistence})),
                )
                .await?,
                Agents::List { project } => {
                    call(&cli, "GET", format!("/v1/projects/{project}/agents"), None).await?
                }
            }
        }
        Command::Memory { command } => match command {
            Memory::Add {
                project,
                category,
                content,
                source,
            } => {
                call_memory(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/memory"),
                    Some(json!({"category":category,"content":content,"source":source})),
                )
                .await?
            }
            Memory::List { project, limit } => {
                let suffix = limit
                    .map(|value| format!("?limit={value}"))
                    .unwrap_or_default();
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/memory{suffix}"),
                    None,
                )
                .await?
            }
        },
        Command::Artifacts { command } => match command {
            Artifacts::List { project, job } => {
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/jobs/{job}/artifacts"),
                    None,
                )
                .await?
            }
            Artifacts::Download {
                project,
                artifact,
                output,
            } => download_artifact(&cli, &project, &artifact, &output).await?,
        },
        Command::Consents { command } => match command {
            Consents::List { project } => {
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/consents"),
                    None,
                )
                .await?
            }
            Consents::Approve {
                project,
                consent,
                approver,
            } => {
                call_approver(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/consents/{consent}/approve"),
                    &approver,
                )
                .await?
            }
            Consents::Reject {
                project,
                consent,
                approver,
            } => {
                call_approver(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/consents/{consent}/reject"),
                    &approver,
                )
                .await?
            }
        },
        Command::Continuity { command } => match command {
            Continuity::Pack { project } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/continuity-packs"),
                    None,
                )
                .await?
            }
            Continuity::Recover { project, pack_hash } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/continuity-packs/{pack_hash}/recover"),
                    None,
                )
                .await?
            }
            Continuity::Drill { project } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/recovery-drill"),
                    None,
                )
                .await?
            }
            Continuity::GitConsent { project, pack_hash } => {
                call(
                    &cli,
                    "POST",
                    format!(
                        "/v1/projects/{project}/continuity-packs/{pack_hash}/delivery-consents"
                    ),
                    Some(json!({"target":"private_git"})),
                )
                .await?
            }
            Continuity::DeliverGit {
                project,
                pack_hash,
                consent,
            } => {
                call(
                    &cli,
                    "POST",
                    format!("/v1/projects/{project}/continuity-packs/{pack_hash}/deliver"),
                    Some(json!({"consent_id":consent})),
                )
                .await?
            }
            Continuity::Timeline {
                project,
                after,
                category,
            } => {
                let mut query = Vec::new();
                if let Some(after) = after {
                    query.push(format!("after={after}"));
                }
                if let Some(category) = category {
                    query.push(format!("category={category}"));
                }
                let suffix = if query.is_empty() {
                    String::new()
                } else {
                    format!("?{}", query.join("&"))
                };
                call(
                    &cli,
                    "GET",
                    format!("/v1/projects/{project}/timeline{suffix}"),
                    None,
                )
                .await?
            }
            Continuity::Simulate {
                project,
                policy,
                artifact_bytes,
                outbound,
            } => {
                let policy: Value =
                    serde_json::from_str(&policy).context("--policy must be JSON")?;
                call(&cli, "POST", format!("/v1/projects/{project}/policy/simulate"), Some(json!({"policy":policy,"artifact_bytes":artifact_bytes,"outbound":outbound}))).await?
            }
        },
    };
    Ok(())
}

/// The machine-readable half of `ferry enable`.
///
/// This lives in the binary rather than in `ferryman-ops` because it is a *presentation*
/// of the outcome, and the library has other callers - a tray application wants the
/// `Outcome` struct, not a string it has to parse back.
/// Resolve whether to create a dashboard operator during `ferry enable`.
///
/// What an interactive `enable` should do about the dashboard operator, or the
/// instruction an agent-driven `enable` should pass on to the human.
enum DashboardSetup {
    /// The human is at the terminal and has just typed their password privately.
    Create { name: String, password: String },
    /// An agent is driving: the human must create the operator in the browser,
    /// out of the agent's sight.
    DeferToBrowser,
}

/// The result of the dashboard setup, for reporting.
enum DashboardOutcome {
    Created {
        operator: String,
        public_key: String,
    },
    Deferred,
}

/// Resolve whether to create a dashboard operator during `ferry enable`.
///
/// A human at a terminal is asked and types the password privately (never
/// echoed). An agent (`--json`, or piped stdin) never sees or supplies the
/// password: it is told to hand the human a browser instead.
fn resolve_dashboard_setup(
    dashboard: bool,
    operator: Option<String>,
    email: &str,
    as_json: bool,
) -> Result<Option<DashboardSetup>> {
    use std::io::{IsTerminal, Write};
    let interactive = !as_json && std::io::stdin().is_terminal();

    if !dashboard {
        if !interactive {
            return Ok(None);
        }
        print!("Set up the web dashboard (approve work from a browser)? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Ok(None);
        }
    }

    // An agent cannot type the operator's password here, and must not see it:
    // the human creates the operator in the browser.
    if !interactive {
        return Ok(Some(DashboardSetup::DeferToBrowser));
    }

    let name = match operator {
        Some(name) => name,
        None => {
            let default =
                ferryman_ops::identity::slug(email.split('@').next().unwrap_or("operator"));
            let default = if default.is_empty() {
                "operator".to_string()
            } else {
                default
            };
            print!("dashboard operator name [{default}]: ");
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let input = answer.trim().to_string();
            if input.is_empty() { default } else { input }
        }
    };

    let first = rpassword::prompt_password("dashboard password: ")?;
    let second = rpassword::prompt_password("repeat dashboard password: ")?;
    if first != second {
        bail!("dashboard passwords did not match");
    }

    Ok(Some(DashboardSetup::Create {
        name,
        password: first,
    }))
}

fn report_enable_json(
    outcome: &enable::Outcome,
    dashboard: Option<&DashboardOutcome>,
) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "enabled": true,
            "project": outcome.project,
            "agent": outcome.agent,
            "workspace": outcome.workspace.display().to_string(),
            "channel": outcome.route.communications.display().to_string(),
            "syncthing": outcome.syncthing,
            "agent_command": outcome.config.command,
            "review": outcome.config.review.as_str(),
            "public_key": outcome.public_key,
            "already_configured": outcome.steps.iter().all(|s| !s.created),
            "dashboard": dashboard.map(|d| match d {
                DashboardOutcome::Created { operator, public_key } => json!({
                    "operator": operator,
                    "public_key": public_key,
                    "then_run": ["ferry dashboard"],
                }),
                DashboardOutcome::Deferred => json!({
                    "create_in_browser": true,
                    "note": "hand the human a browser; they create their operator there, out of this agent's sight",
                    "then_run": ["ferry dashboard"],
                }),
            }),
            "license": {
                "seats": outcome.counted.seats,
                "computers": outcome.counted.computers,
                "mobile_devices": outcome.counted.mobile_devices,
                "agents": "unlimited",
                "over_limit": outcome.counted.over_limit(),
                "exceeded": outcome.counted.exceeded(),
            },
            "files": outcome.steps.iter().map(|s| json!({
                "what": s.what,
                "path": s.path.display().to_string(),
                "created": s.created,
            })).collect::<Vec<_>>(),
            "next": {
                "share_this_folder": outcome.route.communications.display().to_string(),
                "with_folder_id": format!("{}-ferryman", outcome.project),
                "then_run": ["ferry agent run", "ferry agent review"],
            },
        }))?
    );
    Ok(())
}

/// The same facts, for a person.
fn report_enable_human(outcome: &enable::Outcome, dashboard: Option<&DashboardOutcome>) {
    println!("ferryman enabled for '{}'", outcome.project);
    for step in &outcome.steps {
        println!(
            "  {:<16} {}  {}",
            step.what,
            if step.created { "created" } else { "present" },
            step.path.display()
        );
    }
    println!();
    println!("  agent      {}", outcome.agent);
    println!("  runs       {}", outcome.config.command);
    println!("  review     {}", outcome.config.review.as_str());
    println!("  public key {}", outcome.public_key);
    match dashboard {
        Some(DashboardOutcome::Created { operator, .. }) => {
            println!("  dashboard  operator '{operator}' created");
            println!("             run `ferry dashboard` and sign in as {operator}");
        }
        Some(DashboardOutcome::Deferred) => {
            println!("  dashboard  run `ferry dashboard` and create the operator in the browser");
        }
        None => {}
    }
    println!();
    match &outcome.syncthing {
        Some(setup) if setup.available => {
            println!("  syncthing  folder '{}' registered", setup.folder_id);
            if setup.shared_with.is_empty() {
                println!("             no other devices paired yet");
            } else {
                for peer in &setup.shared_with {
                    println!("             shared with {}", peer.name);
                }
            }
            if let Some(id) = &setup.device_id {
                println!("             this device: {id}");
            }
        }
        Some(setup) => println!("  syncthing  not wired: {}", setup.note),
        None => println!("  syncthing  skipped (--no-syncthing)"),
    }
    println!();
    println!("Then, on each machine:");
    println!("  ferry agent run        # does work");
    println!("  ferry agent review     # judges results");
    if outcome.counted.over_limit() {
        eprint!(
            "{}",
            ferryman_channel::licensing::over_limit_notice(&outcome.counted)
        );
    }
}

/// How an artifact's signature reads in a log line.
///
/// An unsigned artifact is not an error - older peers wrote them - but a log that does
/// not distinguish them is a log that quietly implies provenance it cannot show.
fn signed_suffix(signed_by: Option<&str>) -> String {
    match signed_by {
        Some(who) => format!("  [signed {who}]"),
        None => "  [unsigned]".to_string(),
    }
}

async fn jobs(cli: &Cli, command: Jobs) -> Result<()> {
    match command {
        Jobs::Submit {
            project,
            input,
            requires_approval,
            requires_review,
            max_attempts,
            idempotency_key,
        } => {
            let input: Value = serde_json::from_str(&input).context("--input must be JSON")?;
            call(cli,"POST",format!("/v1/projects/{project}/jobs"),Some(json!({"input":input,"requires_approval":requires_approval,"requires_review":requires_review,"max_attempts":max_attempts,"idempotency_key":idempotency_key}))).await?
        }
        Jobs::Get { project, job } => {
            call(
                cli,
                "GET",
                format!("/v1/projects/{project}/jobs/{job}"),
                None,
            )
            .await?
        }
        Jobs::AwaitingReview { project } => {
            call(
                cli,
                "GET",
                format!("/v1/projects/{project}/jobs/awaiting-review"),
                None,
            )
            .await?
        }
        Jobs::Accept {
            project,
            reviewer,
            job,
        } => {
            call(
                cli,
                "POST",
                format!("/v1/projects/{project}/jobs/{job}/accept"),
                Some(serde_json::json!({ "reviewer": reviewer })),
            )
            .await?
        }
        Jobs::RequestChanges {
            project,
            reviewer,
            notes,
            job,
        } => {
            call(
                cli,
                "POST",
                format!("/v1/projects/{project}/jobs/{job}/request-changes"),
                Some(serde_json::json!({ "reviewer": reviewer, "notes": notes })),
            )
            .await?
        }
        Jobs::Approve { project, job } => {
            call(
                cli,
                "POST",
                format!("/v1/projects/{project}/jobs/{job}/approve"),
                None,
            )
            .await?
        }
        Jobs::Reject { project, job } => {
            call(
                cli,
                "POST",
                format!("/v1/projects/{project}/jobs/{job}/cancel"),
                None,
            )
            .await?
        }
        Jobs::List {
            project,
            status,
            limit,
            cursor,
        } => {
            let mut query = Vec::new();
            if let Some(status) = status {
                query.push(format!("status={status}"));
            }
            if let Some(limit) = limit {
                query.push(format!("limit={limit}"));
            }
            if let Some(cursor) = cursor {
                query.push(format!("cursor={cursor}"));
            }
            let suffix = if query.is_empty() {
                String::new()
            } else {
                format!("?{}", query.join("&"))
            };
            call(
                cli,
                "GET",
                format!("/v1/projects/{project}/jobs{suffix}"),
                None,
            )
            .await?
        }
        Jobs::Tail { project, job } => tail_events(cli, &project, &job).await?,
    };
    Ok(())
}
async fn tail_events(cli: &Cli, project: &str, job: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/projects/{project}/jobs/{job}/events",
            cli.endpoint
        ))
        .bearer_auth(server_token(cli)?)
        .send()
        .await?
        .error_for_status()?;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        print!("{}", String::from_utf8_lossy(&chunk?));
    }
    Ok(())
}
async fn download_artifact(
    cli: &Cli,
    project: &str,
    artifact: &str,
    output: &PathBuf,
) -> Result<()> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/projects/{project}/artifacts/{artifact}/content",
            cli.endpoint
        ))
        .bearer_auth(server_token(cli)?)
        .send()
        .await?
        .error_for_status()?;
    let bytes = response.bytes().await?;
    std::fs::write(output, bytes)?;
    println!("wrote {}", output.display());
    Ok(())
}
/// The token for a server call, with an error that says what to do rather than a panic.
fn server_token(cli: &Cli) -> Result<&str> {
    cli.token.as_deref().filter(|t| !t.is_empty()).context(
        "this command talks to a Ferryman server, which needs --token or FERRYMAN_TOKEN. \
         The `ferry channel` commands need no server and no token.",
    )
}

async fn call(cli: &Cli, method: &str, path: String, body: Option<Value>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client
        .request(method.parse()?, format!("{}{}", cli.endpoint, path))
        .bearer_auth(server_token(cli)?);
    if let Some(body) = body {
        request = request.json(&body)
    };
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("bridge returned {status}: {text}")
    };
    println!("{text}");
    Ok(())
}
async fn call_memory(cli: &Cli, method: &str, path: String, body: Option<Value>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client
        .request(method.parse()?, format!("{}{}", cli.endpoint, path))
        .bearer_auth(server_token(cli)?);
    if let Some(token) = &cli.memory_token {
        request = request.header("x-ferryman-memory-token", token);
    };
    if let Some(body) = body {
        request = request.json(&body)
    };
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("bridge returned {status}: {text}")
    };
    println!("{text}");
    Ok(())
}
async fn call_approver(cli: &Cli, method: &str, path: String, approver: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .request(method.parse()?, format!("{}{}", cli.endpoint, path))
        .bearer_auth(server_token(cli)?)
        .header("x-ferryman-approver", approver)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("bridge returned {status}: {text}")
    };
    println!("{text}");
    Ok(())
}

/// Channel commands, all of which work with nothing running.
///
/// Every one of these reads or writes the synced folder directly. There is no server to
/// start, no port to open and no token to mint: locating the channel is a walk up the
/// directory tree, and delivering a message is writing a file that Syncthing then
/// carries. The server offers the same operations over HTTP for callers that want them,
/// but it was never doing anything a local process could not do for itself.
/// Licence accounting.
async fn license_command(command: License) -> Result<()> {
    let route_for = |workspace: Option<PathBuf>| -> Result<ferryman_channel::ProjectRoute> {
        let start = match workspace {
            Some(path) => path,
            None => std::env::current_dir().context("read the current directory")?,
        };
        ferryman_channel::route_for(&start)
    };
    match command {
        License::Status { workspace, json } => license::status(&route_for(workspace)?, json)?,
        License::Register {
            workspace,
            email,
            device,
        } => license::register(
            &route_for(workspace)?,
            &email,
            ferryman_channel::licensing::DeviceKind::parse(&device)?,
        )?,
        License::Checkin { workspace, dry_run } => {
            license::check_in(&route_for(workspace)?, dry_run).await?
        }
    }
    Ok(())
}

/// The agentic loop.
///
/// A pass that fails does not stop the loop: an agent CLI that is briefly missing, or a
/// single task whose reply cannot be parsed, must not take the whole machine off the
/// fleet. The failure is printed and the next pass tries again.
/// What the worker loops report through: the terminal, and this machine's run log.
///
/// The loops themselves did not change to gain a log - deciding where their output goes
/// is the caller's job, which is what the `Progress` trait was separated out for.
fn worker_progress() -> ferryman_ops::runlog::Logged<ferryman_ops::Stdout> {
    ferryman_ops::runlog::Logged {
        inner: ferryman_ops::Stdout,
    }
}

async fn agent_command(command: Agent) -> Result<()> {
    let route_for = |workspace: Option<PathBuf>| -> Result<ferryman_channel::ProjectRoute> {
        let start = match workspace {
            Some(path) => path,
            None => std::env::current_dir().context("read the current directory")?,
        };
        ferryman_channel::route_for(&start)
    };
    match command {
        Agent::Run {
            workspace,
            once,
            dry_run,
        } => {
            let route = route_for(workspace)?;
            let config = agent::AgentConfig::load(&route.attachment)?;
            if dry_run {
                let plan = agent::plan(&route, &config)?;
                println!("would run as '{}' on {}", plan.agent, route.project_id);
                println!("  command   {}", config.command);
                if let Some(note) = ferryman_ops::governor::paused() {
                    println!("  paused    {note}");
                }
                match ferryman_ops::governor::presence() {
                    ferryman_ops::governor::Presence::Active(idle) => println!(
                        "  presence  last input {}s ago (pauses under {}s)",
                        idle.as_secs(),
                        config.idle_after.as_secs()
                    ),
                    ferryman_ops::governor::Presence::Unknown => {
                        println!("  presence  no desktop session; nobody to wait for");
                    }
                }
                match &plan.gate {
                    ferryman_ops::governor::Decision::Go => {
                        println!("  memory    enough free to start");
                    }
                    ferryman_ops::governor::Decision::Wait(reason) => {
                        println!("  memory    would hold off: {reason}");
                    }
                }
                if plan.would_do.is_empty() {
                    println!("  nothing to do right now");
                } else {
                    for (id, what) in &plan.would_do {
                        println!("  {id}  {what}");
                    }
                }
                println!("nothing was claimed, written or sent");
                return Ok(());
            }
            // Recorded, not only printed: a worker that started and a worker that
            // failed on every pass look the same in an empty log, and "why did nothing
            // happen last night" is the question this has to be able to answer.
            let report = worker_progress();
            report.info(&format!(
                "worker '{}' started on {}, running '{}'",
                config.agent, route.project_id, config.command
            ));
            // Optional settings are announced because agent.toml ignores keys it does
            // not recognise - which is what lets one machine run a newer Ferryman than
            // another without either config breaking, and is worth keeping. The cost is
            // that a misspelled key does nothing and says nothing. Printing what is
            // actually in force turns that into something visible on the first line:
            // set preamble_file, see no preamble line, check your spelling.
            if let Some(preamble) = &config.preamble {
                report.info(&format!(
                    "  preamble  {} bytes at the front of every prompt, from {}",
                    preamble.len(),
                    config.preamble_file.as_deref().unwrap_or("?")
                ));
            }
            if let Some(window) = &config.claim_window {
                report.info(&format!("  hours     claims work {}", window.describe()));
            }
            loop {
                match agent::work_once(&route, &config, &report).await {
                    Ok(0) => {}
                    Ok(count) => report.info(&format!("did {count} task(s)")),
                    Err(error) => report.warn(&format!("pass failed, will retry: {error:#}")),
                }
                if once {
                    break;
                }
                tokio::time::sleep(config.poll).await;
            }
        }
        Agent::Review { workspace, once } => {
            let route = route_for(workspace)?;
            let config = agent::AgentConfig::load(&route.attachment)?;
            let report = worker_progress();
            report.info(&format!(
                "reviewer '{}' started on {}, authority '{}'",
                config.agent,
                route.project_id,
                config.review.as_str()
            ));
            loop {
                match agent::review_once(&route, &config, &report).await {
                    Ok(0) => {}
                    Ok(count) => report.info(&format!("judged {count} result(s)")),
                    Err(error) => report.warn(&format!("pass failed, will retry: {error:#}")),
                }
                if once {
                    break;
                }
                tokio::time::sleep(config.poll).await;
            }
        }
        Agent::Pending {
            workspace,
            json: as_json,
        } => {
            let route = route_for(workspace)?;
            let waiting = agent::pending(&route)?;
            if as_json {
                let rows: Vec<Value> = waiting
                    .iter()
                    .map(|(check, r)| json!({ "signature": check, "recommendation": r }))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if waiting.is_empty() {
                println!("nothing waiting on a human");
            } else {
                for (check, r) in &waiting {
                    println!(
                        "  {} r{}  recommends {}  [{check}]",
                        r.order_id,
                        r.revision,
                        if r.accept { "accept" } else { "changes" }
                    );
                    println!("      {}", r.reasoning);
                }
                println!("settle with: ferry channel review --accept <id>   (or --notes \"...\")");
            }
        }
    }
    Ok(())
}

/// The core memory-bank files, in the order the memory bank's own README
/// prescribes. Reference files follow, alphabetically.
const MEMORY_BANK_ORDER: &[&str] = &[
    "projectbrief.md",
    "productContext.md",
    "systemPatterns.md",
    "techContext.md",
    "activeContext.md",
    "progress.md",
];

/// `ferry loadmem`: print the project's persistent memory so an agent that lost
/// its context (or a human) can reload it in one command.
///
/// Deliberately forgiving: it works from the checkout, the channel folder, or
/// anywhere the memory bank is reachable. No channel is required — the memory
/// bank is the recovery record, and a machine that just failed is exactly the
/// machine that must be able to read it.
fn loadmem(
    workspace: Option<PathBuf>,
    project: Option<String>,
    agent: Option<String>,
    list_agents: bool,
    record: Option<String>,
) -> Result<()> {
    let start = match workspace {
        Some(path) => path,
        None => std::env::current_dir().context("read the current directory")?,
    };
    // The route is nice to have (channel path, canonical project id) but not
    // required: memory must be readable even when the attachment is gone.
    let route = ferryman_channel::route_for(&start).ok();
    let slug = project
        .or_else(|| route.as_ref().map(|route| route.project_id.clone()))
        .unwrap_or_else(|| slug_of(&start));

    let bank = find_memory_bank(&start, route.as_ref());
    let log = find_durable_log(&start, &slug, route.as_ref());

    // Refresh the derived roster so anyone reading roster.md sees the current
    // profiles. Best-effort: it is a view, not the source of truth.
    if let Some(bank_dir) = bank.as_deref() {
        let _ = ferryman_channel::memory::regenerate_roster(bank_dir);
    }

    // Record mode: append a note to one agent's specialization profile, then fall
    // through so the operator sees the updated profile.
    if let Some(note) = record {
        let name = agent
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--record needs --agent <name>"))?;
        let Some(bank_dir) = bank.as_deref() else {
            bail!("no memory bank found to record into for '{slug}'");
        };
        record_agent_profile(bank_dir, name, &note)?;
        println!(
            "recorded into {}",
            ferryman_channel::memory::agent_profile_path(bank_dir, name).display()
        );
        println!();
    }

    // List mode: just the chooser, no shared memory.
    if list_agents {
        if !print_agent_list(bank.as_deref()) {
            println!("no agent profiles yet. Create one with:");
            println!("  ferry loadmem --agent <name> --record \"<what this agent is good at>\"");
        }
        return Ok(());
    }

    println!("project   {slug}");
    if let Some(path) = &bank {
        println!("memory    {}", path.display());
    }
    if let Some(path) = &log {
        println!("log       {}", path.display());
    }
    println!();

    let mut printed = false;

    if let Some(dir) = bank.as_deref() {
        let readme = dir.join("README.md");
        if readme.is_file() {
            print_memory_file("## Memory review order (read this first)", &readme)?;
            printed = true;
        }
        for name in MEMORY_BANK_ORDER {
            let path = dir.join(name);
            if path.is_file() {
                print_memory_file(&format!("## {name}"), &path)?;
                printed = true;
            }
        }
        let mut others = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy().to_string();
                if name.ends_with(".md")
                    && name != "README.md"
                    && !MEMORY_BANK_ORDER.contains(&name.as_str())
                {
                    others.push(name);
                }
            }
        }
        others.sort();
        for name in others {
            print_memory_file(&format!("## {name}"), &dir.join(&name))?;
            printed = true;
        }
    }

    if let Some(path) = log {
        print_memory_file("## Durable memory (append-only log)", &path)?;
        printed = true;
    }

    // The agent layer: load one agent's specialization, or list them all and ask
    // which one to load.
    match &agent {
        Some(name) => printed |= print_one_agent(bank.as_deref(), name),
        None => printed |= choose_agent(bank.as_deref()),
    }

    if !printed {
        bail!(
            "no memory found for '{slug}'. Expected a memory-bank/ directory, or a \
             MEMORY.md under ./memory/, ./ or FERRYMAN_MEMORY_FILE. Run \
             'ferryman-memory-init' (or 'ferryman-memory-record \"<note>\"') to create it"
        );
    }
    Ok(())
}

/// The project slug, derived the way the fleet protocol derives it: the
/// directory name, lowercased, non-alphanumerics collapsed to a dash.
fn slug_of(dir: &std::path::Path) -> String {
    let name = dir
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    ferryman_channel::memory::slugify(&name)
}

/// Locate the memory bank: the channel's synced copy first, then the local
/// checkout's, then an explicit override.
fn find_memory_bank(
    start: &std::path::Path,
    route: Option<&ferryman_channel::ProjectRoute>,
) -> Option<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if let Some(route) = route {
        candidates.push(route.communications.join("memory-bank"));
        candidates.push(route.attachment.join("memory-bank"));
    }
    candidates.push(start.join("memory-bank"));
    if let Ok(path) = std::env::var("FERREY_MEM_BANK") {
        candidates.push(std::path::PathBuf::from(path));
    }
    candidates.into_iter().find(|path| path.is_dir())
}

/// Locate the durable append-only log, from the most explicit location down.
fn find_durable_log(
    start: &std::path::Path,
    slug: &str,
    route: Option<&ferryman_channel::ProjectRoute>,
) -> Option<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("FERRYMAN_MEMORY_FILE") {
        candidates.push(std::path::PathBuf::from(path));
    }
    candidates.push(start.join("memory").join("MEMORY.md"));
    candidates.push(start.join("MEMORY.md"));
    if let Some(route) = route {
        candidates.push(route.workspace.join("memory").join("MEMORY.md"));
        candidates.push(route.workspace.join(slug).join("MEMORY.md"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn print_memory_file(heading: &str, path: &std::path::Path) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    println!("{heading}");
    println!();
    println!("{text}");
    println!();
    Ok(())
}

/// Append a dated note to one agent's specialization profile, creating the file
/// and its `agents/` directory on first use, then refresh the derived roster.
fn record_agent_profile(bank: &std::path::Path, agent: &str, note: &str) -> Result<()> {
    let path = ferryman_channel::memory::agent_profile_path(bank, agent);
    // The very first record becomes the one-line summary; later records append a
    // dated history line, so the summary stays readable in the roster.
    let fresh = std::fs::read_to_string(&path)
        .map(|text| text.trim().is_empty())
        .unwrap_or(true);
    let line = if fresh {
        note.to_string()
    } else {
        format!("- {} {note}", chrono::Utc::now().format("%Y-%m-%d"))
    };
    ferryman_channel::memory::append_agent_profile(bank, agent, &line)
        .with_context(|| format!("append to {}", path.display()))?;
    let _ = ferryman_channel::memory::regenerate_roster(bank);
    Ok(())
}

/// Print one agent's specialization profile. Returns true when a profile was
/// actually printed (as opposed to the "no profile yet" hint).
fn print_one_agent(bank: Option<&std::path::Path>, agent: &str) -> bool {
    let Some(bank) = bank else {
        return false;
    };
    match ferryman_channel::memory::load_agent_profile(bank, agent) {
        Some(profile) if !profile.trim().is_empty() => {
            println!("## Agent profile — {agent}");
            println!();
            println!("{}", profile.trim_end());
            println!();
            true
        }
        _ => {
            println!("## Agent profile — {agent}");
            println!();
            println!("no profile yet. Create one with:");
            println!("  ferry loadmem --agent {agent} --record \"<what this agent is good at>\"");
            println!();
            false
        }
    }
}

/// Print the chooser: every agent that has a profile, with a one-line summary.
/// Returns true when at least one profile exists.
fn print_agent_list(bank: Option<&std::path::Path>) -> bool {
    let Some(bank) = bank else {
        return false;
    };
    let profiles = ferryman_channel::memory::list_agent_profiles(bank);
    if profiles.is_empty() {
        return false;
    }
    println!("## Agents with memory (load one with --agent <name>)");
    println!();
    for (agent, summary) in &profiles {
        if summary.is_empty() {
            println!("  {agent}");
        } else {
            println!("  {agent:<16} {summary}");
        }
    }
    println!();
    true
}

/// The interactive chooser: list every agent that has memory, then — on a
/// terminal — ask which one to load. A piped or headless caller just gets the
/// list and no prompt. Returns true when at least one profile was listed.
fn choose_agent(bank: Option<&std::path::Path>) -> bool {
    let Some(bank) = bank else {
        return false;
    };
    let profiles = ferryman_channel::memory::list_agent_profiles(bank);
    if profiles.is_empty() {
        return false;
    }
    println!("## Agents with memory");
    println!();
    for (index, (agent, summary)) in profiles.iter().enumerate() {
        if summary.is_empty() {
            println!("  {}  {agent}", index + 1);
        } else {
            println!("  {}  {agent:<16} {summary}", index + 1);
        }
    }
    println!();

    // Only a terminal can answer; an agent reading this through a pipe just gets
    // the list above and picks its own profile with --agent <name>.
    if !std::io::stdin().is_terminal() {
        return true;
    }

    use std::io::Write;
    print!(
        "load which agent? [1-{}, 'all', or enter to skip]: ",
        profiles.len()
    );
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return true;
    }
    let line = line.trim();
    if line.is_empty() {
        return true;
    }
    if line.eq_ignore_ascii_case("all") {
        println!();
        for (agent, _) in &profiles {
            print_one_agent(Some(bank), agent);
        }
        return true;
    }
    let Ok(index) = line.parse::<usize>() else {
        return true;
    };
    if index == 0 || index > profiles.len() {
        return true;
    }
    let (agent, _) = &profiles[index - 1];
    println!();
    print_one_agent(Some(bank), agent);
    true
}

fn channel(command: Channel) -> Result<()> {
    let here = |workspace: Option<PathBuf>| -> Result<ferryman_channel::ProjectRoute> {
        let start = match workspace {
            Some(path) => path,
            None => std::env::current_dir().context("read the current directory")?,
        };
        ferryman_channel::route_for(&start)
    };

    match command {
        Channel::Status { workspace } => {
            let route = here(workspace)?;
            let (outbox, acknowledgements, oldest, quarantined) =
                ferryman_channel::filesystem_metrics(&route)?;
            let messages = ferryman_channel::list_messages(&route)?;
            println!("project        {}", route.project_id);
            println!("channel        {}", route.communications.display());
            println!(
                "mode           {}",
                if route.is_team() {
                    "team (master-gated)"
                } else {
                    "single-agent / unmanaged"
                }
            );
            println!(
                "syncthing      {}",
                if route.shared_remote.is_empty() {
                    "(no folder id configured)".to_string()
                } else {
                    format!("folder '{}'", route.shared_remote)
                }
            );
            println!(
                "git backstop   {}",
                if route.git_remote.is_empty() {
                    "(none; Syncthing-only)".to_string()
                } else {
                    route.git_remote.clone()
                }
            );
            println!("messages       {}", messages.len());
            println!("outbox         {outbox} waiting, {acknowledgements} acknowledgements");
            if let Some(age) = oldest {
                println!("oldest queued  {age}s");
            }
            if quarantined > 0 {
                println!("quarantined    {quarantined} (inspect before retrying)");
            }
        }

        Channel::Join {
            workspace,
            name,
            role,
            capabilities,
        } => {
            let route = here(workspace)?;
            let agent = ferryman_channel::AgentRoute {
                name: ferryman_ops::identity::resolve(name, &route.attachment)?,
                role,
                capabilities: capabilities
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect(),
                public_key: None,
            };
            // The private key is created here and stays in the attachment, which is
            // machine-local and outside the folder Syncthing carries. Only the public
            // half is published.
            let identity =
                ferryman_channel::AgentIdentity::load_or_create(&agent.name, &route.attachment)?;
            let path = ferryman_channel::register_agent_key(&route, &agent, &identity)?;
            println!("registered '{}' as {}", agent.name, path.display());
            println!("  public key  {}", identity.public_key_hex());
            println!(
                "  private key stays in {}",
                route.attachment.join("keys").display()
            );
            println!("it will appear on the other machines once Syncthing carries the folder");
        }

        Channel::Agents { workspace } => {
            let route = here(workspace)?;
            if route.agents.is_empty() {
                println!("no agents registered yet - run `ferry channel join`");
            }
            for agent in &route.agents {
                println!(
                    "  {:<20} role={:<12} {}",
                    agent.name,
                    agent.role,
                    agent.capabilities.join(",")
                );
            }
        }

        Channel::Send {
            workspace,
            from,
            to,
            body,
            reply_expected,
        } => {
            let route = here(workspace)?;
            let sender = ferryman_ops::identity::resolve(from, &route.attachment)?;
            // A body that looks like JSON is kept as JSON; anything else is text. Guessing
            // wrong in either direction would be worse than being explicit about the rule.
            let payload = if body.trim_start().starts_with('{') {
                serde_json::from_str(&body).context("--body looked like JSON but did not parse")?
            } else {
                json!({ "text": body })
            };
            let mut message = ferryman_channel::Message::new(
                route.project_id.clone(),
                sender.clone(),
                to,
                "text/plain",
                payload,
                reply_expected,
                None,
            );
            // Sign it if this agent has a key. Unsigned still works - a fleet that has
            // not adopted signing keeps running - but anything that has joined gets
            // attribution for free, which is the point: on a team, every contribution
            // carries a fingerprint.
            if let Ok(identity) =
                ferryman_channel::AgentIdentity::load_or_create(&sender, &route.attachment)
            {
                identity.sign(&mut message);
            }
            let mut engine = ferryman_channel::system_delivery_engine();
            let receipt = engine.send(&route, &message)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }

        Channel::Inbox {
            workspace,
            agent,
            all,
        } => {
            let route = here(workspace)?;
            // An inbox for a name nobody registered is not empty, it is a typo. Printing
            // `[]` for both makes a misspelled name indistinguishable from silence.
            let roster = ferryman_channel::read_agent_roster(&route.communications)?;
            if !roster.iter().any(|entry| entry.name == agent) {
                let known = roster
                    .iter()
                    .map(|entry| entry.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "no agent called '{agent}' has joined this channel{}",
                    if known.is_empty() {
                        "; nobody has joined yet".to_string()
                    } else {
                        format!("; the roster has: {known}")
                    }
                )
            }
            let messages = ferryman_channel::list_messages(&route)?;
            let mine: Vec<_> = messages
                .into_iter()
                .filter(|m| m.recipient == agent || m.recipient == "all")
                .filter(|m| all || !ferryman_channel::is_acknowledged(&route, &m.id))
                .map(|m| {
                    let verdict = ferryman_channel::verify_message(&m, &route.agents);
                    serde_json::json!({ "message": m, "signature": format!("{verdict:?}") })
                })
                .collect();
            if mine.is_empty() {
                println!("nothing waiting for {agent}");
            } else {
                println!("{}", serde_json::to_string_pretty(&mine)?);
            }
        }

        Channel::Order {
            workspace,
            agent,
            id,
            to,
            task,
            requires_review,
            require,
            requires_approval,
            depends_on,
        } => {
            let route = here(workspace)?;
            let issuer = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let payload = if task.trim_start().starts_with('{') {
                serde_json::from_str(&task).context("--task looked like JSON but did not parse")?
            } else {
                json!({ "task": task })
            };
            let mut order = ferryman_channel::Order {
                id: id.clone(),
                project_id: route.project_id.clone(),
                issued_by: issuer.clone(),
                assigned_to: to,
                created_at: chrono::Utc::now(),
                payload,
                requires_review,
                requires_approval,
                depends_on,
                signed_by: None,
                signature: None,
                result_contract: if require.is_empty() {
                    None
                } else {
                    Some(ferryman_channel::contract::ResultContract { required: require })
                },
            };
            // Actually sign it. Setting signed_by without a signature would claim
            // attribution nothing could check, which is worse than claiming none.
            if let Ok(identity) =
                ferryman_channel::AgentIdentity::load_or_create(&issuer, &route.attachment)
            {
                identity.sign_order(&mut order);
            }
            let path = ferryman_channel::issue_order(&route, &order)?;
            if let Ok(identity) =
                ferryman_channel::AgentIdentity::load_or_create(&issuer, &route.attachment)
            {
                let _ = ferryman_channel::ledger::append_ledger_entry(
                    &route,
                    &identity,
                    "order",
                    &issuer,
                    &format!("issued order {id}"),
                    Some(&id),
                );
            }
            println!("issued {id} -> {}", path.display());
            match order.assigned_to {
                Some(ref who) => println!("  addressed to {who}: nothing to race over"),
                None => println!("  open: whichever agent claims first wins"),
            }
        }

        Channel::Source {
            workspace,
            agent,
            name,
            command,
        } => {
            let route = here(workspace)?;
            let issuer = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let identity =
                ferryman_channel::AgentIdentity::load_or_create(&issuer, &route.attachment)?;
            let source = ferryman_channel::source::TaskSource::Shell { name, command };
            let imported = ferryman_channel::source::import(&route, &source, &issuer, &identity)?;
            println!("imported {imported} order(s) from {}", source.name());
        }

        Channel::Sources { workspace } => {
            let route = here(workspace)?;
            let triggers = ferryman_channel::source::load_triggers(&route)?;
            if triggers.is_empty() {
                println!(
                    "no sources configured; write {} with [[source]] entries",
                    route.attachment.join("sources.toml").display()
                );
            } else {
                for trigger in &triggers {
                    println!(
                        "{}  every {}s  {}",
                        trigger.name, trigger.interval_secs, trigger.command
                    );
                }
            }
        }

        Channel::Watch {
            workspace,
            agent,
            interval,
            once,
        } => {
            let route = here(workspace)?;
            let issuer = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let identity =
                ferryman_channel::AgentIdentity::load_or_create(&issuer, &route.attachment)?;
            let triggers = ferryman_channel::source::load_triggers(&route)?;
            if triggers.is_empty() {
                bail!(
                    "no sources configured; write {} with [[source]] entries",
                    route.attachment.join("sources.toml").display()
                );
            }
            loop {
                for trigger in &triggers {
                    match ferryman_channel::source::poll_if_due(&route, trigger, &issuer, &identity)
                    {
                        Ok(0) => {}
                        Ok(n) => println!("imported {n} order(s) from {}", trigger.name),
                        Err(e) => eprintln!("source '{}' failed: {e:#}", trigger.name),
                    }
                }
                if once {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        }

        Channel::Worktree { workspace, action } => {
            let route = here(workspace)?;
            match action {
                WorktreeAction::Branch { order, agent } => {
                    let branch = ferryman_channel::worktree::branch_name(&order, &agent);
                    println!("{branch}");
                }
                WorktreeAction::Create { order, agent } => {
                    let (dir, branch) = ferryman_channel::worktree::create_worktree(
                        &route.workspace,
                        &order,
                        &agent,
                    )?;
                    println!("worktree {branch} at {}", dir.display());
                }
                WorktreeAction::Cleanup { order, agent } => {
                    let branch = ferryman_channel::worktree::branch_name(&order, &agent);
                    ferryman_channel::worktree::remove_worktree(&route.workspace, &branch)?;
                    println!("removed worktree {branch}");
                }
            }
        }

        Channel::Interrupt {
            workspace,
            agent,
            order,
            action,
            note,
        } => {
            let route = here(workspace)?;
            let issuer = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let identity =
                ferryman_channel::AgentIdentity::load_or_create(&issuer, &route.attachment)?;
            let mut interrupt = ferryman_channel::interrupt::Interrupt {
                order_id: order.clone(),
                action: ferryman_channel::interrupt::InterruptAction::parse(&action)?,
                note,
                issued_by: issuer.clone(),
                created_at: chrono::Utc::now(),
                signed_by: None,
                signature: None,
            };
            identity.sign_interrupt(&mut interrupt);
            let path = ferryman_channel::interrupt::write_interrupt(&route, &interrupt)?;
            ferryman_channel::ledger::append_ledger_entry(
                &route,
                &identity,
                "interrupt",
                &issuer,
                &format!("{} interrupt on {order}", interrupt.action.as_str()),
                Some(&order),
            )?;
            println!(
                "interrupt {} on {order} -> {}",
                interrupt.action.as_str(),
                path.display()
            );
        }

        Channel::Work { workspace, agent } => {
            let route = here(workspace)?;
            let agent = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let work = ferryman_channel::work_for(&route, &agent)?;
            if work.is_empty() {
                // "nothing for you" is ambiguous, and a first user read it as broken
                // identity resolution: their agent name was in the config, tasks existed,
                // and this printed nothing. Saying what was skipped and why turns a
                // suspected bug into an obvious explanation.
                println!("nothing for {agent} to pick up right now");
                let all = ferryman_channel::list_tasks(&route)?;
                if all.is_empty() {
                    println!("  the channel has no tasks at all");
                } else {
                    println!("  {} task(s) exist, none claimable by you:", all.len());
                    for task in &all {
                        let why = match task.state() {
                            ferryman_channel::TaskState::AwaitingReview { by, revision } => {
                                format!("revision {revision} by {by} is waiting on a reviewer")
                            }
                            ferryman_channel::TaskState::Accepted => "finished".to_string(),
                            ferryman_channel::TaskState::Done => {
                                "finished, no review asked for".to_string()
                            }
                            ferryman_channel::TaskState::Claimed { by } => {
                                format!("held by {by}")
                            }
                            ferryman_channel::TaskState::ChangesRequested { revision } => {
                                format!(
                                    "revision {revision} owed by {}",
                                    task.holder().unwrap_or("someone")
                                )
                            }
                            ferryman_channel::TaskState::Open => {
                                format!(
                                    "open, but addressed to {}",
                                    task.order.assigned_to.as_deref().unwrap_or("someone else")
                                )
                            }
                        };
                        println!("    {:<12} {why}", task.order.id);
                    }
                }
            }
            for task in work {
                println!(
                    "  {:<12} {:<28} {:?}",
                    task.order.id,
                    task.order
                        .payload
                        .get("task")
                        .and_then(Value::as_str)
                        .unwrap_or("(structured)"),
                    task.state()
                );
            }
        }

        Channel::Claim {
            workspace,
            agent,
            id,
        } => {
            let route = here(workspace)?;
            let agent = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            ferryman_channel::claim_order(&route, &id, &agent)?;
            let task = ferryman_channel::read_task(&route, &id)?;
            match task.holder() {
                Some(holder) if holder == agent => println!("{agent} holds {id}"),
                Some(holder) => println!(
                    "{holder} holds {id} - claimed first. Backing off costs seconds, not correctness."
                ),
                None => println!("claim recorded; no holder yet"),
            }
        }

        Channel::Submit {
            workspace,
            agent,
            result,
            id,
        } => {
            let route = here(workspace)?;
            let agent = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let task = ferryman_channel::read_task(&route, &id)?;
            let revision = task.latest_revision().unwrap_or(0) + 1;
            let payload = if result.trim_start().starts_with('{') {
                serde_json::from_str(&result)
                    .context("--result looked like JSON but did not parse")?
            } else {
                json!({ "text": result })
            };
            let mut submission = ferryman_channel::TaskResult {
                order_id: id.clone(),
                agent: agent.clone(),
                revision,
                submitted_at: chrono::Utc::now(),
                payload,
                signed_by: None,
                signature: None,
            };
            // The fingerprint on a contribution: this agent, this work, checkable later.
            if let Ok(identity) =
                ferryman_channel::AgentIdentity::load_or_create(&agent, &route.attachment)
            {
                identity.sign_result(&mut submission);
            }
            let signed = submission.signature.is_some();
            let path = ferryman_channel::submit_result(&route, &submission)?;
            println!(
                "submitted revision {revision} of {id} -> {}",
                path.display()
            );
            if signed {
                println!("  signed by {agent}");
            }
        }

        Channel::Review {
            workspace,
            reviewer,
            accept,
            notes,
            id,
        } => {
            let route = here(workspace)?;
            let reviewer = ferryman_ops::identity::resolve(reviewer, &route.attachment)?;
            let task = ferryman_channel::read_task(&route, &id)?;
            let revision = task
                .latest_revision()
                .context("there is no result to review yet")?;
            // A contract violation must be fixed before acceptance: this is the
            // mechanical rejection a result schema exists to provide.
            if accept
                && let Some(missing) = task.contract_violations()
                && !missing.is_empty()
            {
                bail!(
                    "result for {id} does not satisfy the order's contract; missing keys: {}",
                    missing.join(", ")
                );
            }
            let mut verdict = ferryman_channel::Review {
                order_id: id.clone(),
                revision,
                reviewer: reviewer.clone(),
                reviewed_at: chrono::Utc::now(),
                accepted: accept,
                notes: notes.clone(),
                signed_by: None,
                signature: None,
            };
            // A verdict is signed too, so an acceptance cannot later be denied or forged.
            if let Ok(identity) =
                ferryman_channel::AgentIdentity::load_or_create(&reviewer, &route.attachment)
            {
                identity.sign_review(&mut verdict);
            }
            ferryman_channel::submit_review(&route, &verdict)?;
            if accept {
                println!("accepted revision {revision} of {id}");
            } else {
                println!("sent {id} back for revision {}", revision + 1);
                println!("  {}", notes.unwrap_or_default());
            }
        }

        Channel::Skills { workspace, task } => {
            let route = here(workspace)?;
            let skills = ferryman_channel::skills::load_skills(&route)?;
            if skills.is_empty() {
                println!(
                    "no skills yet; add SKILL.md files under {}/skills",
                    route.attachment.display()
                );
            } else {
                let matched: Vec<&ferryman_channel::skills::Skill> = match &task {
                    Some(task) => ferryman_channel::skills::route(&skills, task),
                    None => Vec::new(),
                };
                for skill in &skills {
                    let tag = if matched.iter().any(|m| m.name == skill.name) {
                        "  -> matches"
                    } else {
                        ""
                    };
                    println!("  {:<24} {}{}", skill.name, skill.description, tag);
                }
            }
        }

        Channel::Stats { workspace } => {
            let route = here(workspace)?;
            let stats = ferryman_channel::learning::engine_stats(&route)?;
            if stats.is_empty() {
                println!("nothing learned yet; reviews and 'ferry bench' record outcomes here");
            } else {
                println!("  {:<16} {:>6} {:>8}  total", "engine", "kept", "rate");
                for s in &stats {
                    println!(
                        "  {:<16} {:>6} {:>7.0}%  {}",
                        s.engine,
                        s.accepted,
                        s.rate() * 100.0,
                        s.total
                    );
                }
            }
        }

        Channel::Tasks { workspace } => {
            let route = here(workspace)?;
            let tasks = ferryman_channel::list_tasks(&route)?;
            if tasks.is_empty() {
                println!("no tasks yet");
            }
            for task in tasks {
                println!(
                    "  {:<12} {:<14} {:?}",
                    task.order.id,
                    task.holder().unwrap_or("-"),
                    task.state()
                );
                println!(
                    "               order {:?}",
                    ferryman_channel::verify_order(&task.order, &route.agents)
                );
                if let Some(missing) = task.contract_violations() {
                    if missing.is_empty() {
                        println!("               contract satisfied");
                    } else {
                        println!("               contract MISSING: {}", missing.join(", "));
                    }
                }
                for result in &task.results {
                    println!(
                        "               result r{} by {:<10} {:?}",
                        result.revision,
                        result.agent,
                        ferryman_channel::verify_result(result, &route.agents)
                    );
                }
                for review in &task.reviews {
                    println!(
                        "               review r{} by {:<10} {:?}",
                        review.revision,
                        review.reviewer,
                        ferryman_channel::verify_review(review, &route.agents)
                    );
                }
            }
        }

        Channel::Log { workspace, limit } => {
            let route = here(workspace)?;
            // This used to print messages only. The channel's actual history is its
            // signed artifacts - orders, claims, results, reviews - and a first user
            // watched it print zero bytes, exit 0, and say nothing, while four signed
            // artifacts sat in the folder. Work had provably run and left no visible
            // record. Everything that happened now appears, in the order it happened.
            let mut entries: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
            for task in ferryman_channel::list_tasks(&route)? {
                let id = task.order.id.clone();
                entries.push((
                    task.order.created_at,
                    format!("{id}  order issued by {}", task.order.issued_by),
                ));
                for claim in &task.claims {
                    entries.push((
                        claim.claimed_at,
                        format!("{id}  claimed by {}", claim.agent),
                    ));
                }
                for result in &task.results {
                    entries.push((
                        result.submitted_at,
                        format!(
                            "{id}  result r{} by {}{}",
                            result.revision,
                            result.agent,
                            signed_suffix(result.signed_by.as_deref())
                        ),
                    ));
                }
                for recommendation in &task.recommendations {
                    entries.push((
                        recommendation.recommended_at,
                        format!(
                            "{id}  recommendation r{} by {}: {}{}",
                            recommendation.revision,
                            recommendation.reviewer,
                            if recommendation.accept {
                                "accept"
                            } else {
                                "reject"
                            },
                            signed_suffix(recommendation.signed_by.as_deref())
                        ),
                    ));
                }
                for review in &task.reviews {
                    entries.push((
                        review.reviewed_at,
                        format!(
                            "{id}  review r{} by {}: {}{}",
                            review.revision,
                            review.reviewer,
                            if review.accepted {
                                "accepted"
                            } else {
                                "changes requested"
                            },
                            signed_suffix(review.signed_by.as_deref())
                        ),
                    ));
                }
            }
            for message in ferryman_channel::list_messages(&route)? {
                entries.push((
                    message.created_at,
                    format!(
                        "message   {} -> {}  {}{}",
                        message.sender,
                        message.recipient,
                        message
                            .payload
                            .get("text")
                            .and_then(Value::as_str)
                            .map_or_else(|| message.payload.to_string(), ToString::to_string),
                        if message.reply_required {
                            "  [reply expected]"
                        } else {
                            ""
                        }
                    ),
                ));
            }
            entries.sort_by_key(|(at, _)| *at);
            if entries.is_empty() {
                // Silence is indistinguishable from breakage. Say which channel was read.
                println!("nothing has happened in this channel yet");
                println!("  {}", route.communications.display());
            } else {
                let shown = entries.len().min(limit);
                if shown < entries.len() {
                    println!(
                        "showing the last {shown} of {} entries; --limit for more",
                        entries.len()
                    );
                }
                for (at, line) in entries.iter().rev().take(limit).rev() {
                    println!("{}  {line}", at.format("%Y-%m-%d %H:%M:%SZ"));
                }
            }
        }
        Channel::Trust { workspace, action } => {
            let route = here(workspace)?;
            match action {
                TrustAction::List => {
                    let store = ferryman_channel::trust_store(&route)?;
                    if store.signers.is_empty() {
                        println!("no trusted signers");
                    }
                    for grant in &store.signers {
                        let id = match grant.signer_id() {
                            Ok(id) => id.as_str().to_owned(),
                            Err(_) => "<invalid key>".to_owned(),
                        };
                        println!(
                            "{id}  projects=[{}]  roles=[{}]  capabilities=[{}]  revoked={}",
                            grant.projects.join(","),
                            grant.roles.join(","),
                            grant.capabilities.join(","),
                            grant.revoked
                        );
                    }
                }
                TrustAction::Revoke { signer } => {
                    let changed = ferryman_channel::revoke_trusted_signer(&route, &signer)?;
                    println!(
                        "{}",
                        if changed {
                            "revoked"
                        } else {
                            "no change (signer not found or already revoked)"
                        }
                    );
                }
                TrustAction::Add {
                    public_key,
                    projects,
                    roles,
                    capabilities,
                } => {
                    let split = |value: Option<&String>| -> Vec<String> {
                        value
                            .map(|v| {
                                v.split(',')
                                    .filter(|item| !item.trim().is_empty())
                                    .map(|item| item.trim().to_owned())
                                    .collect()
                            })
                            .unwrap_or_default()
                    };
                    let grant = ferryman_channel::portable_auth::SignerGrant {
                        public_key,
                        projects: split(projects.as_ref()),
                        roles: split(roles.as_ref()),
                        capabilities: split(capabilities.as_ref()),
                        revoked: false,
                    };
                    let added = ferryman_channel::add_trusted_signer(&route, grant)?;
                    println!("{}", if added { "added" } else { "no change" });
                }
            }
        }
        Channel::Master { workspace, action } => {
            let route = here(workspace)?;
            match action {
                MasterAction::Init { name } => {
                    let master = ferryman_ops::identity::resolve(name, &route.attachment)?;
                    let identity = ferryman_channel::AgentIdentity::load_or_create(
                        &master,
                        &route.attachment,
                    )?;
                    let declaration =
                        ferryman_channel::master::initialize_master(&route, &identity, &master)?;
                    println!(
                        "{} is now the master of project {}",
                        declaration.master, route.project_id
                    );
                    println!("three folders a team agent needs:");
                    println!("  work repository: {}", route.workspace.display());
                    println!(
                        "  shared channel:  {}  (Syncthing folder '{}')",
                        route.communications.display(),
                        route.shared_remote
                    );
                    println!(
                        "  master folder:   {}  (Syncthing folder '{}')",
                        route.master_dir().display(),
                        ferryman_channel::master::master_folder_name(&route.project_id)
                    );
                }
                MasterAction::Status => match ferryman_channel::master::read_master(&route)? {
                    Some(declaration) => {
                        println!(
                            "master {}  signed by {}",
                            declaration.master,
                            declaration.signed_by.as_deref().unwrap_or("?")
                        );
                        println!("  folder: {}", declaration.folder);
                        println!("  since:  {}", declaration.created_at.to_rfc3339());
                    }
                    None => {
                        println!("no master yet; run 'ferry channel master init' to choose one")
                    }
                },
                MasterAction::Transfer { name } => {
                    let current = match ferryman_channel::master::read_master(&route)? {
                        Some(declaration) => declaration.master,
                        None => bail!("this project has no master yet"),
                    };
                    let identity = ferryman_channel::AgentIdentity::load_or_create(
                        &current,
                        &route.attachment,
                    )?;
                    let declaration =
                        ferryman_channel::master::transfer_master(&route, &identity, &name)?;
                    println!(
                        "master role transferred to {} (disclaimed by {})",
                        declaration.master, current
                    );
                }
                MasterAction::Grant {
                    name,
                    public_key,
                    roles,
                    capabilities,
                } => {
                    let current = match ferryman_channel::master::read_master(&route)? {
                        Some(declaration) => declaration.master,
                        None => bail!("this project has no master yet"),
                    };
                    let identity = ferryman_channel::AgentIdentity::load_or_create(
                        &current,
                        &route.attachment,
                    )?;
                    let split = |value: Option<&String>| -> Vec<String> {
                        value
                            .map(|v| {
                                v.split(',')
                                    .filter(|item| !item.trim().is_empty())
                                    .map(|item| item.trim().to_owned())
                                    .collect()
                            })
                            .unwrap_or_default()
                    };
                    let grant = ferryman_channel::master::grant_member(
                        &route,
                        &identity,
                        &name,
                        &public_key,
                        vec![route.project_id.clone()],
                        split(roles.as_ref()),
                        split(capabilities.as_ref()),
                    )?;
                    println!(
                        "granted {} roles=[{}] capabilities=[{}] (signed by {})",
                        grant.grantee,
                        grant.roles.join(","),
                        grant.capabilities.join(","),
                        current
                    );
                }
                MasterAction::Grants => {
                    let grants = ferryman_channel::master::member_grants(&route)?;
                    if grants.is_empty() {
                        println!("no grants yet");
                    }
                    for (grant, check) in grants {
                        println!(
                            "{}  roles=[{}]  capabilities=[{}]  {:?}",
                            grant.grantee,
                            grant.roles.join(","),
                            grant.capabilities.join(","),
                            check
                        );
                    }
                }
            }
        }
        Channel::Lease { workspace, action } => {
            let route = here(workspace)?;
            match action {
                LeaseAction::Mint { to, scope, minutes } => {
                    let master_name = match ferryman_channel::master::read_master(&route)? {
                        Some(declaration) => declaration.master,
                        None => {
                            bail!("this project has no master yet; run 'ferry channel master init'")
                        }
                    };
                    let identity = ferryman_channel::AgentIdentity::load_or_create(
                        &master_name,
                        &route.attachment,
                    )?;
                    let scope = scope
                        .map(|s| {
                            s.split(',')
                                .map(str::trim)
                                .filter(|part| !part.is_empty())
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    let lease = ferryman_channel::lease::mint_lease(
                        &route,
                        &identity,
                        &to,
                        scope,
                        chrono::Duration::minutes(minutes),
                    )?;
                    println!(
                        "leased to {} until {}  scope=[{}]",
                        lease.issued_to,
                        lease.expires_at.to_rfc3339(),
                        lease.scope.join(",")
                    );
                }
                LeaseAction::Verify { to } => {
                    let path = route
                        .communications
                        .join("leases")
                        .join(format!("{to}.json"));
                    let token: ferryman_channel::lease::LeaseToken =
                        serde_json::from_slice(&std::fs::read(&path)?)
                            .with_context(|| format!("read lease for '{to}'"))?;
                    if ferryman_channel::lease::verify_lease(&route, &token)? {
                        let left = token.expires_at - chrono::Utc::now();
                        println!(
                            "valid: {} may [{}] for another {} minutes",
                            token.issued_to,
                            token.scope.join(","),
                            left.num_minutes()
                        );
                    } else {
                        println!("invalid or expired");
                    }
                }
            }
        }
        Channel::Report {
            workspace,
            agent,
            json,
        } => {
            let route = here(workspace)?;
            let exporter = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let identity =
                ferryman_channel::AgentIdentity::load_or_create(&exporter, &route.attachment)?;
            let report = ferryman_channel::ledger::build_report(&route, &identity)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("project   {}", report.project_id);
                println!(
                    "exported  {} by {}",
                    report.generated_at.to_rfc3339(),
                    report.generated_by
                );
                println!(
                    "integrity {}",
                    if report.ledger_intact {
                        "verified".to_string()
                    } else {
                        format!("BROKEN at entry {}", report.broken_at.unwrap_or(0))
                    }
                );
                if report.entries.is_empty() {
                    println!("no recorded activity yet");
                }
                for entry in &report.entries {
                    let mark = if entry.signature_ok {
                        ""
                    } else {
                        "  [UNVERIFIED]"
                    };
                    println!(
                        "  {}  {}  {}{}",
                        entry.created_at.to_rfc3339(),
                        entry.kind,
                        entry.summary,
                        mark
                    );
                    println!(
                        "       by {}  ref: {}",
                        entry.actor,
                        entry.reference.as_deref().unwrap_or("-")
                    );
                }
            }
        }

        Channel::Syncthing { action } => match action {
            SyncthingAction::Devices => {
                let peers = ferryman_channel::syncthing_peers()?;
                if peers.is_empty() {
                    println!("no other devices are paired with this Syncthing yet");
                }
                for peer in peers {
                    println!("{}  {}", peer.device_id, peer.name);
                }
            }
            SyncthingAction::Status { workspace } => {
                let route = here(workspace)?;
                let known = ferryman_channel::syncthing_peers()?;
                let notes = load_device_notes(&route);
                println!("folder  {}", ferryman_channel::channel_folder_id(&route));
                let ids = ferryman_channel::syncthing_folder_device_ids(&route)?;
                if ids.is_empty() {
                    println!("shared  (no other devices)");
                }
                for id in ids {
                    let name = known
                        .iter()
                        .find(|peer| peer.device_id == id)
                        .map(|peer| peer.name.clone())
                        .unwrap_or_default();
                    println!("shared  {id}  {name}  ({})", owner_label(&notes, &id));
                }
            }
            SyncthingAction::Share {
                workspace,
                with,
                name,
            } => {
                if with.is_empty() {
                    bail!("--with is required: the device id to share this folder with");
                }
                let route = here(workspace)?;
                let trusted = ferryman_channel::syncthing_peers()?;
                for id in &with {
                    if !trusted.iter().any(|peer| &peer.device_id == id) {
                        ferryman_channel::syncthing_add_device(
                            id,
                            name.as_deref().unwrap_or_default(),
                        )?;
                        println!(
                            "added {id} to Syncthing (was not trusted before; name: \"{}\")",
                            name.as_deref().unwrap_or_default()
                        );
                    }
                }
                print_syncthing_setup(&ferryman_channel::syncthing_share_folder(&route, &with)?);
                note_unclassified_shares(&route, &with, &ferryman_channel::syncthing_peers()?);
            }
            SyncthingAction::Unshare { workspace, with } => {
                if with.is_empty() {
                    bail!("--with is required: the device id to stop sharing with");
                }
                let route = here(workspace)?;
                print_syncthing_setup(&ferryman_channel::syncthing_unshare_folder(&route, &with)?);
            }
            SyncthingAction::On { workspace } => {
                let route = here(workspace)?;
                print_syncthing_setup(&ferryman_channel::syncthing_register_folder(&route, &[])?);
            }
            SyncthingAction::Off { workspace } => {
                let route = here(workspace)?;
                print_syncthing_setup(&ferryman_channel::syncthing_unregister_folder(&route)?);
            }
            SyncthingAction::Mark {
                workspace,
                with,
                owner,
            } => {
                let route = here(workspace)?;
                let peers = ferryman_channel::syncthing_peers()?;
                let name = peers
                    .iter()
                    .find(|peer| peer.device_id == with)
                    .map(|peer| peer.name.clone())
                    .unwrap_or_default();
                let mut notes = load_device_notes(&route);
                notes.devices.insert(
                    with.clone(),
                    DeviceNote {
                        name,
                        owner: owner.clone(),
                    },
                );
                save_device_notes(&route, &notes)?;
                println!("marked {with} as {}", owner_label(&notes, &with));
            }
        },

        Channel::Deprecate { workspace } => {
            let route = here(workspace)?;
            let moved = ferryman_channel::deprecate_legacy_bridge(&route.workspace)?;
            if moved.is_empty() {
                println!("no legacy bridge artifacts found; nothing to move");
            } else {
                println!(
                    "moved {} legacy bridge item(s) into {}/deprecated/",
                    moved.len(),
                    route.workspace.display()
                );
                for path in &moved {
                    println!("  {}", path.display());
                }
            }
        }
    }
    Ok(())
}

fn print_syncthing_setup(setup: &ferryman_channel::SyncthingSetup) {
    println!("folder  {}", setup.folder_id);
    println!("path    {}", setup.folder_path);
    if setup.available && !setup.shared_with.is_empty() {
        for peer in &setup.shared_with {
            println!("shared  {}  {}", peer.device_id, peer.name);
        }
    } else if setup.available {
        println!("shared  (no other devices)");
    }
    println!("note    {}", setup.note);
}

/// Who a shared device belongs to, recorded by the operator so the share list
/// stays auditable. Lives per project under `.ferryman/syncthing-devices.json`.
#[derive(Serialize, Deserialize, Default)]
struct DeviceNotes {
    #[serde(default)]
    devices: BTreeMap<String, DeviceNote>,
}

#[derive(Serialize, Deserialize)]
struct DeviceNote {
    name: String,
    owner: String,
}

fn device_notes_path(route: &ferryman_channel::ProjectRoute) -> PathBuf {
    route.attachment.join("syncthing-devices.json")
}

fn load_device_notes(route: &ferryman_channel::ProjectRoute) -> DeviceNotes {
    std::fs::read_to_string(device_notes_path(route))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_device_notes(route: &ferryman_channel::ProjectRoute, notes: &DeviceNotes) -> Result<()> {
    std::fs::create_dir_all(&route.attachment)?;
    std::fs::write(
        device_notes_path(route),
        serde_json::to_string_pretty(notes)?,
    )?;
    Ok(())
}

fn owner_label(notes: &DeviceNotes, id: &str) -> &'static str {
    match notes.devices.get(id).map(|note| note.owner.as_str()) {
        Some("self") => "own machine",
        Some("other") => "other person",
        _ => "unclassified",
    }
}

/// After a share, flag any device this project has never been asked to classify,
/// so a new share is a conscious decision rather than a silent widening.
fn note_unclassified_shares(
    route: &ferryman_channel::ProjectRoute,
    device_ids: &[String],
    peers: &[ferryman_channel::SyncthingPeer],
) {
    let notes = load_device_notes(route);
    let fresh: Vec<&String> = device_ids
        .iter()
        .filter(|id| !notes.devices.contains_key(*id))
        .collect();
    if fresh.is_empty() {
        return;
    }
    println!();
    for id in fresh {
        let name = peers
            .iter()
            .find(|peer| &peer.device_id == id)
            .map(|peer| peer.name.clone())
            .unwrap_or_default();
        println!("⚠ new share: {id}  {name}");
        println!("  is this a device you own, or a different person?");
        println!("  record it with:  ferry channel syncthing mark --with {id} --owner self|other");
    }
}

#[cfg(test)]
mod tests {
    use super::slug_of;
    use std::path::Path;

    #[test]
    fn slug_derives_from_the_directory_name() {
        assert_eq!(
            slug_of(Path::new("/mnt/nvme-storage/repos/ferryman")),
            "ferryman"
        );
        assert_eq!(slug_of(Path::new("/home/you/My Project")), "my-project");
        assert_eq!(
            slug_of(Path::new("/tmp/groundcrew_borrows")),
            "groundcrew-borrows"
        );
        assert_eq!(slug_of(Path::new("/tmp/foo--bar--")), "foo-bar");
        assert_eq!(slug_of(Path::new("/")), "");
    }
}

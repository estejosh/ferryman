#![forbid(unsafe_code)]
mod license;
mod mcp;
mod mcp_client;
mod telegram;
mod tgmap;

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

/// What `ferry --version` reports: the crate version plus the commit it was built from.
///
/// The version alone was not enough, and an outside upgrade report proved it: `0.3.1` before a
/// day of changes and `0.3.1` after, so the one check the upgrade instructions asked for could
/// not distinguish the builds. Machines here build from `main`, so two builds days apart share
/// a version legitimately. The commit makes "did that machine get the new build?" answerable
/// at any moment rather than only just after a tag. See `build.rs`.
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), env!("FERRYMAN_BUILD"));

#[derive(Parser, Clone)]
#[command(version = VERSION, about = "Private coordination for a fleet of AI agents")]
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
/// Carrying one human identity between the machines that person works from.
#[derive(Subcommand, Clone)]
enum Operator {
    /// Create an operator identity on this machine.
    ///
    /// The person types their own password, here, at their own terminal. An agent
    /// driving this never sees it - which is why the password is prompted for rather
    /// than passed as an argument, where it would sit in shell history and in the
    /// process list for anyone on the machine to read.
    Create {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The operator name, e.g. your handle or the person's first name.
        #[arg(long, value_parser = agent_name)]
        name: String,
        /// Make this operator THIS project's, rather than the machine's. The right
        /// choice when the person operates one project here and not the others.
        #[arg(long)]
        this_project_only: bool,
    },
    /// Write your sealed identity to a file, to carry to another machine.
    ///
    /// The file is encrypted with your password. Moving it is not moving a key: without
    /// the password it is a password-cracking problem, not an identity. That is exactly
    /// why an operator does not need a separate identity per machine the way an agent
    /// does - and why a machine key, which is NOT sealed, has no equivalent command.
    Export {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Your operator name.
        #[arg(long, value_parser = agent_name)]
        name: String,
        /// Where to write it. Defaults to <name>.ferryman-operator here.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Install a sealed identity exported from another machine.
    ///
    /// Installed for the whole machine, so one import makes you yourself in every
    /// project here rather than only the one you happened to be standing in.
    Import {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The file written by `ferry operator export`.
        #[arg(long)]
        file: PathBuf,
        /// Give THIS project a different operator from the rest of the machine - a
        /// client's repository approved by that client's account, say. Rare, and
        /// deliberately not the default.
        #[arg(long)]
        this_project_only: bool,
    },
    /// Which operator identities this machine can sign as.
    List {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
}

/// One machine's operator identity, derived from its seed (ADR 0016).
///
/// The seed is created by `ferry enable` on first run and shown once as a recovery
/// phrase. These two commands are the rest of that story: `show` prints the one
/// fingerprint a person verifies out of band, and `recover` brings the seed back from
/// the phrase onto a new machine.
#[derive(Subcommand, Clone)]
enum Identity {
    /// Print this machine's operator fingerprint and which agent identities derive
    /// from the seed.
    Show,
    /// Restore this machine's operator seed from its recovery phrase.
    Recover {
        /// Replace an existing seed after confirmation. Without this, `recover`
        /// refuses when a seed is already present.
        #[arg(long)]
        force: bool,
    },
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
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
        /// Name this as an unattended worker: `ichabod-<machine>-<engine>`.
        ///
        /// An agent with a human in the conversation and the same machine's agent running
        /// alone at three in the morning are two actors. Both are machines and both sign
        /// with machine keys - the difference is whether anyone was there, which is a
        /// question a ledger has to be able to answer. So the unattended one takes its
        /// own name, and the machine's plain name keeps meaning the supervised one.
        ///
        /// Generated rather than typed, because typing it is how a convention drifts.
        #[arg(long, conflicts_with = "agent")]
        headless: bool,
        /// What to call the engine in a headless name. Defaults to the CLI being run.
        ///
        /// Worth setting to what is actually running - `deepseek` rather than `cline` -
        /// because that is what the name is for. Changing it later changes the worker's
        /// identity, and its past work stays attributed to the old one.
        #[arg(long, requires = "headless")]
        engine: Option<String>,
        /// Contact email for this deployment. Free production use is conditioned on
        /// registering one (LICENSE section 3). Nothing about your code or your work is
        /// ever sent - see PRIVACY.md.
        ///
        /// Asked for at a terminal when it is not given. It was a required argument, and
        /// the first command in this repository's own AGENTS.md omitted it, so the first
        /// thing a stranger following our instructions saw was `error: the following
        /// required arguments were not provided`, exit code 2, nothing created and no
        /// explanation. The problem was never which flag: it was that the page written
        /// for the reader who has nobody to ask was wrong, in the first thirty seconds,
        /// before Ferryman had shown them anything it does well.
        #[arg(long, env = "FERRYMAN_EMAIL")]
        email: Option<String>,
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
    /// Check whether this machine is ready to run a task, before one fails.
    ///
    /// Reads only: the channel, `agent.toml`, the signing key's presence, the
    /// roster, whether the engine resolves on PATH, and whether Syncthing
    /// answers. Never prints credential contents. Every failing check states
    /// its remedy, because the CLI knows the answer and should not make you
    /// discover it. Exit code 0 when every required check passes.
    Doctor {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Emit one JSON object instead of prose.
        #[arg(long)]
        json: bool,
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
    /// A report you can paste into an issue while soak-testing.
    ///
    /// Counts, category labels and the build string. No file paths, task text, prompts,
    /// results, agent output or credentials - the report is assembled out of values whose
    /// type cannot carry them, rather than filtered afterwards.
    ///
    /// Nothing is sent unless you pass `--send`. It prints, and you decide.
    Soak {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Print JSON instead of markdown, for scripting.
        #[arg(long)]
        json: bool,
        /// Also write the report here, for attaching to an issue.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Send the report to the soak endpoint. Off by default, and per invocation:
        /// there is no setting that makes this happen on its own.
        #[arg(long)]
        send: bool,
        /// Print exactly what `--send` would transmit, and send nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Your own identity, as a person rather than a machine.
    ///
    /// An agent's key belongs to the machine it runs on. Yours belongs to you, and you
    /// work from more than one machine - so it is sealed under your password and can be
    /// carried, which a machine key deliberately cannot be.
    Operator {
        #[command(subcommand)]
        command: Operator,
    },
    /// Your machine's operator identity: the one fingerprint, and recovery from the
    /// phrase (ADR 0016).
    Identity {
        #[command(subcommand)]
        command: Identity,
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
    /// Estimate spend: published per-engine rates, a single prompt's cost, or
    /// this project's recorded usage. Prices are list prices, computed offline.
    Cost {
        #[command(subcommand)]
        command: Cost,
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
        #[arg(long, value_parser = agent_name)]
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
    /// The orchestrator's own continuity. `brief` records what only the
    /// orchestrator knows — the objective, what is in flight and why, the
    /// standing constraints, what is waiting on you — and `resume` prints it
    /// back in the order a replacement needs it. ADR 0017.
    ///
    /// Written continuously, not at handoff: running out of context is never a
    /// graceful event, so there is no moment at which a dying orchestrator
    /// reliably gets to summarise itself.
    Orchestrator {
        #[command(subcommand)]
        command: OrchestratorCommand,
    },
    /// Talk MCP. `serve` exposes this project's read-only query surface as tools
    /// for an MCP client; `list` and `call` connect to an external MCP server
    /// and use its tools instead.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Ask this project a question and get an auditable answer (MAARAG) — every
    /// claim carries its signed source, so the answer can be verified rather
    /// than trusted. Read-only.
    Ask {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The question to answer.
        question: String,
        /// Emit the claims as JSON instead of prose.
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand, Clone)]
enum OrchestratorCommand {
    /// Record or update this orchestrator's brief. Only the sections you pass are
    /// touched, so a running orchestrator can update one thing after a decision
    /// without restating everything it already knows.
    ///
    /// With no sections given, it prints the brief as it stands.
    Brief {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Whose brief. Defaults to the only agent this machine holds a key for.
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
        /// One line: what this is all for right now.
        #[arg(long)]
        objective: Option<String>,
        /// When it has to be true by, if that is real rather than a wish.
        #[arg(long)]
        deadline: Option<String>,
        /// What the human has said that still binds.
        #[arg(long)]
        constraints: Option<String>,
        /// What is moving, and why each thing sits where it does.
        #[arg(long)]
        in_flight: Option<String>,
        /// Load-bearing decisions that never became ADRs, with the reason.
        #[arg(long)]
        decided: Option<String>,
        /// Tried, and not taken — so a successor does not rediscover it.
        #[arg(long)]
        rejected: Option<String>,
        /// Waiting on the human, not on a machine.
        #[arg(long)]
        waiting_on_human: Option<String>,
        /// What to do next, in the order to do it.
        #[arg(long)]
        next: Option<String>,
    },
    /// Print everything a replacement orchestrator needs, in the order it needs
    /// it. Meant to be pasted whole into a fresh orchestrator as its opening
    /// context.
    Resume {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Whose brief to resume from. Defaults to the most recently updated.
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
    },
    /// Every brief in the channel, newest first, with its age and whether it
    /// verifies. More than one is normal: an orchestrator that has handed over
    /// leaves its brief behind.
    List {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
}

#[derive(Subcommand, Clone)]
enum McpCommand {
    /// Serve this project over MCP (Model Context Protocol) on stdio, exposing
    /// the channel's query surface — tasks, memory, roster, ledger, learnings,
    /// skills — as tools an MCP client (Claude Desktop, Codex, Claude Code) can
    /// call. Read-only: an MCP connection is a stranger, not the operator.
    Serve {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Connect to an external MCP server and print the tools it advertises.
    List {
        /// The server command and its arguments, e.g.
        /// "npx -y @modelcontextprotocol/server-github". Split on whitespace;
        /// quoting is not supported.
        #[arg(long)]
        server: String,
    },
    /// Call one tool on an external MCP server and print its text result.
    Call {
        /// The server command and its arguments, as for `list`.
        #[arg(long)]
        server: String,
        /// The tool name to call.
        #[arg(long)]
        tool: String,
        /// Tool arguments as a JSON object, e.g. '{"query":"ferryman"}'.
        #[arg(long)]
        arguments: Option<String>,
    },
    /// Configure an external MCP server for this project, so `ferry mcp serve`
    /// proxies its tools to agents under a `name_` prefix.
    Add {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The server name, e.g. "github".
        name: String,
        /// The server command and its arguments, as for `list`.
        #[arg(long)]
        server: String,
    },
    /// Remove a configured external MCP server.
    Remove {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The server name to remove.
        name: String,
    },
    /// List the external MCP servers configured for this project.
    Servers {
        /// The project directory. Defaults to where you are.
        #[arg(long)]
        workspace: Option<PathBuf>,
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
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
        agent: String,
        /// Include messages that have already been acknowledged.
        #[arg(long)]
        all: bool,
    },
    /// Put one identity's key into every channel under a folder, so it can sign in all
    /// of them.
    ///
    /// A key lives per attachment, and an attachment is per project. That is right for a
    /// worker - one machine, one project's work - and wrong for anything that spans
    /// projects. An orchestrator that reads a request about one project and issues the
    /// order into another needs to sign in both, and finds out it cannot at the moment it
    /// tries.
    ///
    /// This moves the key this machine already holds. It does not mint one: a second key
    /// under a name the roster knows makes every signature it produces read as an
    /// impostor, so a name this machine has never held is a refusal, not an invitation.
    Seat {
        /// The folder holding the channels.
        #[arg(long)]
        comms: PathBuf,
        /// Whose key to seat.
        ///
        /// Defaults to the name this machine is *configured* to work under, which is the
        /// `agent` key in the first channel's `agent.toml` - not the hostname. Those
        /// differ more often than they look: a fleet whose channels all pin
        /// `agent = "operator"` will default to seating the operator, who already has a
        /// key everywhere, and report "already has it" nineteen times while seating
        /// nothing. Name it explicitly when you mean a machine.
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
        /// What to call it in the rosters it is published to.
        #[arg(long, default_value = "operator")]
        role: String,
        /// List what would be seated, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Retire an identity that is gone, releasing every claim it holds. Signed and
    /// recorded, so the ledger keeps who held a task, who let it go, and why. Refuses
    /// to retire a name whose worker is currently alive on this machine.
    Retire {
        /// The folder holding the channels. Defaults to the parent of the current
        /// directory, so it can be run from inside one of the channels.
        #[arg(long)]
        comms: Option<PathBuf>,
        /// The name being retired: whose claims are released.
        #[arg(long, value_parser = agent_name)]
        agent: String,
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
        /// Mark this agent as the fleet's MCP gateway. Only one agent should
        /// carry this; a second one is reported as a conflict.
        #[arg(long)]
        mcp: bool,
    },
    /// Reserve a name for an agent that has not come online yet, so messages can
    /// be addressed to it (and queued) before its device syncs. When the real
    /// agent registers, its key binds to the reserved name.
    Expect {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// The agent name to reserve, e.g. the machine that will join later.
        #[arg(long, value_parser = agent_name)]
        name: String,
        #[arg(long, default_value = "worker")]
        role: String,
        /// Comma-separated capabilities, e.g. "messages.receive".
        #[arg(long, default_value = "messages.receive")]
        capabilities: String,
        /// Mark this agent as the fleet's MCP gateway. Only one agent should
        /// carry this; a second one is reported as a conflict.
        #[arg(long)]
        mcp: bool,
    },
    /// Who is taking part in this channel.
    Agents {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Emit the machine-readable discovery manifest (JSON) instead of the
        /// human list: agents, their specializations, skills, and the MCP agent.
        #[arg(long)]
        json: bool,
    },
    /// Issue work into the channel. Addressed to a machine, or open to anyone.
    Order {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who is issuing it. Defaults to this machine's name. Give the name this
        /// agent joined under, or the order is signed by an identity the roster
        /// does not know and every reader reports it as UnknownSigner.
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
        /// Task id, e.g. t-4f2a.
        #[arg(long)]
        id: String,
        /// The machine to do it. Omit for "whoever picks it up first".
        #[arg(long, value_parser = agent_name)]
        to: Option<String>,
        /// The work itself. Use --task-file instead for anything longer than a line:
        /// a shell mangles a multi-line brief, and a mangled order is worse than a
        /// missing one because it looks like it worked.
        #[arg(
            long,
            required_unless_present = "task_file",
            conflicts_with = "task_file"
        )]
        task: Option<String>,
        /// Read the work from a file, verbatim. `-` reads standard input.
        ///
        /// An order worth issuing is usually worth writing in an editor, and every
        /// quote and newline survives the trip - which is not true of a command line.
        #[arg(long)]
        task_file: Option<PathBuf>,
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
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
    },
    /// Stake a claim on an open order.
    Claim {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
        id: String,
    },
    /// Submit a result for an order.
    Submit {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
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
        #[arg(long, value_parser = agent_name)]
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
    /// Bridge one Telegram chat to this channel: a message becomes a signed order,
    /// and a result comes back to the chat. Runs until stopped.
    ///
    /// Reads TELEGRAM_BOT_TOKEN and TELEGRAM_APPROVER_ID from the environment, and
    /// refuses to start without both: an unauthenticated bridge would take orders
    /// from whoever finds the bot.
    Telegram {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who the orders are signed by. Defaults to this machine's name, but the
        /// operator's own identity is usually what you want - a human asked for this
        /// work, and the ledger should say so.
        #[arg(long, value_parser = agent_name)]
        agent: Option<String>,
        /// Where an unaddressed message goes. Without it, a bare line is an open order
        /// and the fastest poller wins.
        ///
        /// That is the wrong race to leave running once machines stop being
        /// interchangeable. They differ in what they cost per task - a fleet mixing a
        /// metered engine with a subscription one has a cheap machine and an expensive
        /// one, and "whoever claims first" reliably picks whichever polls more often
        /// rather than whichever you would have chosen. `/to <agent>` still overrides
        /// this per message.
        #[arg(long, value_parser = agent_name)]
        default_to: Option<String>,
        /// The `.tgferryman` map: which Telegram topic is which project. Without it, the
        /// bridge looks for one from the working directory upwards, and serves a single
        /// project the old way if there is none.
        ///
        /// Telegram has no call that lists a group's topics, so this file is the only
        /// record of the thread ids - Ferryman writes every id it is given back into it.
        /// A topic listed with no id is one it creates on the next start.
        #[arg(long)]
        map: Option<PathBuf>,
    },
    /// Set, list and remove sealed secrets.
    ///
    /// The dashboard form is the normal way a human does this; these commands are
    /// the thing the form calls, and exist for scripts and machines with no
    /// browser. A value is read from the terminal or stdin, never from argv.
    Secret {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[command(subcommand)]
        command: SecretCommand,
    },
}

#[derive(Subcommand, Clone)]
enum SecretCommand {
    /// Seal a value to one or more recipients and write the signed envelope
    /// into this project's channel. Reads the value from the terminal, or from
    /// stdin when piped - never from argv.
    Set {
        /// The secret name, e.g. GH_TOKEN.
        name: String,
        /// Comma-separated recipients (agents with a published encryption key).
        #[arg(long)]
        to: String,
        /// Sign as this roster identity. Defaults to this machine's agent; pass
        /// your operator name to be on the record as a person.
        #[arg(long = "as", value_parser = agent_name)]
        signer: Option<String>,
    },
    /// List secret names, recipients, who sealed each, and when - never values.
    List,
    /// Decrypt and print one secret's value, for debugging or scripts. Refuses
    /// if this machine's agent is not a recipient.
    Get {
        /// The secret name.
        name: String,
    },
    /// Remove a secret envelope. The copies already synced remain, so the real
    /// way to revoke a value is to rotate it and re-seal.
    Rm {
        /// The secret name.
        name: String,
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
        #[arg(long, value_parser = agent_name)]
        agent: String,
    },
    /// Create the worktree for an (order, agent) pair.
    Create {
        #[arg(long)]
        order: String,
        #[arg(long, value_parser = agent_name)]
        agent: String,
    },
    /// Remove the worktree (and its branch) for an (order, agent) pair.
    Cleanup {
        #[arg(long)]
        order: String,
        #[arg(long, value_parser = agent_name)]
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
    /// Issue an access grant (ADR 0013): a signed lease naming one subject,
    /// some scopes, optionally one resource - a secret id, a repository.
    ///
    /// Renewal is how it stays alive: the issuer rewrites the same file with a
    /// later horizon, so revocation is stopping the renewal, and an offline
    /// holder expires out of authority at a horizon you chose. Who may be
    /// trusted as an issuer is policy; this proves who signed and that it is
    /// still live.
    Grant {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Who signs the grant. Defaults to this machine's configured agent.
        #[arg(long)]
        agent: Option<String>,
        /// The principal receiving the authority.
        #[arg(long)]
        to: String,
        /// Comma-separated scopes, e.g. "view,message" or "use-secret".
        #[arg(long)]
        scope: String,
        /// One thing the grant is about: a vault secret id, a repository name.
        #[arg(long)]
        resource: Option<String>,
        /// Lifetime in minutes. Keep it small: the horizon is the bound on
        /// exposure if you never renew or revoke in time.
        #[arg(long, default_value_t = 240)]
        minutes: i64,
    },
    /// Extend one of your grants from now. A lapse is real and is not quietly
    /// papered over; a revoked grant refuses renewal.
    Renew {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        to: String,
        /// The grant id printed at issue time.
        #[arg(long)]
        grant: String,
        #[arg(long, default_value_t = 240)]
        minutes: i64,
    },
    /// Withdraw a grant now where this record is visible. Expiry remains what
    /// ends it everywhere, including machines that never see this file.
    Revoke {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        to: String,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Every grant on the channel with its current state: active, expired,
    /// revoked, or invalid (signature does not check out).
    List {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand, Clone)]
/// The agentic loop. Every one of these runs unattended and needs no terminal.
enum Agent {
    /// Pick up work, run the configured agent CLI on it, submit a signed result.
    Run {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Watch every channel under this folder instead of one project.
        ///
        /// A channel is the unit of work, and the agent that does the work is already
        /// spun up per task and torn down after it. Only the polling was pinned to one
        /// project, which meant one process per project - and so a channel nobody had
        /// started a process for could accept a signed order that nothing would ever
        /// read. Watching is a directory listing; doing is what costs, and that is paid
        /// per task either way.
        ///
        /// Each channel uses its own agent.toml if it has one, and otherwise an
        /// agent.toml beside the channels.
        #[arg(long, conflicts_with = "workspace")]
        comms: Option<PathBuf>,
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
    /// Why this machine is (or is not) working right now.
    ///
    /// Doctor proves the setup; this reads the loop: is the worker process
    /// alive, what does it hold, and - when nothing is happening - the same
    /// decision the poll makes, with the setting that causes it. Read-only.
    Status {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Emit one JSON object instead of prose.
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
enum Cost {
    /// The published per-engine price table, dollars per million tokens.
    Rates,
    /// Estimate a whole project's cost: describe the project in your own words,
    /// and the estimator models the work items and prices them against every
    /// engine. An estimate, not a bid.
    Plan {
        /// The project description/goals.
        #[arg(long)]
        prompt: Option<String>,
        /// Read the description from a file instead of --prompt.
        #[arg(long)]
        prompt_file: Option<PathBuf>,
        /// Override the estimated number of work items.
        #[arg(long)]
        tasks: Option<u64>,
        /// Load per-engine rates from this project's rates.toml.
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// This project's recorded per-engine usage and cost, from trajectories and
    /// review outcomes.
    Project {
        #[arg(long)]
        workspace: Option<PathBuf>,
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
/// How much stack the command thread gets.
///
/// 16 MiB, chosen to be far larger than anything measured rather than tuned to fit: the point
/// is to stop this being a number anyone has to think about again.
const COMMAND_STACK: usize = 16 * 1024 * 1024;

/// Run everything on a thread whose stack size we set, rather than the platform's default.
///
/// # Why this is not `#[tokio::main]`
///
/// It was, and a debug build died before running a line of its own code:
///
/// ```text
/// > ferry --version
/// thread 'main' has overflowed its stack
/// ```
///
/// [`run`] is one `async fn` holding a match over every subcommand, so its state machine is
/// the union of every arm's locals - hundreds of them, several holding whole config structs.
/// A future's storage lives in its caller's frame, and Windows gives the main thread 1 MB
/// where Linux gives 8. So it overflowed on Windows and was fine everywhere the work was
/// being done. `--version` crashing is the tell that the command never mattered: the frame is
/// allocated on entry, so every invocation died.
///
/// `Box::pin(run(cli))` was the obvious fix and it does not work, which is worth recording
/// because it looks like it should: the future is *constructed on the stack* and then moved to
/// the heap, so the stack still has to hold it once. Verified on a real Windows machine, which
/// is the only reason this is not still in the tree.
///
/// Release builds survived either way, because optimisation shrinks the state machine. That is
/// not a margin to ship on - the next subcommand spends it, and the failure mode is a binary
/// that dies instantly on one platform with nothing but that one line to explain itself.
///
/// So the stack stops being the platform's decision. `main` spawns one thread with a size we
/// chose, builds the runtime there, and joins it. The cost is one thread; what it buys is that
/// the CLI's command surface can keep growing without a platform-specific cliff waiting for
/// it.
fn main() -> Result<()> {
    let worker = std::thread::Builder::new()
        .name("ferry".to_string())
        .stack_size(COMMAND_STACK)
        .spawn(|| {
            // OTLP export, when an endpoint is configured: spans from the agent loop go
            // to a collector so a fleet can be observed from one place. No-op otherwise.
            ferryman_ops::telemetry::init();
            // Parsed in here too: `Cli` is a large enum and clap's generated parser is not
            // small either, so keeping it inside the roomy stack costs nothing and removes
            // another thing that has to stay under 1 MB. `--version` and `--help` exit from
            // here, which is fine from any thread.
            let cli = Cli::parse();
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("start the async runtime")?
                .block_on(run(cli))
        })
        .context("start the command thread")?;
    // A panic in there has already printed its own message; propagate the failure without
    // wrapping it in a second, less informative one.
    match worker.join() {
        Ok(result) => result,
        Err(_) => bail!("ferry exited abnormally"),
    }
}

/// Everything the CLI does. Runs on the thread `main` sized for it.
async fn run(cli: Cli) -> Result<()> {
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
            headless,
            engine,
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
            // Before anything is written: a machine may not be configured to be a person.
            if let Some(name) = &agent_name {
                let start = workspace
                    .clone()
                    .unwrap_or(std::env::current_dir().context("read the current directory")?);
                refuse_person_as_machine(&start.join(".ferryman"), name)?;
            }
            let agent_name = if headless {
                let machine = ferryman_ops::identity::machine_name()?;
                let engine =
                    engine.unwrap_or_else(|| ferryman_ops::identity::engine_label(&command));
                let name = ferryman_ops::identity::headless_name(&machine, &engine);
                println!("unattended worker, joining as '{name}'");
                Some(name)
            } else {
                agent_name
            };
            let email = resolve_contact_email(email, as_json)?;
            // The operator seed is the one secret that has to survive, and its
            // recovery phrase must reach a human's terminal exactly once. It is
            // created here, before any project file is written, so the agent
            // identity `perform` is about to create derives from it (ADR 0016).
            // Under `--json` - or any run where nobody is at a terminal - it is
            // deliberately NOT created: there would be no one to write the phrase
            // down, and a seed whose phrase was never seen is worse than no seed.
            let interactive = !as_json && std::io::stdin().is_terminal();
            let (seed_report, phrase) = match ferryman_channel::licensing::machine_state_dir() {
                Some(dir) => ensure_operator_seed(&dir, interactive)?,
                None => (SeedReport::absent(), None),
            };
            let outcome = match enable::perform(enable::Request {
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
            }) {
                Ok(outcome) => outcome,
                Err(err) => {
                    // The seed may have been created a moment ago. Its phrase is the
                    // only copy that will ever exist, so make sure it reaches the
                    // operator even though the rest of enable failed below.
                    if let Some(phrase) = &phrase {
                        println!();
                        println!(
                            "  Your operator identity was created, and its recovery phrase is"
                        );
                        println!("  the only copy. Write it down before fixing the problem below:");
                        println!();
                        println!("    {phrase}");
                        println!();
                    }
                    return Err(err);
                }
            };
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
                report_enable_json(&outcome, dashboard.as_ref(), &seed_report)?;
            } else {
                report_enable_human(
                    &outcome,
                    dashboard.as_ref(),
                    &seed_report,
                    phrase.as_deref(),
                );
            }
        }
        Command::Doctor { workspace, json } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let report = ferryman_ops::doctor::examine(&start);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for check in &report.checks {
                    // Informational checks are marked as such rather than as
                    // failures: a machine without Syncthing still works locally.
                    let mark = match (check.ok, check.required) {
                        (true, _) => "ok",
                        (false, true) => "FIX",
                        (false, false) => "note",
                    };
                    println!("  {mark:<4} {:<17} {}", check.name, check.detail);
                }
                if report.ready {
                    println!("\nready: this machine can claim and run tasks");
                    println!("  next: ferry agent run        # does work");
                    println!("        ferry agent review     # judges results");
                } else {
                    println!(
                        "\nnot ready: fix the checks marked FIX above, then run \
                         'ferry doctor' again"
                    );
                }
            }
            if !report.ready {
                bail!("readiness checks failed");
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
        Command::Soak {
            workspace,
            json,
            out,
            send,
            dry_run,
        } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = ferryman_channel::route_for(&start)?;
            // The config is optional on purpose: a report must be obtainable from a machine
            // whose `agent.toml` is missing or broken, which is exactly when someone most
            // needs to file an issue.
            let config = ferryman_ops::agent::AgentConfig::load(&route.attachment).ok();
            let report = ferryman_ops::soak::report(&route, config.as_ref(), VERSION);
            let text = if json {
                serde_json::to_string_pretty(&report)?
            } else {
                ferryman_ops::soak::render(&report)
            };
            // Printed first, always. This is the consent step: the operator reads the whole
            // report before deciding to send it, so they never have to trust a claim about
            // what it contains.
            println!("{text}");
            if let Some(path) = out {
                std::fs::write(&path, &text)
                    .with_context(|| format!("write {}", path.display()))?;
                println!("written to {}", path.display());
            }
            // Sending is a separate, explicit act. `--dry-run` prints the same `report`
            // binding that `--send` transmits, so the two cannot drift - the property that
            // makes `ferry license checkin --dry-run` worth believing, applied here.
            if dry_run {
                println!("-- dry run: nothing was sent --");
                match soak_endpoint() {
                    Some(url) => println!("would POST the JSON form of the above to {url}"),
                    None => println!(
                        "no soak URL is set (FERRYMAN_SOAK_URL), so --send would do nothing"
                    ),
                }
            } else if send {
                match soak_endpoint() {
                    None => println!(
                        "no soak URL is set (FERRYMAN_SOAK_URL); nothing sent. \
                         Paste the report into an issue instead."
                    ),
                    Some(url) => {
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(10))
                            .build()
                            .context("build the HTTP client")?;
                        // A failure is reported and ignored, never fatal: a soak report is a
                        // favour to the maintainers and must not become a reason someone's
                        // fleet stops.
                        match client.post(&url).json(&report).send().await {
                            Ok(response) if response.status().is_success() => {
                                println!("sent to {url} — thank you");
                            }
                            Ok(response) => {
                                eprintln!("refused by {url}: {}", response.status());
                            }
                            Err(error) => {
                                eprintln!("could not be delivered (ignored): {error}");
                            }
                        }
                    }
                }
            } else if !json {
                println!(
                    "Nothing was sent. To help with soak testing, open an issue at\n  \
                     https://github.com/estejosh/ferryman/issues/new/choose\n\
                     and paste the report above, or email it to lafamiliahale@gmail.com.\n\
                     \n\
                     If you would rather it went straight to the maintainers, set\n  \
                     FERRYMAN_SOAK_URL=<url>\n\
                     and run 'ferry soak --send'. There is no setting that sends on its own."
                );
            }
        }
        Command::Operator { command } => operator_command(command)?,
        Command::Identity { command } => identity_command(command)?,
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
        Command::Cost { command } => cost_command(command)?,
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
        // `channel` is sync, and the Telegram bridge is a long-poll loop that needs the
        // runtime this function already has. Splitting it here keeps every other channel
        // command free of async it does not use.
        Command::Channel { command } => match command {
            Channel::Telegram {
                workspace,
                agent,
                default_to,
                map,
            } => telegram::bridge(workspace, agent, default_to, map).await?,
            rest => channel(rest)?,
        },
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
        Command::Orchestrator { command } => orchestrator_command(command)?,
        Command::Mcp { command } => match command {
            McpCommand::Serve { workspace } => mcp::serve(workspace)?,
            McpCommand::List { server } => mcp_client::list(&server)?,
            McpCommand::Call {
                server,
                tool,
                arguments,
            } => mcp_client::call(&server, &tool, arguments)?,
            McpCommand::Add {
                workspace,
                name,
                server,
            } => {
                let route = mcp::route_for(workspace)?;
                mcp::add_server(&route, &name, &server)?;
                println!("configured MCP server '{name}'; agents see its tools as {name}_<tool>");
            }
            McpCommand::Remove { workspace, name } => {
                let route = mcp::route_for(workspace)?;
                mcp::remove_server(&route, &name)?;
                println!("removed MCP server '{name}'");
            }
            McpCommand::Servers { workspace } => {
                let route = mcp::route_for(workspace)?;
                let servers = mcp::load_servers(&route)?;
                if servers.is_empty() {
                    println!(
                        "no external MCP servers configured — run `ferry mcp add <name> --server '<command>'`"
                    );
                } else {
                    for (name, spec) in servers {
                        println!("  {name:<20} {spec}");
                    }
                }
            }
        },
        Command::Ask {
            workspace,
            question,
            json,
        } => {
            let start =
                workspace.unwrap_or(std::env::current_dir().context("read the current directory")?);
            let route = ferryman_channel::route_for(&start)?;
            let claims = ferryman_channel::ask::ask(&route, &question)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "question": question,
                        "claims": claims,
                    }))?
                );
            } else {
                println!("{}", ferryman_channel::ask::render(&question, &claims));
            }
        }
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
                let identity = signing_identity(&route, &agent)?;

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
/// The contact address, asked for rather than demanded.
///
/// The licence conditions free production use on registering one, so `enable` does need
/// it. What it does not need is to be the reason a stranger's first command fails with
/// clap's default message and nothing else. At a terminal this asks, and says in one
/// sentence why it is asking. Anywhere else - `--json`, a pipe, an unattended agent -
/// it fails as before, but with an error that explains the condition and names the two
/// ways to satisfy it, because the caller there cannot answer a question.
fn resolve_contact_email(email: Option<String>, as_json: bool) -> Result<String> {
    use std::io::{IsTerminal, Write};
    if let Some(email) = email {
        let email = email.trim().to_string();
        if !email.is_empty() {
            return Ok(email);
        }
    }
    if as_json || !std::io::stdin().is_terminal() {
        bail!(
            "this deployment needs a contact address before it can be enabled.\n\
             \n\
             Free production use is conditioned on registering one (LICENSE section 3).\n\
             Nothing about your code, your channel or your work is ever sent - PRIVACY.md\n\
             lists the entire payload, and a downloaded release has no endpoint configured\n\
             at all, so it sends nothing until you set one yourself.\n\
             \n\
             Pass it, or set it once:\n\
             \n\
             ferry enable --email you@example.com\n\
             FERRYMAN_EMAIL=you@example.com ferry enable"
        );
    }
    println!(
        "Ferryman asks for a contact address once. Free production use is conditioned on\n\
         registering one, and it is the only way anyone can reach you about licensing.\n\
         Nothing about your code or your work is ever sent - see PRIVACY.md."
    );
    loop {
        print!("Your email: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer)? == 0 {
            bail!("no address given, and no terminal left to ask on");
        }
        let answer = answer.trim();
        // Deliberately the weakest check that catches a typo: an address is a thing a
        // human reads, not a thing this program validates. Refusing a legitimate address
        // because it does not match somebody's regex is worse than accepting a wrong one,
        // which costs an email nobody reads.
        if answer.contains('@') && !answer.starts_with('@') && !answer.ends_with('@') {
            return Ok(answer.to_string());
        }
        println!("That does not look like an email address. Try again, or press Ctrl-C.");
    }
}

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
    seed: &SeedReport,
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
            "agent_args": outcome.config.args,
            // Checked now rather than discovered at first-task time: a missing
            // engine is the most common reason a fresh setup does nothing.
            "command_found": outcome.command_found,
            "review": outcome.config.review.as_str(),
            "public_key": outcome.public_key,
            "already_configured": outcome.steps.iter().all(|s| !s.created),
            // The operator seed, without its phrase. The phrase is the one secret
            // that has to survive and must never reach a result payload: an agent
            // running `--json` is told here that the seed was created or found, and
            // never given the words. "absent" means the machine has no seed yet -
            // a human should run `ferry enable` at a terminal (or restore a phrase).
            "operator": {
                "seed": seed.state,
                "fingerprint": seed.fingerprint,
                "note": (seed.state == "absent").then_some(
                    "no operator identity yet - run 'ferry enable' at a terminal to create one, \
                     or 'ferry identity recover' to restore one"
                ),
            },
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
fn report_enable_human(
    outcome: &enable::Outcome,
    dashboard: Option<&DashboardOutcome>,
    seed: &SeedReport,
    phrase: Option<&str>,
) {
    // Identity first, then what changed on disk.
    //
    // This used to open with a list of eight files and put the agent's name and key
    // underneath them, which is the wrong way round for the one moment that decides
    // whether a stranger keeps going. The first thing a person wants after running
    // setup is not an inventory of what was written - it is to know that they are now
    // someone, with a name and a key, in a thing that has a shape. The files are still
    // here, below, for the reader who wants them.
    println!();
    println!("  You are '{}' on this machine.", outcome.agent);

    // The first run of all, in the same breath as the identity it belongs to: the
    // recovery phrase is the only copy that will ever exist, so it is printed once,
    // here, and never again. An existing seed is used silently - never re-displayed.
    if let Some(phrase) = phrase {
        println!();
        println!("  Your recovery phrase - the only copy, shown once:");
        println!();
        println!("    {phrase}");
        println!();
        println!("  It is the only secret that has to survive: this one phrase restores");
        println!("  every identity on this machine. Write it down and keep it safe.");
        println!("  Ferryman will not show it again.");
    }

    // The one fingerprint a person reads aloud to verify out of band, versus the
    // O(agents) fingerprints verification used to demand. Shown whenever a seed
    // exists - it is a public key, not a secret.
    if let Some(fingerprint) = &seed.fingerprint {
        println!();
        println!("  Operator fingerprint");
        println!("  {fingerprint}");
        println!("  This is how a colleague verifies, out of band, that they are talking");
        println!("  to you and not someone else.");
    } else if seed.state == "absent" {
        println!();
        println!("  No operator identity yet - run 'ferry enable' at a terminal to create");
        println!("  one, or 'ferry identity recover' to restore one.");
    }

    println!();
    println!("  Key      {}", outcome.public_key);
    println!(
        "           This is how every other machine will know your work is yours.\n\
         \x20          Nothing signs as you without it, and it never leaves this machine."
    );
    println!();
    println!("  Project  {}", outcome.project);
    println!(
        "  Engine   {} {}",
        outcome.config.command,
        outcome.config.args.join(" ")
    );
    println!("  Review   {}", outcome.config.review.as_str());
    if !outcome.command_found {
        println!(
            "  WARNING  '{}' is not on this machine's PATH - tasks would fail to \
             start. Install it, or edit command/args in .ferryman/agent.toml \
             (see docs/ENGINE_SETUP.md). Run 'ferry doctor' after fixing.",
            outcome.config.command
        );
    }
    println!();
    println!("  Written:");
    for step in &outcome.steps {
        println!(
            "    {:<16} {}  {}",
            step.what,
            if step.created { "created" } else { "present" },
            step.path.display()
        );
    }
    println!();
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
            // `--comms` and `--workspace` are mutually exclusive at the parser, so this
            // arm is the fleet and has no single project to speak of.
            workspace: _,
            comms: Some(comms),
            once,
            dry_run,
        } => {
            let fleet = agent::fleet_under(&comms)?;
            let report = worker_progress();
            for (path, why) in &fleet.skipped {
                // Named, not swallowed. A project missing from the served list is a
                // project whose orders will sit unread.
                report.warn(&format!("  not watching {}: {why}", path.display()));
            }
            if fleet.served.is_empty() {
                bail!(
                    "no Ferryman channels under {}. Each project's folder needs a \
                     .ferryman directory - run 'ferry enable' in it.",
                    comms.display()
                );
            }
            if dry_run {
                for (route, config) in &fleet.served {
                    let plan = agent::plan(route, config)?;
                    println!(
                        "{} as '{}' running '{}'",
                        route.project_id, plan.agent, config.command
                    );
                    for (id, what) in &plan.would_do {
                        println!("  {id}  {what}");
                    }
                }
                println!("nothing was claimed, written or sent");
                return Ok(());
            }
            // One worker per identity per channel. Two under one name resume each other's
            // claims and run the same order twice; see WorkerLock.
            let mut locks = Vec::new();
            let mut contested = Vec::new();
            for (route, config) in &fleet.served {
                match agent::WorkerLock::take(&route.attachment, &config.agent)? {
                    Some(lock) => locks.push(lock),
                    None => contested.push(route.project_id.clone()),
                }
            }
            if !contested.is_empty() {
                bail!(
                    "another worker on this machine is already watching {} as the same \
                     agent. Two workers under one identity resume each other's claims and \
                     run the same order twice - stop the other one first.",
                    contested.join(", ")
                );
            }
            report.info(&format!(
                "worker watching {} channel(s) under {}",
                fleet.served.len(),
                comms.display()
            ));
            for (route, config) in &fleet.served {
                report.info(&format!(
                    "  {} as '{}' running '{}'",
                    route.project_id, config.agent, config.command
                ));
            }
            // The shortest poll wins. A fleet paced by its slowest channel would leave the
            // one that asked for attention every ten seconds waiting five minutes.
            let poll = fleet
                .served
                .iter()
                .map(|(_, config)| config.poll)
                .min()
                .unwrap_or(std::time::Duration::from_secs(300));
            let mut fleet = fleet;
            loop {
                for (route, config) in &mut fleet.served {
                    match agent::work_once(route, config, &report).await {
                        Ok(0) => {}
                        Ok(count) => {
                            report.info(&format!("did {count} task(s) on {}", route.project_id));
                        }
                        // One project's failure must not stop the other eighteen being
                        // watched: a broken credential in one channel is not a reason to
                        // stop reading the rest.
                        Err(error) => report.warn(&format!(
                            "{} failed, will retry: {error:#}",
                            route.project_id
                        )),
                    }
                }
                if once {
                    break;
                }
                tokio::time::sleep(poll).await;
            }
        }
        Agent::Run {
            workspace,
            comms: None,
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
            let _lock = match agent::WorkerLock::take(&route.attachment, &config.agent)? {
                Some(lock) => lock,
                None => bail!(
                    "another worker on this machine is already watching {} as '{}'. Two \
                     workers under one identity resume each other's claims and run the \
                     same order twice - stop the other one first.",
                    route.project_id,
                    config.agent
                ),
            };
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
        Agent::Status { workspace, json } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let status = ferryman_ops::status::examine(&start)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            println!(
                "project {} · agent {} · runs '{}'",
                status.project, status.agent, status.engine
            );
            println!(
                "  worker     {}",
                if status.worker_alive {
                    "running".to_string()
                } else {
                    "not running - start with 'ferry agent run'".to_string()
                }
            );
            match &status.current_task {
                Some(task) => {
                    let beat = match task.heartbeat_age_secs {
                        Some(secs) => format!("heartbeat {secs}s ago"),
                        None => "no heartbeat yet".to_string(),
                    };
                    println!("  working    {} ({beat})", task.order_id);
                }
                None => println!("  working    nothing held right now"),
            }
            if let Some(reason) = &status.claim_blocked_reason {
                println!("  new work   waiting: {reason}");
            } else {
                println!("  new work   ready to claim");
            }
            if let Some(window) = &status.claim_window {
                println!("  hours      {window}");
            }
            println!(
                "  memory     {} MB available / keeps {} MB free",
                status
                    .memory_available_mb
                    .map(|mb| mb.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                status.min_free_ram_mb
            );
            if !status.engine_on_path {
                println!(
                    "  WARNING    '{}' is not on PATH - tasks would fail to start; \
                     run 'ferry doctor' for the fix",
                    status.engine
                );
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
    let confidence = confidence_by_agent(route.as_ref());

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
        // Signed as that agent, which means only the machine holding that agent's key can
        // record into its profile. Refusing here is the point: `load_or_create` would mint a
        // second key under a name the roster already knows, and every signature it made
        // would then read as an impostor to every other machine.
        let Some(route) = route.as_ref() else {
            bail!("recording into a profile needs a Ferryman channel; run this inside a project");
        };
        let identity = ferryman_channel::AgentIdentity::load_existing(name, &route.attachment)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no signing key for '{name}' on this machine, so its profile cannot be \
                     signed here. A profile is prompt text carried to every machine, so it is \
                     signed by the agent it belongs to - record this on {name}'s own machine, \
                     or use --agent with a name this machine holds a key for."
                )
            })?;
        record_agent_profile(bank_dir, name, &note, &identity)?;
        println!(
            "recorded into {}",
            ferryman_channel::memory::agent_profile_path(bank_dir, name).display()
        );
        println!();
    }

    // List mode: just the chooser, no shared memory.
    if list_agents {
        if !print_agent_list(bank.as_deref(), &confidence) {
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
        None => printed |= choose_agent(bank.as_deref(), &confidence),
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
/// Where `ferry soak --send` posts, when the operator has set one.
///
/// Unset means this build cannot send a soak report at all, which is the default and the
/// state every downloaded release is in. Deliberately an environment variable and not an
/// `agent.toml` key: a config file is something a project carries, and carrying it would
/// make a report get sent on a machine whose owner never chose to. This has to be set where
/// the command runs, by whoever runs it.
///
/// `off` is accepted as a synonym for unset, matching `FERRYMAN_CHECKIN_URL`, so a wrapper
/// script can disable it without unsetting the variable.
fn soak_endpoint() -> Option<String> {
    std::env::var("FERRYMAN_SOAK_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "off")
}

/// The signing key for a name the OPERATOR named, refusing rather than inventing one.
///
/// # Why this exists, and why it is a function rather than a rule
///
/// `AgentIdentity::load_or_create` mints a fresh key when none is on disk. That is correct in
/// exactly one place - `ferry channel join`, where this machine is establishing its own
/// identity for the first time - and wrong everywhere else, because everywhere else the name
/// came from `--agent`, `--to`, `--reviewer`, or was read out of the channel.
///
/// It was called in fifteen other places, and the consequence was not theoretical. Reproduced
/// during review: a peer holding nothing but the synced folder ran
/// `ferry channel master transfer bob`, which read the *current* master's name out of the
/// channel and called `load_or_create` on it - forging the master's key, overwriting
/// `master.json`, and printing "master role transferred to bob (disclaimed by alice)". Every
/// machine then failed `master status`, `lease` and `grants` with "signature does not verify",
/// and there was no way back: `init` said the project already had a master, and `transfer`
/// failed the signature check it had just broken.
///
/// The general rule: **a machine can only sign as an identity it holds the key for.** A
/// forged key is worse than a refusal, because a refusal is a message and a forged key is a
/// roster the whole fleet rejects.
///
/// This is a function so the rule has one place to live. Fifteen careful call sites is
/// fifteen chances for the sixteenth to be wrong.
/// Fold an agent name as it arrives from the operator, before anything compares it.
///
/// # Why this is a `value_parser` and not a rule
///
/// Same lesson as `signing_identity` directly below, learned the same way. The channel
/// folds names when it *writes* them, so the roster holds one `fang` however it was
/// typed - but the CLI then compared the operator's raw `--agent FANG` against that
/// folded roster with `==`, and told the operator that no such agent had joined while
/// listing `fang` in the very same sentence. Rewriting the four or five comparisons
/// that happen to exist today is how you get a sixth one wrong next month.
///
/// Attached to every argument that names an agent - `--agent`, `--to`, `--reviewer`,
/// `--name` on `expect` - so by the time any handler sees a name, it is already the one
/// spelling the channel uses. Nothing downstream has to remember.
fn agent_name(value: &str) -> Result<String, String> {
    let folded = ferryman_channel::canonical_agent_name(value);
    if folded.is_empty() {
        return Err("an agent name cannot be empty".to_string());
    }
    if !ferryman_channel::is_safe_component(&folded) {
        return Err(format!(
            "'{value}' is not a usable agent name: it must be letters, digits, '-', '_' or '.'"
        ));
    }
    Ok(folded)
}

/// Sign as `name`, or establish that signing unsigned is honest here.
///
/// # The distinction this exists to draw
///
/// Every signing site in the CLI was written as `if let Ok(identity) =
/// signing_identity(..)`, which computes the refusal and throws it away. The reasoning
/// was sound and is worth keeping: a fleet that has not adopted signing must keep
/// working, so a missing key cannot be fatal.
///
/// But that reasoning covers one case and was applied to two.
///
///   * Nobody in this channel has a published key. Unsigned is the only thing available
///     and everyone reads it as unsigned. Fine.
///   * The roster knows this sender AND carries a key for them, and this machine does
///     not hold it. Sending unsigned "from" them is claiming to be a person whose
///     signature every reader can check, while supplying none.
///
/// The second is what let `ferry channel send --from op` publish a message from a human
/// who was nowhere near it. Not a forgery - readers see `Unsigned` - but the fleet was
/// told something about who spoke, with nothing behind it, and nothing said so.
///
/// So: refuse when the roster can verify this name and we cannot produce it. Otherwise
/// carry on unsigned, exactly as before.
fn sign_as(
    route: &ferryman_channel::ProjectRoute,
    name: &str,
) -> Result<Option<ferryman_channel::AgentIdentity>> {
    match signing_identity(route, name) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) => {
            let known_key = ferryman_channel::read_agent_roster(&route.communications)
                .unwrap_or_default()
                .into_iter()
                .find(|agent| agent.name.eq_ignore_ascii_case(name))
                .and_then(|agent| agent.public_key)
                .is_some_and(|key| !key.is_empty());
            if known_key {
                return Err(error);
            }
            Ok(None)
        }
    }
}

/// Refuse to configure a machine to work as a person.
///
/// # Why this is worth a hard refusal
///
/// An operator identity is a human's: sealed under their password, opened by typing it.
/// A worker's identity is a machine's: a key on disk, usable with nobody present. They are
/// not two flavours of the same thing, and the difference only shows up later.
///
/// `ferry enable --agent operator` was run in eighteen projects. Nothing objected. What
/// followed: every worker in those channels looked for a machine key called `operator`,
/// found none, fell back to the sealed store, and asked for a password - on headless
/// boxes, with nobody there. A fleet spent its nights at a prompt. The configuration was
/// wrong at the moment it was written and stayed silent for as long as it took someone to
/// notice the machines were idle.
///
/// The operator issues work. The machine does it, as itself. Anything that blurs those two
/// produces a signature that says a person did something a machine did, which is also the
/// one claim this project's whole signing scheme exists to keep honest.
fn refuse_person_as_machine(attachment: &std::path::Path, name: &str) -> anyhow::Result<()> {
    let operators = ferryman_server::operators::OperatorStore::new(attachment);
    if !operators.exists(name) {
        return Ok(());
    }
    anyhow::bail!(
        "'{name}' is an operator identity on this machine - a person's, sealed under their \
         password - so a worker cannot sign as it without someone present to type that \
         password.\n\
         \n\
         A machine works under its own name. The operator issues the work; the machine \
         does it, as itself, and the signature says which.\n\
         \n\
         Leave --agent off to use this machine's own name."
    )
}

fn signing_identity(
    route: &ferryman_channel::ProjectRoute,
    name: &str,
) -> anyhow::Result<ferryman_channel::AgentIdentity> {
    if let Some(identity) = ferryman_channel::AgentIdentity::load_existing(name, &route.attachment)?
    {
        return Ok(identity);
    }
    // A human operator is not a machine, and their key is not stored like one.
    //
    // Machine keys sit in plaintext in `keys/<name>.key`, which is right for an unattended
    // agent: nobody is present to type a password at 3am. An operator is the opposite -
    // they are a *person*, they move between machines, and there IS someone present. So
    // their seed is sealed under their password in `operators/<name>.json`, and only their
    // password opens it.
    //
    // Both halves already existed; nothing joined them. The dashboard could unseal an
    // operator and the CLI could sign as a machine, so `ferry channel send --from op`
    // found no `keys/op.key`, and rather than refusing it published the message UNSIGNED.
    // That is the worst of the three possible answers: it is not a forgery, because a
    // reader sees `Unsigned` - but it is a message claiming to be from a person, carrying
    // no proof, and saying nothing about it. This project's own rule is that a refusal is
    // a message. Silently downgrading is a fourth option nobody chose.
    let operators = ferryman_server::operators::OperatorStore::new(&route.attachment);
    if operators.exists(name) {
        let password = operator_password(name)?;
        return operators.login(name, &password);
    }
    anyhow::bail!(
        "this machine holds no signing key for '{name}', so it cannot sign as '{name}'.\n\
         \n\
         If '{name}' is this machine, run 'ferry channel join --agent {name}' first.\n\
         If '{name}' is you, and your operator identity lives on another machine, carry it \
         here with 'ferry operator export --name {name}' there and 'ferry operator import' \
         here - the file is sealed under your password, so it is safe to move.\n\
         If '{name}' is another machine, run this command there - a key cannot be created \
         on demand, because a second key under a name the roster already knows makes every \
         signature it produces read as an impostor to every other machine."
    )
}

fn operator_command(command: Operator) -> anyhow::Result<()> {
    let here = |workspace: Option<PathBuf>| -> Result<ferryman_channel::ProjectRoute> {
        let start = match workspace {
            Some(path) => path,
            None => std::env::current_dir().context("read the current directory")?,
        };
        ferryman_channel::route_for(&start)
    };
    match command {
        Operator::Create {
            workspace,
            name,
            this_project_only,
        } => {
            let route = here(workspace)?;
            let store = ferryman_server::operators::OperatorStore::new(&route.attachment);
            let password = new_operator_password(&name)?;
            let identity = ferryman_server::operators::create_operator_identity_scoped(
                &route,
                &store,
                &name,
                &password,
                this_project_only,
            )?;
            println!("created operator '{}'", identity.name());
            println!("  public key  {}", identity.public_key_hex());
            if this_project_only {
                println!("  scope       this project only");
            } else {
                println!("  scope       every project on this machine");
            }
            println!("  published to the roster, so the fleet can verify what they sign");
            println!();
            println!("  the password is the only thing that opens this identity: there is no");
            println!("  reset, because nothing on any machine holds a copy of it.");
        }
        Operator::Export {
            workspace,
            name,
            out,
        } => {
            let route = here(workspace)?;
            let store = ferryman_server::operators::OperatorStore::new(&route.attachment);
            let sealed = store.export(&name)?;
            let path = out.unwrap_or_else(|| PathBuf::from(format!("{name}.ferryman-operator")));
            std::fs::write(&path, &sealed)?;
            // Owner-only even though it is sealed. The seal is one password away from a
            // signing identity the whole fleet trusts, and 600k PBKDF2 iterations is a
            // strong online policy and a weak offline one - so it should not be sitting
            // world-readable in a download directory while it waits to be carried.
            ferryman_channel::restrict_to_owner(&path)?;
            println!("wrote {}", path.display());
            println!("  sealed under your password; safe to carry, useless without it");
            println!(
                "  on the other machine:  ferry operator import --file {}",
                path.display()
            );
            println!("  delete it once imported - it is not a backup, your password is");
        }
        Operator::Import {
            workspace,
            file,
            this_project_only,
        } => {
            let route = here(workspace)?;
            let store = ferryman_server::operators::OperatorStore::new(&route.attachment);
            let sealed =
                std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            // Check the record against the roster BEFORE installing it.
            //
            // Fang asked for this explicitly and was right to. An operator record
            // whose public key disagrees with the roster is not a usable identity: every
            // signature it produces reads as `KeyChanged` on every other machine, and the
            // person finds out at the moment their approval is rejected rather than at
            // the moment they imported the wrong file. The roster is the fleet's opinion
            // of who this person is, so it is the thing worth checking against.
            let record = ferryman_server::operators::peek(&sealed)?;
            let roster = ferryman_channel::read_agent_roster(&route.communications)?;
            let known = roster
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(&record.name))
                .and_then(|a| a.public_key.clone())
                .filter(|key| !key.is_empty());
            if let Some(known) = &known
                && known != &record.public_key
            {
                anyhow::bail!(
                    "this file is operator '{}' with key {}, but the roster here already \
                     knows '{}' with key {}.\n\
                     \n\
                     Importing it would install an identity every other machine reads as \
                     KeyChanged. Export from the machine whose key the roster already \
                     carries, or settle which key is the real one first.",
                    record.name,
                    record.public_key,
                    record.name,
                    known
                )
            }
            let name = store.import(&sealed, this_project_only)?;
            println!("imported operator '{name}'");
            if this_project_only {
                println!("  for THIS project only; the rest of the machine is unchanged");
            } else {
                println!("  for every project on this machine, present and future");
            }
            println!("  this machine can now sign as '{name}' when you give the password");
            match known {
                Some(key) => println!("  matches the key the roster already trusts: {key}"),
                None => println!(
                    "  note: '{name}' is not in this project's roster yet, so signatures \
                     will read as UnknownSigner until it syncs"
                ),
            }
        }
        Operator::List { workspace } => {
            let route = here(workspace)?;
            let store = ferryman_server::operators::OperatorStore::new(&route.attachment);
            let names = store.names()?;
            if names.is_empty() {
                println!("this machine holds no operator identity for this project");
                println!("  carry yours here with 'ferry operator import --file <file>'");
            } else {
                for name in names {
                    // Where an identity comes from is the thing a person actually needs
                    // to know here: whether editing this project changes it, and whether
                    // it follows them to the next one.
                    let scope = if store.is_project_local(&name) {
                        "this project only"
                    } else {
                        "this machine"
                    };
                    println!("  {name:<20} {scope}");
                }
            }
        }
    }
    Ok(())
}

/// What `ferry enable` found or did about the operator seed, ready to report.
///
/// Carries the fingerprint - a public key, safe to print anywhere - but never the
/// phrase: the phrase is returned separately and only ever printed by the human
/// report, exactly once.
struct SeedReport {
    /// "created", "present", or "absent".
    state: &'static str,
    /// The operator fingerprint when a seed exists.
    fingerprint: Option<String>,
}

impl SeedReport {
    fn absent() -> Self {
        Self {
            state: "absent",
            fingerprint: None,
        }
    }
}

/// Make sure this machine has an operator seed, creating it when a person is at a
/// terminal and there is none yet (ADR 0016).
///
/// Returns a report for `ferry enable`'s output, and - only when a seed was created
/// just now, which implies interactive - the recovery phrase to show once. An existing
/// seed is used and never replaced, and its phrase is never re-displayed. A
/// non-interactive run never creates a seed: there would be no one to write the phrase
/// down, and a seed whose phrase was never seen is worse than no seed.
fn ensure_operator_seed(
    machine_dir: &std::path::Path,
    interactive: bool,
) -> Result<(SeedReport, Option<String>)> {
    use ferryman_channel::seed::OperatorSeed;
    if let Some(seed) = OperatorSeed::load(machine_dir)? {
        let report = SeedReport {
            state: "present",
            fingerprint: Some(seed.operator_fingerprint()?),
        };
        return Ok((report, None));
    }
    if !interactive {
        return Ok((SeedReport::absent(), None));
    }
    let seed = OperatorSeed::create_in(machine_dir)?;
    let report = SeedReport {
        state: "created",
        fingerprint: Some(seed.operator_fingerprint()?),
    };
    let phrase = ferryman_channel::seed::seed_to_phrase(seed.expose_bytes())?;
    Ok((report, Some(phrase)))
}

/// The `ferry identity` subcommands: the one fingerprint, and recovery from the phrase.
fn identity_command(command: Identity) -> Result<()> {
    match command {
        Identity::Show => identity_show(),
        Identity::Recover { force } => identity_recover(force),
    }
}

fn identity_show() -> Result<()> {
    use ferryman_channel::seed::OperatorSeed;
    let Some(dir) = ferryman_channel::licensing::machine_state_dir() else {
        bail!("this machine has no per-user state directory, so it cannot hold an operator seed");
    };
    match OperatorSeed::load(&dir)? {
        None => {
            println!("This machine has no operator identity yet.");
            println!();
            println!(
                "  To create one:  ferry enable           # at a terminal; write down the phrase"
            );
            println!("  To restore one: ferry identity recover  # from a phrase you already have");
        }
        Some(seed) => {
            println!("  Operator fingerprint");
            println!("  {}", seed.operator_fingerprint()?);
            println!();
            println!("  This is how a colleague verifies, out of band, that they are talking");
            println!("  to you and not someone else. One fingerprint covers every identity");
            println!("  this machine derives from its seed.");
            println!();
            println!("  Agent identities on this machine:");
            let identities = machine_identities(&dir, &seed)?;
            if identities.is_empty() {
                println!("    (none yet)");
            } else {
                for (name, derives) in identities {
                    let how = if derives {
                        "derives from the seed"
                    } else {
                        "does not derive - rotated, or minted before the seed existed"
                    };
                    println!("    {name:<20} {how}");
                }
            }
        }
    }
    Ok(())
}

/// Every signing identity in this machine's keystore, and whether it derives from the
/// seed. Returns (name, derives) sorted by name.
fn machine_identities(
    machine_dir: &std::path::Path,
    seed: &ferryman_channel::seed::OperatorSeed,
) -> Result<Vec<(String, bool)>> {
    let keys = machine_dir.join("keys");
    let Ok(entries) = std::fs::read_dir(&keys) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Signing keys are `name.key`; encryption keys are `name.enc.key` and are not
        // identities, so they are skipped here.
        if !file_name.ends_with(".key") || file_name.ends_with(".enc.key") {
            continue;
        }
        let name = file_name.trim_end_matches(".key").to_owned();
        let Ok(encoded) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(bytes) = hex::decode(encoded.trim()) else {
            continue;
        };
        let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
            continue;
        };
        let actual = ferryman_channel::AgentIdentity::from_seed(&name, bytes).public_key_hex();
        let derives = match seed.signing_identity(&name) {
            Ok(derived) => derived.public_key_hex() == actual,
            Err(_) => false,
        };
        out.push((name, derives));
    }
    out.sort();
    Ok(out)
}

fn identity_recover(force: bool) -> Result<()> {
    use ferryman_channel::seed::OperatorSeed;
    let Some(dir) = ferryman_channel::licensing::machine_state_dir() else {
        bail!("this machine has no per-user state directory, so it cannot hold an operator seed");
    };
    let existing = OperatorSeed::load(&dir)?;
    if existing.is_some() && !force {
        confirm_replacing_seed(&dir)?;
    }
    // Read and validate the phrase BEFORE touching the existing seed, so a typo can
    // never cost a machine its current identity.
    let mut bytes = None;
    for _ in 0..3 {
        let phrase = read_recovery_phrase()?;
        match ferryman_channel::seed::phrase_to_seed(&phrase) {
            Ok(valid) => {
                bytes = Some(valid);
                break;
            }
            Err(err) => eprintln!("{err:#}\n"),
        }
    }
    let Some(bytes) = bytes else {
        bail!("could not read a valid recovery phrase; nothing was changed");
    };
    let seed = OperatorSeed::from_bytes(bytes);
    // A confirmed replacement moves the old seed aside rather than deleting it, so the
    // operator can change their mind. `restore_in` then finds no file and writes fresh.
    if existing.is_some() {
        move_seed_aside(&dir)?;
    }
    seed.restore_in(&dir)?;
    println!("Restored the operator identity from your recovery phrase.");
    println!();
    println!("  Operator fingerprint");
    println!("  {}", seed.operator_fingerprint()?);
    println!();
    println!("  If this matches the fingerprint you wrote down, you are yourself again.");
    println!("  If it does not, you typed a different phrase - run `ferry identity recover`");
    println!("  again.");
    Ok(())
}

/// Confirm, at a terminal, that the operator means to replace an existing seed.
///
/// Refusing is the default: replacing a seed does not re-key anything already on disk,
/// but it changes what every FUTURE identity derives to, so the old phrase would restore
/// strangers. The refusal names the remedy rather than just saying no.
fn confirm_replacing_seed(dir: &std::path::Path) -> Result<()> {
    let path = ferryman_channel::seed::OperatorSeed::path_in(dir);
    if !std::io::stdin().is_terminal() {
        bail!(
            "an operator seed already exists at {} - refusing to replace it.\n\
             \n\
             Replacing a seed changes what every future identity on this machine derives\n\
             to, and the old phrase would then restore strangers. If you are restoring this\n\
             machine from its recovery phrase and mean to replace the existing seed, run:\n\
             \n\
             ferry identity recover --force\n\
             \n\
             That moves the existing seed aside first (it is not deleted).",
            path.display()
        );
    }
    use std::io::Write;
    print!(
        "An operator seed already exists at {}.\n\
         Replacing it changes what every future identity derives to. Replace it? [y/N] ",
        path.display()
    );
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("nothing changed; the existing seed is still in place");
    }
    Ok(())
}

/// Read the recovery phrase from the operator's terminal, hidden.
///
/// Hidden for the same reason the operator password is: a phrase echoed into a pipe or a
/// scrollback is the one secret that forges every identity, and `rpassword` reads the
/// terminal directly rather than stdin.
fn read_recovery_phrase() -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "restoring needs the recovery phrase typed at a terminal, and there is none \
             here - run `ferry identity recover` yourself"
        );
    }
    let phrase = rpassword::prompt_password("Recovery phrase (24 words): ")?;
    let phrase = phrase.trim().to_string();
    if phrase.is_empty() {
        bail!("no phrase given");
    }
    Ok(phrase)
}

/// Move an existing seed aside, preserving it, before a confirmed replacement writes a
/// new one. `restore_in` refuses to clobber, so this is the deliberate gap-closing step.
fn move_seed_aside(dir: &std::path::Path) -> Result<()> {
    let path = ferryman_channel::seed::OperatorSeed::path_in(dir);
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let aside = dir.join(format!("operator.seed.before-{unix}.bak"));
    std::fs::rename(&path, &aside)
        .with_context(|| format!("move {} to {}", path.display(), aside.display()))?;
    Ok(())
}

/// The password for an operator being created now.
///
/// Typed twice when a person is present, because there is no recovery: nothing on any
/// machine holds a copy of this, so a typo does not lock you out of a service that can
/// mail you a reset - it destroys an identity before it has signed anything.
///
/// Read once from the environment when it is set, and NOT confirmed, because there is
/// nothing to confirm against: a scripted caller cannot mistype twice differently, and
/// asking a machine to repeat itself only turns a headless setup into a hang. It is the
/// same variable the signing path reads, so an unattended machine has one answer to
/// "where does the operator password come from" rather than two.
///
/// `rpassword` reads the terminal directly rather than stdin - correct, because a
/// password echoed into a pipe is a password in a log - which is also why the environment
/// variable is the only way to reach this without a human. Found by trying to script it,
/// and watching it hang.
fn new_operator_password(name: &str) -> anyhow::Result<String> {
    if let Ok(password) = std::env::var("FERRYMAN_OPERATOR_PASSWORD")
        && !password.is_empty()
    {
        return Ok(password);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "creating operator '{name}' needs a password, and there is no terminal to ask \
             on. Set FERRYMAN_OPERATOR_PASSWORD to create one unattended."
        )
    }
    let first = rpassword::prompt_password(format!("password for new operator '{name}': "))?;
    let second = rpassword::prompt_password("repeat it: ")?;
    if first != second {
        anyhow::bail!("the passwords did not match; nothing was created")
    }
    Ok(first)
}

/// The operator's password, from the environment when unattended, from the terminal when
/// a person is present.
///
/// The environment variable exists because Ferryman's whole point is loops that run with
/// nobody watching, and a prompt in that setting is a hang rather than a question. It is
/// read once, here, and never placed in a child process's environment - `send` signs in
/// this process and passes on the signature, not the secret.
fn operator_password(name: &str) -> anyhow::Result<String> {
    if let Ok(password) = std::env::var("FERRYMAN_OPERATOR_PASSWORD")
        && !password.is_empty()
    {
        return Ok(password);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "signing as operator '{name}' needs their password, and there is no terminal to \
             ask on. Set FERRYMAN_OPERATOR_PASSWORD for unattended use."
        )
    }
    Ok(rpassword::prompt_password(format!(
        "password for operator '{name}': "
    ))?)
}

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

/// Measured confidence per agent identity, keyed by the slugified agent name so it
/// matches the roster's profile file names. Built from live review outcomes only;
/// benchmarks carry no identity and are excluded.
fn confidence_by_agent(
    route: Option<&ferryman_channel::ProjectRoute>,
) -> std::collections::BTreeMap<String, String> {
    let Some(route) = route else {
        return Default::default();
    };
    let Ok(stats) = ferryman_channel::learning::agent_stats(route) else {
        return Default::default();
    };
    stats
        .into_iter()
        .map(|s| (ferryman_channel::memory::slugify(&s.engine), s.describe()))
        .collect()
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
fn record_agent_profile(
    bank: &std::path::Path,
    agent: &str,
    note: &str,
    identity: &ferryman_channel::AgentIdentity,
) -> Result<()> {
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
    ferryman_channel::memory::append_agent_profile(bank, agent, &line, identity)
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

/// Print the chooser: every agent that has a profile, with a one-line summary and
/// (when measured) its confidence. Returns true when at least one profile exists.
fn print_agent_list(
    bank: Option<&std::path::Path>,
    confidence: &std::collections::BTreeMap<String, String>,
) -> bool {
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
        let conf = confidence
            .get(agent)
            .map(|c| format!("  [{c}]"))
            .unwrap_or_default();
        if summary.is_empty() {
            println!("  {agent}{conf}");
        } else {
            println!("  {agent:<16} {summary}{conf}");
        }
    }
    println!();
    true
}

/// The interactive chooser: list every agent that has memory, then — on a
/// terminal — ask which one to load. A piped or headless caller just gets the
/// list and no prompt. Returns true when at least one profile was listed.
fn choose_agent(
    bank: Option<&std::path::Path>,
    confidence: &std::collections::BTreeMap<String, String>,
) -> bool {
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
        let conf = confidence
            .get(agent)
            .map(|c| format!("  [{c}]"))
            .unwrap_or_default();
        if summary.is_empty() {
            println!("  {}  {agent}{conf}", index + 1);
        } else {
            println!("  {}  {agent:<16} {summary}{conf}", index + 1);
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

fn cost_command(command: Cost) -> Result<()> {
    match command {
        Cost::Rates => {
            println!(
                "  {:<22} {:>10} {:>14}",
                "engine family", "prompt $/M", "completion $/M"
            );
            for (family, prompt, completion) in ferryman_channel::cost::published_rates() {
                println!("  {family:<22} {prompt:>10.2} {completion:>14.2}");
            }
            println!();
            println!("  list prices, dollars per million tokens; unknown engines fall back");
            println!("  to the default row. `ferry cost plan` prices a whole project.");
        }
        Cost::Plan {
            prompt,
            prompt_file,
            tasks,
            workspace,
        } => {
            let prompt = resolve_prompt(prompt, prompt_file)?;
            let (tasks, prompt_tokens, completion_tokens) =
                ferryman_channel::cost::estimate_project_tokens(&prompt, tasks);
            let route = match &workspace {
                Some(path) => Some(ferryman_channel::route_for(path)?),
                None => None,
            };
            let rates = match &route {
                Some(r) => ferryman_channel::cost::Rates::load(r),
                None => ferryman_channel::cost::Rates::defaults(),
            };
            println!("project scope  ~{tasks} tasks");
            println!(
                "               ~{prompt_tokens} prompt + ~{completion_tokens} completion tokens total \
                 ({} + {} per task, ×{} revisions)",
                ferryman_channel::cost::PROMPT_TOKENS_PER_TASK,
                ferryman_channel::cost::COMPLETION_TOKENS_PER_TASK,
                ferryman_channel::cost::REVISION_FACTOR
            );
            println!();
            println!("  {:<22} {:>12}  quality", "engine", "est. cost");
            for (family, _, _) in ferryman_channel::cost::published_rates() {
                let key = family.split_whitespace().next().unwrap_or(family);
                let cost = ferryman_channel::cost::project_cost(
                    &rates,
                    key,
                    prompt_tokens,
                    completion_tokens,
                );
                let (quality, measured, total, accepted) = match &route {
                    Some(r) => ferryman_channel::cost::effective_quality(r, &rates, key),
                    None => (rates.quality_for(key), false, 0, 0),
                };
                let qs = if measured {
                    format!(
                        "{} ({quality:.2} · {accepted}/{total} accepted)",
                        ferryman_channel::cost::quality_label(quality)
                    )
                } else {
                    format!(
                        "{} ({quality:.2})",
                        ferryman_channel::cost::quality_label(quality)
                    )
                };
                println!("  {family:<22} ${cost:>11.2}  {qs}");
            }
            println!();
            println!("  an estimate, not a bid — recorded spend is in `ferry cost project`.");
            println!("  quality is measured confidence where this project has run that engine,");
            println!("  and a static model-capability hint otherwise.");
        }
        Cost::Project { workspace } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = ferryman_channel::route_for(&start)?;
            let costs = ferryman_channel::cost::engine_costs(&route)?;
            if costs.is_empty() {
                println!("no recorded usage yet; runs and reviews populate this over time");
                return Ok(());
            }
            let mut total = 0.0;
            println!(
                "  {:<16} {:>5} {:>8} {:>12} {:>12} {:>10}",
                "engine", "runs", "accepted", "prompt tok", "completion", "cost"
            );
            for c in &costs {
                total += c.estimated_cost_usd;
                println!(
                    "  {:<16} {:>5} {:>8} {:>12} {:>12} ${:>9.4}",
                    c.engine,
                    c.runs,
                    c.accepted,
                    c.prompt_tokens,
                    c.completion_tokens,
                    c.estimated_cost_usd
                );
            }
            println!(
                "  {:<16} {:>5} {:>8} {:>12} {:>12} ${:>9.4}",
                "total", "", "", "", "", total
            );
        }
    }
    Ok(())
}

/// Resolve a prompt from --prompt, --prompt-file, or piped stdin, in that order.
fn resolve_prompt(prompt: Option<String>, prompt_file: Option<PathBuf>) -> Result<String> {
    if let Some(prompt) = prompt {
        return Ok(prompt);
    }
    if let Some(path) = prompt_file {
        return std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()));
    }
    if !std::io::stdin().is_terminal() {
        use std::io::Read;
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        if !text.trim().is_empty() {
            return Ok(text);
        }
    }
    bail!("no prompt given; use --prompt, --prompt-file, or pipe one in on stdin")
}

fn read_secret_value(name: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        let value = rpassword::prompt_password(format!("secret value for '{name}': "))?;
        if value.is_empty() {
            bail!("a secret value cannot be empty");
        }
        return Ok(value);
    }
    use std::io::Read;
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    let value = value.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() {
        bail!("a secret value cannot be empty");
    }
    Ok(value)
}

fn secret_command(route: &ferryman_channel::ProjectRoute, command: SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Set { name, to, signer } => {
            let signer_name = match signer {
                Some(s) => s,
                None => ferryman_ops::identity::resolve(None, &route.attachment)?,
            };
            // Signing is not optional for a secret: an unsigned envelope is a
            // forged one. `signing_identity` refuses when this machine cannot
            // sign as the named identity rather than silently downgrading.
            let identity = signing_identity(route, &signer_name)?;
            let value = read_secret_value(&name)?;
            let recipients: Vec<String> = to
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            let path = ferryman_channel::secrets::set_secret(
                route,
                &identity,
                &name,
                &value,
                &recipients,
            )?;
            println!("sealed '{name}' for {} recipient(s)", recipients.len());
            println!("  written to {}", path.display());
            println!("  signed by '{signer_name}'");
        }
        SecretCommand::List => {
            let summaries = ferryman_channel::secrets::list_secrets(route)?;
            if summaries.is_empty() {
                println!("no secrets in this channel");
                return Ok(());
            }
            for s in summaries {
                println!(
                    "{:<24} -> {}  [{}]  by {}  {}",
                    s.name,
                    s.recipients.join(","),
                    s.signature,
                    s.signed_by.as_deref().unwrap_or("nobody"),
                    s.created_at
                );
            }
        }
        SecretCommand::Get { name } => {
            let agent = ferryman_ops::identity::resolve(None, &route.attachment)?;
            let Some(identity) = ferryman_channel::secrets::EncryptionIdentity::load_existing(
                &agent,
                &route.attachment,
            )?
            else {
                bail!(
                    "this machine's agent ('{agent}') has no encryption key; \
                     run 'ferry channel join' on this machine first"
                );
            };
            let value = ferryman_channel::secrets::open_secret(route, &name, &identity)?;
            println!("{value}");
        }
        SecretCommand::Rm { name } => {
            if ferryman_channel::secrets::remove_secret(route, &name)? {
                println!("removed secret '{name}'");
            } else {
                println!("no secret named '{name}'");
            }
        }
    }
    Ok(())
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
        Channel::Secret { workspace, command } => {
            let route = here(workspace)?;
            secret_command(&route, command)?;
        }
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

        Channel::Seat {
            comms,
            agent,
            role,
            dry_run,
        } => {
            // `fleet_under` deliberately excludes a channel whose configured agent has
            // no key there. That is exactly the state `seat` exists to repair, so using
            // the fleet's *served* list here made the repair command skip its targets.
            // Discover routable channels directly; a malformed channel is still named
            // and skipped, but a valid channel with no local identity remains eligible.
            let mut paths: Vec<PathBuf> = std::fs::read_dir(&comms)
                .with_context(|| format!("read {}", comms.display()))?
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.join(".ferryman").is_dir())
                .collect();
            paths.sort();
            let mut routes = Vec::new();
            for path in paths {
                match ferryman_channel::route_for(&path) {
                    Ok(route) => routes.push(route),
                    Err(error) => println!("  skipping {}: {error:#}", path.display()),
                }
            }
            if routes.is_empty() {
                bail!("no Ferryman channels under {}", comms.display());
            }
            // Whose key, resolved once against a channel that has one. Resolving per
            // channel would let a machine seat two different names in one pass.
            let name = ferryman_ops::identity::resolve(agent, &routes[0].attachment)?;
            let Some(identity) = routes.iter().find_map(|route| {
                ferryman_channel::AgentIdentity::load_existing(&name, &route.attachment)
                    .ok()
                    .flatten()
            }) else {
                bail!(
                    "this machine holds no key for '{name}' in any channel under {}. Join \
                     once, in any one of them, and then seat it in the rest - a key cannot \
                     be created here, because a second key under a name the roster already \
                     knows makes every signature it produces read as an impostor.",
                    comms.display()
                )
            };
            println!("seating '{name}' ({})", identity.public_key_hex());
            let mut seated = 0;
            for route in &routes {
                let held =
                    ferryman_channel::AgentIdentity::load_existing(&name, &route.attachment)?;
                if held.is_some() {
                    println!("  {}  already has it", route.project_id);
                    continue;
                }
                if dry_run {
                    println!("  {}  would seat and publish", route.project_id);
                    continue;
                }
                let published = ferryman_channel::AgentRoute {
                    name: name.clone(),
                    role: role.clone(),
                    capabilities: Vec::new(),
                    public_key: None,
                    encryption_key: None,
                };
                match identity.seat_in(&route.attachment).and_then(|()| {
                    ferryman_channel::register_agent_key(route, &published, &identity)
                }) {
                    Ok(_) => {
                        println!("  {}  seated and published", route.project_id);
                        seated += 1;
                    }
                    // Named and stepped over. The case that fails here is a roster that
                    // already knows this name under another key, which is a conflict worth
                    // seeing rather than a reason to abandon the other channels.
                    Err(error) => println!("  {}  refused: {error}", route.project_id),
                }
            }
            if dry_run {
                println!("nothing was written");
            } else {
                println!("seated in {seated} channel(s)");
            }
        }
        Channel::Retire { comms, agent } => {
            // Default to the folder this channel lives in: running `ferry channel retire`
            // from inside a project should find the whole fleet, not just this project.
            let comms = comms.unwrap_or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|cwd| cwd.parent().map(|parent| parent.to_path_buf()))
                    .unwrap_or_else(|| PathBuf::from("."))
            });
            let fleet = ferryman_ops::agent::fleet_under(&comms)?;
            if fleet.served.is_empty() {
                bail!("no Ferryman channels under {}", comms.display());
            }
            // Refuse while that worker is alive on this machine. Retiring is for a holder
            // that is gone, not one that is mid-task.
            let mut live = Vec::new();
            for (route, _) in &fleet.served {
                if ferryman_ops::agent::worker_alive(&route.attachment, &agent) {
                    live.push(route.project_id.clone());
                }
            }
            if !live.is_empty() {
                bail!(
                    "refusing to retire '{agent}': a worker is alive on this machine in {}",
                    live.join(", ")
                );
            }
            let mut released = 0;
            let mut tasks = 0;
            for (route, _) in &fleet.served {
                // The releaser is this machine, resolved the same way every other
                // command resolves an acting identity - so the record says who retired
                // the name, not merely that someone did.
                let releaser = ferryman_ops::identity::resolve(None, &route.attachment)?;
                let identity = signing_identity(route, &releaser)?;
                for task in ferryman_channel::list_tasks(route)? {
                    if task.holder() != Some(agent.as_str()) {
                        continue;
                    }
                    // Only a claim that is actually holding the task - no result yet - is
                    // released. A claim beside a finished task is history, not a hold.
                    if task.latest_revision().is_some() {
                        continue;
                    }
                    tasks += 1;
                    match ferryman_channel::release_claim(
                        route,
                        &task.order.id,
                        &agent,
                        &releaser,
                        "retired",
                        &identity,
                    ) {
                        Ok(_) => {
                            println!(
                                "  {}: released {}'s claim on {}",
                                route.project_id, agent, task.order.id
                            );
                            released += 1;
                        }
                        Err(error) => {
                            println!(
                                "  {}: refused {}: {error:#}",
                                route.project_id, task.order.id
                            );
                        }
                    }
                }
            }
            println!("retired '{agent}': released {released} of {tasks} held claim(s)");
        }
        Channel::Join {
            workspace,
            name,
            role,
            capabilities,
            mcp,
        } => {
            let route = here(workspace)?;
            // Joining is where a machine takes a name. The same rule as `enable`: it may
            // not take a person's.
            if let Some(name) = &name {
                refuse_person_as_machine(&route.attachment, name)?;
            }
            let agent_name = ferryman_ops::identity::resolve(name, &route.attachment)?;
            // The encryption key is the recipient half of sealed secrets: X25519,
            // kept beside the signing key, never synced. Generated at join so this
            // machine can be a recipient the moment it is registered.
            let encryption = ferryman_channel::secrets::EncryptionIdentity::load_or_create(
                &agent_name,
                &route.attachment,
            )?;
            let agent = ferryman_channel::AgentRoute {
                name: agent_name,
                role,
                capabilities: {
                    let mut caps: Vec<String> = capabilities
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToString::to_string)
                        .collect();
                    if mcp
                        && !caps
                            .iter()
                            .any(|c| c == ferryman_channel::discovery::MCP_CAPABILITY)
                    {
                        caps.push(ferryman_channel::discovery::MCP_CAPABILITY.to_string());
                    }
                    caps
                },
                public_key: None,
                encryption_key: Some(encryption.public_key_hex()),
            };
            // The private key is created here and stays in the attachment, which is
            // machine-local and outside the folder Syncthing carries. Only the public
            // half is published.
            //
            // This is the ONLY place in the CLI that may create a key, and the only one that
            // still calls `load_or_create`. Joining is by definition the act of establishing
            // this machine's own identity; every other command signs as an identity that must
            // already exist, and uses `signing_identity` so a missing key is a refusal rather
            // than a forgery. `register_agent_key` refuses to republish a name under a
            // different key, so joining twice cannot silently take a name over either.
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

        Channel::Expect {
            workspace,
            name,
            role,
            capabilities,
            mcp,
        } => {
            let route = here(workspace)?;
            let mut capabilities: Vec<String> = capabilities
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect();
            if mcp
                && !capabilities
                    .iter()
                    .any(|c| c == ferryman_channel::discovery::MCP_CAPABILITY)
            {
                capabilities.push(ferryman_channel::discovery::MCP_CAPABILITY.to_string());
            }
            let path =
                ferryman_channel::register_expected_agent(&route, &name, &role, &capabilities)?;
            println!("reserved '{name}' as {role}; it can now receive messages");
            println!("  written to {}", path.display());
            println!("  when the real '{name}' registers, its key binds to this name");
        }

        Channel::Agents { workspace, json } => {
            let route = here(workspace)?;
            if json {
                let manifest = ferryman_channel::discovery::manifest(&route)?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                if route.agents.is_empty() {
                    println!("no agents registered yet - run `ferry channel join`");
                }
                let claimants = ferryman_channel::discovery::mcp_agents(&route);
                if claimants.len() > 1 {
                    eprintln!(
                        "warning: {} agents claim the mcp capability ({}); '{}' is the effective MCP agent",
                        claimants.len(),
                        claimants
                            .iter()
                            .map(|a| a.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        ferryman_channel::discovery::mcp_agent(&route)
                            .map(|a| a.name.as_str())
                            .unwrap_or("")
                    );
                }
                for agent in &route.agents {
                    println!(
                        "  {:<20} role={:<12} {}{}",
                        agent.name,
                        agent.role,
                        if ferryman_channel::discovery::is_mcp(agent) {
                            "mcp "
                        } else {
                            ""
                        },
                        agent.capabilities.join(",")
                    );
                }
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
            if let Some(identity) = sign_as(&route, &sender)? {
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
                // Case-insensitive against what is STORED: messages written before names
                // were folded carry whatever spelling their sender used, and they are
                // still addressed to this agent.
                .filter(|m| m.recipient.eq_ignore_ascii_case(&agent) || m.recipient == "all")
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
            task_file,
            requires_review,
            require,
            requires_approval,
            depends_on,
        } => {
            let route = here(workspace)?;
            let issuer = ferryman_ops::identity::resolve(agent, &route.attachment)?;
            let task = match (task, task_file) {
                (Some(task), _) => task,
                (None, Some(path)) if path.as_os_str() == "-" => {
                    let mut buffer = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)
                        .context("read the order from standard input")?;
                    buffer
                }
                (None, Some(path)) => std::fs::read_to_string(&path)
                    .with_context(|| format!("read the order from {}", path.display()))?,
                // clap's `required_unless_present` makes this unreachable; refusing an
                // empty order beats issuing one nobody can act on.
                (None, None) => bail!("give the work with --task or --task-file"),
            };
            if task.trim().is_empty() {
                bail!("an order with no work in it cannot be acted on")
            }
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
            if let Some(identity) = sign_as(&route, &issuer)? {
                identity.sign_order(&mut order);
            }
            let path = ferryman_channel::issue_order(&route, &order)?;
            if let Some(identity) = sign_as(&route, &issuer)? {
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
            let identity = signing_identity(&route, &issuer)?;
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
            let identity = signing_identity(&route, &issuer)?;
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
            let identity = signing_identity(&route, &issuer)?;
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
                            ferryman_channel::TaskState::Stale { by, .. } => {
                                format!("held by {by}, but its heartbeat has lapsed")
                            }
                            ferryman_channel::TaskState::Offered { to } => {
                                format!("addressed to {to}, who has not picked it up")
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
            if let Some(identity) = sign_as(&route, &agent)? {
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
            if let Some(identity) = sign_as(&route, &reviewer)? {
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
                println!("  {:<16} {:>6}  confidence", "engine", "total");
                for s in &stats {
                    println!("  {:<16} {:>6}  {}", s.engine, s.total, s.describe());
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
                // Why it is not being picked up, when the state alone does not say.
                //
                // `Offered` means "addressed to that machine", not "ready". An order
                // held back by `--depends-on` reads exactly like one a worker is
                // ignoring, and an operator watching a queue cannot tell the difference
                // - I could not, and I wrote the order. The state is the truth about
                // the claim; this line is the truth about whether anything will happen.
                if matches!(
                    task.state(),
                    ferryman_channel::TaskState::Open | ferryman_channel::TaskState::Offered { .. }
                ) && !ferryman_channel::dependencies_satisfied(&route, &task.order)?
                {
                    let waiting: Vec<&str> = task
                        .order
                        .depends_on
                        .iter()
                        .filter(|id| {
                            !matches!(
                                ferryman_channel::read_task(&route, id).map(|t| t.state()),
                                Ok(ferryman_channel::TaskState::Accepted
                                    | ferryman_channel::TaskState::Done)
                            )
                        })
                        .map(String::as_str)
                        .collect();
                    println!("               waiting on {}", waiting.join(", "));
                }
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
                    let identity = signing_identity(&route, &master)?;
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
                    let identity = signing_identity(&route, &current)?;
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
                    let identity = signing_identity(&route, &current)?;
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
        // Dispatched in `run`, which has the async runtime its long poll needs.
        Channel::Telegram { .. } => {
            bail!("internal: the telegram bridge is dispatched before this point")
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
                    let identity = signing_identity(&route, &master_name)?;
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
                LeaseAction::Grant {
                    workspace: _,
                    agent,
                    to,
                    scope,
                    resource,
                    minutes,
                } => {
                    // Grants are signed by their owner, not necessarily the
                    // master - that is what makes them usable for personal
                    // agents and vault secrets.
                    let name = ferryman_ops::identity::resolve(agent, &route.attachment)?;
                    let identity = signing_identity(&route, &name)?;
                    let scopes: Vec<String> = scope
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_string)
                        .collect();
                    if scopes.is_empty() {
                        bail!("a grant with no scopes grants nothing; pass --scope");
                    }
                    let token = ferryman_channel::lease::issue_grant(
                        &route,
                        &identity,
                        &to,
                        scopes,
                        resource.as_deref(),
                        chrono::Duration::minutes(minutes),
                    )?;
                    println!(
                        "granted [{}] on {} until {}  grant {}",
                        token.scope.join(","),
                        token.issued_to,
                        token.expires_at.to_rfc3339(),
                        token.grant_id.as_deref().unwrap_or("?")
                    );
                    println!(
                        "  renew with: ferry channel lease renew --to {} --grant {} --agent {}",
                        token.issued_to,
                        token.grant_id.as_deref().unwrap_or("?"),
                        identity.name()
                    );
                }
                LeaseAction::Renew {
                    workspace: _,
                    agent,
                    to,
                    grant,
                    minutes,
                } => {
                    let name = ferryman_ops::identity::resolve(agent, &route.attachment)?;
                    let identity = signing_identity(&route, &name)?;
                    let token = ferryman_channel::lease::renew_grant(
                        &route,
                        &identity,
                        &to,
                        &grant,
                        chrono::Duration::minutes(minutes),
                    )?;
                    println!(
                        "renewed: {} holds [{}] until {}",
                        token.issued_to,
                        token.scope.join(","),
                        token.expires_at.to_rfc3339()
                    );
                }
                LeaseAction::Revoke {
                    workspace: _,
                    agent,
                    to,
                    grant,
                    reason,
                } => {
                    let name = ferryman_ops::identity::resolve(agent, &route.attachment)?;
                    let identity = signing_identity(&route, &name)?;
                    ferryman_channel::lease::revoke_grant(
                        &route,
                        &identity,
                        &to,
                        &grant,
                        reason.as_deref(),
                    )?;
                    println!(
                        "revoked {grant} on {to}. Expiry remains the bound everywhere else; \
                         this record ends it wherever it is visible."
                    );
                }
                LeaseAction::List { workspace: _, json } => {
                    let listed = ferryman_channel::lease::list_grants(&route)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&listed)?);
                        return Ok(());
                    }
                    if listed.is_empty() {
                        println!("no access grants on this channel");
                        return Ok(());
                    }
                    for g in &listed {
                        println!(
                            "  {:<8} {:<10} [{}] {}  by {}  until {}",
                            format!("{:?}", g.status).to_lowercase(),
                            g.token.issued_to,
                            g.token.scope.join(","),
                            g.token.resource.as_deref().unwrap_or("-"),
                            g.token.signed_by.as_deref().unwrap_or("?"),
                            g.token.expires_at.to_rfc3339()
                        );
                        if let Some(id) = &g.token.grant_id {
                            println!("           grant {id}");
                        }
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
            let identity = signing_identity(&route, &exporter)?;
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

/// The one agent this machine holds a signing key for.
///
/// A machine that has joined a project has exactly one identity in the normal case, and
/// making the operator type it every time is the sort of friction that stops a brief from
/// being updated - which is the only way this feature fails. When there is more than one,
/// refuse and list them: guessing would sign a brief under a name this machine is not.
fn only_local_agent(route: &ferryman_channel::ProjectRoute) -> Result<String> {
    let keys = route.attachment.join("keys");
    let mut names: Vec<String> = std::fs::read_dir(&keys)
        .with_context(|| {
            format!(
                "no identities on this machine; looked in {}",
                keys.display()
            )
        })?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension()? != "key" {
                return None;
            }
            Some(ferryman_channel::canonical_agent_name(
                path.file_stem()?.to_str()?,
            ))
        })
        .collect();
    names.sort();
    names.dedup();
    match names.len() {
        0 => bail!("no signing key on this machine; run `ferry enable` first"),
        1 => Ok(names.remove(0)),
        _ => bail!(
            "this machine holds keys for {}; say which one with --agent",
            names.join(", ")
        ),
    }
}

/// How a signature reads to a human who has to decide whether to trust the brief.
fn signature_line(check: &ferryman_channel::SignatureCheck) -> &'static str {
    match check {
        ferryman_channel::SignatureCheck::Valid => "signature verifies against the roster",
        ferryman_channel::SignatureCheck::Unsigned => "UNSIGNED - anyone could have written this",
        ferryman_channel::SignatureCheck::Invalid => {
            "SIGNATURE DOES NOT VERIFY - do not act on this brief"
        }
        ferryman_channel::SignatureCheck::UnknownSigner => {
            "signer has no published key, so nothing can be concluded"
        }
        ferryman_channel::SignatureCheck::KeyChanged { .. } => {
            "A DIFFERENT KEY is claiming this name - treat as hostile until explained"
        }
    }
}

/// Age in words. A successor reasoning about a four-hour-old brief must behave
/// differently from one trusting it as current, so the age is never buried.
fn age_phrase(minutes: i64) -> String {
    match minutes {
        0 => "just now".to_string(),
        1 => "1 minute ago".to_string(),
        m if m < 60 => format!("{m} minutes ago"),
        m if m < 120 => format!("1 hour {} minutes ago", m % 60),
        m if m < 2880 => format!("{} hours ago", m / 60),
        m => format!("{} days ago", m / 1440),
    }
}

fn print_brief(
    brief: &ferryman_channel::orchestrator::Brief,
    route: &ferryman_channel::ProjectRoute,
) {
    let age = brief.age_minutes(chrono::Utc::now());
    println!("  {} — updated {}", brief.agent, age_phrase(age));
    println!(
        "  {}",
        signature_line(&ferryman_channel::orchestrator::verify_brief(
            brief,
            &route.agents
        ))
    );
    if age > 240 {
        println!("  This brief is stale. Whatever it says was true four hours ago at best.");
    }
    println!();
    println!("  Objective");
    println!("    {}", brief.objective);
    if let Some(deadline) = &brief.deadline {
        println!("    by {deadline}");
    }
    for (heading, body) in [
        ("Standing constraints", &brief.constraints),
        ("In flight", &brief.in_flight),
        ("Decided (and why)", &brief.decided),
        ("Tried and rejected", &brief.rejected),
        ("Waiting on the human", &brief.waiting_on_human),
        ("Next, in order", &brief.next),
    ] {
        if body.trim().is_empty() {
            continue;
        }
        println!();
        println!("  {heading}");
        for line in body.lines() {
            println!("    {line}");
        }
    }
}

fn orchestrator_command(command: OrchestratorCommand) -> Result<()> {
    let here = |workspace: Option<PathBuf>| -> Result<ferryman_channel::ProjectRoute> {
        let start = match workspace {
            Some(path) => path,
            None => std::env::current_dir().context("read the current directory")?,
        };
        ferryman_channel::route_for(&start)
    };

    match command {
        OrchestratorCommand::Brief {
            workspace,
            agent,
            objective,
            deadline,
            constraints,
            in_flight,
            decided,
            rejected,
            waiting_on_human,
            next,
        } => {
            let route = here(workspace)?;
            let name = match agent {
                Some(name) => name,
                None => only_local_agent(&route)?,
            };

            let sections = [
                &objective,
                &deadline,
                &constraints,
                &in_flight,
                &decided,
                &rejected,
                &waiting_on_human,
                &next,
            ];
            let nothing_to_write = sections.iter().all(|section| section.is_none());

            let existing = ferryman_channel::orchestrator::read_brief(&route, &name)?;

            if nothing_to_write {
                let Some(brief) = existing else {
                    println!("no brief for '{name}' yet.");
                    println!();
                    println!(
                        "  Start one:  ferry orchestrator brief --objective \"what this is all for\""
                    );
                    return Ok(());
                };
                print_brief(&brief, &route);
                return Ok(());
            }

            // Only the sections given are touched. An orchestrator recording one decision
            // mid-flight must not have to restate the other five, because the version that
            // costs six paragraphs is the version that stops being written.
            let mut brief = existing.unwrap_or_else(|| {
                ferryman_channel::orchestrator::Brief::new(
                    &name,
                    objective.as_deref().unwrap_or(""),
                )
            });
            if let Some(value) = objective {
                brief.objective = value;
            }
            if let Some(value) = deadline {
                brief.deadline = Some(value).filter(|v| !v.trim().is_empty());
            }
            if let Some(value) = constraints {
                brief.constraints = value;
            }
            if let Some(value) = in_flight {
                brief.in_flight = value;
            }
            if let Some(value) = decided {
                brief.decided = value;
            }
            if let Some(value) = rejected {
                brief.rejected = value;
            }
            if let Some(value) = waiting_on_human {
                brief.waiting_on_human = value;
            }
            if let Some(value) = next {
                brief.next = value;
            }

            // `load_existing`, never `load_or_create`: minting a second key under a name the
            // roster already knows would make every signature it produces read as an impostor.
            let identity =
                ferryman_channel::AgentIdentity::load_existing(&name, &route.attachment)?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no signing key for '{name}' on this machine, so a brief cannot be \
                             signed here. Write it on {name}'s own machine, or use --agent with \
                             a name this machine holds a key for."
                        )
                    })?;

            let path = ferryman_channel::orchestrator::write_brief(&route, &brief, &identity)?;
            println!("brief recorded at {}", path.display());
            println!("  A replacement reads it with: ferry orchestrator resume");
        }

        OrchestratorCommand::List { workspace } => {
            let route = here(workspace)?;
            let briefs = ferryman_channel::orchestrator::list_briefs(&route)?;
            if briefs.is_empty() {
                println!("no orchestrator briefs in this channel yet.");
                return Ok(());
            }
            let now = chrono::Utc::now();
            for brief in briefs {
                println!(
                    "  {:<14} {:<18} {}",
                    brief.agent,
                    age_phrase(brief.age_minutes(now)),
                    brief.objective
                );
                println!(
                    "                 {}",
                    signature_line(&ferryman_channel::orchestrator::verify_brief(
                        &brief,
                        &route.agents
                    ))
                );
            }
        }

        OrchestratorCommand::Resume { workspace, agent } => {
            let route = here(workspace)?;
            let brief = match &agent {
                Some(name) => ferryman_channel::orchestrator::read_brief(&route, name)?,
                // No name given: the newest brief, because that is the one the fleet was
                // most recently being run from.
                None => ferryman_channel::orchestrator::list_briefs(&route)?
                    .into_iter()
                    .next(),
            };

            println!(
                "Ferryman — orchestrator handover for '{}'",
                route.project_id
            );
            println!();

            match &brief {
                Some(brief) => print_brief(brief, &route),
                None => {
                    println!("  No brief was left behind.");
                    println!(
                        "  Everything below is what the channel knows. What the last \
                         orchestrator knew is gone."
                    );
                }
            }

            // The roster, so a successor knows who it can address work to at all.
            println!();
            println!("  Who is in this fleet");
            if route.agents.is_empty() {
                println!("    nobody on the roster yet");
            }
            // Widths from the data, not from a guess. A fleet with one long agent name
            // otherwise turns the whole roster into ragged columns, and this text is
            // meant to be pasted into a successor as its opening context.
            let name_width = route
                .agents
                .iter()
                .map(|agent| agent.name.chars().count())
                .max()
                .unwrap_or(0);
            let role_width = route
                .agents
                .iter()
                .map(|agent| agent.role.chars().count())
                .max()
                .unwrap_or(0);
            for agent in &route.agents {
                let signing = if agent.public_key.is_some() {
                    "signs"
                } else {
                    "unsigned"
                };
                println!(
                    "    {:name_width$} {:role_width$} {}",
                    agent.name, agent.role, signing
                );
            }

            // Work in flight, from the channel rather than from the brief, so a stale brief
            // cannot hide a task. The two disagreeing is itself information.
            println!();
            println!("  Work the channel is carrying");
            let tasks = ferryman_channel::list_tasks(&route)?;
            let unfinished: Vec<_> = tasks
                .iter()
                .filter(|task| {
                    !matches!(
                        task.state(),
                        ferryman_channel::TaskState::Accepted | ferryman_channel::TaskState::Done
                    )
                })
                .collect();
            let id_width = unfinished
                .iter()
                .map(|task| task.order.id.chars().count())
                .max()
                .unwrap_or(0);
            let holder_width = unfinished
                .iter()
                .map(|task| task.holder().unwrap_or("-").chars().count())
                .max()
                .unwrap_or(0);
            let mut open = 0;
            for task in &tasks {
                if matches!(
                    task.state(),
                    ferryman_channel::TaskState::Accepted | ferryman_channel::TaskState::Done
                ) {
                    continue;
                }
                open += 1;
                println!(
                    "    {:id_width$} {:holder_width$} {:?}",
                    task.order.id,
                    task.holder().unwrap_or("-"),
                    task.state()
                );
            }
            if open == 0 {
                println!("    nothing open");
            }

            if let Some(brief) = &brief
                && !brief.waiting_on_human.trim().is_empty()
            {
                println!();
                println!("  Before anything else, these need the human");
                for line in brief.waiting_on_human.lines() {
                    println!("    {line}");
                }
            }

            println!();
            println!("  Keep this current as you work:  ferry orchestrator brief --next \"...\"");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::slug_of;
    use std::path::Path;

    #[test]
    fn slug_derives_from_the_directory_name() {
        assert_eq!(slug_of(Path::new("/srv/repos/ferryman")), "ferryman");
        assert_eq!(slug_of(Path::new("/home/you/My Project")), "my-project");
        assert_eq!(
            slug_of(Path::new("/tmp/groundcrew_borrows")),
            "groundcrew-borrows"
        );
        assert_eq!(slug_of(Path::new("/tmp/foo--bar--")), "foo-bar");
        assert_eq!(slug_of(Path::new("/")), "");
    }

    /// The recovery phrase is the one secret that has to survive: whatever it holds
    /// must round-trip exactly, or a machine restored from its phrase comes back a
    /// stranger to every roster that knew it.
    #[test]
    fn the_recovery_phrase_round_trips_the_seed_bytes() {
        let bytes = [0x5a; 32];
        let phrase = ferryman_channel::seed::seed_to_phrase(bytes).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24, "got: {phrase}");
        assert_eq!(
            ferryman_channel::seed::phrase_to_seed(&phrase).unwrap(),
            bytes
        );
    }

    /// The standard BIP-39 test vector for 256 zero bits: 23 `abandon` words and then
    /// `art`. Pins that we are using the real BIP-39 word list and checksum, not some
    /// near-cousin that a phrase from another wallet would not recover.
    #[test]
    fn the_bip39_zero_entropy_vector_is_correct() {
        let phrase = ferryman_channel::seed::seed_to_phrase([0u8; 32]).unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        assert!(words[..23].iter().all(|w| *w == "abandon"), "got: {phrase}");
        assert_eq!(words[23], "art", "got: {phrase}");
        assert_eq!(
            ferryman_channel::seed::phrase_to_seed(&phrase).unwrap(),
            [0u8; 32]
        );
    }

    /// A seed is created once, used silently after that, and never created unattended.
    #[test]
    fn enable_creates_a_seed_once_and_never_unattended() {
        let machine = tempfile::tempdir().unwrap();

        let (report, phrase) = super::ensure_operator_seed(machine.path(), true).unwrap();
        assert_eq!(report.state, "created");
        assert!(report.fingerprint.is_some());
        let phrase = phrase.expect("a created seed carries its phrase once");
        assert_eq!(phrase.split_whitespace().count(), 24);

        // Re-running uses the seed and never re-displays the phrase.
        let (report, phrase) = super::ensure_operator_seed(machine.path(), true).unwrap();
        assert_eq!(report.state, "present");
        assert!(phrase.is_none());

        // Unattended runs never create a seed.
        let fresh = tempfile::tempdir().unwrap();
        let (report, phrase) = super::ensure_operator_seed(fresh.path(), false).unwrap();
        assert_eq!(report.state, "absent");
        assert!(phrase.is_none());
        assert!(!ferryman_channel::seed::OperatorSeed::path_in(fresh.path()).exists());
    }

    /// `identity show` reports which keys derive from the seed, and it skips the
    /// encryption keys that live beside them.
    #[test]
    fn machine_identities_separates_derived_from_rotated() {
        use ferryman_channel::seed::OperatorSeed;
        let machine = tempfile::tempdir().unwrap();
        let seed = OperatorSeed::create_in(machine.path()).unwrap();

        // A key derived from the seed, exactly as `load_or_create` would persist it.
        let derived = seed.signing_identity("fang").unwrap();
        let keys = machine.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("fang.key"), hex::encode(derived.seed_bytes())).unwrap();
        // A rotated key that predates the seed, and an encryption key that is not an
        // identity at all.
        std::fs::write(keys.join("rotated.key"), hex::encode([0x77u8; 32])).unwrap();
        std::fs::write(keys.join("fang.enc.key"), hex::encode([0x33u8; 32])).unwrap();

        let identities = super::machine_identities(machine.path(), &seed).unwrap();
        assert_eq!(
            identities,
            vec![("fang".to_string(), true), ("rotated".to_string(), false),]
        );
    }
}

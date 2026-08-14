#![forbid(unsafe_code)]
mod license;

use ferryman_ops::Progress;
use ferryman_ops::agent;
use ferryman_ops::enable;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use serde_json::{Value, json};
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
        /// Become this project's master. Ask the user first; this is an explicit choice.
        #[arg(long)]
        master: bool,
        /// Emit one JSON object describing the result, for a caller that is a program.
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
    /// Run the agentic loop: pick work up, do it, and judge what comes back.
    Agent {
        #[command(subcommand)]
        command: Agent,
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
            master,
            json: as_json,
        } => {
            let outcome = enable::perform(enable::Request {
                workspace,
                project,
                agent: agent_name,
                role,
                email,
                command,
                review,
                no_syncthing,
                as_json,
                master,
            })?;
            if as_json {
                report_enable_json(&outcome)?;
            } else {
                report_enable_human(&outcome);
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
fn report_enable_json(outcome: &enable::Outcome) -> Result<()> {
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
fn report_enable_human(outcome: &enable::Outcome) {
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
                signed_by: None,
                signature: None,
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
            }
        }
    }
    Ok(())
}

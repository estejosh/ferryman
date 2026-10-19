//! `ferry lane iroh`: the iroh lane's key, its records, and what it is doing.
//!
//! See [`ferryman_iroh`]. The lane itself runs inside `ferry agent run --all-projects`;
//! these commands only prepare a machine and look at it, so nothing here listens.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use ferryman_channel::ProjectRoute;
use ferryman_iroh::IrohConfig;
use ferryman_ops::Progress;

#[derive(clap::Subcommand, Clone)]
pub(crate) enum LaneCommand {
    /// Channels over iroh (QUIC) through our own relay, beside Syncthing.
    Iroh {
        #[command(subcommand)]
        command: IrohCommand,
    },
}

#[derive(clap::Subcommand, Clone)]
pub(crate) enum IrohCommand {
    /// Make this machine's iroh key (once) and publish its endpoint id, signed by this
    /// machine's worker identity, into every channel that worker serves. Safe to run
    /// again: an unchanged record is not rewritten.
    Init {
        /// Where the worker's own agent.toml and keys are (its home checkout). Defaults to
        /// the current directory.
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// This machine's endpoint id, whether the relay lets us in, and every peer the
    /// worker's lane has synced with: when, and how many files each way.
    Status {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

pub(crate) async fn command(command: LaneCommand) -> Result<()> {
    let LaneCommand::Iroh { command } = command;
    match command {
        IrohCommand::Init { workspace } => init(workspace),
        IrohCommand::Status { json } => status(json).await,
    }
}

fn root() -> Result<ferryman_channel::ferry::Root> {
    ferryman_channel::ferry::find_root()
        .context("no ferry root yet - make one with `ferry root init`")
}

/// The routes this machine's all-projects worker serves, and its identity: exactly what
/// `ferry agent run --all-projects` would serve, from the same plan.
fn served(
    root: &ferryman_channel::ferry::Root,
    workspace: Option<PathBuf>,
) -> Result<(Vec<ProjectRoute>, ferryman_channel::AgentIdentity)> {
    let start = match workspace {
        Some(path) => path,
        None => std::env::current_dir().context("read the current directory")?,
    };
    let home = ferryman_channel::route_for(&start)?;
    let config = ferryman_ops::agent::AgentConfig::load(&home.attachment)?;
    let (plan, identity) = ferryman_ops::fleet::plan_worker(root, &home.attachment, &config)?;
    let routes = plan
        .rows
        .into_iter()
        .filter_map(|row| match row.standing {
            ferryman_ops::fleet::Standing::Serves { route, .. } => Some(*route),
            ferryman_ops::fleet::Standing::Skips(_) => None,
        })
        .collect();
    Ok((routes, identity))
}

fn init(workspace: Option<PathBuf>) -> Result<()> {
    let machine = ferryman_iroh::machine_dir()?;
    let (key, created) = ferryman_iroh::load_or_create_key(&machine)?;
    let id = key.public();
    println!(
        "endpoint id {} ({}, {})",
        ferryman_iroh::endpoint_hex(&id),
        if created { "new" } else { "already here" },
        machine.join(ferryman_iroh::KEY_FILE).display()
    );
    let root = root()?;
    let config = IrohConfig::load(&root.path);
    let (routes, identity) = served(&root, workspace)?;
    let (written, failed) =
        ferryman_iroh::publish_everywhere(&routes, &identity, &id, config.relay_url.as_deref());
    println!(
        "transports record for '{}': {written} written, {} already current, in {} channel(s)",
        identity.name(),
        routes.len() - written - failed.len(),
        routes.len()
    );
    for line in &failed {
        println!("  not written: {line}");
    }
    if !config.enabled {
        println!(
            "the lane is off on this machine. To turn it on, add to {}:",
            root.path.join("ferry.toml").display()
        );
        println!("  [iroh]\n  enabled = true\n  relay_url = \"https://<relay>\"");
        println!("  relay_cert_sha256 = \"<the relay certificate's SHA-256>\"");
        println!(
            "and put the relay's access token in {}",
            machine
                .join(ferryman_iroh::config::DEFAULT_TOKEN_FILE)
                .display()
        );
    }
    Ok(())
}

async fn status(json: bool) -> Result<()> {
    let machine = ferryman_iroh::machine_dir()?;
    let root = root()?;
    let config = IrohConfig::load(&root.path);
    let key = ferryman_iroh::load_key(&machine)?;
    let token_file = config.relay_token_file.clone();
    let token_present = token_file.as_ref().is_some_and(|path| path.is_file());
    let relay = if config.relay_url.is_some() {
        Some(ferryman_iroh::lane::probe_relay(&config, Duration::from_secs(10)).await)
    } else {
        None
    };
    let lane = ferryman_iroh::Status::read(&machine.join(ferryman_iroh::STATUS_FILE));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "endpoint_id": key.as_ref().map(|k| ferryman_iroh::endpoint_hex(&k.public())),
                "enabled": config.enabled,
                "relay_url": config.relay_url,
                "relay_cert_pinned": config.relay_cert_sha256.is_some(),
                "relay_token_file": token_file,
                "relay_token_present": token_present,
                "relay_reachable": relay.as_ref().map(Result::is_ok),
                "relay_problem": relay.as_ref().and_then(|r| r.as_ref().err().map(|e| format!("{e:#}"))),
                "notes": config.notes,
                "worker": lane,
            }))?
        );
        return Ok(());
    }
    match &key {
        Some(key) => println!(
            "endpoint id   {}",
            ferryman_iroh::endpoint_hex(&key.public())
        ),
        None => println!("endpoint id   none yet: run `ferry lane iroh init`"),
    }
    println!(
        "lane          {}",
        if config.enabled {
            "on (runs inside `ferry agent run --all-projects`)"
        } else {
            "off ([iroh] enabled = true in ferry.toml turns it on)"
        }
    );
    println!(
        "relay         {}{}",
        config.relay_url.as_deref().unwrap_or("none (direct only)"),
        match config.relay_cert_sha256 {
            Some(_) => ", certificate pinned",
            None if config.relay_url.is_some() => ", public CAs (no pin)",
            None => "",
        }
    );
    if let Some(path) = &token_file {
        println!(
            "relay token   {} ({})",
            path.display(),
            if token_present { "present" } else { "missing" }
        );
    }
    match &relay {
        Some(Ok(())) => println!("relay reached yes"),
        Some(Err(error)) => println!("relay reached no: {error:#}"),
        None => {}
    }
    for note in &config.notes {
        println!("note          {note}");
    }
    let Some(lane) = lane else {
        println!("worker        no lane has run on this machine yet");
        return Ok(());
    };
    println!(
        "worker        last round {}, relay {}{}",
        lane.updated.map_or_else(
            || "never".to_owned(),
            |t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        ),
        if lane.relay_connected {
            "connected"
        } else {
            "not connected"
        },
        lane.relay_problem
            .as_deref()
            .map_or_else(String::new, |why| format!(" ({why})"))
    );
    if lane.peers.is_empty() {
        println!("peers         none trusted yet: each machine runs `ferry lane iroh init`");
    }
    for (id, peer) in &lane.peers {
        println!(
            "peer {}  {}  projects {}",
            &id[..16.min(id.len())],
            peer.agents.join(", "),
            if peer.projects.is_empty() {
                "-".to_owned()
            } else {
                peer.projects.join(", ")
            }
        );
        println!(
            "     last sync {}, received {} file(s), sent {}{}",
            peer.last_sync.map_or_else(
                || "never".to_owned(),
                |t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
            ),
            peer.received,
            peer.sent,
            peer.last_error
                .as_deref()
                .map_or_else(String::new, |why| format!("; last error: {why}"))
        );
    }
    Ok(())
}

/// The lane, ready to start inside the worker.
pub(crate) struct WorkerLane {
    config: IrohConfig,
    identity: ferryman_channel::AgentIdentity,
}

/// Whether this machine's worker should run the lane. Says why not when it was meant to.
pub(crate) fn for_worker(
    root: &ferryman_channel::ferry::Root,
    identity: ferryman_channel::AgentIdentity,
    report: &impl Progress,
) -> Option<WorkerLane> {
    let config = IrohConfig::load(&root.path);
    for note in &config.notes {
        report.warn(&format!("iroh lane: {note}"));
    }
    config.enabled.then_some(WorkerLane { config, identity })
}

impl WorkerLane {
    /// Bind the endpoint, publish this worker's record into every channel it serves, and
    /// leave the lane running in the background for as long as the worker runs. A lane
    /// that cannot start is a warning, never a reason for the worker to stop: Syncthing
    /// still carries the channels.
    pub(crate) async fn start(self, routes: Vec<ProjectRoute>, report: &impl Progress) {
        if let Err(error) = self.try_start(routes, report).await {
            report.warn(&format!("iroh lane not started: {error:#}"));
        }
    }

    async fn try_start(self, routes: Vec<ProjectRoute>, report: &impl Progress) -> Result<()> {
        let machine = ferryman_iroh::machine_dir()?;
        let (key, _) = ferryman_iroh::load_or_create_key(&machine)?;
        let endpoint = ferryman_iroh::lane::bind(&self.config, key).await?;
        let id = endpoint.id();
        let (written, failed) = ferryman_iroh::publish_everywhere(
            &routes,
            &self.identity,
            &id,
            self.config.relay_url.as_deref(),
        );
        for line in failed {
            report.warn(&format!("iroh lane: no transports record in {line}"));
        }
        report.info(&format!(
            "iroh lane on as {} over {} channel(s){}{}",
            ferryman_iroh::endpoint_hex(&id),
            routes.len(),
            self.config.relay_url.as_deref().map_or_else(
                || ", direct only".to_owned(),
                |url| format!(", relay {url}")
            ),
            if written > 0 {
                format!(", {written} record(s) published")
            } else {
                String::new()
            }
        ));
        let lane = ferryman_iroh::Lane::new(
            endpoint,
            routes,
            self.config.relay_url.clone(),
            Some(machine.join(ferryman_iroh::STATUS_FILE)),
        );
        // Who this machine's worker is, so a Worker-level agent here listens to a channel
        // and publishes none of it (its writes go out through its hand-ins folder).
        lane.set_local_agents(vec![self.identity.name().to_owned()]);
        tokio::spawn(lane.run(ferryman_iroh::lane::ROUND_EVERY));
        Ok(())
    }
}

/// How this machine's iroh lane carries one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Carried {
    /// This machine's endpoint id, as the channel's transports record names it.
    pub endpoint_id: String,
    /// The worker's lane finished a round recently, so it is running now.
    pub running: bool,
    /// When the worker's lane last finished a round.
    pub last_round: Option<chrono::DateTime<chrono::Utc>>,
    /// Peers whose last exchange covered this project.
    pub peers: usize,
}

impl Carried {
    /// The line `channel send` and `channel status` print.
    pub(crate) fn describe(&self) -> String {
        let peers = match self.peers {
            0 => "no peer has synced it yet".to_owned(),
            1 => "1 peer has synced it".to_owned(),
            n => format!("{n} peers have synced it"),
        };
        if self.running {
            format!("the iroh lane is carrying this channel ({peers})")
        } else {
            format!(
                "the iroh lane carries this channel, but the worker's lane has not run lately \
                 ({peers}); it goes out when `ferry agent run --all-projects` is running"
            )
        }
    }
}

/// Whether the iroh lane, not Syncthing, is what carries `route`'s channel off this
/// machine. Reads this machine's own settings and the channel; asks no service anything.
pub(crate) fn carried_by_iroh(route: &ProjectRoute) -> Option<Carried> {
    let root = ferryman_channel::ferry::find_root()?;
    let config = IrohConfig::load(&root.path);
    let machine = ferryman_iroh::machine_dir().ok()?;
    carried_in(route, config.enabled, &machine, chrono::Utc::now())
}

/// The lane carries a channel from this machine when it is switched on, the machine has an
/// iroh key, and the channel holds a record, honoured by its roster, that names that key.
fn carried_in(
    route: &ProjectRoute,
    enabled: bool,
    machine: &std::path::Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Carried> {
    if !enabled {
        return None;
    }
    let key = ferryman_iroh::load_key(machine).ok()??;
    let me = ferryman_iroh::endpoint_hex(&key.public());
    if !ferryman_channel::transports::honoured_records(route)
        .iter()
        .any(|record| record.endpoint_id.eq_ignore_ascii_case(&me))
    {
        return None;
    }
    let status = ferryman_iroh::Status::read(&machine.join(ferryman_iroh::STATUS_FILE));
    let last_round = status.as_ref().and_then(|status| status.updated);
    // A few rounds' grace: a round can be slow, and one missed is not "stopped".
    let running = last_round.is_some_and(|at| {
        now - at < chrono::Duration::from_std(ferryman_iroh::lane::ROUND_EVERY * 6).unwrap()
    });
    let peers = status.map_or(0, |status| {
        status
            .peers
            .values()
            .filter(|peer| peer.projects.iter().any(|id| id == &route.project_id))
            .count()
    });
    Some(Carried {
        endpoint_id: me,
        running,
        last_round,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferryman_channel::{AgentIdentity, AgentRoute};

    fn route(base: &std::path::Path) -> ProjectRoute {
        let workspace = base.join("demo");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        ProjectRoute {
            project_id: "demo".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "demo-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn enrolled(route: &ProjectRoute, name: &str) -> AgentIdentity {
        let identity = AgentIdentity::load_or_create(name, &route.attachment).unwrap();
        ferryman_channel::register_agent(
            route,
            &AgentRoute {
                name: name.into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        identity
    }

    #[test]
    fn a_channel_with_this_machines_record_is_carried_by_iroh_and_one_without_is_not() {
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let machine = dir.path().join("machine");
        std::fs::create_dir_all(&machine).unwrap();
        let route = route(dir.path());
        let wisp = enrolled(&route, "wisp");
        let now = chrono::Utc::now();

        // No key yet, and no record: Syncthing's channel, as before.
        assert!(carried_in(&route, true, &machine, now).is_none());

        let (key, _) = ferryman_iroh::load_or_create_key(&machine).unwrap();
        let me = ferryman_iroh::endpoint_hex(&key.public());
        // A key but no record in this channel.
        assert!(carried_in(&route, true, &machine, now).is_none());

        ferryman_channel::transports::publish(&route, &wisp, &me, None).unwrap();
        let carried = carried_in(&route, true, &machine, now).unwrap();
        assert_eq!(carried.endpoint_id, me);
        assert!(!carried.running, "no worker has run the lane yet");
        assert!(carried.describe().contains("has not run lately"));

        // Switched off in ferry.toml: not carried.
        assert!(carried_in(&route, false, &machine, now).is_none());

        // A record that names some other machine's key is not this machine's.
        let other = tempfile::tempdir().unwrap();
        ferryman_iroh::load_or_create_key(other.path()).unwrap();
        assert!(carried_in(&route, true, other.path(), now).is_none());
    }

    #[test]
    fn a_lane_that_ran_lately_is_running_and_counts_the_peers_that_have_this_project() {
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let machine = dir.path().join("machine");
        std::fs::create_dir_all(&machine).unwrap();
        let route = route(dir.path());
        let wisp = enrolled(&route, "wisp");
        let (key, _) = ferryman_iroh::load_or_create_key(&machine).unwrap();
        ferryman_channel::transports::publish(
            &route,
            &wisp,
            &ferryman_iroh::endpoint_hex(&key.public()),
            None,
        )
        .unwrap();
        let now = chrono::Utc::now();
        let mut status = ferryman_iroh::Status {
            updated: Some(now - chrono::Duration::seconds(20)),
            ..Default::default()
        };
        status.peers.insert(
            "aa".repeat(32),
            ferryman_iroh::lane::PeerStatus {
                projects: vec!["demo".into()],
                ..Default::default()
            },
        );
        status.peers.insert(
            "bb".repeat(32),
            ferryman_iroh::lane::PeerStatus {
                projects: vec!["other".into()],
                ..Default::default()
            },
        );
        std::fs::write(
            machine.join(ferryman_iroh::STATUS_FILE),
            serde_json::to_vec(&status).unwrap(),
        )
        .unwrap();
        let carried = carried_in(&route, true, &machine, now).unwrap();
        assert!(carried.running);
        assert_eq!(carried.peers, 1);
        assert!(carried.describe().contains("1 peer has synced it"));
        // The same lane, an hour later with no new round: not running.
        let later = now + chrono::Duration::hours(1);
        assert!(!carried_in(&route, true, &machine, later).unwrap().running);
    }
}

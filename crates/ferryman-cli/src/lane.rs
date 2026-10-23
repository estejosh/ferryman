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

/// `[iroh]` from `ferry.toml`, plus the relays the fleet's master listed in the fleet
/// folder (signed; only the master's list counts). The machine's own relays come first.
pub(crate) fn load_config(root: &ferryman_channel::ferry::Root) -> IrohConfig {
    load_config_checked(root).0
}

/// [`load_config`], and what is wrong with the fleet's relay list, if anything.
///
/// It fails closed. A list that is missing, unsigned, edited, empty or older than the last one
/// accepted is not used; the last good one stays in use, and with none the lane has only the
/// relays `ferry.toml` names, or none. It never becomes iroh's public relays: those need
/// `public_relays = true`, written by the person who owns this machine.
pub(crate) fn load_config_checked(
    root: &ferryman_channel::ferry::Root,
) -> (IrohConfig, Option<String>) {
    let config = IrohConfig::load(&root.path);
    if !config.enabled {
        return (config, None);
    }
    let choice = ferryman_channel::fleethome::choose_relays_here(root);
    let mut config = config.with_fleet_relays(
        choice
            .relays
            .iter()
            .map(|relay| ferryman_iroh::config::FleetRelayEntry {
                url: relay.url.clone(),
                pin: relay.pin(),
            })
            .collect(),
    );
    if config.relayless_for_want_of_a_relay() {
        config.notes.push(
            "[iroh] no relay is named (in ferry.toml or the fleet's relay list), so the lane \
             runs without one: machines must reach each other directly. Name a relay, or set \
             `public_relays = true` to use iroh's public relays."
                .into(),
        );
    }
    #[cfg(feature = "hive-rescue")]
    let config = crate::hive::with_rescue_trust(config, root);
    (config, choice.problem)
}

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
pub(crate) fn served(
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
    let mut routes: Vec<ProjectRoute> = routes;
    // The fleet folder rides the lane too (ADR 0026), once it exists and this worker is on its
    // roster; the worker enrols itself there when it starts.
    if ferryman_channel::fleethome::exists(root) {
        crate::fleethome::WorkerPass::enrol_worker(root, &identity);
        routes.push(ferryman_channel::fleethome::route(root));
    }
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
    let config = load_config(&root);
    let (routes, identity) = served(&root, workspace)?;
    // Public-relay setups publish no relay: the worker adds its home relay once connected.
    let (written, failed) = ferryman_iroh::publish_everywhere(
        &routes,
        &identity,
        &id,
        config.all_relays().first().map(String::as_str),
    );
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
        println!("  [iroh]\n  enabled = true");
        println!(
            "that is all a new setup needs: with no relay named the lane uses iroh's public \
             relays, no server and no token."
        );
        println!("To use a relay of your own instead, add:");
        println!("  relay_url = \"https://<relay>\"");
        println!("  relay_cert_sha256 = \"<the relay certificate's SHA-256>\"   # if self-signed");
        println!(
            "and, only if the relay asks for one, its access token in {}",
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
    let config = load_config(&root);
    let key = ferryman_iroh::load_key(&machine)?;
    let token_file = config.relay_token_file.clone();
    let token_present = token_file.as_ref().is_some_and(|path| path.is_file());
    let relay = if config.relay_plan() != ferryman_iroh::config::RelayPlan::Direct {
        Some(ferryman_iroh::lane::probe_relay(&config, Duration::from_secs(10)).await)
    } else {
        None
    };
    let lane = ferryman_iroh::Status::read(&machine.join(ferryman_iroh::STATUS_FILE));
    let alerts = ferryman_channel::lanealerts::read(&machine);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "endpoint_id": key.as_ref().map(|k| ferryman_iroh::endpoint_hex(&k.public())),
                "version": env!("CARGO_PKG_VERSION"),
                "enabled": config.enabled,
                "relay_plan": config.describe_relays(),
                "relay_url": config.relay_url,
                "relays": config.all_relays(),
                "fleet_relays": config.fleet_relays.iter().map(|r| r.url.clone()).collect::<Vec<_>>(),
                "fallback_public_relays": config.fallback_public_relays,
                "direct_only": config.direct_only,
                "relay_cert_pinned": config.relay_cert_sha256.is_some(),
                "relay_token_file": token_file,
                "relay_token_present": token_present,
                "relay_reachable": relay.as_ref().map(Result::is_ok),
                "relay_problem": relay.as_ref().and_then(|r| r.as_ref().err().map(|e| format!("{e:#}"))),
                "alert_after_minutes": config.alert_after_minutes,
                "alerts": alerts,
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
    println!("version       {}", env!("CARGO_PKG_VERSION"));
    println!(
        "lane          {}",
        if config.enabled {
            "on (runs inside `ferry agent run --all-projects`)"
        } else {
            "off ([iroh] enabled = true in ferry.toml turns it on)"
        }
    );
    println!(
        "relays        {}{}",
        config.describe_relays(),
        match config.relay_cert_sha256 {
            Some(_) => ", our certificate pinned",
            None if !config.relays.is_empty() => ", public CAs (no pin)",
            None => "",
        }
    );
    if !config.fleet_relays.is_empty() {
        println!(
            "fleet relays  {} from the master's signed list (after any in ferry.toml)",
            config
                .fleet_relays
                .iter()
                .map(|r| format!(
                    "{}{}",
                    r.url,
                    if r.pin.is_some() { " (pinned)" } else { "" }
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(path) = &token_file {
        println!(
            "relay token   {} ({})",
            path.display(),
            if token_present {
                "present"
            } else {
                "none; optional"
            }
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
    print_alerts(alerts.as_ref());
    let Some(lane) = lane else {
        println!("worker        no lane has run on this machine yet");
        return Ok(());
    };
    print_worker(&lane, chrono::Utc::now());
    Ok(())
}

/// The standing alerts, or a line saying there are none.
fn print_alerts(alerts: Option<&ferryman_channel::lanealerts::State>) {
    match alerts {
        Some(state) if !state.active.is_empty() => {
            for alert in &state.active {
                println!(
                    "ALERT         {} (since {})",
                    alert.title,
                    alert.since.format("%Y-%m-%d %H:%M UTC")
                );
                println!("              {}", alert.text);
            }
        }
        Some(state) => println!(
            "alerts        none (warns after {} min without a good sync)",
            state.threshold_minutes
        ),
        None => println!("alerts        none checked yet (the worker checks every pass)"),
    }
}

fn ago(at: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> String {
    let minutes = (now - at).num_minutes().max(0);
    match minutes {
        0 => "under a minute ago".to_owned(),
        1..=119 => format!("{minutes} min ago"),
        _ => format!("{} h ago", minutes / 60),
    }
}

/// What the worker's lane last did: the relay, and for each peer when it last worked, what
/// went wrong, how it travelled and which version it runs.
fn print_worker(lane: &ferryman_iroh::Status, now: chrono::DateTime<chrono::Utc>) {
    println!(
        "worker        last round {}, relay {}{}{}",
        lane.updated.map_or_else(
            || "never".to_owned(),
            |t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        ),
        match (&lane.home_relay, lane.relay_connected) {
            (Some(url), true) => format!("connected ({url})"),
            (None, true) => "connected".to_owned(),
            _ if !lane.relay_expected => "not used (direct only)".to_owned(),
            _ => "not connected".to_owned(),
        },
        lane.relay_problem
            .as_deref()
            .map_or_else(String::new, |why| format!(" ({why})")),
        if lane.public_fallback_active {
            "; iroh's public relays were added because none of ours answered"
        } else {
            ""
        }
    );
    if lane.peers.is_empty() {
        println!("peers         none trusted yet: each machine runs `ferry lane iroh init`");
    }
    let mine = env!("CARGO_PKG_VERSION");
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
            "     last success  {}",
            peer.last_sync.map_or_else(
                || "never".to_owned(),
                |t| format!("{} ({})", t.format("%Y-%m-%d %H:%M:%S UTC"), ago(t, now))
            )
        );
        println!(
            "     last error    {}",
            match (&peer.last_error, peer.failing_since) {
                (Some(why), Some(since)) => format!("{why} (failing since {})", ago(since, now)),
                (Some(why), None) => why.clone(),
                (None, _) => "none".to_owned(),
            }
        );
        println!(
            "     relay used    {}",
            match peer.path.as_deref() {
                Some("direct") => "no, direct connection".to_owned(),
                Some(path) => format!("yes, {}", path.trim_start_matches("relay ")),
                None => "not known yet (no exchange completed)".to_owned(),
            }
        );
        println!(
            "     version       {}{}",
            peer.version.as_deref().unwrap_or("not told (older build)"),
            match peer.version.as_deref() {
                Some(theirs) if theirs != mine => format!(" (this machine runs {mine})"),
                _ => String::new(),
            }
        );
        println!(
            "     files         received {}, sent {} since the worker started",
            peer.received, peer.sent
        );
    }
}
/// The lane, ready to start inside the worker.
pub(crate) struct WorkerLane {
    config: IrohConfig,
    /// What is wrong with the fleet's relay list, if anything (see [`load_config_checked`]).
    config_problem: Option<String>,
    identity: ferryman_channel::AgentIdentity,
}

/// Whether this machine's worker should run the lane. Says why not when it was meant to.
pub(crate) fn for_worker(
    root: &ferryman_channel::ferry::Root,
    identity: ferryman_channel::AgentIdentity,
    report: &impl Progress,
) -> Option<WorkerLane> {
    let (config, config_problem) = load_config_checked(root);
    for note in &config.notes {
        report.warn(&format!("iroh lane: {note}"));
    }
    if let Some(problem) = &config_problem {
        report.warn(&format!("iroh lane: {problem}"));
    }
    config.enabled.then_some(WorkerLane {
        config,
        config_problem,
        identity,
    })
}

impl WorkerLane {
    /// The worker's identity, so it can be put on the fleet folder's roster.
    pub(crate) fn identity(&self) -> &ferryman_channel::AgentIdentity {
        &self.identity
    }

    /// Bind the endpoint, publish this worker's record into every channel it serves, and
    /// leave the lane running in the background for as long as the worker runs. A lane
    /// that cannot start is a warning, never a reason for the worker to stop: Syncthing
    /// still carries the channels.
    pub(crate) async fn start(
        self,
        routes: Vec<ProjectRoute>,
        report: &impl Progress,
    ) -> Option<LiveLane> {
        match self.try_start(routes, report).await {
            Ok(live) => Some(live),
            Err(error) => {
                report.warn(&format!("iroh lane not started: {error:#}"));
                None
            }
        }
    }

    async fn try_start(
        self,
        routes: Vec<ProjectRoute>,
        report: &impl Progress,
    ) -> Result<LiveLane> {
        let machine = ferryman_iroh::machine_dir()?;
        let (key, _) = ferryman_iroh::load_or_create_key(&machine)?;
        let (endpoint, fallback_map, shared_map) =
            ferryman_iroh::lane::bind_shared(&self.config, key).await?;
        let id = endpoint.id();
        let (written, failed) = ferryman_iroh::publish_everywhere(
            &routes,
            &self.identity,
            &id,
            self.config.all_relays().first().map(String::as_str),
        );
        for line in failed {
            report.warn(&format!("iroh lane: no transports record in {line}"));
        }
        report.info(&format!(
            "iroh lane on as {} over {} channel(s){}{}",
            ferryman_iroh::endpoint_hex(&id),
            routes.len(),
            match self.config.relay_plan() {
                ferryman_iroh::config::RelayPlan::Direct => ", direct only".to_owned(),
                ferryman_iroh::config::RelayPlan::Public => ", iroh's public relays".to_owned(),
                ferryman_iroh::config::RelayPlan::Custom { .. } =>
                    format!(", relay {}", self.config.describe_relays()),
            },
            if written > 0 {
                format!(", {written} record(s) published")
            } else {
                String::new()
            }
        ));
        let lane = ferryman_iroh::Lane::new(
            endpoint,
            routes,
            self.config.all_relays().first().cloned(),
            Some(machine.join(ferryman_iroh::STATUS_FILE)),
        );
        // Who this machine's worker is, so a Worker-level agent here listens to a channel
        // and publishes none of it (its writes go out through its hand-ins folder).
        lane.set_local_agents(vec![self.identity.name().to_owned()]);
        lane.configure_relays(
            self.config.relay_plan() != ferryman_iroh::config::RelayPlan::Direct,
            fallback_map,
        );
        lane.set_config_problem(self.config_problem.clone());
        let live = LiveLane {
            lane: std::sync::Arc::clone(&lane),
            identity: self.identity,
            relay_url: self.config.all_relays().first().cloned(),
            alert_after_minutes: self.config.alert_after_minutes,
            bound_relays: self.config.all_relays(),
            told_of_new_list: std::sync::atomic::AtomicBool::new(false),
            intermittent: self.config.intermittent_peers.clone(),
            reported_health: std::sync::atomic::AtomicBool::new(false),
        };
        #[cfg(feature = "hive-rescue")]
        crate::hive::start_in_worker(&lane, shared_map, live.identity_ref(), report);
        #[cfg(not(feature = "hive-rescue"))]
        let _ = shared_map;
        tokio::spawn(lane.run(ferryman_iroh::lane::ROUND_EVERY));
        Ok(live)
    }
}

/// The running lane, kept by the worker so projects approved after it started can join it.
pub(crate) struct LiveLane {
    lane: std::sync::Arc<ferryman_iroh::Lane>,
    identity: ferryman_channel::AgentIdentity,
    /// The primary relay of ours from `ferry.toml`, if any.
    relay_url: Option<String>,
    alert_after_minutes: u64,
    /// The relays this lane was bound with, to notice the fleet's list changing under it.
    bound_relays: Vec<String>,
    told_of_new_list: std::sync::atomic::AtomicBool,
    /// Peers `ferry.toml` says come and go (laptops): never raised on.
    intermittent: Vec<String>,
    /// This run has told the fleet folder where it stands at least once.
    reported_health: std::sync::atomic::AtomicBool,
}

impl LiveLane {
    #[cfg(feature = "hive-rescue")]
    fn identity_ref(&self) -> &ferryman_channel::AgentIdentity {
        &self.identity
    }

    /// The relays are fixed when the lane binds (the certificates it will trust are too), so
    /// a changed fleet list takes effect when the worker restarts: say so, once.
    fn check_relay_list(&self, report: &impl Progress) {
        use std::sync::atomic::Ordering;
        let Some(root) = ferryman_channel::ferry::find_root() else {
            return;
        };
        // Every pass: a list that has gone bad is an alert, and one that is mended clears it.
        let (config, problem) = load_config_checked(&root);
        self.lane.set_config_problem(problem);
        if self.told_of_new_list.load(Ordering::Relaxed) {
            return;
        }
        let now = config.all_relays();
        if now != self.bound_relays {
            self.told_of_new_list.store(true, Ordering::Relaxed);
            report.warn(
                "iroh lane: the fleet's relay list changed since this worker started; it \
                 takes effect on restart (`ferry fleet order restart-worker`)",
            );
        }
    }

    /// The relay a peer should dial us through: the one we are connected to now, else the
    /// primary of ours, else none (direct, or a public-relay setup not yet connected).
    fn current_relay(&self) -> Option<String> {
        self.lane
            .home_relay_url()
            .or_else(|| self.relay_url.clone())
    }

    /// Publish this worker's record in `route`'s channel and serve the channel from now on.
    pub(crate) fn add(&self, route: &ProjectRoute, report: &impl Progress) {
        let id = self.lane.endpoint().id();
        let (_, failed) = ferryman_iroh::publish_everywhere(
            std::slice::from_ref(route),
            &self.identity,
            &id,
            self.current_relay().as_deref(),
        );
        for line in failed {
            report.warn(&format!("iroh lane: no transports record in {line}"));
        }
        self.lane.add_project(route.clone());
    }

    /// Keep the lane in step with whether the worker still serves `route`: a project that
    /// was archived, or that its master took the worker out of, leaves the lane (it would
    /// otherwise stay in it, and keep being synced, until the worker restarted), and joins
    /// again if it comes back.
    pub(crate) fn follow(&self, route: &ProjectRoute, served: bool, report: &impl Progress) {
        let id = &route.project_id;
        let carried = self.lane.project_ids().contains(id);
        if served && !carried {
            self.add(route, report);
            report.info(&format!("iroh lane: serving {id} again"));
        } else if !served && self.lane.remove_project(id) {
            report.info(&format!("iroh lane: no longer serving {id}"));
        }
    }
}

/// Say what is wrong with this machine's lane in the fleet folder (`lane-health/`, signed by
/// this machine's own identity). Never a reason to stop: a machine the master has not
/// admitted still has the alerts in `ferry doctor` and the dashboard.
///
/// It is not a fleet notice. A notice of a kind a 0.6.1 or 0.5.30 machine does not know is
/// rejected and shown by its `ferry doctor` as ignored; the `lane-health/` folder is one
/// those versions never read.
fn post_lane_health(alerts: &[ferryman_channel::lanealerts::Alert], report: &impl Progress) {
    let Some(root) = ferryman_channel::ferry::find_root() else {
        return;
    };
    if !ferryman_channel::fleethome::exists(&root) {
        return;
    }
    let (Ok(machine), Ok(identity)) = (
        ferryman_ops::identity::machine_name(),
        ferryman_ops::fleethome::machine_identity(&root),
    ) else {
        return;
    };
    if let Err(error) =
        ferryman_channel::fleethome::publish_health(&root, &identity, &machine, alerts)
    {
        report.warn(&format!(
            "iroh lane: could not report lane health to the fleet ({error:#}); the alerts are \
             still in `ferry doctor` here"
        ));
    }
}

impl LiveLane {
    /// Once a pass: keep the TRANSPORTS record pointing at the relay we are on, work out what
    /// is wrong with the lane, and say so once. An alert is raised when it starts to hold and
    /// cleared when it stops; the fleet sees it in `lane-health/<machine>.json`, and this
    /// machine as a line in `ferry doctor` and the dashboard. The worker's own log says it too.
    pub(crate) fn check_health(&self, report: &impl Progress) {
        self.check_relay_list(report);
        let relay = self.current_relay();
        if relay.is_some() {
            // An unchanged record is not rewritten, so this costs a read per channel.
            let (_, failed) = ferryman_iroh::publish_everywhere(
                &self.lane.routes(),
                &self.identity,
                &self.lane.endpoint().id(),
                relay.as_deref(),
            );
            for line in failed {
                report.warn(&format!("iroh lane: no transports record in {line}"));
            }
        }
        let Ok(machine) = ferryman_iroh::machine_dir() else {
            return;
        };
        let now = chrono::Utc::now();
        let minutes = i64::try_from(self.alert_after_minutes).unwrap_or(15);
        let status = self.lane.status();
        let quiet_for = chrono::Duration::minutes(minutes);
        let found = ferryman_iroh::health::evaluate(&status, now, quiet_for, &self.intermittent);
        let previous = ferryman_channel::lanealerts::read(&machine).unwrap_or_default();
        // Alerts stand across a restart: a new lane has seen nothing yet, so an alert is
        // cleared only on positive evidence that its subject is fine.
        let standing: Vec<String> = previous.active.iter().map(|a| a.key.clone()).collect();
        let proven = ferryman_iroh::health::proven_ok(
            &status,
            now,
            quiet_for,
            &self.intermittent,
            &standing,
        );
        let (state, transitions) = ferryman_channel::lanealerts::reconcile(
            &previous,
            found,
            &proven,
            self.alert_after_minutes,
            now,
        );
        if let Err(error) = ferryman_channel::lanealerts::write(&machine, &state) {
            report.warn(&format!("iroh lane: could not record alerts: {error:#}"));
        }
        for transition in &transitions {
            match transition {
                ferryman_channel::lanealerts::Transition::Raised(alert) => {
                    report.warn(&format!(
                        "iroh lane alert: {} - {}",
                        alert.title, alert.text
                    ));
                }
                ferryman_channel::lanealerts::Transition::Cleared(alert) => {
                    report.info(&format!("iroh lane recovered: {}", alert.title));
                }
            }
        }
        let first = !self
            .reported_health
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        if first || !transitions.is_empty() {
            post_lane_health(&state.active, report);
        }
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

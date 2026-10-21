//! The lane itself: one endpoint, every channel the worker serves, a round every
//! [`ROUND_EVERY`] with every trusted peer.
//!
//! # The exchange, per shared project
//!
//! The side that dials (A) opens one stream per project it shares with the other (B):
//!
//! ```text
//! A -> B   Hello { project_id, manifest }       everything A would carry
//! B -> A   Plan { want, give } | Refused        B decides, on B's own rules
//! A -> B   one item per `want`                  Some(entry) + bytes, or None: gone
//! B -> A   one item per `give`
//! ```
//!
//! B is the one who decides because B is the one who has to be convinced: it checks A's
//! endpoint against ITS copy of that channel's TRANSPORTS records, and plans from A's
//! manifest only what its own rules allow. A then sends only what it offered and lets in
//! only what passes its own rules again. Each side checks every byte it writes; neither
//! trusts the other's plan.
//!
//! Both sides run rounds, so a pair of machines syncs twice per period. That is the
//! price of having no leader to elect, and it is two manifests when nothing changed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, Watcher as _,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use ferryman_channel::{ProjectRoute, access, ferry, syncscope};

use crate::config::RelayPlan;
use crate::manifest::{self, Entry, HashCache, Plan, Rules};
use crate::{ALPN, IrohConfig, MAX_FILE, endpoint_hex};

/// How often a worker syncs with each peer.
pub const ROUND_EVERY: Duration = Duration::from_secs(30);
/// How long a peer gets to answer a dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the relays of ours may all be unreachable before the public relays are added
/// (only when `fallback_public_relays` is on).
const FALLBACK_AFTER: chrono::Duration = chrono::Duration::minutes(2);
/// A peer that has failed for this long is worth a warning; a single bad round is not.
pub const ERROR_GRACE: chrono::Duration = chrono::Duration::minutes(2);
/// How long one peer's whole round may take before it is abandoned until the next.
const PEER_TIMEOUT: Duration = Duration::from_secs(600);
/// The largest message that is not a file. A manifest of a big channel is the biggest.
const MAX_FRAME: usize = 32 * 1024 * 1024;

/// Close code for a connection from an endpoint no channel here has on record.
const NOT_TRUSTED: u32 = 403;

/// The relay mode a configuration asks for (see [`IrohConfig::relay_plan`]):
///
/// - direct only: no relay;
/// - our own relays: exactly those, in the order given, each with the shared token when
///   there is one (the token is optional) - public relays are not in the map;
/// - nothing named: iroh's public relays, which need no pin and no token.
///
/// # Errors
/// A relay URL does not parse or the token file cannot be read.
pub fn relay_mode(config: &IrohConfig) -> Result<RelayMode> {
    match config.relay_plan() {
        RelayPlan::Direct => Ok(RelayMode::Disabled),
        RelayPlan::Public => Ok(RelayMode::Default),
        RelayPlan::Custom { urls, .. } => {
            let token = config.token()?;
            let mut configs = Vec::new();
            for url in urls {
                let parsed: RelayUrl = url
                    .parse()
                    .with_context(|| format!("relay '{url}' is not a URL"))?;
                let mut relay = RelayConfig::from(parsed);
                if let Some(quic) = relay.quic.as_mut() {
                    quic.port = config.relay_quic_port;
                }
                if let Some(token) = &token {
                    relay = relay.with_auth_token(token.clone());
                }
                configs.push(relay);
            }
            Ok(RelayMode::Custom(RelayMap::from_iter(configs)))
        }
    }
}

/// The host part of each relay URL, for telling our relays from public ones.
fn relay_hosts(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| url.parse::<RelayUrl>().ok())
        .filter_map(|url| url.host_str().map(str::to_owned))
        .collect()
}

/// Bind this machine's endpoint for `config`: our relays, iroh's public relays, or none,
/// as [`relay_mode`] says. Public relays are added to a custom setup later and only if
/// asked for ([`Lane::round`]).
///
/// `presets::Minimal` sets the crypto provider and nothing else, so there is no address
/// lookup service (no n0 DNS, no pkarr) to opt out of. Peers are dialed by endpoint id and
/// the relay URL their signed record names; iroh then finds a direct path between the two
/// machines through that relay when one exists.
///
/// # Errors
/// A relay URL does not parse, the token file cannot be read, or the endpoint cannot
/// bind a socket.
pub async fn bind(config: &IrohConfig, key: iroh::SecretKey) -> Result<Endpoint> {
    Ok(bind_with_map(config, key).await?.0)
}

/// [`bind`], and the relay map the endpoint shares when it is one of ours and public relays
/// may be added to it later; hand that to [`Lane::configure_relays`].
///
/// # Errors
/// As [`bind`].
pub async fn bind_with_map(
    config: &IrohConfig,
    key: iroh::SecretKey,
) -> Result<(Endpoint, Option<RelayMap>)> {
    let mode = relay_mode(config)?;
    let keep = match (&mode, config.relay_plan()) {
        (
            RelayMode::Custom(map),
            RelayPlan::Custom {
                fallback_public: true,
                ..
            },
        ) => Some(map.clone()),
        _ => None,
    };
    let fallback = matches!(
        config.relay_plan(),
        RelayPlan::Custom {
            fallback_public: true,
            ..
        }
    );
    let builder = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(crate::tls::ca_config(
            // The pin is for our own relays; with none named it would wrongly bind the
            // public ones to it.
            config
                .relay_cert_sha256
                .filter(|_| !config.relays.is_empty() && !config.direct_only),
            &relay_hosts(&config.relays),
            fallback,
        ))
        .relay_mode(mode);
    let endpoint = builder.bind().await.context("bind the iroh endpoint")?;
    Ok((endpoint, keep))
}

/// Whether the relay in `config` lets an endpoint in: `Ok` once one is connected to it,
/// otherwise why not (the TLS pin, the token, or no answer within `wait`).
///
/// A throwaway endpoint with a fresh key, not this machine's: two endpoints with one id
/// on one relay would knock the worker's own connection off it. The relay's access is
/// the shared token, so any key proves the same thing.
///
/// # Errors
/// The relay did not accept a connection within `wait`, and why when it is known.
pub async fn probe_relay(config: &IrohConfig, wait: Duration) -> Result<()> {
    if config.relay_plan() == RelayPlan::Direct {
        bail!("no relay configured (direct only)");
    }
    let endpoint = bind(config, iroh::SecretKey::generate()).await?;
    let mut watcher = endpoint.home_relay_status();
    let deadline = tokio::time::Instant::now() + wait;
    let outcome = loop {
        let relays = watcher.get();
        if relays.iter().any(iroh::endpoint::RelayStatus::is_connected) {
            break Ok(());
        }
        if let Some(reason) = relays.iter().find_map(|r| r.auth_denied_reason()) {
            break Err(anyhow::anyhow!("the relay refused the token: {reason}"));
        }
        if tokio::time::Instant::now() >= deadline {
            let why = relays
                .iter()
                .find_map(|r| r.last_error().map(|error| format!("{error:#}")))
                .unwrap_or_else(|| format!("no connection within {wait:?}"));
            break Err(anyhow::anyhow!(why));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    endpoint.close().await;
    outcome
}

/// A peer this machine will sync with, and what it may have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    pub agents: BTreeSet<String>,
    pub projects: BTreeSet<String>,
    /// Projects served here that this peer is not yet trusted in, but is trusted in another
    /// channel the two share: offered the `transports/` records of these and nothing else.
    pub bootstrap: BTreeSet<String>,
    pub relay: Option<RelayUrl>,
}

/// What the lane last did, for `ferry lane iroh status`. Written beside the key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub endpoint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    pub relay_connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    /// When this lane started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<DateTime<Utc>>,
    /// This lane's version, so `status` can set it beside each peer's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The relay this endpoint is homed on right now (ours or a public one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_relay: Option<String>,
    /// Since when no relay has been connected, while one is meant to be. Cleared on connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_down_since: Option<DateTime<Utc>>,
    /// Whether a relay is meant to be in use at all (false for direct only).
    #[serde(default)]
    pub relay_expected: bool,
    /// iroh's public relays were added because none of ours could be reached.
    #[serde(default)]
    pub public_fallback_active: bool,
    /// By endpoint id.
    #[serde(default)]
    pub peers: BTreeMap<String, PeerStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub agents: Vec<String>,
    /// The projects the last completed exchange covered: trusted on both sides.
    pub projects: Vec<String>,
    /// Last exchange that completed, in either direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Files written here from this peer, since the worker started.
    pub received: u64,
    /// Files sent to this peer, since the worker started.
    pub sent: u64,
    /// The version of ferry the peer runs, as it said in the exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// How the last exchange travelled: `direct`, or `relay <url>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Since when every exchange with this peer has failed. Cleared by a good one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<DateTime<Utc>>,
}

impl Status {
    /// Read what a worker last wrote. `None` when no worker has run the lane here.
    #[must_use]
    pub fn read(path: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    /// The project, or `<project>+handins` for its hand-ins folder.
    project_id: String,
    manifest: Vec<Entry>,
    /// False when the dialer will send nothing from this folder (a Worker's machine and the
    /// channel: it only listens). The answerer then asks for nothing, rather than asking for
    /// files that will be skipped. A dialer that does not say sends.
    #[serde(default = "yes")]
    send: bool,
    /// The dialer's version of ferry, so the answerer can show it. Older peers say none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

fn yes() -> bool {
    true
}

/// The key a project's hand-ins folder is exchanged under, beside the channel's own.
/// A peer that predates the hand-ins folder does not know it and refuses it, which is the
/// compatible answer: the channel still syncs.
pub const HANDINS_SUFFIX: &str = "+handins";

/// One folder of a project that is exchanged: the channel, or its hand-ins.
struct Share {
    key: String,
    dir: PathBuf,
    rules: Rules,
    /// Whether this machine offers what is in the folder. False only for the channel on a
    /// machine whose agents are all Workers: it hears the fleet and says nothing back
    /// through it (ADR 0024).
    send: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
enum Reply {
    Plan(Plan),
    Refused { reason: String },
}

/// What one exchange with a peer moved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub received: u64,
    pub sent: u64,
    /// The projects that were actually exchanged. A project only one side serves, or
    /// only one side trusts the other in, is refused by the other side and left out.
    pub projects: Vec<String>,
    /// The version the peer said it runs.
    pub peer_version: Option<String>,
    /// How the connection travelled: `direct` or `relay <url>`.
    pub path: Option<String>,
}

/// This build's version, as it is told to peers.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How a connection is travelling now: the selected path, direct or through a relay.
fn path_of(connection: &Connection) -> Option<String> {
    let paths = connection.paths();
    let chosen = paths
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .or_else(|| paths.iter().next())?;
    Some(if chosen.is_relay() {
        match chosen.remote_addr() {
            iroh::TransportAddr::Relay(url) => format!("relay {url}"),
            _ => "relay".to_owned(),
        }
    } else {
        "direct".to_owned()
    })
}

/// One endpoint serving and syncing every channel in `projects`.
pub struct Lane {
    endpoint: Endpoint,
    /// The channels served. Grows while the worker runs ([`Lane::add_project`]).
    projects: Mutex<Vec<ProjectRoute>>,
    own: String,
    cache: Mutex<HashCache>,
    status: Mutex<Status>,
    status_file: Option<PathBuf>,
    /// The agents that run on this machine, so the lane knows when every one of them is a
    /// Worker and the channel is receive-only here. Empty (tests) means none are known.
    local_agents: Mutex<Vec<String>>,
    /// The relay map the endpoint was bound with, kept when public relays may be added to it
    /// later (`fallback_public_relays`): the endpoint shares it, so an entry added here is
    /// seen by iroh.
    fallback_map: Mutex<Option<RelayMap>>,
}

impl Lane {
    /// A lane over an endpoint that is already bound (see [`bind`]). `status_file` is where
    /// it records what it did; `None` records nothing (tests).
    #[must_use]
    pub fn new(
        endpoint: Endpoint,
        projects: Vec<ProjectRoute>,
        relay_url: Option<String>,
        status_file: Option<PathBuf>,
    ) -> Arc<Self> {
        let own = endpoint_hex(&endpoint.id());
        Arc::new(Self {
            status: Mutex::new(Status {
                endpoint_id: own.clone(),
                started: Some(Utc::now()),
                version: Some(VERSION.to_owned()),
                relay_url,
                ..Status::default()
            }),
            endpoint,
            projects: Mutex::new(projects),
            own,
            cache: Mutex::new(HashCache::default()),
            status_file,
            local_agents: Mutex::new(Vec::new()),
            fallback_map: Mutex::new(None),
        })
    }

    /// Say how relays are meant to be used, so the lane knows what "relay unreachable"
    /// means and what to do about it: `expected` is false for direct only; `fallback` is the
    /// map the endpoint was bound with when iroh's public relays may be added to it once
    /// none of ours has answered for a couple of minutes.
    pub fn configure_relays(&self, expected: bool, fallback: Option<RelayMap>) {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .relay_expected = expected;
        *self
            .fallback_map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fallback;
    }

    /// A snapshot of the channels served now.
    #[must_use]
    pub fn routes(&self) -> Vec<ProjectRoute> {
        self.projects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Serve one more channel from the next connection and round on, or replace the route
    /// of one already served. For a worker that finds a project newly approved while it
    /// runs, so it need not be restarted for the lane to carry it.
    pub fn add_project(&self, route: ProjectRoute) {
        let mut projects = self
            .projects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match projects
            .iter_mut()
            .find(|have| have.project_id == route.project_id)
        {
            Some(have) => *have = route,
            None => projects.push(route),
        }
    }

    /// Stop serving a channel, from the next connection and round on: it was archived, or
    /// its master took this worker out of it. Returns whether it had been served.
    pub fn remove_project(&self, project_id: &str) -> bool {
        let mut projects = self
            .projects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = projects.len();
        projects.retain(|route| route.project_id != project_id);
        projects.len() != before
    }

    /// The ids of the channels served now.
    #[must_use]
    pub fn project_ids(&self) -> Vec<String> {
        self.routes()
            .into_iter()
            .map(|route| route.project_id)
            .collect()
    }

    /// Say which agents run on this machine. A project in which all of them are Workers is
    /// then listened to and never published: the channel is receive-only here.
    pub fn set_local_agents(&self, names: Vec<String>) {
        *self
            .local_agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = names;
    }

    /// The folders of `route` exchanged with `peer`, on this machine's rules:
    ///
    /// - the channel, minus anything a Worker-level agent authored, and offered only if some
    ///   agent here is above Worker;
    /// - the hand-ins folder when the project keeps it apart from the channel (layout 2 or a
    ///   recorded path), minus the head's verdict files unless the peer is the head.
    ///
    /// Read from disk each time: a level changed a second ago applies on the next exchange.
    fn shares(&self, route: &ProjectRoute, peer: &Peer) -> Vec<Share> {
        let channel = &route.communications;
        let id = &route.project_id;
        let local = self
            .local_agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if peer.bootstrap.contains(id) && !peer.projects.contains(id) {
            // First contact: the agents' records and nothing more, in both directions.
            return vec![Share {
                key: id.clone(),
                dir: channel.clone(),
                rules: Rules::for_channel(channel).transports_only(route.clone()),
                send: !access::machine_is_worker_only(channel, id, &local),
            }];
        }
        let handins_elsewhere = !ferry::handins_dir_for(channel, id).starts_with(channel);
        let mut channel_rules = fleet_scoped(Rules::for_channel(channel), id);
        if handins_elsewhere {
            // `handins/` in the channel is the old layout's; the project's hand-ins are
            // exchanged as their own share, so an unmigrated peer cannot re-create it here.
            channel_rules = channel_rules.excluding("handins/");
        }
        // A project's data is machine-local wherever it sits (ADR 0026): if it is inside the
        // channel, it stays out of what is exchanged; if it IS the channel, nothing is.
        let mut skip_channel = false;
        match data_spot(channel, id) {
            Some(DataSpot::Inside(pattern)) => channel_rules = channel_rules.excluding(&pattern),
            Some(DataSpot::Whole) => skip_channel = true,
            None => {}
        }
        let mut shares = vec![Share {
            key: id.clone(),
            dir: channel.clone(),
            rules: channel_rules
                .refusing_authors(access::refused_authors(channel, id))
                .refusing_roster(access::unadmitted_names(channel, id))
                // A peer whose agents are all Workers writes its hand-ins, never the channel.
                .refusing_incoming(access::machine_is_worker_only(
                    channel,
                    id,
                    &peer.agents.iter().cloned().collect::<Vec<_>>(),
                )),
            send: !access::machine_is_worker_only(channel, id, &local),
        }];
        if skip_channel {
            shares.clear();
        }
        let handins = ferry::handins_dir_for(channel, id);
        if !handins.starts_with(channel) {
            // The folder is the project's own and a hand-in is written into it; making it
            // here is what a worker does on start anyway.
            let _ = std::fs::create_dir_all(&handins);
            let verdicts = access::may_write_verdicts(channel, id, &peer.agents);
            let mut rules = Rules::for_channel(&handins).refusing_verdicts(!verdicts);
            match data_spot(&handins, id) {
                Some(DataSpot::Inside(pattern)) => rules = rules.excluding(&pattern),
                Some(DataSpot::Whole) => return shares,
                None => {}
            }
            shares.push(Share {
                key: format!("{id}{HANDINS_SUFFIX}"),
                rules,
                dir: handins,
                send: true,
            });
        }
        shares
    }

    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// A copy of what the lane has done so far.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Every peer some channel here has an honoured TRANSPORTS record for, and the
    /// projects it is trusted in. Read from disk on every call.
    #[must_use]
    pub fn trusted(&self) -> BTreeMap<EndpointId, Peer> {
        let mut peers: BTreeMap<EndpointId, Peer> = BTreeMap::new();
        let projects = self.routes();
        for route in &projects {
            for record in ferryman_channel::transports::honoured_records(route) {
                if record.endpoint_id == self.own {
                    continue;
                }
                let Ok(bytes) = hex::decode(&record.endpoint_id) else {
                    continue;
                };
                let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
                    continue;
                };
                let Ok(id) = EndpointId::from_bytes(&bytes) else {
                    continue;
                };
                let peer = peers.entry(id).or_default();
                peer.agents.insert(record.agent.clone());
                peer.projects.insert(route.project_id.clone());
                if peer.relay.is_none() {
                    peer.relay = record.relay_url.as_deref().and_then(|u| u.parse().ok());
                }
            }
        }
        // A peer trusted in one channel may be offered the transports records of any other
        // channel served here that it has none in yet, so two machines that already share
        // a project can find each other in a new one without a hand-copied file.
        //
        // Only where that peer's agent is already on the channel's roster: a record is
        // let in for an agent the channel knows, so offering the channel to a peer that
        // has no place on it would only be asking to be refused, and would tell it the
        // project exists.
        for peer in peers.values_mut() {
            peer.bootstrap = projects
                .iter()
                .filter(|route| !peer.projects.contains(&route.project_id))
                .filter(|route| {
                    peer.agents.iter().any(|agent| {
                        route
                            .communications
                            .join("agents")
                            .join(format!(
                                "{}.json",
                                ferryman_channel::canonical_agent_name(agent)
                            ))
                            .is_file()
                    })
                })
                .map(|route| route.project_id.clone())
                .collect();
        }
        peers
    }

    /// Serve every incoming connection until the endpoint closes.
    pub async fn serve(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let lane = Arc::clone(&self);
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    lane.answer_connection(connection).await;
                }
            });
        }
    }

    async fn answer_connection(&self, connection: Connection) {
        let remote = connection.remote_id();
        let trusted = self.trusted();
        // The connection-level refusal: an endpoint no channel here vouches for is closed
        // before a single stream is read.
        let Some(peer) = trusted.get(&remote).cloned() else {
            connection.close(NOT_TRUSTED.into(), b"not trusted by any channel here");
            return;
        };
        while let Ok((send, recv)) = connection.accept_bi().await {
            let mut outcome = self.answer(&peer, send, recv).await;
            if let Ok(done) = &mut outcome {
                done.path = path_of(&connection);
            }
            self.note(&remote, &peer, outcome);
        }
    }

    async fn answer(
        &self,
        peer: &Peer,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<Outcome> {
        let hello: Hello = read_frame(&mut recv).await?;
        let peer_version = hello.version.clone();
        // `<project>` is the channel, `<project>+handins` its hand-ins folder.
        let project_id = hello
            .project_id
            .strip_suffix(HANDINS_SUFFIX)
            .unwrap_or(&hello.project_id);
        let projects = self.routes();
        let route = projects.iter().find(|route| route.project_id == project_id);
        let share = route
            .filter(|_| peer.projects.contains(project_id) || peer.bootstrap.contains(project_id))
            .and_then(|route| {
                self.shares(route, peer)
                    .into_iter()
                    .find(|share| share.key == hello.project_id)
            });
        let Some(share) = share else {
            write_frame(
                &mut send,
                &Reply::Refused {
                    reason: format!("{} is not shared with you here", hello.project_id),
                },
            )
            .await?;
            send.finish()?;
            // Normal, not a fault: the dialer offers every project it trusts us in, and
            // this one we do not serve, or do not trust it in.
            return Ok(Outcome::default());
        };
        let (channel, rules) = (&share.dir, &share.rules);
        let ours = self.scan(channel, rules);
        let mut plan = manifest::plan(&hello.manifest, &ours, rules);
        // A folder this machine only listens to gives nothing; a dialer that only listens
        // is asked for nothing.
        if !share.send {
            plan.give.clear();
        }
        if !hello.send {
            plan.want.clear();
        }
        plan.version = Some(VERSION.to_owned());
        write_frame(&mut send, &Reply::Plan(plan.clone())).await?;
        let mut received = 0;
        for path in &plan.want {
            received += u64::from(receive_item(&mut recv, channel, rules, path).await?);
        }
        let mut sent = 0;
        for path in &plan.give {
            sent += u64::from(send_item(&mut send, channel, rules, &ours, path).await?);
        }
        send.finish()?;
        Ok(Outcome {
            received,
            sent,
            projects: vec![share.key.clone()],
            peer_version,
            path: None,
        })
    }

    /// One round: every trusted peer, every project shared with it.
    pub async fn round(&self) {
        for (id, peer) in self.trusted() {
            let outcome = tokio::time::timeout(PEER_TIMEOUT, self.sync_peer(id, &peer))
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("took longer than {PEER_TIMEOUT:?}")));
            self.note(&id, &peer, outcome);
        }
        self.record_relay();
    }

    /// Sync every project shared with one peer, as the side that dials.
    ///
    /// # Errors
    /// The peer cannot be reached, refuses, or breaks the protocol.
    pub async fn sync_peer(&self, id: EndpointId, peer: &Peer) -> Result<Outcome> {
        let mut addr = EndpointAddr::new(id);
        if let Some(relay) = &peer.relay {
            addr = addr.with_relay_url(relay.clone());
        }
        let connection = tokio::time::timeout(CONNECT_TIMEOUT, self.endpoint.connect(addr, ALPN))
            .await
            .context("no answer")?
            .context("connect")?;
        let mut totals = Outcome::default();
        let mut failures = Vec::new();
        let projects = self.routes();
        for route in projects.iter().filter(|route| {
            peer.projects.contains(&route.project_id) || peer.bootstrap.contains(&route.project_id)
        }) {
            for share in self.shares(route, peer) {
                match self.sync_share(&connection, &share).await {
                    Ok(Some((received, sent, version))) => {
                        totals.received += received;
                        totals.sent += sent;
                        totals.projects.push(share.key.clone());
                        if version.is_some() {
                            totals.peer_version = version;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => failures.push(format!("{}: {error:#}", share.key)),
                }
            }
        }
        totals.path = path_of(&connection);
        connection.close(0u32.into(), b"done");
        if failures.is_empty() {
            Ok(totals)
        } else {
            bail!("{}", failures.join("; "))
        }
    }

    /// `None`: the other side does not share this project with us.
    async fn sync_share(
        &self,
        connection: &Connection,
        share: &Share,
    ) -> Result<Option<(u64, u64, Option<String>)>> {
        let (channel, rules) = (&share.dir, &share.rules);
        let ours = self.scan(channel, rules);
        // What this side offers: everything it has, or - for a folder it only listens to -
        // nothing, so even a peer that asks is told "skip" (the sender enforces it too).
        let offered = if share.send {
            ours.clone()
        } else {
            BTreeMap::new()
        };
        let (mut send, mut recv) = connection.open_bi().await?;
        write_frame(
            &mut send,
            &Hello {
                project_id: share.key.clone(),
                manifest: ours.values().cloned().collect(),
                send: share.send,
                version: Some(VERSION.to_owned()),
            },
        )
        .await?;
        let plan = match read_frame::<Reply>(&mut recv).await? {
            Reply::Plan(plan) => plan,
            Reply::Refused { .. } => return Ok(None),
        };
        let mut sent = 0;
        for path in &plan.want {
            sent += u64::from(send_item(&mut send, channel, rules, &offered, path).await?);
        }
        send.finish()?;
        let mut received = 0;
        for path in &plan.give {
            received += u64::from(receive_item(&mut recv, channel, rules, path).await?);
        }
        // Wait for the answerer to finish its side: it does that only after it has read and
        // written everything sent to it. Closing the connection before then discards what
        // is still in flight, which is exactly the case where there was nothing to receive.
        let _ = recv.read_to_end(64).await;
        Ok(Some((received, sent, plan.version)))
    }

    fn scan(&self, channel: &Path, rules: &Rules) -> BTreeMap<String, Entry> {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        manifest::scan(channel, rules, &mut cache)
    }

    fn note(&self, id: &EndpointId, peer: &Peer, outcome: Result<Outcome>) {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = status.peers.entry(endpoint_hex(id)).or_default();
        entry.agents = peer.agents.iter().cloned().collect();
        match outcome {
            Ok(outcome) => {
                entry.last_sync = Some(Utc::now());
                entry.last_error = None;
                entry.failing_since = None;
                entry.received += outcome.received;
                entry.sent += outcome.sent;
                if !outcome.projects.is_empty() {
                    entry.projects = outcome.projects;
                }
                if outcome.peer_version.is_some() {
                    entry.version = outcome.peer_version;
                }
                if outcome.path.is_some() {
                    entry.path = outcome.path;
                }
            }
            Err(error) => {
                entry.last_error = Some(format!("{error:#}"));
                entry.failing_since.get_or_insert_with(Utc::now);
            }
        }
    }

    /// The relay this endpoint is homed on, as a URL, for the TRANSPORTS record: a peer
    /// dials us through it. Falls back to the primary relay of ours when none is connected.
    #[must_use]
    pub fn home_relay_url(&self) -> Option<String> {
        let relays = self.endpoint.home_relay_status().get();
        relays
            .iter()
            .find(|relay| relay.is_connected())
            .map(|relay| relay.url().to_string())
    }

    fn record_relay(&self) {
        let relays = self.endpoint.home_relay_status().get();
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.relay_connected = relays.iter().any(iroh::endpoint::RelayStatus::is_connected);
        status.home_relay = relays
            .iter()
            .find(|relay| relay.is_connected())
            .map(|relay| relay.url().to_string());
        if !status.relay_expected || status.relay_connected {
            status.relay_down_since = None;
        } else {
            status.relay_down_since.get_or_insert_with(Utc::now);
        }
        // Our own relays are all unreachable, and public ones were asked for as a fallback:
        // add them now. The map is shared with the endpoint, so iroh sees them on its next
        // look at the network. Once added they stay for the life of the worker.
        if !status.public_fallback_active
            && status
                .relay_down_since
                .is_some_and(|since| Utc::now() - since >= FALLBACK_AFTER)
            && let Some(map) = self
                .fallback_map
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
        {
            map.extend(&RelayMode::Default.relay_map());
            status.public_fallback_active = true;
        }
        status.relay_problem = relays.iter().find_map(|relay| {
            relay
                .auth_denied_reason()
                .map(|why| format!("the relay refused our token: {why}"))
                .or_else(|| relay.last_error().map(|error| format!("{error:#}")))
        });
        status.updated = Some(Utc::now());
        if let Some(path) = &self.status_file
            && let Ok(bytes) = serde_json::to_vec_pretty(&*status)
        {
            let temp = path.with_extension("json.tmp");
            if std::fs::write(&temp, bytes).is_ok() {
                let _ = std::fs::rename(&temp, path);
            }
        }
    }

    /// Serve, and run a round every `every`, until the endpoint is closed.
    pub async fn run(self: Arc<Self>, every: Duration) {
        tokio::spawn(Arc::clone(&self).serve());
        while !self.endpoint.is_closed() {
            self.round().await;
            tokio::time::sleep(every).await;
        }
    }
}

async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME {
        bail!("a message of {} bytes is over the limit", bytes.len());
    }
    let length = u32::try_from(bytes.len())?;
    send.write_all(&length.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut length = [0_u8; 4];
    recv.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))?;
    if length > MAX_FRAME {
        bail!("the peer sent a message of {length} bytes, over the limit");
    }
    let mut bytes = vec![0_u8; length];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Send `path`, but only a path this side offered, and only as it is now.
async fn send_item(
    send: &mut SendStream,
    channel: &Path,
    rules: &Rules,
    offered: &BTreeMap<String, Entry>,
    path: &str,
) -> Result<bool> {
    let item = offered
        .contains_key(path)
        .then(|| manifest::read_for_send(channel, rules, path))
        .flatten();
    match item {
        Some((entry, bytes)) => {
            write_frame(send, &Some(entry)).await?;
            send.write_all(&bytes).await?;
            Ok(true)
        }
        None => {
            write_frame(send, &None::<Entry>).await?;
            Ok(false)
        }
    }
}

/// Receive the item for `expected`. A file this side cannot take (it breaks a rule, or a
/// newer copy is here) is read and dropped, so the stream stays in step; a peer that sends
/// a different path than the one asked for is a peer that is not speaking the protocol.
async fn receive_item(
    recv: &mut RecvStream,
    channel: &Path,
    rules: &Rules,
    expected: &str,
) -> Result<bool> {
    let Some(entry) = read_frame::<Option<Entry>>(recv).await? else {
        return Ok(false);
    };
    if entry.path != expected {
        bail!("sent '{}' when '{expected}' was asked for", entry.path);
    }
    if entry.size > MAX_FILE {
        bail!(
            "sent '{}' at {} bytes, over the limit",
            entry.path,
            entry.size
        );
    }
    let mut bytes = vec![0_u8; usize::try_from(entry.size)?];
    recv.read_exact(&mut bytes).await?;
    Ok(manifest::write_received(channel, rules, &entry, &bytes).unwrap_or(false))
}

/// The fleet channel keeps its top-level `local/` (this machine's own part) to itself, even
/// when its `.stignore` is lost. Only the fleet channel, and only at the top: a project's
/// `handins/local/` is an ordinary folder and replicates.
fn fleet_scoped(rules: Rules, project_id: &str) -> Rules {
    if project_id == ferryman_channel::fleethome::PROJECT {
        rules.excluding("local/")
    } else {
        rules
    }
}

/// Where a project's machine-local data sits relative to a folder the lane would exchange.
#[derive(Debug, PartialEq, Eq)]
enum DataSpot {
    /// Inside it: the folder-anchored pattern that keeps it out.
    Inside(String),
    /// It is the folder, or the folder is inside it: nothing here may be exchanged.
    Whole,
}

/// The project's data folder (`projects/<id>/data`, or the path recorded) against `dir`.
/// Data is never synced, by Syncthing or here, however a person placed it.
fn data_spot(dir: &Path, id: &str) -> Option<DataSpot> {
    let root = ferry::find_root_from(dir)?;
    let entry = root
        .projects()
        .into_iter()
        .find(|entry| entry.project_id == id)?;
    let data = entry.data_path(&root);
    // The scope guard's comparison: case-insensitive on Windows, separators and trailing
    // slashes alike, so `X:\Ferry\..` and `X:\ferry\..` are one place.
    if syncscope::is_within(dir, &data) {
        return Some(DataSpot::Whole);
    }
    let text = syncscope::below(&data, dir)?;
    (!text.is_empty())
        .then(|| format!("{text}/"))
        .map(DataSpot::Inside)
}

#[cfg(test)]
mod data_tests {
    use super::*;

    #[test]
    fn local_is_the_fleet_channels_alone_and_only_at_the_top() {
        let dir = tempfile::tempdir().unwrap();
        let channel = dir.path();
        let fleet = fleet_scoped(Rules::for_channel(channel), "fleet");
        assert!(fleet.excludes("local/key.json"));
        assert!(fleet.excludes_incoming("local/agents-pinned/x.json"));
        assert!(!fleet.excludes("notices/local.json"));
        let project = fleet_scoped(Rules::for_channel(channel), "demo");
        assert!(!project.excludes("local/x.json"), "not a project's rule");
        assert!(!project.excludes("handins/local/t-1/order.json"));
        assert!(!project.excludes_incoming("handins/local/t-1/order.json"));
        assert!(
            !fleet.excludes("handins/local/t-1/order.json"),
            "top level only"
        );
    }

    #[test]
    fn a_data_folder_is_compared_the_way_the_scope_guard_compares_paths() {
        ferry::isolate_root_search_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let root = ferry::Root::create_with_layout(&dir.path().join("Ferry"), 2).unwrap();
        let channel = root.comms_home("demo");
        std::fs::create_dir_all(&channel).unwrap();
        root.adopt("demo", &channel, None).unwrap();
        let recorded = channel.join("scratch").join("db");
        root.update_entry("demo", |entry| entry.data = Some(recorded.clone()))
            .unwrap();
        // Trailing slash and the other separator do not change the answer.
        let sloppy = format!("{}/", channel.display()).replace('\\', "/");
        assert_eq!(
            data_spot(Path::new(&sloppy), "demo"),
            Some(DataSpot::Inside("scratch/db/".into()))
        );
        // The same place spelled in another case: one place on Windows, two elsewhere.
        let shouted = PathBuf::from(channel.display().to_string().to_uppercase());
        assert_eq!(
            data_spot(&shouted, "demo").is_some(),
            cfg!(windows),
            "X:\\Ferry and X:\\ferry are one place only where paths are case-insensitive"
        );
        // The data folder inside the (differently cased) folder being exchanged.
        root.update_entry("demo", |entry| entry.data = Some(channel.clone()))
            .unwrap();
        assert_eq!(
            data_spot(&shouted.join("sub"), "demo") == Some(DataSpot::Whole),
            cfg!(windows)
        );
    }

    #[test]
    fn a_projects_data_inside_what_the_lane_exchanges_is_kept_out() {
        ferry::isolate_root_search_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let root = ferry::Root::create_with_layout(&dir.path().join("ferry"), 2).unwrap();
        let channel = root.comms_home("demo");
        std::fs::create_dir_all(&channel).unwrap();
        root.adopt("demo", &channel, None).unwrap();
        // The default sits beside the channel, not in it.
        assert_eq!(data_spot(&channel, "demo"), None);

        // Recorded inside the channel (a hand edit, or an old manifest): kept out.
        root.update_entry("demo", |entry| {
            entry.data = Some(channel.join("scratch").join("db"))
        })
        .unwrap();
        let spot = data_spot(&channel, "demo");
        assert_eq!(spot, Some(DataSpot::Inside("scratch/db/".into())));
        let rules = Rules::for_channel(&channel).excluding("scratch/db/");
        assert!(rules.excludes("scratch/db/model.bin"));
        assert!(rules.excludes_incoming("scratch/db/x"));
        assert!(!rules.excludes("tasks/t-1/order.json"));

        // The data folder as the channel itself: nothing is exchanged.
        root.update_entry("demo", |entry| entry.data = Some(channel.clone()))
            .unwrap();
        assert_eq!(data_spot(&channel, "demo"), Some(DataSpot::Whole));
        assert_eq!(
            data_spot(&channel.join("sub"), "demo"),
            Some(DataSpot::Whole)
        );
        // Another project is not affected.
        assert_eq!(data_spot(&channel, "other"), None);
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    fn config(extra: &str, state: &Path) -> IrohConfig {
        IrohConfig::parse(&format!("[iroh]\nenabled = true\n{extra}"), Some(state))
    }

    fn urls(mode: &RelayMode) -> Vec<String> {
        let mut urls: Vec<String> = mode
            .relay_map()
            .urls::<Vec<RelayUrl>>()
            .iter()
            .map(ToString::to_string)
            .collect();
        urls.sort();
        urls
    }

    #[test]
    fn nothing_named_is_iroh_s_public_relays() {
        let dir = tempfile::tempdir().unwrap();
        let mode = relay_mode(&config("", dir.path())).unwrap();
        assert_eq!(mode, RelayMode::Default);
        assert!(!mode.relay_map().is_empty());
    }

    #[test]
    fn direct_only_is_no_relay() {
        let dir = tempfile::tempdir().unwrap();
        let mode = relay_mode(&config("direct_only = true\n", dir.path())).unwrap();
        assert!(mode.relay_map().is_empty());
    }

    #[test]
    fn our_relays_are_exactly_ours_and_no_public_one_unless_added_later() {
        let dir = tempfile::tempdir().unwrap();
        let both = config(
            "relay_url = \"https://a.example\"\nrelays = [\"https://b.example\"]\n\
             fallback_public_relays = true\n",
            dir.path(),
        );
        let mode = relay_mode(&both).unwrap();
        assert_eq!(urls(&mode), ["https://a.example/", "https://b.example/"]);
    }

    #[test]
    fn the_token_is_optional_and_is_put_on_our_relays_only_when_there_is_one() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config("relay_url = \"https://a.example\"\n", dir.path());
        let token_of = |mode: &RelayMode| -> Vec<Option<String>> {
            mode.relay_map()
                .relays::<Vec<Arc<RelayConfig>>>()
                .iter()
                .map(|relay| relay.auth_token.clone())
                .collect()
        };
        assert_eq!(token_of(&relay_mode(&cfg).unwrap()), [None]);
        std::fs::write(
            dir.path().join(crate::config::DEFAULT_TOKEN_FILE),
            "s3cret\n",
        )
        .unwrap();
        assert_eq!(
            token_of(&relay_mode(&cfg).unwrap()),
            [Some("s3cret".to_owned())]
        );
    }

    #[test]
    fn our_hosts_are_told_apart_from_public_ones_by_host() {
        let hosts = relay_hosts(&[
            "https://162.35.10.46".into(),
            "https://Relay.Example".into(),
        ]);
        assert!(hosts.contains(&"162.35.10.46".to_owned()), "{hosts:?}");
        assert!(
            hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case("relay.example"))
        );
    }

    #[tokio::test]
    async fn the_lane_binds_with_no_token_in_each_of_the_three_modes() {
        let dir = tempfile::tempdir().unwrap();
        for extra in [
            "",
            "relay_url = \"https://127.0.0.1:9\"\n",
            "relay_url = \"https://127.0.0.1:9\"\nfallback_public_relays = true\n",
            "direct_only = true\n",
        ] {
            let cfg = config(extra, dir.path());
            assert_eq!(cfg.token().unwrap(), None);
            let (endpoint, kept) = bind_with_map(&cfg, iroh::SecretKey::generate())
                .await
                .unwrap_or_else(|error| panic!("{extra:?}: {error:#}"));
            assert_eq!(
                kept.is_some(),
                cfg.fallback_public_relays && !cfg.relays.is_empty()
            );
            endpoint.close().await;
        }
    }
}

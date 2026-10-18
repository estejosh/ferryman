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

use ferryman_channel::{ProjectRoute, access, ferry};

use crate::manifest::{self, Entry, HashCache, Plan, Rules};
use crate::{ALPN, IrohConfig, MAX_FILE, endpoint_hex};

/// How often a worker syncs with each peer.
pub const ROUND_EVERY: Duration = Duration::from_secs(30);
/// How long a peer gets to answer a dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long one peer's whole round may take before it is abandoned until the next.
const PEER_TIMEOUT: Duration = Duration::from_secs(600);
/// The largest message that is not a file. A manifest of a big channel is the biggest.
const MAX_FRAME: usize = 32 * 1024 * 1024;

/// Close code for a connection from an endpoint no channel here has on record.
const NOT_TRUSTED: u32 = 403;

/// Bind this machine's endpoint for `config`: our relay or none, never n0's.
///
/// `presets::Minimal` sets the crypto provider and nothing else, so there is no address
/// lookup service (no n0 DNS, no pkarr) to opt out of. Peers are dialed by endpoint id and
/// the relay URL their signed record names; iroh then finds a direct path between the two
/// machines through that relay when one exists.
///
/// # Errors
/// The relay URL does not parse, the token file cannot be read, or the endpoint cannot
/// bind a socket.
pub async fn bind(config: &IrohConfig, key: iroh::SecretKey) -> Result<Endpoint> {
    let builder = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(crate::tls::ca_config(config.relay_cert_sha256));
    let builder = match &config.relay_url {
        Some(url) => {
            let url: RelayUrl = url
                .parse()
                .with_context(|| format!("relay_url '{url}' is not a URL"))?;
            let mut relay = RelayConfig::from(url);
            if let Some(quic) = relay.quic.as_mut() {
                quic.port = config.relay_quic_port;
            }
            if let Some(token) = config.token()? {
                relay = relay.with_auth_token(token);
            }
            builder.relay_mode(RelayMode::Custom(RelayMap::from(relay)))
        }
        None => builder.relay_mode(RelayMode::Disabled),
    };
    builder.bind().await.context("bind the iroh endpoint")
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
    if config.relay_url.is_none() {
        bail!("no relay_url configured");
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
}

/// One endpoint serving and syncing every channel in `projects`.
pub struct Lane {
    endpoint: Endpoint,
    projects: Vec<ProjectRoute>,
    own: String,
    cache: Mutex<HashCache>,
    status: Mutex<Status>,
    status_file: Option<PathBuf>,
    /// The agents that run on this machine, so the lane knows when every one of them is a
    /// Worker and the channel is receive-only here. Empty (tests) means none are known.
    local_agents: Mutex<Vec<String>>,
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
                relay_url,
                ..Status::default()
            }),
            endpoint,
            projects,
            own,
            cache: Mutex::new(HashCache::default()),
            status_file,
            local_agents: Mutex::new(Vec::new()),
        })
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
        let mut shares = vec![Share {
            key: id.clone(),
            dir: channel.clone(),
            rules: Rules::for_channel(channel)
                .refusing_authors(access::refused_authors(channel, id)),
            send: !access::machine_is_worker_only(channel, id, &local),
        }];
        let handins = ferry::handins_dir_for(channel, id);
        if !handins.starts_with(channel) {
            // The folder is the project's own and a hand-in is written into it; making it
            // here is what a worker does on start anyway.
            let _ = std::fs::create_dir_all(&handins);
            let verdicts = access::may_write_verdicts(channel, id, &peer.agents);
            shares.push(Share {
                key: format!("{id}{HANDINS_SUFFIX}"),
                rules: Rules::for_channel(&handins).refusing_verdicts(!verdicts),
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
        for route in &self.projects {
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
            let outcome = self.answer(&peer, send, recv).await;
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
        // `<project>` is the channel, `<project>+handins` its hand-ins folder.
        let project_id = hello
            .project_id
            .strip_suffix(HANDINS_SUFFIX)
            .unwrap_or(&hello.project_id);
        let route = self
            .projects
            .iter()
            .find(|route| route.project_id == project_id);
        let share = route
            .filter(|_| peer.projects.contains(project_id))
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
        for route in self
            .projects
            .iter()
            .filter(|route| peer.projects.contains(&route.project_id))
        {
            for share in self.shares(route, peer) {
                match self.sync_share(&connection, &share).await {
                    Ok(Some((received, sent))) => {
                        totals.received += received;
                        totals.sent += sent;
                        totals.projects.push(share.key.clone());
                    }
                    Ok(None) => {}
                    Err(error) => failures.push(format!("{}: {error:#}", share.key)),
                }
            }
        }
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
    ) -> Result<Option<(u64, u64)>> {
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
        Ok(Some((received, sent)))
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
                entry.received += outcome.received;
                entry.sent += outcome.sent;
                if !outcome.projects.is_empty() {
                    entry.projects = outcome.projects;
                }
            }
            Err(error) => entry.last_error = Some(format!("{error:#}")),
        }
    }

    fn record_relay(&self) {
        let relays = self.endpoint.home_relay_status().get();
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.relay_connected = relays.iter().any(iroh::endpoint::RelayStatus::is_connected);
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

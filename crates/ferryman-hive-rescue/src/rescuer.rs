//! The rescue channel's behaviour: when to post, when to read, and what to do with a
//! record that counts.
//!
//! ```text
//! cut off from the relay AND every peer for cut_off_minutes
//!     master:  post one sealed, master-signed record (again every repost_minutes while
//!              still cut off, so a fresh one is always there)
//!     backup:  post only if cut off for backup_after_minutes AND no master record that
//!              fresh exists on Hive
//!     all:     read Hive every poll_minutes; a record that verifies feeds iroh a dial
//!              address (a custom address-lookup source) and the rescue relay
//! the master's relay or relay list changes (connected): post, so the next look finds it
//! routine_hours > 0: a baseline post. Off by default.
//! ```
//!
//! Nothing here grants access. A record is a way to dial; the ordinary iroh checks (the
//! roster-honoured TRANSPORTS records, a phone's signed grant) decide who is let in.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ferryman_channel::fleethome::FleetRelay;
use ferryman_channel::secrets::EncryptionIdentity;
use ferryman_channel::{AgentIdentity, AgentRoute, canonical_agent_name};
use ferryman_iroh::lane::Status;
use iroh::address_lookup::MemoryLookup;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayUrl};

use crate::config::{Credentials, RescueConfig};
use crate::record::{self, Body, Kind, RescueRelay, Signed, Verifier, Where};
use crate::rpc::HiveClient;
use crate::state::{Posted, State};
use crate::tx::CustomJson;

/// What the fleet folder says right now.
#[derive(Debug, Clone, Default)]
pub struct FleetView {
    pub roster: Vec<AgentRoute>,
    /// The master's canonical name.
    pub master: Option<String>,
    pub relays: Vec<FleetRelay>,
    pub relays_version: Option<DateTime<Utc>>,
    /// Roster names the master revoked: not wrapped to from then on.
    pub revoked: std::collections::BTreeSet<String>,
}

/// A source of [`FleetView`]: the fleet folder in production, a fixture in tests.
pub type ViewFn = Arc<dyn Fn() -> FleetView + Send + Sync>;

/// The view of the fleet folder under a ferry root.
#[must_use]
pub fn view_from_root(root: ferryman_channel::ferry::Root) -> ViewFn {
    Arc::new(move || {
        let dir = root.fleet_dir();
        let trust = ferryman_channel::fleethome::Trust::load(&dir);
        let list = ferryman_channel::fleethome::read_relays(&root);
        let roster = trust.roster().to_vec();
        let revoked = roster
            .iter()
            .map(|a| canonical_agent_name(&a.name))
            .filter(|name| ferryman_channel::master::is_revoked_in(&dir, &roster, name))
            .collect();
        FleetView {
            roster,
            master: trust.master().map(str::to_owned),
            relays: list.relays,
            relays_version: list.written_at,
            revoked,
        }
    })
}

/// Make this machine a recipient: publish its X25519 key on the fleet roster entry it
/// already has (same signing key, so first-key-wins is untouched). Returns whether the
/// entry changed.
///
/// # Errors
/// The entry cannot be written, or the name carries a different signing key.
pub fn publish_encryption_key(
    root: &ferryman_channel::ferry::Root,
    identity: &AgentIdentity,
    enc: &EncryptionIdentity,
) -> Result<bool> {
    let route = ferryman_channel::fleethome::route(root);
    let name = canonical_agent_name(identity.name());
    let mine = enc.public_key_hex();
    let existing = route
        .agents
        .iter()
        .find(|a| canonical_agent_name(&a.name) == name);
    if existing.is_some_and(|a| a.encryption_key.as_deref() == Some(mine.as_str())) {
        return Ok(false);
    }
    let role = existing.map_or_else(|| "worker".to_owned(), |a| a.role.clone());
    let capabilities = existing.map(|a| a.capabilities.clone()).unwrap_or_default();
    ferryman_channel::register_agent_key(
        &route,
        &AgentRoute {
            name: identity.name().to_owned(),
            role,
            capabilities,
            public_key: None,
            encryption_key: Some(mine),
        },
        identity,
    )?;
    Ok(true)
}

/// What the lane knows about itself that goes in a record.
#[derive(Debug, Clone, Default)]
pub struct LaneInfo {
    pub endpoint_id: String,
    /// The relay the endpoint is homed on and connected to.
    pub home_relay: Option<String>,
    pub direct: Vec<String>,
}

/// Since when this machine has been cut off from the relay and every peer, if it has.
///
/// Cut off means: there are peers, every one of them has been failing, and (when a relay
/// is meant to be in use) the relay is not connected. The start is the latest of those
/// beginnings, so it is the moment the last door closed.
#[must_use]
pub fn cut_off_since(status: &Status) -> Option<DateTime<Utc>> {
    if status.peers.is_empty() {
        return None;
    }
    let mut since: Option<DateTime<Utc>> = None;
    for peer in status.peers.values() {
        let failing = peer.failing_since?;
        since = Some(since.map_or(failing, |s| s.max(failing)));
    }
    if status.relay_expected {
        if status.relay_connected {
            return None;
        }
        let down = status.relay_down_since?;
        since = since.map(|s| s.max(down));
    }
    since
}

/// The result of reading Hive.
#[derive(Debug, Default, Clone)]
pub struct PollReport {
    pub answered: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub scanned: usize,
    pub records: Vec<Finding>,
    /// A record was accepted and applied this time.
    pub applied: bool,
}

/// What became of one operation read.
#[derive(Debug, Clone)]
pub struct Finding {
    pub trx_id: String,
    pub timestamp: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone)]
pub enum Verdict {
    /// Verifies; `new` is false when it is one already seen.
    Valid {
        kind: Kind,
        signer: String,
        seq: u64,
        issued: DateTime<Utc>,
        expires: DateTime<Utc>,
        endpoint: String,
        new: bool,
    },
    /// Opened but does not count.
    Refused(String),
    /// Not sealed to this machine, or not a record at all.
    Unreadable(String),
}

/// What a post did (or would do).
#[derive(Debug, Clone)]
pub struct PostOutcome {
    pub kind: Kind,
    pub reason: String,
    pub record: Signed,
    pub op_json_len: usize,
    pub recipients: Vec<String>,
    pub tx_id: String,
    pub node: Option<String>,
}

/// What one tick did.
#[derive(Debug, Default, Clone)]
pub struct TickReport {
    pub cut_off_since: Option<DateTime<Utc>>,
    pub read: Option<PollReport>,
    pub posted: Option<PostOutcome>,
    pub notes: Vec<String>,
}

/// A dry run's output: the record, the operation, and the transaction, unsigned.
#[derive(Debug, Clone)]
pub struct Preview {
    pub record: Signed,
    pub recipients: Vec<String>,
    pub op: CustomJson,
    pub tx_hex: Option<String>,
    pub digest_hex: Option<String>,
}

pub struct Rescuer {
    cfg: RescueConfig,
    creds: Credentials,
    hive: HiveClient,
    view: ViewFn,
    state_dir: PathBuf,
    signer: AgentIdentity,
    enc: EncryptionIdentity,
    lookup: MemoryLookup,
    relay_map: Mutex<Option<RelayMap>>,
    endpoint: Mutex<Option<Endpoint>>,
    state: Mutex<State>,
    last: Mutex<TickReport>,
}

impl Rescuer {
    /// A rescuer for this machine. `state_dir` is the machine state directory.
    #[must_use]
    pub fn new(
        cfg: RescueConfig,
        creds: Credentials,
        view: ViewFn,
        state_dir: PathBuf,
        signer: AgentIdentity,
        enc: EncryptionIdentity,
    ) -> Self {
        let hive = HiveClient::new(cfg.nodes.clone());
        Self::with_client(cfg, creds, hive, view, state_dir, signer, enc)
    }

    /// As [`Self::new`] with the Hive client given (tests point it at a mock node).
    #[must_use]
    pub fn with_client(
        cfg: RescueConfig,
        creds: Credentials,
        hive: HiveClient,
        view: ViewFn,
        state_dir: PathBuf,
        signer: AgentIdentity,
        enc: EncryptionIdentity,
    ) -> Self {
        let state = State::load(&state_dir);
        Self {
            cfg,
            creds,
            hive,
            view,
            state_dir,
            signer,
            enc,
            lookup: MemoryLookup::with_provenance("hive-rescue"),
            relay_map: Mutex::new(None),
            endpoint: Mutex::new(None),
            state: Mutex::new(state),
            last: Mutex::new(TickReport::default()),
        }
    }

    /// Plug the rescue address source into `endpoint`, and keep `relay_map` (the map the
    /// endpoint shares, from [`ferryman_iroh::lane::bind_shared`]) to add the rescue relay.
    /// Anything already accepted (a record cached from before a restart) is applied now.
    ///
    /// # Errors
    /// The endpoint is closed.
    pub fn attach(&self, endpoint: &Endpoint, relay_map: Option<RelayMap>) -> Result<()> {
        endpoint
            .address_lookup()
            .map_err(|e| anyhow!("{e}"))?
            .add(self.lookup.clone());
        *self
            .relay_map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = relay_map;
        *self
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(endpoint.clone());
        let cached = {
            let state = self.state();
            [state.latest_master.clone(), state.latest_backup.clone()]
        };
        let now = Utc::now();
        for record in cached.into_iter().flatten() {
            if record.body.expires > now {
                self.apply(&record);
            }
        }
        Ok(())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn save(&self) {
        let _ = self.state().save(&self.state_dir);
    }

    /// The address source plugged into iroh: what an accepted record taught it.
    #[must_use]
    pub fn lookup(&self) -> &MemoryLookup {
        &self.lookup
    }

    #[must_use]
    pub fn config(&self) -> &RescueConfig {
        &self.cfg
    }

    #[must_use]
    pub fn credentials(&self) -> &Credentials {
        &self.creds
    }

    #[must_use]
    pub fn snapshot(&self) -> State {
        self.state().clone()
    }

    #[must_use]
    pub fn last_tick(&self) -> TickReport {
        self.last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn fleet_tag(view: &FleetView) -> Option<String> {
        let master = view.master.as_deref()?;
        let key = view
            .roster
            .iter()
            .find(|a| canonical_agent_name(&a.name) == master)?
            .public_key
            .clone()?;
        Some(record::fleet_tag(&key))
    }

    /// Read Hive and take in what counts. `apply: false` only reports (no ledger change,
    /// nothing fed to iroh).
    pub async fn poll(&self, now: DateTime<Utc>, apply: bool) -> Result<PollReport> {
        let view = (self.view)();
        let fleet = Self::fleet_tag(&view).context("the fleet folder names no master yet")?;
        let master = view.master.clone().unwrap_or_default();
        let read = self
            .hive
            .read_history(&self.creds.account, &self.cfg.op_id, 100)
            .await;
        let mut report = PollReport {
            answered: read.answered.clone(),
            failed: read.failed.clone(),
            scanned: read.ops.len(),
            ..PollReport::default()
        };
        let verifier = Verifier {
            fleet: &fleet,
            roster: &view.roster,
            master: &master,
            backups: &self.cfg.backup_agents,
            now,
        };
        let mut accepted = Vec::new();
        // Oldest first, so a replay of an old record after a newer one is seen as one.
        for op in &read.ops {
            let verdict = match record::parse_op_json(&op.json, &fleet)
                .and_then(|sealed| record::open(&sealed, &fleet, &self.enc))
            {
                Err(why) => Verdict::Unreadable(format!("{why:#}")),
                Ok(signed) => match verifier.check(&signed) {
                    Err(why) => Verdict::Refused(why.0),
                    Ok(()) => {
                        let seen = self
                            .state()
                            .seen_seq
                            .get(&canonical_agent_name(&signed.body.signer))
                            .copied()
                            .unwrap_or(0);
                        let new = signed.body.seq > seen;
                        let verdict = Verdict::Valid {
                            kind: signed.body.kind,
                            signer: signed.body.signer.clone(),
                            seq: signed.body.seq,
                            issued: signed.body.issued,
                            expires: signed.body.expires,
                            endpoint: signed.body.at.id.clone(),
                            new,
                        };
                        if apply && new && self.state().accept(&signed).is_ok() {
                            accepted.push(signed);
                        }
                        verdict
                    }
                },
            };
            report.records.push(Finding {
                trx_id: op.trx_id.clone(),
                timestamp: op.timestamp.clone(),
                verdict,
            });
        }
        if apply {
            self.state().last_poll = Some(now);
            // Only the newest of each kind is worth feeding to iroh.
            for kind in [Kind::Master, Kind::Backup] {
                if let Some(newest) = accepted
                    .iter()
                    .filter(|r| r.body.kind == kind)
                    .max_by_key(|r| r.body.seq)
                {
                    self.apply(newest);
                    report.applied = true;
                }
            }
            self.save();
        }
        Ok(report)
    }

    /// Feed a verified record to iroh: where to dial, and the relay to use.
    pub fn apply(&self, record: &Signed) {
        let body = &record.body;
        let Ok(bytes) = hex::decode(&body.at.id) else {
            return;
        };
        let Ok(id) =
            EndpointId::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).unwrap_or([0; 32]))
        else {
            return;
        };
        let mut addr = EndpointAddr::new(id);
        let mut relays: Vec<RelayConfig> = Vec::new();
        if let Some(url) = body
            .at
            .relay_url
            .as_deref()
            .and_then(|u| u.parse::<RelayUrl>().ok())
        {
            addr = addr.with_relay_url(url.clone());
            relays.push(RelayConfig::from(url));
        }
        for direct in &body.at.direct {
            if let Ok(socket) = direct.parse::<std::net::SocketAddr>() {
                addr = addr.with_ip_addr(socket);
            }
        }
        // The master's rescue relay is for everyone to use; a backup's record is only a
        // pointer to its own machine.
        if body.kind == Kind::Master
            && let Some(relay) = &body.rescue_relay
            && let Ok(url) = relay.url.parse::<RelayUrl>()
        {
            addr = addr.with_relay_url(url.clone());
            relays.push(RelayConfig::from(url));
        }
        self.lookup.set_endpoint_info(addr);
        if let Some(map) = self
            .relay_map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            && !relays.is_empty()
        {
            map.extend(&RelayMap::from_iter(relays));
            // iroh looks at its relays on a network change; tell it one happened, so a
            // relay added now is tried now rather than at its next scheduled look.
            let endpoint = self
                .endpoint
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(endpoint) = endpoint
                && tokio::runtime::Handle::try_current().is_ok()
            {
                tokio::spawn(async move { endpoint.network_change().await });
            }
        }
    }

    // ------------------------------------------------------------------ posting

    fn body_for(
        &self,
        kind: Kind,
        view: &FleetView,
        info: &LaneInfo,
        now: DateTime<Utc>,
    ) -> Result<Body> {
        let master = view
            .master
            .clone()
            .context("the fleet folder names no master yet")?;
        let fleet = Self::fleet_tag(view).context("the master's key is not on the fleet roster")?;
        let expires = now + ChronoDuration::minutes(i64::try_from(self.cfg.expires_minutes)?);
        let rescue_relay = self.cfg.rescue_relay.as_ref().map(|url| RescueRelay {
            url: url.clone(),
            cert_sha256: self.cfg.rescue_relay_cert_sha256.clone(),
        });
        let seq = self.state().next_own_seq(now);
        let master_kind = kind == Kind::Master;
        let signer = canonical_agent_name(self.signer.name());
        if master_kind && signer != master {
            bail!("only the fleet's master ({master}) posts master records");
        }
        Ok(Body {
            v: record::VERSION,
            fleet,
            kind,
            signer,
            seq,
            issued: now,
            expires,
            at: Where {
                id: info.endpoint_id.clone(),
                relay_url: info.home_relay.clone(),
                direct: if self.cfg.include_direct_addresses {
                    info.direct.clone()
                } else {
                    Vec::new()
                },
            },
            relay_list_version: master_kind.then_some(view.relays_version).flatten(),
            rescue_relay: if master_kind { rescue_relay } else { None },
            relays: (master_kind && !view.relays.is_empty()).then(|| view.relays.clone()),
        })
    }

    fn sealed_op(&self, signed: &Signed, view: &FleetView) -> Result<(CustomJson, Vec<String>)> {
        let skip = |name: &str| view.revoked.contains(name);
        let recipients = record::recipients(&view.roster, skip);
        let names = recipients.iter().map(|r| r.name.clone()).collect();
        let sealed = record::seal(signed, &recipients)?;
        let op = CustomJson {
            required_auths: Vec::new(),
            required_posting_auths: vec![self.creds.account.clone()],
            id: self.cfg.op_id.clone(),
            json: record::op_json(&signed.body.fleet, &sealed),
        };
        op.check()?;
        Ok((op, names))
    }

    /// What a post would be, signed and sealed but not sent (`post --dry-run`).
    ///
    /// # Errors
    /// No master or recipients, not the right machine for that kind, or too big.
    pub async fn preview(
        &self,
        kind: Kind,
        info: &LaneInfo,
        now: DateTime<Utc>,
    ) -> Result<Preview> {
        let view = (self.view)();
        let body = self.body_for(kind, &view, info, now)?;
        let signed = record::sign(body, &self.signer)?;
        let (op, recipients) = self.sealed_op(&signed, &view)?;
        // The reference block comes from a node; without one the preview still shows the
        // record and the operation.
        let (tx_hex, digest_hex) = match self.hive.build(op.clone()).await {
            Ok(tx) => (
                Some(hex::encode(tx.serialize())),
                tx.digest(crate::tx::MAINNET_CHAIN_ID).ok().map(hex::encode),
            ),
            Err(_) => (None, None),
        };
        Ok(Preview {
            record: signed,
            recipients,
            op,
            tx_hex,
            digest_hex,
        })
    }

    /// Sign, seal and broadcast one record.
    ///
    /// # Errors
    /// No posting key, nothing to seal to, or no node accepted it.
    pub async fn post(
        &self,
        kind: Kind,
        reason: &str,
        info: &LaneInfo,
        now: DateTime<Utc>,
        cut_off_since: Option<DateTime<Utc>>,
    ) -> Result<PostOutcome> {
        let Some(key) = &self.creds.key else {
            bail!("no posting key: set HIVE_RESCUE_POSTING_KEY (environment or the secrets file)");
        };
        if self.creds.account.is_empty() {
            bail!("no fleet account: set HIVE_RESCUE_ACCOUNT or [hive_rescue] account");
        }
        let view = (self.view)();
        let body = self.body_for(kind, &view, info, now)?;
        let signed = record::sign(body, &self.signer)?;
        let (op, recipients) = self.sealed_op(&signed, &view)?;
        let op_json_len = op.json.len();
        let tx = self.hive.build(op).await?;
        let sent = self.hive.broadcast(&tx, key).await?;
        {
            let mut state = self.state();
            // Our own record counts as seen, so reading it back is not a "new" one; and it
            // is applied here and now: the poster needs the rescue relay as much as anyone.
            let _ = state.accept(&signed);
            state.posted = Posted {
                at: Some(now),
                seq: signed.body.seq,
                kind: Some(kind),
                relay_url: info.home_relay.clone(),
                relay_list_version: view.relays_version,
                cut_off_since,
                tx_id: Some(sent.trx_id.clone()),
            };
        }
        self.apply(&signed);
        self.save();
        Ok(PostOutcome {
            kind,
            reason: reason.to_owned(),
            record: signed,
            op_json_len,
            recipients,
            tx_id: sent.trx_id,
            node: Some(sent.node),
        })
    }

    // ------------------------------------------------------------------ the loop

    /// One look at the world. `status` and `info` come from the lane.
    pub async fn tick(&self, status: &Status, info: &LaneInfo, now: DateTime<Utc>) -> TickReport {
        let mut report = TickReport::default();
        let view = (self.view)();
        let cut = cut_off_since(status);
        report.cut_off_since = cut;
        let Some(master) = view.master.clone() else {
            report
                .notes
                .push("the fleet folder names no master yet".into());
            return report;
        };
        let me = canonical_agent_name(self.signer.name());
        let is_master = me == master;
        let cut_for = cut.map(|c| now - c);
        let minutes = |m: u64| ChronoDuration::minutes(i64::try_from(m).unwrap_or(i64::MAX));

        // Read while cut off.
        let last_poll = self.state().last_poll;
        let poll_due = last_poll.is_none_or(|t| now - t >= minutes(self.cfg.poll_minutes));
        if cut.is_some() && poll_due {
            match self.poll(now, true).await {
                Ok(read) => report.read = Some(read),
                Err(error) => report.notes.push(format!("read failed: {error:#}")),
            }
        }

        if !self.cfg.enabled {
            return report;
        }
        let posted = self.state().posted.clone();
        let since_post = posted.at.map(|t| now - t);
        let episode_posted = cut.zip(posted.at).is_some_and(|(c, p)| p >= c);
        let refresh_due = self.cfg.repost_minutes > 0
            && since_post.is_some_and(|d| d >= minutes(self.cfg.repost_minutes));

        let decision: Option<(Kind, String)> = if is_master {
            if cut_for.is_some_and(|d| d >= minutes(self.cfg.cut_off_minutes))
                && (!episode_posted || refresh_due)
            {
                Some((
                    Kind::Master,
                    if episode_posted {
                        "still cut off, refreshing the record".into()
                    } else {
                        format!("cut off for {} minutes", self.cfg.cut_off_minutes)
                    },
                ))
            } else if let Some(reason) = self.change_reason(&posted, &view, info, since_post) {
                Some((Kind::Master, reason))
            } else if self.cfg.routine_hours > 0
                && since_post.is_none_or(|d| {
                    d >= ChronoDuration::hours(
                        i64::try_from(self.cfg.routine_hours).unwrap_or(i64::MAX),
                    )
                })
            {
                Some((Kind::Master, "routine post".into()))
            } else {
                None
            }
        } else if self.cfg.backup
            && cut_for.is_some_and(|d| d >= minutes(self.cfg.backup_after_minutes))
            && (!episode_posted || refresh_due)
        {
            // Look first: a fresh master record means the master is fine.
            if report.read.is_none() {
                match self.poll(now, true).await {
                    Ok(read) => report.read = Some(read),
                    Err(error) => report.notes.push(format!("read failed: {error:#}")),
                }
            }
            let fresh = self.state().latest_master.as_ref().is_some_and(|r| {
                now - r.body.issued < minutes(self.cfg.backup_after_minutes) && r.body.expires > now
            });
            if fresh {
                report
                    .notes
                    .push("a fresh master record exists, so the backup does not post".into());
                None
            } else {
                Some((
                    Kind::Backup,
                    format!(
                        "cut off for {} minutes and no fresh master record",
                        self.cfg.backup_after_minutes
                    ),
                ))
            }
        } else {
            None
        };

        if let Some((kind, reason)) = decision {
            match self.post(kind, &reason, info, now, cut).await {
                Ok(outcome) => report.posted = Some(outcome),
                Err(error) => report
                    .notes
                    .push(format!("would post ({reason}) but could not: {error:#}")),
            }
        }
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = report.clone();
        report
    }

    /// The master's relay or relay list changed since the last post (while connected).
    fn change_reason(
        &self,
        posted: &Posted,
        view: &FleetView,
        info: &LaneInfo,
        since_post: Option<ChronoDuration>,
    ) -> Option<String> {
        let relay = info.home_relay.clone()?;
        if posted.at.is_none() {
            // Never posted: this is the first sighting, a baseline, not a change.
            let mut state = self.state();
            state.posted.relay_url = Some(relay);
            state.posted.relay_list_version = view.relays_version;
            drop(state);
            self.save();
            return None;
        }
        if since_post.is_some_and(|d| d < ChronoDuration::minutes(10)) {
            return None;
        }
        if posted.relay_url.as_deref() != Some(relay.as_str()) {
            return Some(format!("the home relay changed to {relay}"));
        }
        if posted.relay_list_version != view.relays_version {
            return Some("the fleet relay list changed".into());
        }
        None
    }

    /// Run until the endpoint closes, ticking every `every`.
    pub async fn run(self: Arc<Self>, lane: Arc<ferryman_iroh::Lane>, every: Duration) {
        while !lane.endpoint().is_closed() {
            let status = lane.status();
            let info = lane_info(&lane, self.cfg.include_direct_addresses);
            let _ = self.tick(&status, &info, Utc::now()).await;
            tokio::time::sleep(every).await;
        }
    }
}

/// What a record says about the lane.
#[must_use]
pub fn lane_info(lane: &ferryman_iroh::Lane, include_direct: bool) -> LaneInfo {
    let endpoint = lane.endpoint();
    LaneInfo {
        endpoint_id: ferryman_iroh::endpoint_hex(&endpoint.id()),
        home_relay: lane.home_relay_url(),
        direct: if include_direct {
            endpoint
                .bound_sockets()
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            Vec::new()
        },
    }
}

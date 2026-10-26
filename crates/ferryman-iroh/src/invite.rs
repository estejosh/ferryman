//! The invite endpoint: bringing a newcomer onto a channel over iroh, with no Syncthing
//! anywhere in the join path.
//!
//! A v2 invitation (`ferry2.` code) carries the inviter's INVITE endpoint id instead of a
//! Syncthing device id. That endpoint is a separate iroh endpoint with its own key
//! (`invite-iroh.key`, never the lane's `iroh.key`), speaking the `ferryman/invite/1`
//! ALPN and nothing else, homed on iroh's public relays (or a pinned `invite_relay_url`).
//! It is bound only while at least one open v2 invite exists in a channel this machine
//! serves, and it serves no channel-sync: it reads only `invites/`, the bootstrap files it
//! hands over, and the roster entries it must fill.
//!
//! ```text
//! newcomer -> inviter   Join { invite_id, nonce, project, agent, agent_key, transports }
//! inviter -> newcomer   Welcome { files } | Refused { reason }
//! newcomer -> inviter   Accept { acceptance, operator_entry? }
//! ```
//!
//! One bi stream, length-prefixed JSON, 64 KiB frames, 20 s per step. The newcomer signs
//! the Join with its agent key over `ferryman-invite-join-v1`; the inviter checks the
//! invite, the nonce (constant time), the reservation, the Join signature and the
//! newcomer's transports record, then binds the reserved name to the first key that passes
//! and replies with the bootstrap files. The newcomer verifies each file before writing
//! anything, atomically.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, canonical_agent_name};

use crate::{INVITE_ALPN, IrohConfig};

/// The largest message the handshake carries (a Welcome's files are the biggest).
const MAX_FRAME: usize = 64 * 1024;
/// How long each step of the handshake may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// Failed nonce attempts on one invite id before it is burned.
const NONCE_BURNS_AFTER: u32 = 5;

// ---------------------------------------------------------------------------------------
// Framing

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

// ---------------------------------------------------------------------------------------
// Protocol

/// What a newcomer sends first: who they are, where they are reachable, and the proof that
/// they were given the code. Signed with `agent_key` over [`join_payload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Join {
    pub invite_id: String,
    pub nonce: String,
    pub project: String,
    pub agent: String,
    /// The newcomer agent's ed25519 public key, hex.
    pub agent_key: String,
    /// The newcomer's signed `transports/<agent>.json` record.
    pub transports: ferryman_channel::transports::Transports,
    pub signature: String,
}

/// Exactly what a Join signature covers.
#[must_use]
pub fn join_payload(join: &Join) -> String {
    format!(
        "ferryman-invite-join-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        join.invite_id,
        join.nonce,
        join.project,
        join.agent,
        join.agent_key,
        serde_json::to_string(&join.transports).unwrap_or_default()
    )
}

/// The bootstrap files the inviter hands over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    pub files: BTreeMap<String, Vec<u8>>,
}

/// The newcomer's acceptance, sent after the Welcome (same connection or a later dial).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accept {
    pub acceptance: ferryman_channel::invite::Acceptance,
    /// The new operator's roster entry, for a generic invite where the operator is created
    /// in the browser after the handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_entry: Option<AgentRoute>,
}

/// What a newcomer sends, wrapped so the server can tell a Join from a later Accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Message {
    Join(Join),
    Accept(Accept),
}

/// The inviter's answer to a Join.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Welcome(Welcome),
    Refused { reason: String },
}

// ---------------------------------------------------------------------------------------
// Shape checks

/// Whether `id` is a well-formed iroh endpoint id (64 hex characters).
#[must_use]
pub fn well_formed_endpoint_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse an endpoint id from 64 hex characters.
pub fn endpoint_id_from_hex(hex: &str) -> Result<EndpointId> {
    let bytes = hex::decode(hex).context("endpoint id is not hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("an endpoint id is 32 bytes"))?;
    Ok(EndpointId::from_bytes(&bytes).map_err(|_| anyhow!("not a valid endpoint id"))?)
}

/// The address a newcomer dials for a v2 code: the inviter's invite endpoint id, through
/// the relay the code names when it names one.
pub fn inviter_addr(code: &ferryman_channel::invite::InviteCode) -> Result<EndpointAddr> {
    let id = endpoint_id_from_hex(code.endpoint.as_deref().context("no invite endpoint in this code")?)?;
    let mut addr = EndpointAddr::new(id);
    if let Some(relay) = code.relay.as_deref() {
        let relay: RelayUrl = relay.parse().context("the invite relay is not a URL")?;
        addr = addr.with_relay_url(relay);
    }
    Ok(addr)
}

// ---------------------------------------------------------------------------------------
// The inviter's checks, as pure functions so they can be unit-tested.

/// A refusal that never says which part of the secret was wrong.
fn refuse() -> anyhow::Error {
    anyhow!("the invitation could not be used")
}

/// Verify a Join against the invite it names, returning the invite record when it passes.
///
/// Checks, in order: the invite exists and its signature verifies (master-signed, or
/// owner-signed for an own-machine invite); it is open (not granted, not expired, not
/// burned); the project matches; the nonce hash matches in constant time; the agent name
/// matches the reservation; the Join signature verifies; the transports record is valid for
/// that agent, key and project, and its endpoint id is well-formed.
pub fn verify_join(
    route: &ProjectRoute,
    join: &Join,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ferryman_channel::invite::Invite> {
    let mut route = route.clone();
    route.agents = ferryman_channel::read_agent_roster(&route.communications)?;
    let (invite, check) = ferryman_channel::invite::list(&route)?
        .into_iter()
        .find(|(invite, _)| invite.id == join.invite_id)
        .ok_or_else(refuse)?;
    if check != SignatureCheck::Valid || invite.endpoint.is_none() {
        return Err(refuse());
    }
    if !ferryman_channel::invite::is_open(&invite, now) {
        return Err(refuse());
    }
    if join.project != invite.project_id {
        return Err(refuse());
    }
    if !ferryman_channel::invite::nonce_matches(&invite, &join.nonce) {
        return Err(refuse());
    }
    // The agent name: a named invite is for that agent and no other; a generic invite takes
    // the sent name when it is free, else the guest placeholder the newcomer already uses.
    let agent_ok = match &invite.agent {
        Some(reserved) => join.agent.eq_ignore_ascii_case(reserved),
        None => {
            join.agent.eq_ignore_ascii_case(&format!("guest-{}", invite.id))
                || matches!(
                    ferryman_channel::invite::check_name(&route, &join.agent),
                    Ok(ferryman_channel::invite::NameCheck::Free)
                )
        }
    };
    if !agent_ok {
        return Err(refuse());
    }
    // The Join signature: the whole message, signed by the key it names.
    if !ferryman_channel::verify_detached(&join.agent_key, &join.signature, &join_payload(join)) {
        return Err(refuse());
    }
    // The transports record: valid for that agent, key and project.
    if !transports_ok(join) {
        return Err(refuse());
    }
    Ok(invite)
}

/// Whether a newcomer's transports record is well-formed for this Join.
fn transports_ok(join: &Join) -> bool {
    let t = &join.transports;
    t.version == ferryman_channel::transports::VERSION
        && t.project_id == join.project
        && t.agent.eq_ignore_ascii_case(&join.agent)
        && t.signed_by.eq_ignore_ascii_case(&join.agent)
        && t.at <= chrono::Utc::now() + ferryman_channel::transports::CLOCK_SKEW
        && well_formed_endpoint_id(&t.endpoint_id)
        && ferryman_channel::verify_detached(
            &join.agent_key,
            &t.signature,
            &ferryman_channel::transports::payload(t),
        )
}

// ---------------------------------------------------------------------------------------
// The failed-nonce counter, persisted beside the invite so a restart does not reset it.

fn fails_path(route: &ProjectRoute, id: &str) -> PathBuf {
    ferryman_channel::invite::invites_dir(route).join(format!("{id}.fails.json"))
}

fn read_fails(route: &ProjectRoute, id: &str) -> u32 {
    std::fs::read_to_string(fails_path(route, id))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Record a failed nonce attempt on `id`, burning the invite once it reaches the limit.
pub fn record_failure(route: &ProjectRoute, id: &str) -> Result<()> {
    let count = read_fails(route, id) + 1;
    let dir = ferryman_channel::invite::invites_dir(route);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(fails_path(route, id), count.to_string())?;
    if count >= NONCE_BURNS_AFTER {
        ferryman_channel::invite::burn(route, id)?;
        let _ = std::fs::remove_file(fails_path(route, id));
    }
    Ok(())
}

/// Clear the failed-nonce counter once a Join has succeeded.
pub fn clear_failures(route: &ProjectRoute, id: &str) {
    let _ = std::fs::remove_file(fails_path(route, id));
}

/// The bootstrap files for a v2 join: exactly the master, the inviter's own roster and
/// transports records, the invite, and the reserved operator's keyless entry.
pub fn welcome_files(
    route: &ProjectRoute,
    invite: &ferryman_channel::invite::Invite,
    inviter_agent: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let add = |files: &mut BTreeMap<String, Vec<u8>>, rel: String, path: PathBuf| -> Result<()> {
        if path.is_file() {
            files.insert(rel, std::fs::read(&path)?);
        }
        Ok(())
    };
    add(&mut files, "master.json".into(), route.communications.join("master.json"))?;
    if let Ok(Some(declaration)) = ferryman_channel::master::read_master(route) {
        let master = canonical_agent_name(&declaration.master);
        add(
            &mut files,
            format!("agents/{master}.json"),
            route.communications.join("agents").join(format!("{master}.json")),
        )?;
    }
    let inviter = canonical_agent_name(inviter_agent);
    add(
        &mut files,
        format!("agents/{inviter}.json"),
        route.communications.join("agents").join(format!("{inviter}.json")),
    )?;
    add(
        &mut files,
        format!("transports/{inviter}.json"),
        route.communications.join("transports").join(format!("{inviter}.json")),
    )?;
    add(
        &mut files,
        format!("invites/{}.json", invite.id),
        route.communications.join("invites").join(format!("{}.json", invite.id)),
    )?;
    if let Some(operator) = &invite.operator {
        let name = canonical_agent_name(operator);
        add(
            &mut files,
            format!("agents/{name}.json"),
            route.communications.join("agents").join(format!("{name}.json")),
        )?;
    }
    Ok(files)
}

/// Whether any route in `routes` holds an open v2 invite. The endpoint is bound only while
/// this is true.
#[must_use]
pub fn has_open_invites(routes: &[ProjectRoute], now: chrono::DateTime<chrono::Utc>) -> bool {
    routes.iter().any(|route| {
        ferryman_channel::invite::list(route)
            .ok()
            .is_some_and(|invites| {
                invites.into_iter().any(|(invite, _)| {
                    invite.endpoint.is_some() && ferryman_channel::invite::is_open(&invite, now)
                })
            })
    })
}

// ---------------------------------------------------------------------------------------
// The inviter's side.

/// One endpoint serving the invite handshake for every channel in `routes`.
pub struct InviteEndpoint {
    endpoint: Endpoint,
    routes: Mutex<Vec<ProjectRoute>>,
    /// The machine's agent identity: signs the binding record.
    identity: AgentIdentity,
}

/// The public relay the invite endpoint homes on when no `invite_relay_url` is set. One
/// specific relay, not the whole public map, so the relay a code carries is always the one
/// the endpoint is actually homed on - a code is created without the endpoint running, and
/// the newcomer must dial through exactly that relay.
pub const PUBLIC_INVITE_RELAY: &str = "https://use1-1.relay.n0.iroh.link";

/// The endpoint a v2 invite's code carries: the invite endpoint's id, the relay it homes
/// on, and the pin when that relay's certificate is not one a public CA signed. The key is
/// created on first use, so a code can be made before the invite endpoint has ever run.
pub fn code_endpoint(
    config: &IrohConfig,
    machine_dir: &std::path::Path,
) -> Result<ferryman_channel::invite::InviteEndpoint> {
    let (key, _) = crate::load_or_create_invite_key(machine_dir)?;
    Ok(ferryman_channel::invite::InviteEndpoint {
        id: crate::endpoint_hex(&key.public()),
        relay: Some(
            config
                .invite_relay_url
                .clone()
                .unwrap_or_else(|| PUBLIC_INVITE_RELAY.to_string()),
        ),
        pin: config.invite_relay_cert_sha256.map(hex::encode),
    })
}

impl InviteEndpoint {
    /// The relay mode the invite endpoint binds with: a pinned `invite_relay_url` when
    /// configured, else one of iroh's public relays ([`PUBLIC_INVITE_RELAY`]). The lane's
    /// relay token is never sent here: the invite endpoint is its own endpoint.
    pub fn relay_mode(config: &IrohConfig) -> Result<RelayMode> {
        let url = config
            .invite_relay_url
            .as_deref()
            .unwrap_or(PUBLIC_INVITE_RELAY);
        let parsed: RelayUrl = url
            .parse()
            .with_context(|| format!("invite_relay_url '{url}' is not a URL"))?;
        Ok(RelayMode::Custom(RelayMap::from_iter([RelayConfig::from(
            parsed,
        )])))
    }

    /// The TLS trust for the invite endpoint's relay: the pin when there is one, public CAs
    /// (iroh's public relays) otherwise.
    fn ca_config(config: &IrohConfig) -> iroh::tls::CaTlsConfig {
        match (config.invite_relay_url.as_deref(), config.invite_relay_cert_sha256) {
            (Some(url), Some(pin)) => {
                let host = url
                    .parse::<RelayUrl>()
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .into_iter()
                    .collect::<Vec<_>>();
                crate::tls::ca_config(Some(pin), &host, false)
            }
            _ => iroh::tls::CaTlsConfig::embedded(),
        }
    }

    /// Bind the invite endpoint with `key` (the machine's invite key) and serve nothing yet.
    pub async fn bind(
        config: &IrohConfig,
        key: iroh::SecretKey,
        routes: Vec<ProjectRoute>,
        identity: AgentIdentity,
    ) -> Result<Arc<Self>> {
        let mode = Self::relay_mode(config)?;
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .alpns(vec![INVITE_ALPN.to_vec()])
            .ca_tls_config(Self::ca_config(config))
            .relay_mode(mode)
            .bind_addr("0.0.0.0:0")
            .context("bind the invite endpoint")?
            .bind()
            .await
            .context("bind the invite endpoint")?;
        Ok(Arc::new(Self {
            endpoint,
            routes: Mutex::new(routes),
            identity,
        }))
    }

    /// Wrap an endpoint that is already bound (the in-process tests bind one with
    /// `RelayMode::Disabled` and a `MemoryLookup`).
    #[must_use]
    pub fn new(endpoint: Endpoint, routes: Vec<ProjectRoute>, identity: AgentIdentity) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            routes: Mutex::new(routes),
            identity,
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Add a route (a project newly approved while the worker runs).
    pub fn add_project(&self, route: ProjectRoute) {
        let mut routes = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match routes.iter_mut().find(|r| r.project_id == route.project_id) {
            Some(have) => *have = route,
            None => routes.push(route),
        }
    }

    /// Serve every incoming connection until the endpoint closes.
    pub async fn serve(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    me.answer_connection(connection).await;
                }
            });
        }
    }

    async fn answer_connection(&self, connection: Connection) {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let message = tokio::time::timeout(STEP_TIMEOUT, read_frame::<Message>(&mut recv)).await;
        let outcome = match message {
            Ok(Ok(Message::Join(join))) => {
                self.process_join(&mut send, &mut recv, &join).await
            }
            Ok(Ok(Message::Accept(accept))) => self.process_accept(&accept),
            _ => Err(refuse()),
        };
        if outcome.is_err() {
            let _ = write_frame(&mut send, &Reply::Refused { reason: refuse().to_string() }).await;
        }
        let _ = send.finish();
    }

    async fn process_join(
        &self,
        send: &mut SendStream,
        recv: &mut RecvStream,
        join: &Join,
    ) -> Result<()> {
        let routes = self.routes();
        let route = routes
            .iter()
            .find(|r| r.project_id == join.project)
            .ok_or_else(refuse)?;
        let invite = verify_join(route, join, chrono::Utc::now())?;
        self.bind_reservation(route, join)?;
        clear_failures(route, &invite.id);
        let files = welcome_files(route, &invite, self.identity.name())?;
        write_frame(send, &Reply::Welcome(Welcome { files })).await?;
        // The acceptance, same connection, is read next; a later dial sends it on its own.
        if let Ok(Ok(Message::Accept(accept))) =
            tokio::time::timeout(STEP_TIMEOUT, read_frame::<Message>(recv)).await
        {
            self.process_accept_at(route, &invite, &accept)?;
        }
        Ok(())
    }

    fn routes(&self) -> Vec<ProjectRoute> {
        self.routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Find the invite named by an acceptance and record it, or refuse.
    fn process_accept(&self, accept: &Accept) -> Result<()> {
        let routes = self.routes();
        let id = &accept.acceptance.invite_id;
        for route in &routes {
            if let Ok(Some(invite)) = ferryman_channel::invite::read(route, id) {
                return self.process_accept_at(route, &invite, accept);
            }
        }
        Err(refuse())
    }

    /// Fill the keyless reservation and write the newcomer's transports record and the
    /// binding record. First-key-wins is unchanged.
    fn bind_reservation(&self, route: &ProjectRoute, join: &Join) -> Result<()> {
        let agent = canonical_agent_name(&join.agent);
        let role = ferryman_channel::read_agent_roster(&route.communications)?
            .into_iter()
            .find(|a| canonical_agent_name(&a.name) == agent)
            .map(|a| a.role)
            .unwrap_or_else(|| "worker".to_string());
        ferryman_channel::register_agent_public_key(
            route,
            &AgentRoute {
                name: agent.clone(),
                role,
                capabilities: vec!["messages.receive".to_string()],
                public_key: None,
                encryption_key: None,
            },
            &join.agent_key,
        )?;
        // Write the newcomer's transports record into the channel.
        let t = &join.transports;
        let dir = route.communications.join("transports");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{agent}.json"));
        let temp = dir.join(format!(".{agent}.json.tmp"));
        std::fs::write(&temp, serde_json::to_vec_pretty(t)?)?;
        std::fs::rename(&temp, &path)?;
        // The binding record, signed by the inviting machine's agent.
        let mut record = serde_json::json!({
            "invite_id": join.invite_id,
            "bound_key": join.agent_key,
            "agent": agent,
            "endpoint": t.endpoint_id,
            "at": chrono::Utc::now().to_rfc3339(),
        });
        let payload = serde_json::to_string(&record)?;
        if let serde_json::Value::Object(map) = &mut record {
            map.insert(
                "signed_by".into(),
                serde_json::Value::String(self.identity.name().to_string()),
            );
            map.insert(
                "signature".into(),
                serde_json::Value::String(self.identity.sign_bytes(payload.as_bytes())),
            );
        }
        let bind_dir = route.communications.join("invites");
        std::fs::create_dir_all(&bind_dir)?;
        let path = bind_dir.join(format!("{}.bind.json", join.invite_id));
        let temp = bind_dir.join(format!(".{}.bind.json.tmp", join.invite_id));
        std::fs::write(&temp, serde_json::to_vec_pretty(&record)?)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }

    /// Verify an acceptance with the settle_pending step-B rules and write it, plus the
    /// new operator's roster entry for a generic invite.
    fn process_accept_at(
        &self,
        route: &ProjectRoute,
        invite: &ferryman_channel::invite::Invite,
        accept: &Accept,
    ) -> Result<()> {
        let a = &accept.acceptance;
        if !ferryman_channel::invite::nonce_matches(invite, &a.nonce) {
            return Err(refuse());
        }
        if let Some(reserved) = &invite.operator
            && !reserved.eq_ignore_ascii_case(&a.operator)
        {
            return Err(refuse());
        }
        if !well_formed_endpoint_id(&a.device_id) {
            return Err(refuse());
        }
        // For a generic invite the operator arrives now, first-key-wins.
        if invite.operator.is_none() {
            let entry = accept.operator_entry.as_ref().ok_or_else(refuse)?;
            if !canonical_agent_name(&entry.name).eq_ignore_ascii_case(&a.operator) {
                return Err(refuse());
            }
            let key = entry
                .public_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .ok_or_else(refuse)?;
            ferryman_channel::register_agent_public_key(route, entry, key)?;
        }
        // The signer's key is on the roster now (the agent for a named invite, the operator
        // for a generic one): verify the acceptance against it.
        let roster = ferryman_channel::read_agent_roster(&route.communications)?;
        let signer = a.signed_by.as_deref().unwrap_or("");
        let key = roster
            .iter()
            .find(|r| canonical_agent_name(&r.name) == canonical_agent_name(signer))
            .and_then(|r| r.public_key.clone())
            .filter(|k| !k.is_empty())
            .ok_or_else(refuse)?;
        if !ferryman_channel::verify_detached(
            &key,
            a.signature.as_deref().unwrap_or(""),
            &ferryman_channel::invite::acceptance_payload(a),
        ) {
            return Err(refuse());
        }
        // Write the acceptance.
        let invites_dir = ferryman_channel::invite::invites_dir(route);
        std::fs::create_dir_all(&invites_dir)?;
        let path = invites_dir.join(format!("{}.accept.json", invite.id));
        let temp = invites_dir.join(format!(".{}.accept.json.tmp", invite.id));
        std::fs::write(&temp, serde_json::to_vec_pretty(a)?)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// The newcomer's side.

/// Build and sign the Join for a v2 code, with the newcomer's signed transports record.
#[must_use]
pub fn build_join(
    code: &ferryman_channel::invite::InviteCode,
    identity: &AgentIdentity,
    transports: ferryman_channel::transports::Transports,
) -> Join {
    let mut join = Join {
        invite_id: code.id.clone(),
        nonce: code.nonce.clone(),
        project: code.project.clone(),
        agent: identity.name().to_string(),
        agent_key: identity.public_key_hex(),
        transports,
        signature: String::new(),
    };
    join.signature = identity.sign_bytes(join_payload(&join).as_bytes());
    join
}

/// Verify every Welcome file the way the lane would, before anything is written:
/// `master.json` against `agents/<master>.json`, the inviter's transports record against
/// its roster key, and the invite record against the master's key. Returns the relative
/// paths verified. Refuses (and the caller writes nothing) if any check fails.
pub fn verify_welcome(files: &BTreeMap<String, Vec<u8>>, project: &str) -> Result<Vec<String>> {
    let master: ferryman_channel::master::MasterDeclaration =
        serde_json::from_slice(files.get("master.json").context("missing master.json")?)?;
    if master.project_id != project {
        bail!("master declaration is for a different project");
    }
    let master_name = canonical_agent_name(&master.master);
    let master_route: AgentRoute = serde_json::from_slice(
        files
            .get(&format!("agents/{master_name}.json"))
            .with_context(|| format!("missing agents/{master_name}.json"))?,
    )?;
    let master_key = master_route
        .public_key
        .as_ref()
        .filter(|k| !k.is_empty())
        .context("the master's key is not published")?;
    if !ferryman_channel::verify_detached(
        master_key,
        master.signature.as_deref().unwrap_or(""),
        &ferryman_channel::master::master_payload(&master),
    ) {
        bail!("master declaration signature does not verify");
    }
    let mut verified = vec!["master.json".to_string(), format!("agents/{master_name}.json")];

    // The inviter's transports record against its roster key.
    for (rel, bytes) in files {
        if !rel.starts_with("transports/") || !rel.ends_with(".json") {
            continue;
        }
        let record: ferryman_channel::transports::Transports =
            serde_json::from_slice(bytes).context("unparseable transports record")?;
        let agent = canonical_agent_name(&record.agent);
        let roster_path = format!("agents/{agent}.json");
        let roster: AgentRoute = serde_json::from_slice(
            files
                .get(&roster_path)
                .with_context(|| format!("missing {roster_path}"))?,
        )?;
        let key = roster
            .public_key
            .as_ref()
            .filter(|k| !k.is_empty())
            .context("the inviter's key is not published")?;
        if record.project_id != project
            || !well_formed_endpoint_id(&record.endpoint_id)
            || !ferryman_channel::verify_detached(
                key,
                &record.signature,
                &ferryman_channel::transports::payload(&record),
            )
        {
            bail!("the inviter's transports record does not verify");
        }
        verified.push(rel.clone());
        verified.push(roster_path);
    }

    // The invite record against the master's key.
    let invite_id = files
        .keys()
        .find_map(|rel| {
            rel.strip_prefix("invites/")
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_string)
        })
        .context("missing invite record")?;
    let invite: ferryman_channel::invite::Invite = serde_json::from_slice(
        files
            .get(&format!("invites/{invite_id}.json"))
            .context("missing invite record")?,
    )?;
    if invite.project_id != project {
        bail!("invite is for a different project");
    }
    if !ferryman_channel::verify_detached(
        master_key,
        invite.signature.as_deref().unwrap_or(""),
        &ferryman_channel::invite::invite_payload(&invite),
    ) {
        bail!("invite record signature does not verify");
    }
    verified.push(format!("invites/{invite_id}.json"));
    Ok(verified)
}

/// Write the verified Welcome files atomically: everything lands, or nothing does.
pub fn write_welcome(route: &ProjectRoute, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (rel, bytes) in files {
        let mut path = route.communications.clone();
        for part in rel.split('/') {
            path.push(part);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("welcome.tmp");
        std::fs::write(&temp, bytes)?;
        staged.push((temp, path));
    }
    for (temp, path) in &staged {
        std::fs::rename(temp, path)?;
    }
    Ok(())
}

/// The newcomer's half of the handshake: dial the inviter's invite endpoint, send the Join,
/// receive and return the Welcome (the caller verifies and writes it), and send the
/// acceptance when one is ready (a named invite accepts on this same connection).
pub async fn join(
    endpoint: &Endpoint,
    inviter: &EndpointAddr,
    join: &Join,
    acceptance: Option<Accept>,
) -> Result<Welcome> {
    let connection = tokio::time::timeout(STEP_TIMEOUT, endpoint.connect(inviter.clone(), INVITE_ALPN))
        .await
        .context("no answer from the inviter")?
        .context("connect")?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_frame(&mut send, &Message::Join(join.clone())).await?;
    let reply: Reply = tokio::time::timeout(STEP_TIMEOUT, read_frame(&mut recv))
        .await
        .context("timed out waiting for the welcome")??;
    match reply {
        Reply::Welcome(welcome) => {
            if let Some(accept) = acceptance {
                write_frame(&mut send, &Message::Accept(accept)).await?;
            }
            send.finish()?;
            Ok(welcome)
        }
        Reply::Refused { reason } => bail!("{reason}"),
    }
}

/// Send an acceptance on a later dial (a generic invite's operator accepts after the
/// browser step). Refuses on the inviter's answer.
pub async fn send_accept(endpoint: &Endpoint, inviter: &EndpointAddr, accept: Accept) -> Result<()> {
    let connection = tokio::time::timeout(STEP_TIMEOUT, endpoint.connect(inviter.clone(), INVITE_ALPN))
        .await
        .context("no answer from the inviter")?
        .context("connect")?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_frame(&mut send, &Message::Accept(accept)).await?;
    send.finish()?;
    if let Ok(Ok(Reply::Refused { reason })) =
        tokio::time::timeout(STEP_TIMEOUT, read_frame::<Reply>(&mut recv)).await
    {
        bail!("{reason}");
    }
    Ok(())
}









//! Web dashboard over the channel: tasks, ledger, engine stats, and learnings
//! in one interactive pane, plus (when not run read-only) the review action an
//! operator needs to accept or send back work. Operators sign in with a
//! password-protected identity and hold a short-lived, idle-expiring session.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Error, bail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{delete, get, post},
};
use ferryman_channel::seed::OperatorSeed;
use ferryman_channel::{AgentIdentity, ProjectRoute, SignatureCheck, TaskState};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::operators::OperatorStore;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Everything the dashboard handlers need. In read-only mode no operator can
/// sign in and the write endpoint is disabled; otherwise each operator
/// authenticates with a password, gets a session, and reviews are signed by
/// that operator's identity, with the channel's own master-gating still
/// binding what the web surface can approve.
#[derive(Clone)]
pub struct DashboardState {
    pub route: Arc<ProjectRoute>,
    pub operators: OperatorStore,
    pub sessions: Sessions,
    pub read_only: bool,
    login_rate: RateLimiter,
    create_rate: RateLimiter,
    /// The one-time secret that authorises creating the FIRST operator.
    ///
    /// Minted at startup only when no operator exists, printed to the terminal, and
    /// consumed by the first successful creation. See [`create_operator`] for why this
    /// exists rather than nothing, and why it is a token rather than a flag.
    bootstrap: Arc<Mutex<Option<String>>>,
}

impl DashboardState {
    pub fn new(
        route: Arc<ProjectRoute>,
        operators: OperatorStore,
        read_only: bool,
        timeout: Duration,
    ) -> Self {
        // Minted only when there is nobody to authenticate as. Once one operator exists,
        // creation is an authenticated action and no bootstrap secret should be in memory
        // at all - a standing one is a standing bypass of the thing it bootstrapped.
        let bootstrap = (!read_only && !operators.any()).then(|| {
            let mut bytes = [0u8; 32];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
            hex::encode(bytes)
        });
        Self {
            route,
            operators,
            sessions: Sessions::new(timeout),
            read_only,
            login_rate: RateLimiter::new(5, Duration::from_secs(60)),
            create_rate: RateLimiter::new(10, Duration::from_secs(3600)),
            bootstrap: Arc::new(Mutex::new(bootstrap)),
        }
    }

    /// The bootstrap token to print, when there is one. The caller shows this to the human
    /// at the terminal; it is deliberately never available over HTTP.
    #[must_use]
    pub fn bootstrap_token(&self) -> Option<String> {
        self.bootstrap.lock().unwrap().clone()
    }

    /// Operators this CHANNEL knows, whose sealed key this MACHINE does not have.
    ///
    /// # Why this is worth its own question
    ///
    /// "No operator exists" was answered by looking at one machine's disk, and the answer
    /// was printed as though it settled the matter: a first-run setup token and a sign-up
    /// form. But a published roster entry is evidence that somebody DID set an operator
    /// up - they signed it, and their signature is still verifying on work in the
    /// channel. A machine holding the public half and not the private half has lost
    /// something, which is a different situation from never having had it.
    ///
    /// This happened here. An operator's sealed record was deleted from `%LOCALAPPDATA%`
    /// by a disk cleaner. The dashboard said "No operator exists for this project yet"
    /// and offered a setup token, so the obvious reading was that setup had never
    /// happened - and the hour that followed went on looking for a bug in identity
    /// resolution rather than for a missing file. The roster had the answer the whole
    /// time and nothing asked it.
    ///
    /// Names only. A public key is safe to display, but there is nothing to be gained
    /// from putting one on a sign-in screen.
    #[must_use]
    pub fn orphaned_operators(&self) -> Vec<String> {
        let Ok(roster) = ferryman_channel::read_agent_roster(&self.route.communications) else {
            return Vec::new();
        };
        roster
            .into_iter()
            .filter(|entry| entry.role.eq_ignore_ascii_case("operator"))
            // A reserved name carries no key. Nobody has lost anything yet.
            .filter(|entry| entry.public_key.as_ref().is_some_and(|k| !k.is_empty()))
            .map(|entry| entry.name)
            .filter(|name| !self.operators.exists(name))
            .collect()
    }

    /// Accept and consume the bootstrap token, or refuse.
    ///
    /// Single-use: taken out of the state on success, so a token that leaks after the first
    /// operator exists is worth nothing. Compared in constant time, because it is a secret
    /// and an early-returning comparison over a hex string is a byte-at-a-time oracle.
    fn consume_bootstrap(&self, offered: &str) -> bool {
        let mut held = self.bootstrap.lock().unwrap();
        let Some(expected) = held.as_deref() else {
            return false;
        };
        if expected.len() != offered.len() {
            return false;
        }
        let matched = expected
            .bytes()
            .zip(offered.bytes())
            .fold(0u8, |differences, (a, b)| differences | (a ^ b))
            == 0;
        if matched {
            *held = None;
        }
        matched
    }
}

impl DashboardState {
    /// The project a request is about: the current project, or a discovered
    /// sibling named by `project`. Lets one dashboard read every project.
    fn route_for(&self, project: Option<&str>) -> Arc<ProjectRoute> {
        match project.filter(|id| !id.is_empty() && *id != self.route.project_id) {
            Some(id) => find_project_route(&self.route, id)
                .map(Arc::new)
                .unwrap_or_else(|| self.route.clone()),
            None => self.route.clone(),
        }
    }
}

/// The query parameter that scopes a read to a particular project.
#[derive(Deserialize)]
struct ProjectParam {
    project: Option<String>,
}

/// Find a sibling project's route by id, scanning the workspace's parent. The
/// same discovery the Fleet tab uses, so a clickable project resolves to the
/// same channel `route_for` would find.
fn find_project_route(current: &ProjectRoute, id: &str) -> Option<ProjectRoute> {
    // The index knows where projects actually are; the scan below only knows what sits
    // next to this one.
    if let Some(root) = ferryman_channel::ferry::find_root()
        && let Some(entry) = root
            .projects()
            .into_iter()
            .find(|entry| entry.project_id == id)
        && let Ok(route) = ferryman_channel::route_for(&entry.repo.unwrap_or(entry.channel))
    {
        return Some(route);
    }
    if let Some(project) = ferryman_channel::known::known()
        .into_iter()
        .find(|project| project.project_id == id)
        && let Ok(route) = ferryman_channel::route_for(&project.workspace)
    {
        return Some(route);
    }
    // The same root discovery uses. Listing a project the reads cannot then resolve would
    // give a picker that silently falls back to the current project - which looks like
    // the switch did nothing, and is worse than not offering it.
    let parent = COMMS_ROOT
        .get()
        .map(PathBuf::as_path)
        .or_else(|| current.workspace.parent())?;
    if !parent.is_dir() {
        return None;
    }
    for entry in std::fs::read_dir(parent).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if !entry.file_type().ok()?.is_dir() {
            continue;
        }
        let Ok(route) = ferryman_channel::route_for(&path) else {
            continue;
        };
        if route.project_id == id {
            return Some(route);
        }
    }
    None
}

/// In-memory operator sessions, keyed by a random bearer token. Idle sessions
/// expire after `timeout` and are pruned on access; a session holds the
/// operator's unlocked signing identity for exactly as long as it is live.
#[derive(Clone)]
pub struct Sessions {
    inner: Arc<Mutex<HashMap<String, Session>>>,
    timeout: Duration,
}

struct Session {
    identity: Arc<AgentIdentity>,
    last_seen: Instant,
}

impl Sessions {
    fn new(timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            timeout,
        }
    }

    /// Start a session for an unlocked identity and return its bearer token.
    fn insert(&self, identity: AgentIdentity) -> String {
        let mut bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
        let token = hex::encode(bytes);
        self.inner.lock().unwrap().insert(
            token.clone(),
            Session {
                identity: Arc::new(identity),
                last_seen: Instant::now(),
            },
        );
        token
    }

    /// Resolve a bearer token to an identity, refreshing its idle deadline.
    /// Returns `None` for an unknown or expired token.
    fn resolve(&self, token: &str) -> Option<Arc<AgentIdentity>> {
        let mut map = self.inner.lock().unwrap();
        map.retain(|_, s| s.last_seen.elapsed() < self.timeout);
        let session = map.get_mut(token)?;
        if session.last_seen.elapsed() >= self.timeout {
            map.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some(session.identity.clone())
    }

    fn revoke(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }
}

/// Fixed-window rate limiter for the credential endpoints.
///
/// The dashboard binds to loopback only, so this is defense-in-depth: a local
/// process (or a rebinding bypass of the Host guard) that hammers sign-in to
/// brute-force a password is throttled to a handful of attempts per window.
/// Keyed by operator name for sign-in, so one name's failures never lock a
/// different operator out; account creation is limited per name as well.
#[derive(Clone)]
struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            limit,
            window,
        }
    }

    /// Record an attempt for `key`; returns `true` when it is within the
    /// window's budget. Entries older than the window are pruned on access, so
    /// the map stays small.
    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.inner.lock().unwrap();
        let bucket = buckets.entry(key.to_string()).or_default();
        bucket.retain(|at| now.duration_since(*at) < self.window);
        if bucket.len() >= self.limit {
            return false;
        }
        bucket.push(now);
        true
    }
}

/// The only paths reachable without a session, listed in one place on purpose.
///
/// Everything not named here requires authentication, because [`require_session`] is a
/// layer over the whole router rather than a check inside each handler.
///
/// That inversion is the fix for a real bug, not a preference. Authentication used to be
/// per-handler: `sessions.resolve()` appeared in three handlers out of seventeen, and the
/// other fourteen served the fleet - order payloads, worker output, the memory bank, the
/// ledger, and `/api/fleet` with every device's operator email - to anyone who could reach
/// the port. Nothing failed, no test noticed, and `openapi/dashboard.yaml` documented a
/// session as required on every path while one path enforced it.
///
/// A check you can forget to add is a check somebody will forget to add. Adding a route is
/// now safe by default and *opening* one is the deliberate act, which is the right way
/// round: the failure mode of this list is a locked door, and the failure mode of the old
/// arrangement was a silent open one.
const PUBLIC_PATHS: &[&str] = &[
    // The page itself. It is a shell that fetches everything through the API, so serving
    // it to an anonymous browser reveals nothing - and it must be reachable, since it is
    // where the sign-in form lives.
    "/",
    // Bootstrap and sign-in. `create` is not unauthenticated - it carries its own gate
    // (see `create_operator`), which is not a session and so cannot live in this layer.
    "/api/auth/create",
    "/api/auth/login",
    // Recovery and the first-run status probe are public for the same reason the page is:
    // they are where a person with no identity yet goes. `create` and `recover` are not
    // unauthenticated - each carries the same gate of its own (an existing operator's
    // session, or the one-time console token), which is not a session and so cannot live
    // in this layer. A recovery PHRASE is not that gate: on a machine with no seed, the
    // caller supplies whichever phrase they like.
    "/api/auth/recover",
    "/api/auth/status",
    // Ending a session must work even after it has expired, or a stale tab can never
    // clear itself. Revoking an unknown token is already a no-op.
    "/api/auth/logout",
];

/// Require a live session for every path except [`PUBLIC_PATHS`].
async fn require_session(
    State(state): State<DashboardState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Exact match, never a prefix. `starts_with` here would be the same class of mistake
    // as the Host guard's `starts_with("127.")` two functions down: `/api/auth/login` as a
    // prefix would also open `/api/auth/login/../tasks`-shaped paths and anything later
    // nested beneath it.
    if PUBLIC_PATHS.contains(&request.uri().path()) {
        return next.run(request).await;
    }
    if state
        .sessions
        .resolve(session_token(request.headers()))
        .is_some()
    {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        "sign in to the dashboard first (no active session)",
    )
        .into_response()
}

/// A `Router` that serves the dashboard. The caller supplies the state to
/// observe and (when not read-only) sign with; this module never binds a
/// listener.
pub fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/auth/create", post(create_operator))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/whoami", get(whoami))
        .route("/api/auth/recover", post(recover_operator))
        .route("/api/auth/status", get(auth_status))
        .route("/api/identity", get(identity))
        .route("/api/team", get(team))
        .route("/api/tasks", get(tasks))
        .route("/api/tasks/{id}", get(task_detail))
        .route("/api/tasks/{id}/review", post(review_task))
        .route("/api/stats", get(stats))
        .route("/api/ledger", get(ledger))
        .route("/api/learnings", get(learnings))
        .route("/api/roster", get(roster))
        .route("/api/fleet", get(fleet))
        .route("/api/release", get(release))
        .route("/api/release/{version}/approve", post(approve_release))
        .route("/api/release/{version}/deny", post(deny_release))
        .route("/api/team/invite", post(invite_teammate))
        .route("/api/master/init", post(master_init))
        .route("/api/master/claim-all", post(master_claim_all))
        .route("/api/head/revoke", post(head_revoke))
        .route("/api/team/{name}/revoke", post(revoke_access))
        .route("/api/team/{name}/access", post(set_access))
        .route("/api/conversations", get(conversations))
        .route("/api/conversations/{topic}", get(conversation).post(say))
        .route("/api/memory", get(memory))
        .route("/api/memory/suggest", post(suggest))
        .route("/api/secrets", get(secrets_list))
        .route("/api/secrets", post(secret_set))
        .route("/api/secrets/{name}", delete(secret_remove))
        .route("/api/cost/rates", get(cost_rates))
        .route("/api/cost/plan", post(cost_plan))
        .route("/api/improve", get(improve_get).post(improve_set))
        .route("/api/improve/all", post(improve_all))
        .route(
            "/api/engine-policy",
            get(engine_policy_get).post(engine_policy_set),
        )
        .route("/api/engine-policy/accept", post(engine_policy_accept))
        .route("/api/engine-policy/choose", post(engine_policy_choose))
        .route(
            "/api/engine-policy/team",
            get(engine_policy_team_get).post(engine_policy_team_accept),
        )
        .route("/api/engine-policy/settings", post(engine_policy_settings))
        .route("/api/improve/pending", get(improve_pending))
        .route("/api/improve/decide", post(improve_decide))
        .route(
            "/api/delegations",
            get(delegations_get).post(delegations_set),
        )
        .route("/api/delegations/revoke", post(delegations_revoke))
        .route("/api/contracts", get(contracts_get))
        .route("/api/contracts/{reference}/lock", post(contract_lock))
        .route("/api/contracts/{reference}/reject", post(contract_reject))
        .route("/api/adversary", get(adversary_get))
        .route("/api/adversary/override", post(adversary_override))
        // Order matters: layers wrap outermost-last, so the Host guard runs BEFORE the
        // session check. A rebinding attempt is refused without its token being examined,
        // and a missing session is never reported to an origin that should not be talking
        // to us at all.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ))
        .layer(axum::middleware::from_fn(loopback_host_guard))
        .with_state(state)
}

/// Whether a `Host` value names this machine's loopback interface.
///
/// # Why this is a parse and not a string test
///
/// This was `host.starts_with("127.")`, meaning to accept 127.0.0.0/8. A prefix test on a
/// hostname is not a test on an address: **`127.0.0.1.evil.com` starts with `127.`**, and
/// that is a name an attacker can register. Pointing it at 127.0.0.1 makes the attacker's
/// page same-origin with this dashboard - identical scheme, host and port strings - so
/// there is no preflight, responses are readable, and the `Host` header the browser sends
/// is the one that just passed the guard. Which is the whole attack this function exists
/// to stop.
///
/// `IpAddr::is_loopback` answers the question that was actually being asked, for v4 and v6
/// at once, and cannot be fooled by a suffix. `localhost` stays a special case because it
/// is a name rather than an address; it is compared whole.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// Hostnames this dashboard will answer to besides loopback.
///
/// # Why this exists, and why it is a list rather than a switch
///
/// The bind stays loopback forever - that part is not negotiable and is not what this
/// changes. What this admits is a proxy running ON THIS MACHINE that terminates a private
/// tunnel and forwards to 127.0.0.1: `tailscale serve`, `cloudflared`, an SSH forward.
/// Those all reach the dashboard over loopback exactly as a local browser does; the only
/// thing that differs is the `Host` header they carry, which the guard was refusing.
///
/// So the operator names the hostname they set up. A blanket "allow any host" switch
/// would re-open DNS rebinding - the entire attack this guard exists to stop - because
/// rebinding works precisely by sending an attacker-controlled `Host` to a loopback
/// listener. A name the operator typed cannot be one an attacker registered.
///
/// Set with `--allow-host`, repeatable, and empty by default.
static ALLOWED_HOSTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// Name the hostnames a fronting proxy will send. Call before `serve`.
pub fn allow_hosts(hosts: Vec<String>) {
    let _ = ALLOWED_HOSTS.set(
        hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect(),
    );
}

fn host_is_allowed(host: &str) -> bool {
    if is_loopback_host(host) {
        return true;
    }
    ALLOWED_HOSTS.get().is_some_and(|allowed| {
        allowed
            .iter()
            .any(|name| name == &host.to_ascii_lowercase())
    })
}

/// Reject requests whose `Host` header is neither loopback nor a name the operator
/// deliberately allowed.
///
/// A raw loopback bind is not a defense against DNS rebinding: a browser can
/// resolve `attacker.example` to 127.0.0.1 and reach the dashboard as
/// "same-origin", reading the fleet and driving the write endpoints. Requiring
/// a known `Host` blocks that. Requests with no `Host` at all (non-browser
/// clients such as `curl`) are allowed. Mirrors the bridge server's guard.
async fn loopback_host_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let host_ok = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|raw| {
            let host = match raw.rsplit_once(':') {
                Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
                _ => raw,
            };
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host_is_allowed(host)
        })
        .unwrap_or(true);
    if host_ok {
        next.run(request).await
    } else {
        use axum::response::IntoResponse;
        (
            StatusCode::FORBIDDEN,
            "this dashboard does not answer to that hostname. If you put a tunnel in \
             front of it, name the hostname with --allow-host.",
        )
            .into_response()
    }
}

/// Bind a loopback listener and serve the dashboard until interrupted.
///
/// The dashboard reveals the whole fleet, so it refuses a non-loopback bind.
/// To view it from another machine, forward a loopback port (e.g.
/// `ssh -L 8788:127.0.0.1:8788 fleet-host`).
pub async fn serve(state: DashboardState, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    if !addr.ip().is_loopback() {
        bail!(
            "refusing to bind {addr}: the dashboard exposes the whole fleet; \
             bind a loopback address and forward it (e.g. `ssh -L {port}:127.0.0.1:{port} fleet-host`)",
            port = addr.port(),
        );
    }
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        "dashboard listening on http://{addr} (read_only={})",
        state.read_only
    );
    // Printed to stdout, not logged: this is an instruction to the human standing at the
    // terminal, and it must survive `--quiet`, a log level, or logs going to a file. It
    // appears only when there is no operator yet, and stops working the moment one exists.
    if let Some(token) = state.bootstrap_token() {
        // Two very different situations share this branch, and announcing the wrong one
        // costs hours. Ask the channel before saying nobody has ever set up.
        let orphaned = state.orphaned_operators();
        if orphaned.is_empty() {
            println!("\nNo operator exists for this project yet.");
            println!("To create the first one, the dashboard needs this single-use setup token:");
        } else {
            println!(
                "\nThis machine holds no operator key, but this channel already knows: {}.",
                orphaned.join(", ")
            );
            println!("Their signatures still verify here, so the identity is intact - the");
            println!("sealed key is simply not on this machine. Get it back with either:");
            println!("    - the 24-word recovery phrase ('Recover it' on the sign-in screen)");
            println!("    - 'ferry operator import --file <file>' from a machine that has it");
            println!();
            println!("Creating a NEW identity under an existing name will be refused: first");
            println!("key wins, and re-keying would make every past signature read as forged.");
            println!("\nIf you are a new person joining this channel, the setup token is:");
        }
        println!("\n    {token}\n");
        println!("Paste it into the sign-up form. It is not stored, is never sent to you");
        println!("over HTTP, and stops working as soon as one operator exists.\n");
    }
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!("failed to install the ctrl-c handler: {error}");
    }
}

type DashboardError = (StatusCode, String);

fn internal(error: Error) -> DashboardError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

/// The roster as it is on disk right now, not as it was when this process started.
///
/// # Why this is not a cache
///
/// `state.route` is a snapshot taken at boot. Verifying against it was fine until
/// identities began being created *through* the dashboard: an operator who signed up two
/// minutes ago is not in that snapshot, so their perfectly good signature came back
/// `UnknownSigner` and the page told them their own approval was from an unknown signer.
///
/// That is the worst possible direction for this particular error. A badge that cries
/// wolf about a valid signature does not make anyone safer - it teaches them the badge is
/// noise, and the one time it means something they will click past it.
///
/// The roster is a handful of small files in a synced folder, and it changes while this
/// process runs whether or not the process notices. So it is read when the question is
/// asked. Falls back to the boot snapshot if the read fails, which is no worse than what
/// it did before.
fn roster_now(route: &ProjectRoute) -> Vec<ferryman_channel::AgentRoute> {
    ferryman_channel::read_agent_roster(&route.communications)
        .unwrap_or_else(|_| route.agents.clone())
}

fn sig(signature: &SignatureCheck) -> &'static str {
    match signature {
        SignatureCheck::Valid => "valid",
        SignatureCheck::Unsigned => "unsigned",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnknownSigner => "unknown",
        SignatureCheck::KeyChanged { .. } => "key_changed",
    }
}

fn session_token(headers: &HeaderMap) -> &str {
    headers
        .get("x-ferryman-dashboard-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// The one-time setup token offered for creating the first operator.
///
/// A separate header from the session token so the two can never be confused for one
/// another: a session token must never authorise bootstrap, and the bootstrap token must
/// never be accepted as a session.
fn bootstrap_token(headers: &HeaderMap) -> &str {
    headers
        .get("x-ferryman-dashboard-setup")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

#[derive(Deserialize)]
struct Credentials {
    name: String,
    password: String,
}

/// POST /api/auth/create — mint a password-sealed operator identity whose signing key
/// derives from the machine's operator seed (ADR 0016), and publish its public key to the
/// roster so the fleet can verify what this human signs. On the very first run - no seed,
/// no operator - it also creates the seed and returns the recovery phrase, once.
async fn create_operator(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(credentials): Json<Credentials>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    if !state.create_rate.allow(&credentials.name) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many operator creations; slow down".to_string(),
        ));
    }
    // Who may create an operator, and why this is not simply "nobody without a session".
    //
    // This endpoint had NO authentication at all. Anyone who could reach the port created
    // an operator, signed in, and approved agent work under a roster identity the whole
    // fleet verifies as valid. What looked like a gate was in the browser: the page used
    // `__ANY_OPERATORS__` to choose which FORM to show, and the server never consulted it.
    //
    // It cannot simply require a session, because the first operator has nobody to
    // authenticate as. So there are exactly two ways in:
    //
    //   * an existing operator's session - ordinary authenticated creation; or
    //   * the one-time token printed on the terminal when the store is empty.
    //
    // The token is proof of access to the machine's console, which is the property that
    // actually matters and the one a network attacker cannot have. Chosen over an `--init`
    // flag because a flag can be left switched on: the failure mode of a forgotten flag is
    // a permanently open door, and the failure mode of a consumed token is nothing.
    if state.operators.any() {
        if state.sessions.resolve(session_token(&headers)).is_none() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "sign in as an existing operator to create another".to_string(),
            ));
        }
    } else if !state.consume_bootstrap(bootstrap_token(&headers)) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "creating the first operator needs the setup token printed in the terminal \
             running the dashboard; pass it as x-ferryman-dashboard-setup"
                .to_string(),
        ));
    }
    // The operator's signing key derives from the machine's one seed. Determine the
    // signing seed WITHOUT persisting anything yet: the seed is committed only after the
    // operator record exists and is published, so a failed creation - a bad or taken name,
    // a roster write error - can never leave behind a seed whose recovery phrase was never
    // shown.
    //
    // The derivation is bound to the operator's NAME, so the name is settled - folded and
    // checked - before anything derives from it. Two operators on one machine are two
    // people and must not share a key.
    let name = ferryman_channel::canonical_agent_name(&credentials.name);
    if !ferryman_channel::is_safe_component(&name) {
        return Err((
            StatusCode::BAD_REQUEST,
            "operator name must be a path-safe identifier (letters, digits, `-`, `_`, `.`)"
                .to_string(),
        ));
    }
    let (signing_seed, pending_seed) = match state.operators.machine_state_dir() {
        None => {
            let mut minted = [0u8; 32];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut minted);
            (minted, None)
        }
        Some(dir) => match OperatorSeed::load(dir).map_err(internal)? {
            Some(seed) => (seed.operator_signing_seed(&name).map_err(internal)?, None),
            None => {
                let mut bytes = [0u8; 32];
                rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
                let seed = OperatorSeed::from_bytes(bytes);
                let signing_seed = seed.operator_signing_seed(&name).map_err(internal)?;
                (signing_seed, Some((dir.to_path_buf(), bytes)))
            }
        },
    };
    // Through `state.operators`, not a store this function builds for itself.
    //
    // It used to construct its own, which was invisible while every store resolved to the
    // same directory - and became a split brain the moment stores could differ: this
    // endpoint wrote an operator into one store while `login`, three functions down, read
    // from `state.operators` and answered 401 for the account that had just been created
    // successfully. One dashboard, one store.
    let identity = crate::operators::create_operator_identity_from_seed(
        &state.route,
        &state.operators,
        &name,
        &credentials.password,
        signing_seed,
    )
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    // The operator is on disk and published. Only now commit the seed, and - when it was
    // minted here - build its phrase for the one response that carries it.
    let phrase = match pending_seed {
        Some((dir, bytes)) => {
            OperatorSeed::from_bytes(bytes)
                .restore_in(&dir)
                .map_err(internal)?;
            Some(ferryman_channel::seed::seed_to_phrase(bytes).map_err(internal)?)
        }
        None => None,
    };

    // A joiner who arrived with a generic invite picks their name here, so this is the
    // moment the acceptance can be written - signed by the identity just made. This
    // machine's agent, if enable made one, rides along as theirs.
    let mut joined = None;
    if let Some(code) = ferryman_channel::invite::take_pending_code(&state.route)
        && let Ok(device) = ferryman_channel::syncthing_my_id()
    {
        let agent = machine_agent_name(&state.route);
        match ferryman_channel::invite::write_acceptance(
            &state.route,
            &identity,
            &code,
            &device,
            identity.name(),
            agent.as_deref(),
        ) {
            Ok(_) => joined = Some(code.project.clone()),
            Err(err) => tracing::warn!("could not write the invitation acceptance: {err:#}"),
        }
    }

    let public_key = identity.public_key_hex();
    let token = state.sessions.insert(identity);
    Ok(Json(json!({
        "token": token,
        "name": &name,
        "public_key": &public_key,
        "fingerprint": &public_key,
        "phrase": phrase,
        "joined": joined,
    })))
}

/// POST /api/auth/recover — restore a machine's operator seed from its recovery phrase and
/// create the operator identity that derives from it, so a person on a new machine is
/// themselves again. The phrase is validated first and never echoed, and it is refused
/// rather than silently honoured when a different seed is already present.
#[derive(Deserialize)]
struct RecoverBody {
    phrase: String,
    name: String,
    password: String,
}

/// Whether this phrase reconstructs the identity the channel ALREADY publishes under
/// this name.
///
/// # Why this is allowed to stand in for the setup token
///
/// The token exists because a phrase, by itself, proves nothing: on a machine with no
/// seed any valid BIP-39 phrase is accepted, and an attacker simply supplies their own.
/// That reasoning is exactly right for creating a NEW name out of nothing.
///
/// It stops being right when the name is already in the roster with a published key. Then
/// the phrase is not free input - it has to derive that exact key, which only the person
/// who owns it can do. Requiring a console token on top of that adds friction without
/// adding security, and it adds it on the worst day somebody will ever have with this
/// tool: the day they have lost their identity and are holding the one thing that gets it
/// back. If the dashboard is running as a service, or in a window they never saw, a
/// person with a valid recovery phrase is simply stuck.
///
/// Checked here, before anything is written, rather than left to fail later at
/// `register_agent_key`: a gate that works by letting the wrong thing happen and then
/// refusing to publish it is not a gate, it is a cleanup.
fn phrase_proves_a_published_identity(
    state: &DashboardState,
    name: &str,
    seed: &OperatorSeed,
) -> bool {
    let name = ferryman_channel::canonical_agent_name(name);
    let Ok(roster) = ferryman_channel::read_agent_roster(&state.route.communications) else {
        return false;
    };
    let Some(published) = roster
        .iter()
        .find(|entry| ferryman_channel::canonical_agent_name(&entry.name) == name)
        .and_then(|entry| entry.public_key.clone())
        .filter(|key| !key.is_empty())
    else {
        return false;
    };
    // Both sides are public keys, so an ordinary comparison is fine - there is no secret
    // here to leak through timing.
    seed.operator_identity_for(&name)
        .is_ok_and(|identity| identity.public_key_hex() == published)
}

async fn recover_operator(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<RecoverBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    if !state.create_rate.allow(&body.name) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many recovery attempts; slow down".to_string(),
        ));
    }
    // Validate the phrase before touching anything, and never echo it. A phrase that does
    // not parse says so without repeating a word of it.
    let bytes = ferryman_channel::seed::phrase_to_seed(&body.phrase)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let seed = OperatorSeed::from_bytes(bytes);

    // Recovery ends in a created operator and a live session, so it is the same act as
    // `create_operator` and it gets the same two ways in - an existing operator's session,
    // or the one-time token printed on the console.
    //
    // The phrase alone is NOT a gate. On a machine with no seed yet, any valid BIP-39
    // phrase is accepted, and the attacker supplies their own: without this check, anyone
    // who could reach the port could seed the machine, create the first operator and get a
    // session, which is precisely the door the setup token was added to close. A machine
    // that already holds operators but no seed was worse still - one unauthenticated POST
    // and the caller was an operator of a fleet they had never been let into.
    //
    // A person locked out of the browser is not stranded: `ferry identity recover` at the
    // terminal restores the seed, and console access is the property this gate is testing
    // for in the first place.
    //
    // Ordered AFTER the phrase check so a mistyped word does not burn the one-time token
    // and wedge a person out of their own first run. Validating a phrase writes nothing
    // and tells an anonymous caller only whether a BIP-39 checksum holds.
    //
    // ...unless the phrase itself is the proof. See
    // `phrase_proves_a_published_identity`: deriving the key this channel already
    // publishes under this name is something only its owner can do, and it is a stronger
    // claim than holding a token printed on a console.
    let proven = phrase_proves_a_published_identity(&state, &body.name, &seed);
    if proven {
        // Nothing else to ask for. Deliberately does NOT consume the bootstrap token: a
        // recovery that never needed it must not burn it for whoever does.
    } else if state.operators.any() {
        if state.sessions.resolve(session_token(&headers)).is_none() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "sign in as an existing operator to recover another identity here, or run \
                 `ferry identity recover` at a terminal on this machine"
                    .to_string(),
            ));
        }
    } else if !state.consume_bootstrap(bootstrap_token(&headers)) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "that phrase does not reconstruct any identity this channel publishes, so it \
             is being treated as creating a new one - which needs the setup token printed \
             in the terminal running the dashboard. Check the name is spelled as the \
             channel has it, and that the phrase is the right one."
                .to_string(),
        ));
    }

    let dir = state.operators.machine_state_dir().ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            "this machine has no state directory, so it cannot hold an operator seed".to_string(),
        )
    })?;
    match OperatorSeed::load(dir).map_err(internal)? {
        Some(existing) if existing.expose_bytes() != bytes => {
            return Err((
                StatusCode::CONFLICT,
                "this machine already has an operator seed, and the phrase you entered \
                 restores a different one. Replacing it would change what every future \
                 identity derives to; use `ferry identity recover --force` at a terminal if \
                 you mean to do that deliberately."
                    .to_string(),
            ));
        }
        Some(_) => {
            // The same seed is already here; fall through to (re)creating the operator.
        }
        None => seed.restore_in(dir).map_err(internal)?,
    }

    let name = ferryman_channel::canonical_agent_name(&body.name);
    if !ferryman_channel::is_safe_component(&name) {
        return Err((
            StatusCode::BAD_REQUEST,
            "operator name must be a path-safe identifier (letters, digits, `-`, `_`, `.`)"
                .to_string(),
        ));
    }
    let signing_seed = seed.operator_signing_seed(&name).map_err(internal)?;
    let identity = crate::operators::create_operator_identity_from_seed(
        &state.route,
        &state.operators,
        &name,
        &body.password,
        signing_seed,
    )
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    let name = identity.name().to_string();
    let public_key = identity.public_key_hex();
    let token = state.sessions.insert(identity);
    Ok(Json(json!({
        "token": token,
        "name": &name,
        "public_key": &public_key,
        "fingerprint": &public_key,
    })))
}

/// GET /api/auth/status — the two facts the first-run page needs before it chooses which
/// form to show: whether an operator already exists here, and whether a seed does. Reveals
/// only existence, never which operators or what the seed is.
async fn auth_status(State(state): State<DashboardState>) -> Result<Json<Value>, DashboardError> {
    let seed_present = match state.operators.machine_state_dir() {
        Some(dir) => OperatorSeed::load(dir).map_err(internal)?.is_some(),
        None => false,
    };
    Ok(Json(json!({
        "any_operators": state.operators.any(),
        "seed_present": seed_present,
        "read_only": state.read_only,
        // So the sign-in screen can tell "you have never set up" from "your identity is
        // missing from this machine". They look identical and call for opposite actions.
        "orphaned_operators": state.orphaned_operators(),
        // A generic invitation is waiting for the person to pick a name; the sign-up
        // screen says so instead of talking about loopback.
        "joining": std::fs::read_to_string(ferryman_channel::invite::pending_code_path(&state.route))
            .ok()
            .and_then(|t| serde_json::from_str::<ferryman_channel::invite::InviteCode>(&t).ok())
            .map(|c| json!({ "project": c.project, "name": c.operator })),
    })))
}

/// GET /api/identity — the operator's one fingerprint, readable aloud, and whether it
/// derives from the machine's seed. The fingerprint is a public key, safe to display and
/// to publish; it is the value a colleague checks out of band.
async fn identity(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Value>, DashboardError> {
    let me = state
        .sessions
        .resolve(session_token(&headers))
        .ok_or((StatusCode::UNAUTHORIZED, "sign in first".to_string()))?;
    let fingerprint = me.public_key_hex();
    let (derives, seed_present) = match state.operators.machine_state_dir() {
        Some(dir) => match OperatorSeed::load(dir).map_err(internal)? {
            // Against the derivation for THIS operator's name, not the machine
            // fingerprint: the machine fingerprint is one value per seed and is nobody's
            // signing key, so comparing a person's key with it would answer "no" for
            // every operator that does derive.
            Some(seed) => (
                seed.operator_identity_for(me.name())
                    .map(|derived| derived.public_key_hex() == fingerprint)
                    .unwrap_or(false),
                true,
            ),
            None => (false, false),
        },
        None => (false, false),
    };
    Ok(Json(json!({
        "name": me.name(),
        "fingerprint": fingerprint,
        "derives": derives,
        "seed_present": seed_present,
    })))
}

/// POST /api/auth/login — unlock an operator identity and start a session.
async fn login(
    State(state): State<DashboardState>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<Value>, DashboardError> {
    // Sign-in is deliberately allowed in read-only mode, which is a change: it used to be
    // refused, on the reasoning that read-only means "nothing to sign with".
    //
    // That reasoning stopped holding the moment reads required a session. Refusing the
    // only way to obtain a session, while every read demands one, does not make a
    // read-only dashboard read-only - it makes it unopenable. What read-only must forbid
    // is *writing*, and that is enforced where writes happen (`create_operator`,
    // `review_task`, `suggest`), not by withholding identity.
    if !state.login_rate.allow(&credentials.name) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many sign-in attempts; wait a minute".to_string(),
        ));
    }
    let identity = state
        .operators
        .login(&credentials.name, &credentials.password)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let name = identity.name().to_string();
    let public_key = identity.public_key_hex();
    let token = state.sessions.insert(identity);
    Ok(Json(
        json!({ "token": token, "name": name, "public_key": public_key }),
    ))
}

/// POST /api/auth/logout — end this session now, regardless of its deadline.
async fn logout(State(state): State<DashboardState>, headers: HeaderMap) -> StatusCode {
    state.sessions.revoke(session_token(&headers));
    StatusCode::NO_CONTENT
}

/// GET /api/auth/whoami — report the session's operator, or 401 when there is
/// no live session. Also touches the idle deadline, so an open tab stays in.
async fn whoami(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Value>, DashboardError> {
    match state.sessions.resolve(session_token(&headers)) {
        Some(identity) => Ok(Json(json!({ "name": identity.name() }))),
        None => Err((StatusCode::UNAUTHORIZED, "no active session".to_string())),
    }
}

/// GET /api/team — the human operators available on this machine and the
/// agents registered in the current project's portable roster.
///
/// Human identities and agent identities are deliberately returned in
/// separate arrays. The dashboard must never infer that a model/worker is a
/// teammate, nor that an operator owns an agent merely because both happen to
/// be present on this machine. Agent ownership and cross-user access require a
/// signed policy; until that contract exists, `owner` remains null and the UI
/// presents access as unconfigured rather than inventing authority.
async fn team(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let current = state
        .sessions
        .resolve(session_token(&headers))
        .ok_or((StatusCode::UNAUTHORIZED, "no active session".to_string()))?;
    let mut names = state.operators.names().map_err(internal)?;
    let roster = ferryman_channel::read_agent_roster(&route.communications).map_err(internal)?;
    // Operators publish a public roster entry so every machine can verify their
    // signatures. Include those remote humans even when this machine does not hold
    // their sealed signing identity; otherwise the team view would silently collapse
    // to "people who can sign in here" rather than the project's actual human team.
    for operator in roster
        .iter()
        .filter(|entry| entry.role.eq_ignore_ascii_case("operator"))
    {
        if !names.iter().any(|name| name == &operator.name) {
            names.push(operator.name.clone());
        }
    }
    names.sort();
    let master = ferryman_channel::master::read_master(&route)
        .map_err(internal)?
        .map(|declaration| declaration.master);
    let teammates = names
        .into_iter()
        .map(|name| {
            let role = if master.as_deref() == Some(name.as_str()) {
                "owner"
            } else {
                "operator"
            };
            let is_current = name == current.name();
            let scope = if state.operators.is_project_local(&name) {
                "project"
            } else if state.operators.exists(&name) {
                "machine"
            } else {
                "channel"
            };
            let revoked = ferryman_channel::master::is_revoked(&route, &name).unwrap_or(false);
            json!({
                "name": name,
                "role": role,
                "current": is_current,
                "scope": scope,
                "revoked": revoked,
            })
        })
        .collect::<Vec<_>>();
    let agents = roster
        .into_iter()
        .filter(|agent| !agent.role.eq_ignore_ascii_case("operator"))
        .map(|agent| {
            json!({
                "name": agent.name,
                "role": agent.role,
                "capabilities": agent.capabilities,
                "owner": Value::Null,
                "access": "unconfigured",
            })
        })
        .collect::<Vec<_>>();
    // What each person may do, and where. This is not new authority - `MasterGrant` has
    // carried projects, roles and capabilities since ADR 0014 - it is authority that
    // existed in the channel and was not on any screen, so nobody could see who could do
    // what without reading JSON.
    // While the dashboard is open it is the inviter's machine: let in any device
    // knocking under a live invite's name, and - since this session holds the master's
    // unlocked key when the master is signed in - sign the grants an invite promised
    // once the newcomer's keys and acceptance have synced back.
    let master_name = ferryman_channel::master::read_master(&route)
        .ok()
        .flatten()
        .map(|d| d.master);
    if master_name
        .as_deref()
        .is_some_and(|m| m.eq_ignore_ascii_case(current.name()))
    {
        let _ = ensure_operator_on_roster(&route, &current);
    }
    let mut settled_notes: Vec<String> = Vec::new();
    if let Ok(Some(name)) = ferryman_channel::invite::finish_handshake(&route) {
        settled_notes.push(format!("this device is now known as {name}"));
    }

    // Spreading an anchor needs no key, so it happens whenever this page is opened.
    // A project enabled or synced since the last visit picks up its master's claim
    // here rather than waiting to be told.
    if let Some(root) = ferryman_channel::ferry::find_root()
        && let Some(master) = master_name.as_deref()
    {
        let held = ferryman_channel::anchor::held_by(&root, master);
        if !held.is_empty() {
            for (project, outcome) in ferryman_channel::anchor::spread(&root, &held) {
                if outcome == ferryman_channel::anchor::Spread::Published {
                    settled_notes.push(format!("{project} picked up the git anchor"));
                }
            }
        }
    }
    // Projects nobody has claimed get the signed-in person as master - the human, never
    // the machine. `enable` leaves the role empty whenever a person is on the machine:
    // it will not make the machine master and cannot sign as the person. The session is
    // the one place that person's key is unlocked, so this is where the gap closes,
    // unasked, whenever the page opens. Only for the master of the project being
    // viewed: a teammate signing in on their own machine must not become master of
    // whatever happens to be unclaimed there.
    if !state.read_only
        && let Some(root) = ferryman_channel::ferry::find_root()
        && master
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(current.name()))
    {
        for (project, outcome) in root.claim_masters(&current) {
            if matches!(outcome, Ok(ferryman_channel::master::Claim::Declared)) {
                settled_notes.push(format!("{} is now the master of {project}", current.name()));
            }
        }
    }
    if let Ok(settled) = ferryman_channel::invite::settle_pending(&route) {
        for (id, device) in settled.paired {
            settled_notes.push(format!(
                "let in a device for invite {id} ({})",
                &device[..device.len().min(7)]
            ));
        }
        // A machine joining under an existing identity is claimed by that identity,
        // whoever the master is. The session holds exactly one unlocked key, so the
        // person signed in as the owner is the one who can finish it.
        {
            let roster_now =
                ferryman_channel::read_agent_roster(&route.communications).unwrap_or_default();
            for (invite, accept) in settled.ready_to_attest {
                let Some(owner) = invite.owner.as_deref() else {
                    continue;
                };
                if !owner.eq_ignore_ascii_case(current.name()) {
                    settled_notes.push(format!(
                        "{} is waiting for {owner} to claim it",
                        accept.operator
                    ));
                    continue;
                }
                let Some(key) = roster_now
                    .iter()
                    .find(|a| a.name.eq_ignore_ascii_case(&accept.operator))
                    .and_then(|a| a.public_key.clone())
                else {
                    continue;
                };
                if ferryman_channel::owner::attest_owner(&route, &current, &accept.operator, &key)
                    .is_ok()
                {
                    let _ = ferryman_channel::invite::mark_granted(&route, &invite.id);
                    let _ = ferryman_channel::ledger::append_ledger_entry(
                        &route,
                        &current,
                        "own",
                        current.name(),
                        &format!(
                            "{owner} claimed {} as their machine on {}; it inherits their access",
                            accept.operator, route.project_id
                        ),
                        None,
                    );
                    settled_notes.push(format!(
                        "{} is yours now and inherits your access",
                        accept.operator
                    ));
                }
            }
        }
        if master_name
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case(current.name()))
        {
            let roster_now =
                ferryman_channel::read_agent_roster(&route.communications).unwrap_or_default();
            for (invite, accept) in settled.ready_to_grant {
                let mut names = vec![accept.operator.clone()];
                names.extend(accept.agent.clone());
                let mut all_ok = true;
                for who in &names {
                    let Some(entry) = roster_now.iter().find(|a| a.name.eq_ignore_ascii_case(who))
                    else {
                        all_ok = false;
                        continue;
                    };
                    let Some(key) = entry.public_key.clone() else {
                        all_ok = false;
                        continue;
                    };
                    let roles = if who == &accept.operator {
                        invite.roles.clone()
                    } else {
                        vec!["worker".to_string()]
                    };
                    if ferryman_channel::master::grant_member(
                        &route,
                        &current,
                        &entry.name,
                        &key,
                        vec![route.project_id.clone()],
                        roles.clone(),
                        Vec::new(),
                    )
                    .is_ok()
                    {
                        let _ = ferryman_channel::ledger::append_ledger_entry(
                            &route,
                            &current,
                            "grant",
                            current.name(),
                            &format!(
                                "granted {} roles [{}] on {} from invite {}",
                                entry.name,
                                roles.join(", "),
                                route.project_id,
                                invite.id
                            ),
                            None,
                        );
                    } else {
                        all_ok = false;
                    }
                }
                if all_ok {
                    let _ = ferryman_channel::invite::mark_granted(&route, &invite.id);
                    // The placeholder a generic joiner carried until they claimed a
                    // name has no key anyone will use again.
                    let _ = std::fs::remove_file(
                        route
                            .communications
                            .join("agents")
                            .join(format!("guest-{}.json", invite.id)),
                    );
                    settled_notes.push(format!("{} has joined and is granted", accept.operator));
                }
            }
        }
    }
    let invites: Vec<Value> = ferryman_channel::invite::list(&route)
        .unwrap_or_default()
        .into_iter()
        .map(|(invite, check)| {
            let now = chrono::Utc::now();
            let state = if invite.granted_at.is_some() {
                "granted"
            } else if invite.accepted_device.is_some() {
                "paired"
            } else if !ferryman_channel::invite::is_open(&invite, now) {
                "expired"
            } else {
                "waiting"
            };
            let accepted_as = ferryman_channel::invite::read_acceptance(&route, &invite.id)
                .ok()
                .flatten()
                .map(|a| a.operator);
            json!({
                "id": invite.id,
                "operator": accepted_as.or(invite.operator.clone()),
                "agent": invite.agent,
                "roles": invite.roles,
                "state": state,
                "expires_at": invite.expires_at.to_rfc3339(),
                "signature": format!("{check:?}"),
            })
        })
        .collect();

    let grants = ferryman_channel::master::member_grants(&route)
        .map_err(internal)?
        .into_iter()
        .map(|(grant, check)| {
            json!({
                "grantee": grant.grantee,
                "projects": grant.projects,
                "roles": grant.roles,
                "capabilities": grant.capabilities,
                "granted_at": grant.granted_at.to_rfc3339(),
                "signature": sig(&check),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "current": current.name(),
        "invites": invites,
        "notes": settled_notes,
        "master": master,
        // Only the master's signature makes a grant, so the page must not offer the
        // controls to anybody else and then fail at the server. Same answer, one place.
        "may_grant": master.as_deref() == Some(current.name()),
        // Who the master named head agent, and the words they did it with.
        "head": ferryman_channel::head::current(&route.communications, &route.project_id)
            .ok()
            .flatten()
            .map(|head| json!({
                "agent": head.agent,
                "by": head.order.by(),
                "words": head.order.words(),
                "at": head.order.at(),
            })),
        "teammates": teammates,
        "agents": agents,
        "grants": grants,
        // The projects a grant can name, so the page offers what exists rather than
        // asking a person to type an id correctly from memory.
        "projects": ferryman_channel::known::known()
            .into_iter()
            .map(|project| project.project_id)
            .collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct InviteBody {
    /// Reserve this name; absent means they pick any free name themselves.
    #[serde(default)]
    name: Option<String>,
    /// Their agent's name; absent for a person with no agent.
    #[serde(default)]
    agent: Option<String>,
    /// Roles the grant will carry once their keys arrive. Empty means reader; ["full"] means every role.
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    expires_days: Option<i64>,
}

/// POST /api/team/invite - reserve a name for a person who has not joined yet.
///
/// # Why this cannot create their identity
///
/// An operator identity is a signing key sealed under that person's own password. This
/// machine must never know that password, so it cannot mint a teammate: a key created
/// here and handed over would be a key this machine had seen, which is the whole thing
/// operator identities exist to prevent. Anyone offering "add a teammate" that produces
/// a working login for someone else has quietly built a master key.
///
/// So an invitation reserves the NAME. No key is published. When that person's own
/// machine registers, their key binds to the reserved name under first-key-wins - a name
/// reservation, not an impersonation.
async fn invite_teammate(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<InviteBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let route = state.route_for(params.project.as_deref());
    // The operator signs on the roster of the project acted on. A key this project
    // has never seen would sign declarations nobody there could verify.
    ensure_operator_on_roster(&route, &current).map_err(internal)?;
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    if let Some(n) = &name
        && !ferryman_channel::is_safe_component(n)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "a teammate name must be a plain identifier: letters, digits, dashes and \
             underscores"
                .to_string(),
        ));
    }
    let agent = body
        .agent
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string);
    if let Some(agent) = &agent
        && !ferryman_channel::is_safe_component(agent)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "an agent name must be a plain identifier".to_string(),
        ));
    }
    // The code carries this machine's Syncthing device id so the newcomer can trust
    // it; without a running Syncthing there is nothing to put in the code.
    let device = ferryman_channel::syncthing_my_id().map_err(|e| {
        (
            StatusCode::CONFLICT,
            format!("Syncthing must be running to invite someone: {e}"),
        )
    })?;
    let (invite, code) = ferryman_channel::invite::create(
        &route,
        &current,
        name.as_deref(),
        agent.as_deref(),
        body.roles.clone(),
        chrono::Duration::days(body.expires_days.unwrap_or(7).max(1)),
        &device,
    )
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "invite",
        current.name(),
        &format!(
            "invited {}{} to {}; code {} expires {}",
            name.as_deref().unwrap_or("someone (they pick their name)"),
            agent
                .as_ref()
                .map(|a| format!(" (agent {a})"))
                .unwrap_or_default(),
            route.project_id,
            invite.id,
            invite.expires_at.format("%Y-%m-%d")
        ),
        None,
    )
    .map_err(internal)?;
    // A second person on the channel is the moment open grants stop being safe.
    let grants_flipped = ferryman_channel::set_grants_required(&route.attachment).unwrap_or(false);
    if grants_flipped {
        let _ = ferryman_channel::ledger::append_ledger_entry(
            &route,
            &current,
            "policy",
            current.name(),
            "grants are now required on this project: a second person was invited",
            None,
        );
    }
    Ok(Json(json!({
        "name": name,
        "agent": agent,
        "project": route.project_id,
        "state": "invited",
        "id": invite.id,
        "code": code,
        "expires_at": invite.expires_at.to_rfc3339(),
        "windows": format!("irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/join.ps1 | iex; ferry-join {code}"),
        "unix": format!("curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/join.sh | sh -s -- {code}"),
        "grants_required": grants_flipped || route.requires_grants(),
    })))
}

/// Publish the operator's public key to a project's roster if it is not there yet.
/// Same entry `publish_operator` writes on creation; first-key-wins means an existing
/// entry under this name is never overwritten.
fn ensure_operator_on_roster(
    route: &ferryman_channel::ProjectRoute,
    identity: &AgentIdentity,
) -> anyhow::Result<()> {
    // The CHANNEL's own agents directory, not the merged roster: the merged view folds
    // in this machine's fleet-level operators, so an operator created at machine level
    // reads as present here while no peer has ever seen their key. A master declaration
    // signed by such a key verifies on this machine and nowhere else - found when the
    // first joiner could not check who the master was.
    let published = route
        .communications
        .join("agents")
        .join(format!("{}.json", identity.name()));
    if published.is_file()
        && std::fs::read_to_string(&published)
            .ok()
            .and_then(|t| serde_json::from_str::<ferryman_channel::AgentRoute>(&t).ok())
            .is_some_and(|a| a.public_key.as_deref().is_some_and(|k| !k.is_empty()))
    {
        return Ok(());
    }
    let published = ferryman_channel::AgentRoute {
        name: identity.name().to_string(),
        role: "operator".to_string(),
        capabilities: vec!["messages.receive".to_string()],
        public_key: Some(identity.public_key_hex()),
        encryption_key: None,
    };
    ferryman_channel::register_agent_key(route, &published, identity)?;
    Ok(())
}

#[derive(Deserialize)]
struct RevokeBody {
    #[serde(default)]
    reason: String,
}

/// POST /api/team/{name}/revoke - end a person's access: a master-signed revocation
/// beside their grant, their agents' grants likewise, the folder unshared from any
/// device this channel knows as theirs, and open invitations in their name burned.
///
/// What it cannot do: unsync what already synced. Everything in the channel up to this
/// moment is on their disk. Secrets sealed to their agent should be rotated - the
/// response says which ones.
async fn revoke_access(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Path(name): Path<String>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let route = state.route_for(params.project.as_deref());
    if name.eq_ignore_ascii_case(current.name()) {
        return Err((
            StatusCode::CONFLICT,
            "you cannot revoke yourself; transfer the master role first".to_string(),
        ));
    }
    let reason = if body.reason.trim().is_empty() {
        "revoked by the master".to_string()
    } else {
        body.reason.trim().to_string()
    };
    // The person, and every agent whose invite named them as its human.
    let mut names = vec![name.clone()];
    let mut devices: Vec<String> = Vec::new();
    for (invite, _) in ferryman_channel::invite::list(&route).unwrap_or_default() {
        let accepted_as = ferryman_channel::invite::read_acceptance(&route, &invite.id)
            .ok()
            .flatten()
            .map(|a| a.operator);
        let theirs = invite
            .operator
            .as_deref()
            .is_some_and(|o| o.eq_ignore_ascii_case(&name))
            || accepted_as
                .as_deref()
                .is_some_and(|o| o.eq_ignore_ascii_case(&name));
        if theirs {
            if let Some(agent) = &invite.agent
                && !names.iter().any(|n| n.eq_ignore_ascii_case(agent))
            {
                names.push(agent.clone());
            }
            if let Some(device) = &invite.accepted_device {
                devices.push(device.clone());
            }
        }
    }
    // The master ends anyone. Everybody else ends their own machines and agents,
    // from whichever one they happen to be signed in on.
    let signed_in_as_master = ferryman_channel::master::read_master(&route)
        .ok()
        .flatten()
        .is_some_and(|declaration| declaration.master.eq_ignore_ascii_case(current.name()));
    let mut revoked = Vec::new();
    for who in &names {
        if signed_in_as_master {
            ferryman_channel::master::revoke_member(&route, &current, who, &reason)
                .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
        } else {
            ferryman_channel::owner::revoke_machine(&route, &current, who, &reason)
                .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
        }
        revoked.push(who.clone());
    }
    let mut unshared = Vec::new();
    if !devices.is_empty() && ferryman_channel::syncthing_unshare_folder(&route, &devices).is_ok() {
        unshared = devices.clone();
    }
    // Open invitations in their name are burned by expiring them now.
    let burned = ferryman_channel::invite::burn_for(&route, &name).unwrap_or(0);
    let sealed_to: Vec<String> = ferryman_channel::secrets::list_secrets(&route)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| {
            s.recipients
                .iter()
                .any(|r| names.iter().any(|n| n.eq_ignore_ascii_case(r)))
        })
        .map(|s| s.name)
        .collect();
    let _ = ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "revoke",
        current.name(),
        &format!(
            "revoked {} on {}: {reason}{}",
            revoked.join(", "),
            route.project_id,
            if unshared.is_empty() {
                String::new()
            } else {
                format!("; folder unshared from {} device(s)", unshared.len())
            }
        ),
        None,
    );
    Ok(Json(json!({
        "revoked": revoked,
        "unshared_devices": unshared,
        "invites_burned": burned,
        "rotate_secrets": sealed_to,
    })))
}

/// This machine's agent on a project, from its `agent.toml`, if there is one.
fn machine_agent_name(route: &ProjectRoute) -> Option<String> {
    let text = std::fs::read_to_string(route.attachment.join("agent.toml")).ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        (key.trim() == "agent").then(|| value.trim().trim_matches('"').to_string())
    })
}

/// POST /api/master/init - the signed-in operator becomes this project's master.
///
/// The person, not the machine: a master declaration signed by an operator's key is one
/// a human can carry between machines and one every grant can be checked against. It is
/// the dashboard's job because the session already holds the unlocked identity - the CLI
/// route to the same file asks for the password again. Refuses when a master exists;
/// `transfer` is the signed way to change one.
async fn master_init(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let route = state.route_for(params.project.as_deref());
    // The operator signs on the roster of the project acted on. A key this project
    // has never seen would sign declarations nobody there could verify.
    ensure_operator_on_roster(&route, &current).map_err(internal)?;
    if let Some(existing) = ferryman_channel::master::read_master(&route).map_err(internal)? {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "{} is already the master of this project; the master can transfer the role",
                existing.master
            ),
        ));
    }
    let declaration = ferryman_channel::master::initialize_master(&route, &current, current.name())
        .map_err(internal)?;
    let flipped = ferryman_channel::set_grants_required(&route.attachment).unwrap_or(false);
    let _ = ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "master",
        current.name(),
        &format!(
            "{} became the master of {}{}",
            declaration.master,
            route.project_id,
            if flipped {
                "; grants are now required"
            } else {
                ""
            }
        ),
        None,
    );
    Ok(Json(json!({
        "master": declaration.master,
        "grants_required": flipped || route.requires_grants(),
    })))
}

/// GET /api/improve - whether this project's master has switched self-improve on, when
/// the weekly loop last ran here, and which engines each worker on the channel can run.
///
/// The engines are each worker's signed inventory, as `ferry engines` reads it: tier,
/// how it is paid, up, down or out of credit until when - never a credential. `may_set`
/// says whether the person signed in is the master, the only one whose switch counts.
async fn improve_get(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let channel = &route.communications;
    let setting = ferryman_channel::ferry::self_improve_setting(channel, &route.project_id);
    let master = ferryman_channel::ferry::master_of(channel).ok().flatten();
    let may_set = !state.read_only
        && state
            .sessions
            .resolve(session_token(&headers))
            .zip(master.as_ref())
            .is_some_and(|(me, master)| master.eq_ignore_ascii_case(me.name()));
    let engines: Vec<Value> = ferryman_channel::receipts::list_engines(&route)
        .unwrap_or_default()
        .into_iter()
        .map(|(inventory, check)| {
            json!({
                "agent": inventory.agent,
                "machine": inventory.machine,
                "updated_at": inventory.updated_at,
                "signature": format!("{check:?}"),
                "engines": inventory.engines,
            })
        })
        .collect();
    Ok(Json(json!({
        "project": route.project_id,
        "enabled": setting.as_ref().is_some_and(|s| s.enabled),
        "set_by": setting.as_ref().map(ferryman_channel::ferry::ImproveSetting::set_by),
        "set_at": setting.as_ref().map(|s| s.set_at),
        "master": master,
        "may_set": may_set,
        "last_run": ferryman_channel::ferry::improve_last_run(channel)
            .map(|(week, steps)| json!({ "week": week, "steps": steps })),
        // Which engine and model, on which machine, did each step of the last run.
        "who": ferryman_channel::ferry::improve_last_run(channel)
            .map(|(week, _)| {
                ferryman_channel::policy::latest_steps(&route, &week)
                    .iter()
                    .map(ferryman_channel::policy::Step::describe)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        "engines": engines,
    })))
}

#[derive(Deserialize)]
struct ImproveBody {
    enabled: bool,
}

/// POST /api/improve - the master switches self-improve on or off for this project.
///
/// Signed with the session's key into the channel, where every machine reads it; the
/// same check as `ferry improve on|off`, so anyone but the master is refused.
async fn improve_set(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<ImproveBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let route = state.route_for(params.project.as_deref());
    let changed = ferryman_channel::ferry::set_self_improve(
        &route.communications,
        &route.project_id,
        body.enabled,
        &current,
    )
    .map_err(|error| (StatusCode::FORBIDDEN, format!("{error:#}")))?;
    if changed {
        let _ = ferryman_channel::ledger::append_ledger_entry(
            &route,
            &current,
            "self-improve",
            current.name(),
            &format!(
                "{} switched self-improve {} for {}",
                current.name(),
                if body.enabled { "on" } else { "off" },
                route.project_id
            ),
            None,
        );
    }
    Ok(Json(json!({ "enabled": body.enabled, "changed": changed })))
}

/// Every project "all my repos" means: the ferry root's projects, or only this one on a
/// machine without a root.
fn every_project(state: &DashboardState) -> Vec<(String, std::path::PathBuf)> {
    match ferryman_channel::ferry::find_root() {
        Some(root) => root
            .projects()
            .into_iter()
            .map(|entry| (entry.project_id, entry.channel))
            .collect(),
        None => vec![(
            state.route.project_id.clone(),
            state.route.communications.clone(),
        )],
    }
}

/// The projects a request acts on: every one the signed-in person is master of when
/// `all`, else the project on screen.
fn acted_on(
    state: &DashboardState,
    project: Option<&str>,
    all: bool,
) -> Vec<(String, std::path::PathBuf)> {
    if all {
        every_project(state)
    } else {
        let route = state.route_for(project);
        vec![(route.project_id.clone(), route.communications.clone())]
    }
}

fn session_identity(
    state: &DashboardState,
    headers: &HeaderMap,
) -> Result<Arc<ferryman_channel::AgentIdentity>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    state.sessions.resolve(session_token(headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))
}

#[derive(Deserialize)]
struct ImproveAllBody {
    enabled: bool,
}

/// POST /api/improve/all - "On for all my repos": self-improve on (or off) in every
/// project the signed-in person is master of. Projects mastered by someone else are
/// listed and left alone.
async fn improve_all(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<ImproveAllBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let mut switched = 0;
    let projects: Vec<Value> = every_project(&state)
        .into_iter()
        .map(|(project, channel)| {
            let outcome = match ferryman_channel::ferry::master_of(&channel) {
                // Left alone: the loop never runs in an archived project.
                _ if body.enabled && ferryman_channel::ferry::is_archived(&channel, &project) => {
                    "archived".to_string()
                }
                Ok(Some(master)) if master.eq_ignore_ascii_case(current.name()) => {
                    match ferryman_channel::ferry::set_self_improve(
                        &channel,
                        &project,
                        body.enabled,
                        &current,
                    ) {
                        Ok(true) => {
                            switched += 1;
                            "switched".to_string()
                        }
                        Ok(false) => "already".to_string(),
                        Err(error) => format!("error: {error:#}"),
                    }
                }
                Ok(Some(master)) => format!("mastered by {master}"),
                Ok(None) => "no master".to_string(),
                Err(error) => format!("error: {error:#}"),
            };
            json!({ "project": project, "outcome": outcome })
        })
        .collect();
    Ok(Json(json!({
        "enabled": body.enabled,
        "switched": switched,
        "projects": projects,
    })))
}

/// GET /api/engine-policy - the engine policy this project's background work runs under:
/// who signed it (or auto), what it says, how it falls on the engines the fleet
/// published - each role's engines in order, every blocked engine and why - and what
/// auto would recommend, with one reason per choice. `may_set` is true only for the
/// signed-in master.
async fn engine_policy_get(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    use ferryman_channel::policy;
    let route = state.route_for(params.project.as_deref());
    let channel = &route.communications;
    let (current, setting) = policy::effective(channel, &route.project_id);
    let now = chrono::Utc::now();
    let fleet = policy::fleet(&route, now);
    let recommended = policy::recommend_for(&route, now);
    let master = ferryman_channel::ferry::master_of(channel).ok().flatten();
    let may_set = !state.read_only
        && state
            .sessions
            .resolve(session_token(&headers))
            .zip(master.as_ref())
            .is_some_and(|(me, master)| master.eq_ignore_ascii_case(me.name()));
    Ok(Json(json!({
        "project": route.project_id,
        "auto": setting.as_ref().is_none_or(|s| s.policy.is_none()),
        "set_by": setting.as_ref().map(policy::PolicySetting::set_by),
        "set_at": setting.as_ref().map(|s| s.set_at),
        "policy": current,
        "describe": current.describe(),
        "effective": policy::view(&current, &fleet),
        "choices": policy::choices(&current, &fleet, &recommended.policy),
        "recommended": { "policy": recommended.policy, "reasons": recommended.reasons },
        // The team preset - plan on high, build on medium, swarm the cheap work - as it
        // would be signed now, keeping the roles already opened to a capped subscription;
        // and what is wrong with the subscriptions the policy opens.
        "team": team_json(&route, &current, now),
        "warnings": policy::subscription_warnings(&current, &fleet),
        "efforts": policy::Effort::ALL.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
        "self_improve": ferryman_channel::ferry::self_improve_enabled(channel, &route.project_id),
        // What the adversary's findings do here: off, advisory or blocking. The policy's
        // own JSON leaves it out while it is the default.
        "adversary_mode": current.adversary.as_str(),
        "may_set": may_set,
    })))
}

#[derive(Deserialize)]
struct EnginePolicyBody {
    /// The new policy; `null` goes back to auto.
    policy: Option<ferryman_channel::policy::Policy>,
    /// Every project the signed-in master is master of, not only this one.
    #[serde(default)]
    all: bool,
}

#[derive(Deserialize, Default)]
struct AcceptBody {
    #[serde(default)]
    all: bool,
}

/// Sign a policy for the project on screen, or with `all` every project in the ferry
/// root, as the signed-in person, who must be each one's master. `policy_for` gives the
/// policy for a project's route.
fn sign_policies(
    state: &DashboardState,
    current: &ferryman_channel::AgentIdentity,
    project: Option<&str>,
    all: bool,
    policy_for: impl Fn(&ferryman_channel::ProjectRoute) -> Option<ferryman_channel::policy::Policy>,
) -> Result<Json<Value>, DashboardError> {
    let mut changed = 0;
    let mut outcomes = Vec::new();
    // The project on screen is the state's own route; "all" finds each channel's.
    let routes: Vec<(String, Result<ferryman_channel::ProjectRoute, String>)> = if all {
        every_project(state)
            .into_iter()
            .map(|(id, channel)| {
                let route = ferryman_channel::route_for(&channel)
                    .map_err(|error| format!("{error:#}"))
                    .and_then(|route| {
                        if route.project_id == id {
                            Ok(route)
                        } else {
                            Err(format!("{} is not {id}", channel.display()))
                        }
                    });
                (id, route)
            })
            .collect()
    } else {
        let route = state.route_for(project);
        vec![(route.project_id.clone(), Ok(route.as_ref().clone()))]
    };
    for (id, route) in routes {
        let outcome = match route {
            Err(error) => format!("error: {error}"),
            Ok(route) => match ferryman_channel::policy::set_policy(
                &route.communications,
                &id,
                policy_for(&route),
                current,
            ) {
                Ok(true) => {
                    changed += 1;
                    let _ = ferryman_channel::ledger::append_ledger_entry(
                        &route,
                        current,
                        "engine-policy",
                        current.name(),
                        &format!("{} set the engine policy for {id}", current.name()),
                        None,
                    );
                    "set".to_string()
                }
                Ok(false) => "already".to_string(),
                // One project refusing does not stop the rest; alone, it is the answer.
                Err(error) if all => format!("skipped: {error:#}"),
                Err(error) => return Err((StatusCode::FORBIDDEN, format!("{error:#}"))),
            },
        };
        outcomes.push(json!({ "project": id, "outcome": outcome }));
    }
    Ok(Json(json!({ "changed": changed, "projects": outcomes })))
}

/// POST /api/engine-policy - the master sets (or, with `null`, clears) the engine policy,
/// signed with the session's key; `all` does it for every project they are master of.
async fn engine_policy_set(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<EnginePolicyBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    if let Some(policy) = &body.policy {
        policy
            .check()
            .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:#}")))?;
    }
    sign_policies(
        &state,
        &current,
        params.project.as_deref(),
        body.all,
        |_| body.policy.clone(),
    )
}

/// POST /api/engine-policy/accept - sign what auto recommends, from each project's own
/// fleet.
async fn engine_policy_accept(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<AcceptBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    sign_policies(
        &state,
        &current,
        params.project.as_deref(),
        body.all,
        |route| {
            // Laid over the policy in force: accepting engine preferences must not drop the
            // master's `never`, caps, auto-merge or adversary mode.
            let (in_force, _) =
                ferryman_channel::policy::effective(&route.communications, &route.project_id);
            let recommended =
                ferryman_channel::policy::recommend_for(route, chrono::Utc::now()).policy;
            Some(ferryman_channel::policy::apply_recommendation(
                &in_force,
                &recommended,
            ))
        },
    )
}

#[derive(Deserialize)]
struct ChooseBody {
    /// The selector that improves (plans and builds) first.
    #[serde(default)]
    improve: Option<String>,
    /// The selector that reviews first.
    #[serde(default)]
    review: Option<String>,
    /// Use what auto recommends for both.
    #[serde(default)]
    recommended: bool,
    /// `none` or `low-risk`: whether fm merges docs, tests and dependency bumps on its
    /// own once both keys are there.
    #[serde(default)]
    auto_merge: Option<String>,
    /// The selector that challenges first (the adversary role).
    #[serde(default)]
    adversary_engine: Option<String>,
    /// `off`, `advisory` or `blocking`: what the adversary's findings do.
    #[serde(default)]
    adversary: Option<String>,
    #[serde(default)]
    all: bool,
}

/// POST /api/engine-policy/choose - the simple choice: the improvement engine, the review
/// engine and the adversary, or what auto recommends for them. Everything else in the
/// policy stays.
async fn engine_policy_choose(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<ChooseBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let auto_merge = body
        .auto_merge
        .as_deref()
        .map(ferryman_channel::policy::AutoMerge::parse)
        .transpose()
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:#}")))?;
    let adversary = body
        .adversary
        .as_deref()
        .map(ferryman_channel::policy::AdversaryMode::parse)
        .transpose()
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:#}")))?;
    if body.improve.is_none()
        && body.review.is_none()
        && body.adversary_engine.is_none()
        && !body.recommended
        && auto_merge.is_none()
        && adversary.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "pick an improvement engine, a review engine, an adversary, the recommended ones, \
             auto-merge or an adversary mode"
                .to_string(),
        ));
    }
    sign_policies(
        &state,
        &current,
        params.project.as_deref(),
        body.all,
        |route| {
            let (mut policy, _) =
                ferryman_channel::policy::effective(&route.communications, &route.project_id);
            if body.recommended {
                let recommended =
                    ferryman_channel::policy::recommend_for(route, chrono::Utc::now()).policy;
                if let Some(improve) = recommended.improvement_engine() {
                    policy.set_improvement_engine(improve);
                }
                if let Some(review) = recommended.review_engine() {
                    policy.set_review_engine(review);
                }
                if let Some(challenger) = recommended.adversary_engine() {
                    policy.set_adversary_engine(challenger);
                }
            }
            if let Some(improve) = body.improve.as_deref().filter(|s| !s.trim().is_empty()) {
                policy.set_improvement_engine(improve);
            }
            if let Some(review) = body.review.as_deref().filter(|s| !s.trim().is_empty()) {
                policy.set_review_engine(review);
            }
            if let Some(challenger) = body
                .adversary_engine
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                policy.set_adversary_engine(challenger);
            }
            if let Some(mode) = auto_merge {
                policy.auto_merge = mode;
            }
            if let Some(mode) = adversary {
                policy.adversary = mode;
            }
            Some(policy)
        },
    )
}

/// The team preset for `route` as the dashboard shows it: the policy it would sign, one
/// reason per choice, and the warnings for any subscription it opens.
fn team_json_for(
    route: &ferryman_channel::ProjectRoute,
    current: &ferryman_channel::policy::Policy,
    options: &ferryman_channel::policy::TeamOptions,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    use ferryman_channel::policy;
    let proposal = policy::team_for(route, now, options);
    // What accepting signs: the preset laid over the policy in force.
    let signed = policy::apply_team(current, &proposal.policy);
    let fleet = policy::fleet(route, now);
    json!({
        "policy": signed,
        "describe": signed.describe(),
        "reasons": proposal.reasons,
        "warnings": policy::subscription_warnings(&signed, &fleet),
        "effective": policy::view(&signed, &fleet),
    })
}

/// [`team_json_for`] with the preset's own width and effort, keeping the roles the policy
/// in force has opened to a capped subscription.
fn team_json(
    route: &ferryman_channel::ProjectRoute,
    current: &ferryman_channel::policy::Policy,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    let options = ferryman_channel::policy::TeamOptions {
        subscription_roles: current.subscription_roles.clone(),
        ..Default::default()
    };
    team_json_for(route, current, &options, now)
}

#[derive(Deserialize, Default)]
struct TeamParams {
    project: Option<String>,
    /// Roles opened to a capped subscription, comma-separated: `build,chore`. Absent keeps
    /// what the policy in force says.
    subscription_roles: Option<String>,
    /// Widths that replace the preset's: `build=4,chore=2`.
    width: Option<String>,
    /// Efforts that replace the preset's: `build=high`.
    effort: Option<String>,
}

/// `build=4,chore=2`: each part a role and a value.
fn role_pairs(list: &str) -> Result<Vec<(ferryman_channel::policy::Role, String)>, String> {
    list.split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let (role, value) = part
                .split_once('=')
                .or_else(|| part.split_once(':'))
                .ok_or_else(|| format!("'{part}' is not role=value"))?;
            let role = ferryman_channel::policy::Role::parse(role.trim())
                .map_err(|error| format!("{error:#}"))?;
            Ok((role, value.trim().to_string()))
        })
        .collect()
}

fn role_list(list: &str) -> Result<Vec<ferryman_channel::policy::Role>, String> {
    let mut roles = Vec::new();
    for part in list.split(',').filter(|part| !part.trim().is_empty()) {
        let role = ferryman_channel::policy::Role::parse(part.trim())
            .map_err(|error| format!("{error:#}"))?;
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    roles.sort();
    Ok(roles)
}

/// GET /api/engine-policy/team - what the team preset would sign for this project: plan
/// on high, build on medium, swarm the cheap work, with one reason per choice. Nothing is
/// signed. `subscription_roles`, `width` and `effort` try other choices.
async fn engine_policy_team_get(
    State(state): State<DashboardState>,
    Query(params): Query<TeamParams>,
) -> Result<Json<Value>, DashboardError> {
    use ferryman_channel::policy;
    let route = state.route_for(params.project.as_deref());
    let bad = |why: String| (StatusCode::BAD_REQUEST, why);
    let (current, _) = policy::effective(&route.communications, &route.project_id);
    let mut options = policy::TeamOptions {
        subscription_roles: current.subscription_roles.clone(),
        ..Default::default()
    };
    if let Some(roles) = &params.subscription_roles {
        options.subscription_roles = role_list(roles).map_err(bad)?;
    }
    for (role, value) in role_pairs(params.width.as_deref().unwrap_or("")).map_err(bad)? {
        let width = value
            .parse::<u8>()
            .ok()
            .filter(|width| *width > 0)
            .ok_or_else(|| bad(format!("width for {} is 1 to 255", role.as_str())))?;
        options.width.insert(role, width);
    }
    for (role, value) in role_pairs(params.effort.as_deref().unwrap_or("")).map_err(bad)? {
        let effort = policy::Effort::parse(&value).map_err(|error| bad(format!("{error:#}")))?;
        options.effort.insert(role, effort);
    }
    Ok(Json(team_json_for(
        &route,
        &current,
        &options,
        chrono::Utc::now(),
    )))
}

#[derive(Deserialize, Default)]
struct TeamBody {
    /// Roles opened to a capped subscription; absent keeps the policy in force's.
    #[serde(default)]
    subscription_roles: Option<Vec<ferryman_channel::policy::Role>>,
    #[serde(default)]
    width: std::collections::BTreeMap<ferryman_channel::policy::Role, u8>,
    #[serde(default)]
    effort: std::collections::BTreeMap<
        ferryman_channel::policy::Role,
        ferryman_channel::policy::Effort,
    >,
    #[serde(default)]
    all: bool,
}

/// POST /api/engine-policy/team - the master signs the team preset as the project's
/// policy, each project from its own fleet; `all` does it for every project they are
/// master of.
async fn engine_policy_team_accept(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<TeamBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    if body.width.values().any(|width| *width == 0) {
        return Err((
            StatusCode::BAD_REQUEST,
            "a width of 0 would stop the role; use 1 or more".to_string(),
        ));
    }
    sign_policies(
        &state,
        &current,
        params.project.as_deref(),
        body.all,
        |route| {
            let (in_force, _) =
                ferryman_channel::policy::effective(&route.communications, &route.project_id);
            let options = ferryman_channel::policy::TeamOptions {
                subscription_roles: body
                    .subscription_roles
                    .clone()
                    .unwrap_or_else(|| in_force.subscription_roles.clone()),
                width: body.width.clone(),
                effort: body.effort.clone(),
            };
            let preset =
                ferryman_channel::policy::team_for(route, chrono::Utc::now(), &options).policy;
            // Laid over the policy in force, so the master's security settings stay.
            Some(ferryman_channel::policy::apply_team(&in_force, &preset))
        },
    )
}

#[derive(Deserialize, Default)]
struct SettingsBody {
    /// Effort per role: `{"build": "medium"}`.
    #[serde(default)]
    effort: std::collections::BTreeMap<
        ferryman_channel::policy::Role,
        ferryman_channel::policy::Effort,
    >,
    /// Orders at once per role: `{"build": 3}`; `null` removes the cap.
    #[serde(default)]
    width: std::collections::BTreeMap<ferryman_channel::policy::Role, Option<u8>>,
    /// Roles whose background work may use a subscription with a weekly cap; `[]` clears.
    #[serde(default)]
    subscription_roles: Option<Vec<ferryman_channel::policy::Role>>,
    #[serde(default)]
    all: bool,
}

/// POST /api/engine-policy/settings - effort, width and subscription_roles per role,
/// signed by the master. Everything else in the policy stays.
async fn engine_policy_settings(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<SettingsBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    if body.effort.is_empty() && body.width.is_empty() && body.subscription_roles.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "set an effort, a width or the roles that may use a subscription".to_string(),
        ));
    }
    if body.width.values().any(|width| *width == Some(0)) {
        return Err((
            StatusCode::BAD_REQUEST,
            "a width of 0 would stop the role; use 1 or more, or null for no cap".to_string(),
        ));
    }
    sign_policies(
        &state,
        &current,
        params.project.as_deref(),
        body.all,
        |route| {
            let (mut policy, _) =
                ferryman_channel::policy::effective(&route.communications, &route.project_id);
            policy.effort.extend(body.effort.clone());
            for (role, width) in &body.width {
                match width {
                    Some(width) => policy.width.insert(*role, *width),
                    None => policy.width.remove(role),
                };
            }
            if let Some(roles) = &body.subscription_roles {
                let mut roles = roles.clone();
                roles.sort();
                roles.dedup();
                policy.subscription_roles = roles;
            }
            Some(policy)
        },
    )
}

/// GET /api/improve/pending - improvements waiting on a key: the review engine's verdict,
/// then the master's approval. Each with its diff stat, its evidence, and what the
/// review engine said.
async fn improve_pending(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let master = ferryman_channel::ferry::master_of(&route.communications)
        .ok()
        .flatten();
    let may_decide = !state.read_only
        && state
            .sessions
            .resolve(session_token(&headers))
            .zip(master.as_ref())
            .is_some_and(|(me, master)| master.eq_ignore_ascii_case(me.name()));
    // Each card carries the adversary's word beside the two keys: the finding as it stands,
    // with who overrode a Block, if anyone did.
    let waiting: Vec<Value> = ferryman_channel::gate::waiting(&route)
        .into_iter()
        .map(|waiting| {
            let standing = waiting.adversary.as_ref().and_then(|_| {
                ferryman_channel::adversary::standing(
                    &route,
                    &waiting.order_id,
                    waiting.revision,
                    ferryman_channel::adversary::Trigger::PreDone,
                )
            });
            let mut card = json!(waiting);
            card["adversary"] = standing
                .as_ref()
                .map_or(Value::Null, ferryman_channel::adversary::Standing::view);
            card
        })
        .collect();
    Ok(Json(json!({
        "project": route.project_id,
        "may_decide": may_decide,
        "waiting": waiting,
    })))
}

#[derive(Deserialize)]
struct DecideBody {
    order: String,
    accept: bool,
    #[serde(default)]
    notes: Option<String>,
}

/// POST /api/improve/decide - the master's key: approve an improvement for live, or send
/// it back with notes. Refused until the review engine has given the first key. Nothing
/// merges: an approved improvement is "approved, ready to merge".
async fn improve_decide(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<DecideBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let route = state.route_for(params.project.as_deref());
    let revision = ferryman_channel::gate::decide(
        &route,
        &body.order,
        body.accept,
        body.notes.as_deref(),
        current.name(),
        &current,
    )
    .map_err(|error| (StatusCode::FORBIDDEN, format!("{error:#}")))?;
    Ok(Json(json!({
        "order": body.order,
        "revision": revision,
        "state": if body.accept { "approved, ready to merge" } else { "sent back" },
    })))
}

/// GET /api/delegations - who may act for the master in this project (the Telegram
/// bridge, say), whether each delegation counts right now, and which agents on the
/// roster could be delegated to.
async fn delegations_get(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let master = ferryman_channel::ferry::master_of(&route.communications)
        .ok()
        .flatten();
    let may_set = !state.read_only
        && state
            .sessions
            .resolve(session_token(&headers))
            .zip(master.as_ref())
            .is_some_and(|(me, master)| master.eq_ignore_ascii_case(me.name()));
    let delegations: Vec<Value> = ferryman_channel::delegation::list(
        &route.communications,
        &route.project_id,
        chrono::Utc::now(),
    )
    .into_iter()
    .map(|(delegation, standing)| {
        json!({
            "delegate": delegation.delegate,
            "principal": delegation.principal,
            "scopes": delegation.scopes,
            "issued_at": delegation.issued_at,
            "expires_at": delegation.expires_at,
            "standing": standing.describe(),
            "active": standing == ferryman_channel::delegation::Standing::Active,
        })
    })
    .collect();
    let candidates: Vec<String> = ferryman_channel::read_agent_roster(&route.communications)
        .unwrap_or_default()
        .into_iter()
        .filter(|agent| {
            agent.public_key.as_ref().is_some_and(|key| !key.is_empty())
                && (agent.role.eq_ignore_ascii_case("delegate")
                    || agent.name.starts_with("telegram-"))
        })
        .map(|agent| agent.name)
        .collect();
    Ok(Json(json!({
        "project": route.project_id,
        "master": master,
        "may_set": may_set,
        "scopes": ferryman_channel::delegation::SCOPES,
        "delegations": delegations,
        "candidates": candidates,
    })))
}

#[derive(Deserialize)]
struct DelegateBody {
    delegate: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_days: Option<i64>,
    #[serde(default)]
    all: bool,
}

/// POST /api/delegations - the master lets an agent act for them, in this project or
/// (`all`) every project they are master of. The browser half of `ferry team delegate`.
async fn delegations_set(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<DelegateBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let scopes: Vec<String> = if body.scopes.is_empty() {
        ferryman_channel::delegation::SCOPES
            .iter()
            .map(ToString::to_string)
            .collect()
    } else {
        body.scopes.clone()
    };
    let expires_at = body
        .expires_days
        .map(|days| chrono::Utc::now() + chrono::Duration::days(days));
    let mut delegated = 0;
    let mut projects = Vec::new();
    for (project, channel) in acted_on(&state, params.project.as_deref(), body.all) {
        let outcome = match ferryman_channel::delegation::grant(
            &channel,
            &project,
            &current,
            &body.delegate,
            &scopes,
            expires_at,
        ) {
            Ok(_) => {
                delegated += 1;
                "delegated".to_string()
            }
            Err(error) if body.all => format!("skipped: {error:#}"),
            Err(error) => return Err((StatusCode::FORBIDDEN, format!("{error:#}"))),
        };
        projects.push(json!({ "project": project, "outcome": outcome }));
    }
    Ok(Json(json!({
        "delegate": body.delegate,
        "principal": current.name(),
        "scopes": scopes,
        "delegated": delegated,
        "projects": projects,
    })))
}

/// The route with its roster read fresh from the channel. The route a dashboard starts
/// with carries the roster as it was at launch, and a contract proposed by an agent that
/// joined since would otherwise read as unsigned - and be invisible to the very person who
/// has to lock it.
fn with_current_roster(route: &ProjectRoute) -> ProjectRoute {
    let mut fresh = route.clone();
    if let Ok(agents) = ferryman_channel::read_agent_roster(&route.communications) {
        fresh.agents = agents;
    }
    fresh
}

/// One order on a contract's side, as the Contracts page lists it.
fn contract_order_row(task: &ferryman_channel::Task) -> Value {
    json!({
        "id": task.order.id,
        "state": state_value(&task.state()),
        "holder": task.holder(),
        "task": task.order.payload.get("task").and_then(Value::as_str).unwrap_or(""),
        "touches": task.order.touches,
    })
}

/// GET /api/contracts - every interface contract in the project: its status (proposed,
/// locked or rejected), its shapes, who proposed and locked it, and the orders on each
/// side, with the reason any of them is being held. `may_decide` is true only for the
/// master, the one person whose Lock counts.
async fn contracts_get(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = with_current_roster(&state.route_for(params.project.as_deref()));
    let master = ferryman_channel::master::read_master(&route)
        .ok()
        .flatten()
        .map(|declaration| declaration.master);
    let may_decide = !state.read_only
        && state
            .sessions
            .resolve(session_token(&headers))
            .zip(master.as_ref())
            .is_some_and(|(me, master)| master.eq_ignore_ascii_case(me.name()));
    let tasks = ferryman_channel::list_tasks(&route).map_err(internal)?;
    let row = |orders: &[ferryman_channel::Order]| -> Vec<Value> {
        orders
            .iter()
            .filter_map(|order| tasks.iter().find(|task| task.order.id == order.id))
            .map(|task| {
                let mut row = contract_order_row(task);
                row["holds"] = json!(ferryman_channel::hold::read(&route, &task.order.id));
                row
            })
            .collect()
    };
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    let mut items = Vec::new();
    for contract in ferryman_channel::interface::list_contracts(&route) {
        let orders = ferryman_channel::interface::orders_for_interface(
            &route,
            &contract.name,
            &contract.version,
        )
        .map_err(internal)?;
        // What the adversary found, next to Lock and Reject; empty when it is off.
        let reference = contract.reference();
        let adversary: Vec<Value> =
            if policy.adversary == ferryman_channel::policy::AdversaryMode::Off {
                Vec::new()
            } else {
                ferryman_channel::adversary::Trigger::ALL
                    .iter()
                    .filter_map(|trigger| {
                        ferryman_channel::adversary::decision_standing(&route, &reference, *trigger)
                    })
                    .map(|standing| standing.view())
                    .collect()
            };
        items.push(json!({
            "adversary": adversary,
            // What a Lock or an override must name, so it lands on what this screen shows:
            // the contract's digest, and the adversary's word on it (`none` when no
            // eligible adversary has read it).
            "digest": ferryman_channel::interface::digest(&route.project_id, &contract),
            "finding_digest": ferryman_channel::adversary::lock_finding_seen(&route, &contract),
            "lock_refusal": ferryman_channel::adversary::lock_refusal(&route, &policy, &contract),
            "reference": contract.reference(),
            "name": contract.name,
            "version": contract.version,
            "description": contract.description,
            "status": ferryman_channel::interface::status(&route, &contract),
            "proposed_by": contract.proposed_by,
            "proposed_at": contract.proposed_at,
            "locked_by": contract.lock.as_ref().map(|lock| lock.by.clone()),
            "locked_at": contract.lock.as_ref().map(|lock| lock.at),
            "request": contract.request,
            "response": contract.response,
            "providers": row(&orders.providers),
            "consumers": row(&orders.consumers),
        }));
    }
    Ok(Json(json!({
        "project": route.project_id,
        "master": master,
        "may_decide": may_decide,
        "adversary_mode": policy.adversary.as_str(),
        "contracts": items,
    })))
}

#[derive(Deserialize, Default)]
struct LockBody {
    /// Lock despite the adversary's Block (the master's signed override).
    #[serde(default, rename = "override")]
    overriding: bool,
    #[serde(default)]
    reason: Option<String>,
    /// The contract's digest as the page showed it (`/api/contracts` `digest`); a lock is
    /// refused unless it is still what this names.
    #[serde(default)]
    digest: String,
    /// For an override: the adversary's word as the page showed it (`finding_digest`).
    #[serde(default)]
    finding: String,
}

/// The contract a request names, checked for what a decision needs: it exists and is
/// genuine, it is not already decided.
fn undecided_contract(
    route: &ProjectRoute,
    reference: &str,
) -> Result<ferryman_channel::interface::InterfaceContract, DashboardError> {
    let (name, version) = ferryman_channel::interface::parse_ref(reference)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:#}")))?;
    let Some(contract) = ferryman_channel::interface::read_contract(route, &name, &version) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("there is no genuine contract {reference} in this project"),
        ));
    };
    match ferryman_channel::interface::status(route, &contract) {
        ferryman_channel::interface::Status::Proposed => Ok(contract),
        other => Err((
            StatusCode::CONFLICT,
            format!("{reference} is already {}", other.as_str()),
        )),
    }
}

/// POST /api/contracts/{reference}/lock - the master freezes a proposed contract, signed
/// with the session's key. The browser half of `ferry contract lock`; it also answers the
/// question Telegram asked, so the buttons there go away. Master only.
async fn contract_lock(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Path(reference): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let route = with_current_roster(&state.route_for(params.project.as_deref()));
    let contract = undecided_contract(&route, &reference)?;
    // The body names what the master looked at: `{"digest": "<contract digest>"}`, and for
    // an override also `"override": true, "finding": "<finding_digest>", "reason": "..."`.
    // A lock that does not say what it is locking is refused.
    let body: LockBody = if body.iter().all(u8::is_ascii_whitespace) {
        LockBody::default()
    } else {
        serde_json::from_slice(&body).map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "the body is {{\"digest\": \"...\", \"override\": true, \"finding\": \"...\", \
                     \"reason\": \"...\"}}: {error}"
                ),
            )
        })?
    };
    if body.digest.trim().len() < ferryman_channel::interface::DIGEST_MIN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "say which contract you looked at: send its `digest` (at least {} characters) \
                 from GET /api/contracts",
                ferryman_channel::interface::DIGEST_MIN
            ),
        ));
    }
    if body.overriding && body.finding.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "say which finding you are overriding: send its `finding_digest` (or `none`) from \
             GET /api/contracts"
                .to_string(),
        ));
    }
    // With the engine policy's adversary on `blocking`, a Block stops this until the
    // master overrides it: the same refusal the CLI and the phone give. `override` signs
    // that and locks in one step.
    let locked = if body.overriding {
        ferryman_channel::interface::lock_overriding(
            &route,
            &contract.name,
            &contract.version,
            &body.digest,
            body.finding.trim(),
            current.name(),
            &current,
            Some(
                body.reason
                    .as_deref()
                    .filter(|reason| !reason.trim().is_empty())
                    .unwrap_or("overridden from the dashboard"),
            ),
        )
    } else {
        ferryman_channel::interface::lock(
            &route,
            &contract.name,
            &contract.version,
            &body.digest,
            current.name(),
            &current,
        )
    }
    .map_err(|error| (StatusCode::FORBIDDEN, format!("{error:#}")))?;
    let _ = ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "contract",
        current.name(),
        &format!(
            "locked interface contract {}{}",
            locked.reference(),
            if body.overriding {
                ", over the adversary's Block"
            } else {
                ""
            }
        ),
        None,
    );
    Ok(Json(json!({
        "reference": locked.reference(),
        "status": "locked",
        "locked_by": locked.lock.as_ref().map(|lock| lock.by.clone()),
    })))
}

/// POST /api/contracts/{reference}/reject - the master declines a proposed contract. The
/// proposer's way forward is a new version. Master only.
async fn contract_reject(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Path(reference): Path<String>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let route = with_current_roster(&state.route_for(params.project.as_deref()));
    let contract = undecided_contract(&route, &reference)?;
    ferryman_channel::interface::reject(
        &route,
        &contract.name,
        &contract.version,
        current.name(),
        &current,
    )
    .map_err(|error| (StatusCode::FORBIDDEN, format!("{error:#}")))?;
    let _ = ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "contract",
        current.name(),
        &format!("rejected interface contract {}", contract.reference()),
        None,
    );
    Ok(Json(
        json!({ "reference": contract.reference(), "status": "rejected" }),
    ))
}

/// GET /api/adversary - what the adversary found in this project: the mode, and every
/// genuine finding newest first, each with who overrode a Block, if anyone did.
/// `may_override` is true only for the signed-in master.
async fn adversary_get(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = with_current_roster(&state.route_for(params.project.as_deref()));
    let master = ferryman_channel::master::read_master(&route)
        .ok()
        .flatten()
        .map(|declaration| declaration.master);
    let may_override = !state.read_only
        && state
            .sessions
            .resolve(session_token(&headers))
            .zip(master.as_ref())
            .is_some_and(|(me, master)| master.eq_ignore_ascii_case(me.name()));
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    // What counts (newest first), and what was ignored with why: a finding from the agent
    // that built the work, from a machine with no inventory, and the like.
    let survey = ferryman_channel::adversary::list_standings(&route);
    Ok(Json(json!({
        "project": route.project_id,
        "mode": policy.adversary.as_str(),
        "engine": policy.adversary_engine(),
        "may_override": may_override,
        "findings": survey.standings.iter().map(ferryman_channel::adversary::Standing::view).collect::<Vec<_>>(),
        "ignored": survey.ignored.iter().map(ferryman_channel::adversary::Ignored::view).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct OverrideBody {
    /// An order id, or a contract as `name@version`.
    subject: String,
    /// `contract-lock`, `repeat-failure` or `pre-done`.
    trigger: String,
    /// The revision the Block is on; defaults to the revision under decision.
    #[serde(default)]
    revision: Option<u32>,
    #[serde(default)]
    reason: Option<String>,
    /// The adversary's word as the page showed it (the finding's `digest`): the override
    /// is refused unless that is still what stands. Required.
    #[serde(default)]
    finding: String,
}

/// POST /api/adversary/override - the master goes ahead despite the adversary's Block,
/// signed with the session's key. For a contract it only records the override (Lock then
/// goes through); for an improvement it lets the review engine's key be granted. Master
/// only, and only for a genuine Block.
async fn adversary_override(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<OverrideBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let route = with_current_roster(&state.route_for(params.project.as_deref()));
    let trigger = ferryman_channel::adversary::Trigger::parse(&body.trigger)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:#}")))?;
    let revision = match body.revision {
        Some(revision) => revision,
        None => ferryman_channel::adversary::decision_revision(&route, &body.subject, trigger)
            .ok_or((
                StatusCode::NOT_FOUND,
                format!(
                    "{} has no {} moment to decide",
                    body.subject,
                    trigger.label()
                ),
            ))?,
    };
    if body.finding.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "say which finding you are overriding: send its `finding` digest (or `none`)"
                .to_string(),
        ));
    }
    let given = ferryman_channel::adversary::override_or_waive(
        &route,
        &body.subject,
        revision,
        trigger,
        body.finding.trim(),
        body.reason
            .as_deref()
            .filter(|reason| !reason.trim().is_empty())
            .or(Some("overridden from the dashboard")),
        current.name(),
        &current,
    )
    .map_err(|error| (StatusCode::FORBIDDEN, format!("{error:#}")))?;
    let _ = ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "adversary",
        current.name(),
        &format!(
            "overrode the adversary's Block on {} r{revision} ({})",
            body.subject,
            trigger.label()
        ),
        None,
    );
    Ok(Json(json!({
        "subject": body.subject,
        "revision": revision,
        "trigger": trigger.as_str(),
        "overridden_by": given.from(),
        "reason": given.reason,
    })))
}

#[derive(Deserialize)]
struct UndelegateBody {
    delegate: String,
    #[serde(default)]
    all: bool,
}

/// POST /api/delegations/revoke - the master ends a delegation here, or everywhere.
async fn delegations_revoke(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Json(body): Json<UndelegateBody>,
) -> Result<Json<Value>, DashboardError> {
    let current = session_identity(&state, &headers)?;
    let mut revoked = 0;
    for (project, channel) in acted_on(&state, params.project.as_deref(), body.all) {
        if body.all && ferryman_channel::delegation::read(&channel, &body.delegate).is_none() {
            continue;
        }
        match ferryman_channel::delegation::revoke(
            &channel,
            &project,
            &current,
            &body.delegate,
            "revoked from the dashboard",
        ) {
            Ok(true) => revoked += 1,
            Ok(false) => {}
            Err(_) if body.all => {}
            Err(error) => return Err((StatusCode::FORBIDDEN, format!("{error:#}"))),
        }
    }
    Ok(Json(
        json!({ "delegate": body.delegate, "revoked": revoked }),
    ))
}

/// POST /api/head/revoke - the master clears the head agent of the project on screen.
///
/// Naming someone else in plain words replaces a head too; this is for having none.
async fn head_revoke(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let route = state.route_for(params.project.as_deref());
    let master = ferryman_channel::master::read_master(&route)
        .map_err(internal)?
        .map(|declaration| declaration.master);
    if !master
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(current.name()))
    {
        return Err((
            StatusCode::FORBIDDEN,
            "only the master names or clears the head agent".to_string(),
        ));
    }
    let removed = ferryman_channel::head::revoke_all(&route.communications).map_err(internal)?;
    Ok(Json(json!({ "removed": removed })))
}

/// POST /api/master/claim-all - the signed-in person becomes master of every project in
/// this machine's ferry root that has none.
///
/// The browser half of `ferry root master`, for a person who is not yet master of the
/// project on screen and so is not offered it unasked. Declares only: it does not turn
/// on required grants the way claiming a single project here does, because switching
/// thirty projects to grants-required at once would stop every agent that has been
/// working in them without one.
async fn master_claim_all(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<Value>, DashboardError> {
    use ferryman_channel::master::Claim;
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let root = ferryman_channel::ferry::find_root().ok_or((
        StatusCode::NOT_FOUND,
        "no ferry root on this machine".to_string(),
    ))?;
    let projects: Vec<Value> = root
        .claim_masters(&current)
        .into_iter()
        .map(|(project, outcome)| {
            let (outcome, detail) = match outcome {
                Ok(Claim::Declared) => ("declared", None),
                Ok(Claim::AlreadyTheirs) => ("already", None),
                Ok(Claim::Other(master)) => ("other", Some(master)),
                Ok(Claim::KeyConflict) => ("key_conflict", None),
                Err(error) => ("error", Some(format!("{error:#}"))),
            };
            json!({ "project": project, "outcome": outcome, "detail": detail })
        })
        .collect();
    let declared = projects
        .iter()
        .filter(|project| project["outcome"] == "declared")
        .count();
    Ok(Json(json!({
        "master": current.name(),
        "declared": declared,
        "projects": projects,
    })))
}

#[derive(Deserialize)]
struct AccessBody {
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

/// POST /api/team/{name}/access - what this person may do, and on which projects.
///
/// Writes a `MasterGrant`, which has carried projects/roles/capabilities since ADR 0014.
/// The authority is not new; what is new is that it can be read and written by a person
/// rather than only by editing JSON in the channel.
async fn set_access(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<ProjectParam>,
    Path(name): Path<String>,
    Json(body): Json<AccessBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let current = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let route = state.route_for(params.project.as_deref());
    // The operator signs on the roster of the project acted on. A key this project
    // has never seen would sign declarations nobody there could verify.
    ensure_operator_on_roster(&route, &current).map_err(internal)?;
    // A grant is only worth anything because the master signed it, so a grant this
    // person cannot sign must be refused here rather than written unsigned.
    let roster = ferryman_channel::read_agent_roster(&route.communications).map_err(internal)?;
    let Some(person) = roster.iter().find(|a| a.name.eq_ignore_ascii_case(&name)) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("{name} is not in this channel; invite them first"),
        ));
    };
    // A reserved name has no key yet, and a grant names the key it is about - otherwise
    // it would attach to whoever claimed the name later, which is the substitution every
    // other gate here refuses.
    let Some(public_key) = person.public_key.clone() else {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "{name} has been invited but has not come online yet, so there is no key \
                 to grant access to. A grant names the key, not the name."
            ),
        ));
    };
    let grant = ferryman_channel::master::grant_member(
        &route,
        &current,
        &person.name,
        &public_key,
        body.projects.clone(),
        body.roles.clone(),
        body.capabilities.clone(),
    )
    // grant_member refuses anyone who is not the master, and says so in words.
    .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    ferryman_channel::ledger::append_ledger_entry(
        &route,
        &current,
        "grant",
        current.name(),
        &format!(
            "granted {} roles [{}] on projects [{}]",
            grant.grantee,
            grant.roles.join(", "),
            if grant.projects.is_empty() {
                "every project".to_string()
            } else {
                grant.projects.join(", ")
            }
        ),
        None,
    )
    .map_err(internal)?;
    Ok(Json(json!({
        "grantee": grant.grantee,
        "projects": grant.projects,
        "roles": grant.roles,
        "capabilities": grant.capabilities,
    })))
}

/// GET /api/tasks — a summary of every task, with signature status.
async fn tasks(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let tasks = ferryman_channel::list_tasks(&route).map_err(internal)?;
    let now = chrono::Utc::now();
    // Contracts, holds and overlaps are only believed when signed by someone on the
    // roster, and a member who joined after the dashboard started must count.
    let current = with_current_roster(&route);
    // Which open or claimed orders are heading for the same files as which, once for the
    // whole list rather than once per card.
    let overlaps = ferryman_channel::overlap::overlap_map(&current, &tasks);
    let items = tasks
        .iter()
        .map(|task| {
            json!({
                "id": task.order.id,
                "state": state_value(&task.state()),
                // How far an unfinished order has got (sent, delivered, read, claimed,
                // done), from signed receipts; null once it is finished.
                "stage": ferryman_channel::receipts::progress(&route, task, now),
                "holder": task.holder(),
                "result_count": task.results.len(),
                "sig": sig(&ferryman_channel::verify_order(&task.order, &route.agents)),
                "requires_review": task.order.requires_review,
                "requires_approval": task.order.requires_approval,
                "task": task.order.payload.get("task").and_then(Value::as_str).unwrap_or(""),
                "depends_on": task.order.depends_on,
                "contract_missing": task.contract_violations_in(&current).unwrap_or_default(),
                "interface": task.order.interface,
                "touches": task.order.touches,
                "allow_overlap": task.order.allow_overlap,
                "overlaps": overlaps.get(&task.order.id).cloned().unwrap_or_default(),
                "holds": ferryman_channel::hold::read(&current, &task.order.id),
            })
        })
        .collect();
    Ok(Json(items))
}

/// GET /api/tasks/{id} — full detail for one task.
async fn task_detail(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let current = with_current_roster(&route);
    let task = ferryman_channel::read_task(&route, &id).map_err(internal)?;
    let results = task
        .results
        .iter()
        .map(|r| {
            let trajectory = ferryman_channel::trajectory::read_trajectory(
                &route,
                &task.order.id,
                &r.agent,
                r.revision,
            );
            json!({
                "revision": r.revision,
                "agent": r.agent,
                "engine": trajectory.as_ref().map(|t| t.engine.clone()),
                "ok": trajectory.as_ref().map(|t| t.ok),
                "sig": sig(&ferryman_channel::verify_result(r, &route.agents)),
                "output": result_text(&r.payload),
            })
        })
        .collect::<Vec<_>>();
    let reviews = task
        .reviews
        .iter()
        .map(|r| {
            json!({
                "revision": r.revision,
                "reviewer": r.reviewer,
                "accepted": r.accepted,
                "notes": r.notes,
                "sig": sig(&ferryman_channel::verify_review(r, &route.agents)),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "id": task.order.id,
        "order": {
            "issued_by": task.order.issued_by,
            "assigned_to": task.order.assigned_to,
            "created_at": task.order.created_at.to_rfc3339(),
            "requires_review": task.order.requires_review,
            "requires_approval": task.order.requires_approval,
            "depends_on": task.order.depends_on,
            "interface": task.order.interface,
            "touches": task.order.touches,
            "allow_overlap": task.order.allow_overlap,
            "payload": task.order.payload,
            "sig": sig(&ferryman_channel::verify_order(&task.order, &route.agents)),
        },
        "holds": ferryman_channel::hold::read(&current, &task.order.id),
        "overlaps": ferryman_channel::overlap::overlap_map(
            &current,
            &ferryman_channel::list_tasks(&route).unwrap_or_default(),
        )
        .remove(&task.order.id)
        .unwrap_or_default(),
        "notes": evidence_notes(&task),
        "claims": task.claims.iter().map(|c| json!({ "agent": c.agent, "at": c.claimed_at.to_rfc3339() })).collect::<Vec<_>>(),
        "results": results,
        "reviews": reviews,
        "contract_missing": task.contract_violations_in(&current).unwrap_or_default(),
    })))
}

/// The notes the worker's evidence carries for a reviewer, newest result last. Information
/// only: they never decide anything.
fn evidence_notes(task: &ferryman_channel::Task) -> Vec<Value> {
    task.results
        .iter()
        .filter_map(|result| {
            let evidence = result.payload.get("evidence")?;
            let notes = evidence.get("notes")?.as_array()?;
            Some(
                notes
                    .iter()
                    .map(move |note| json!({ "revision": result.revision, "note": note })),
            )
        })
        .flatten()
        .collect()
}

/// GET /api/stats — engine acceptance plus cost, merged into one table.
async fn stats(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let acceptance = ferryman_channel::learning::engine_stats(&route).map_err(internal)?;
    let costs = ferryman_channel::cost::engine_costs(&route).map_err(internal)?;
    let items = acceptance
        .iter()
        .map(|stat| {
            let cost = costs.iter().find(|c| c.engine == stat.engine);
            json!({
                "engine": stat.engine,
                "total": stat.total,
                "accepted": stat.accepted,
                "rate": stat.rate(),
                "runs": cost.map(|c| c.runs).unwrap_or(0),
                "prompt_tokens": cost.map(|c| c.prompt_tokens).unwrap_or(0),
                "completion_tokens": cost.map(|c| c.completion_tokens).unwrap_or(0),
                "estimated_cost_usd": cost.map(|c| c.estimated_cost_usd).unwrap_or(0.0),
            })
        })
        .collect();
    Ok(Json(items))
}

/// GET /api/cost/rates — the published per-engine price table, for the
/// estimator's engine picker. Prices are per million tokens.
async fn cost_rates() -> Result<Json<Value>, DashboardError> {
    let rates = ferryman_channel::cost::published_rates();
    Ok(Json(json!({
        "rates": rates
            .iter()
            .map(|(family, prompt, completion)| {
                json!({
                    "key": family.split_whitespace().next().unwrap_or(family),
                    "family": family,
                    "prompt_per_million": prompt,
                    "completion_per_million": completion,
                })
            })
            .collect::<Vec<_>>(),
    })))
}

/// POST /api/cost/plan — model a whole project from a description and price it
/// against every engine. An estimate, not a bid.
#[derive(Deserialize)]
struct PlanBody {
    prompt: String,
    #[serde(default)]
    tasks: Option<u64>,
}

async fn cost_plan(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    Json(body): Json<PlanBody>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let (tasks, prompt_tokens, completion_tokens) =
        ferryman_channel::cost::estimate_project_tokens(&body.prompt, body.tasks);
    let route = route.as_ref();
    let rates = ferryman_channel::cost::Rates::load(route);
    let costs = ferryman_channel::cost::published_rates()
        .iter()
        .map(|(family, _, _)| {
            let key = family.split_whitespace().next().unwrap_or(family);
            let (quality, measured, total, accepted) =
                ferryman_channel::cost::effective_quality(route, &rates, key);
            json!({
                "family": family,
                "key": key,
                "estimated_cost_usd": ferryman_channel::cost::project_cost(
                    &rates, key, prompt_tokens, completion_tokens
                ),
                "quality": quality,
                "quality_label": ferryman_channel::cost::quality_label(quality),
                "measured": measured,
                "total": total,
                "accepted": accepted,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "tasks": tasks,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "costs": costs,
    })))
}

/// GET /api/ledger — the most recent ledger entries, newest first.
async fn ledger(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let log = ferryman_channel::ledger::read_ledger(&route).map_err(internal)?;
    let entries = log
        .entries
        .iter()
        .rev()
        .take(100)
        .map(|e| {
            json!({
                "kind": e.kind,
                "actor": e.actor,
                "summary": e.summary,
                "reference": e.reference,
                "at": e.created_at.to_rfc3339(),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "intact": log.intact, "entries": entries })))
}

/// GET /api/learnings — the most recent learning records, newest first.
async fn learnings(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let learnings = ferryman_channel::learning::read_learnings(&route).map_err(internal)?;
    let items = learnings
        .iter()
        .rev()
        .take(100)
        .map(|l| {
            json!({
                "engine": l.engine,
                "task_id": l.task_id,
                "source": l.source,
                "accepted": l.accepted,
                "note": l.note,
                "at": l.at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(items))
}

/// GET /api/roster — the machines in this project's roster, and the engine each
/// most recently ran. Keeping "which machine" and "which model" as separate
/// columns is the point: a machine runs an engine, they are not the same thing.
async fn roster(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let agents = ferryman_channel::read_agent_roster(&route.communications).map_err(internal)?;
    let runs = ferryman_channel::trajectory::agent_runs(&route).map_err(internal)?;
    let presence = ferryman_channel::receipts::list_presence(&route).map_err(internal)?;
    let absent =
        ferryman_channel::receipts::absent_at(&route.agents, &presence, chrono::Utc::now());
    let items = agents
        .iter()
        .map(|agent| {
            let seen = presence
                .iter()
                .find(|(p, _)| p.agent.eq_ignore_ascii_case(&agent.name))
                .map(|(p, check)| {
                    json!({
                        "machine": p.machine,
                        "seen_at": p.seen_at.to_rfc3339(),
                        "ferry_version": p.ferry_version,
                        "paused": p.paused,
                        "held": p.held,
                        "sig": sig(check),
                    })
                });
            let (engine, last_active, runs) = match runs.get(&agent.name) {
                Some(info) => (
                    Some(info.engine.clone()),
                    Some(info.last_active.to_rfc3339()),
                    info.runs,
                ),
                None => (None, None, 0),
            };
            json!({
                "name": agent.name,
                "role": agent.role,
                "capabilities": agent.capabilities,
                "mcp": ferryman_channel::discovery::is_mcp(agent),
                "key": agent.public_key.as_deref().map(fingerprint).unwrap_or_default(),
                "encryption_key": agent.encryption_key.is_some(),
                "engine": engine,
                "last_active": last_active,
                "runs": runs,
                "presence": seen,
                "absent": absent.iter().any(|a| a.agent.eq_ignore_ascii_case(&agent.name)),
            })
        })
        .collect();
    Ok(Json(items))
}

/// POST /api/memory/suggest — record a human suggestion for improving the
/// project's memory. Appended to the synced memory bank so the whole fleet can
/// read it and fold it into the knowledge graph.
#[derive(Deserialize)]
struct Suggestion {
    text: String,
}

async fn suggest(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    headers: HeaderMap,
    Json(body): Json<Suggestion>,
) -> Result<StatusCode, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let text = body.text.trim().to_string();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "suggestion is empty".to_string()));
    }
    // A byline is a claim about who said something, so it is taken from the session or the
    // request is refused. This used to fall back to the literal string "operator" when
    // there was no session - inventing an author, for an unauthenticated write, into the
    // SYNCED memory bank that every agent on every machine reads. Silent degradation is
    // bad enough on a read; on a signed-looking write it manufactures provenance.
    let author = state
        .sessions
        .resolve(session_token(&headers))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "sign in before suggesting; a suggestion carries your name".to_string(),
        ))?
        .name()
        .to_string();
    // Bounded because this file replicates to every machine in the fleet. Axum's 2 MB body
    // limit caps one request; nothing capped how many times you could append.
    const MAX_SUGGESTION: usize = 4096;
    if text.len() > MAX_SUGGESTION {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("a suggestion is at most {MAX_SUGGESTION} characters"),
        ));
    }
    let entry = format!(
        "\n## {}\n_by {}_\n\n{}\n",
        chrono::Utc::now().to_rfc3339(),
        author,
        text
    );
    let dir = route.communications.join("memory-bank");
    std::fs::create_dir_all(&dir).map_err(|e| internal(e.into()))?;
    let path = dir.join("suggestions.md");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| internal(e.into()))?;
    std::io::Write::write_all(&mut file, entry.as_bytes()).map_err(|e| internal(e.into()))?;
    Ok(StatusCode::CREATED)
}

/// GET /api/secrets — the stored secrets, never their values. Enough for the
/// form to list what exists and what setting a name again would overwrite.
async fn secrets_list(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let summaries = ferryman_channel::secrets::list_secrets(&route).map_err(internal)?;
    let items = summaries
        .iter()
        .map(|s| {
            json!({
                "name": &s.name,
                "recipients": &s.recipients,
                "signed_by": &s.signed_by,
                "created_at": &s.created_at,
                "signature": s.signature,
            })
        })
        .collect();
    Ok(Json(items))
}

/// POST /api/secrets — seal a value to the chosen recipients, signed by the
/// session's operator identity. The value is sealed in memory and written as
/// ciphertext; it is never logged and never leaves the request as plaintext.
#[derive(Deserialize)]
struct SecretBody {
    name: String,
    value: String,
    #[serde(default)]
    recipients: Vec<String>,
}

async fn secret_set(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    headers: HeaderMap,
    Json(body): Json<SecretBody>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    // The seal is signed by the human who signed in - an operator identity the
    // roster verifies - never by the machine's agent, and never unsigned.
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let recipients: Vec<String> = body
        .recipients
        .iter()
        .map(|r| ferryman_channel::canonical_agent_name(r))
        .collect();
    let path = ferryman_channel::secrets::set_secret(
        &route,
        &identity,
        &body.name,
        &body.value,
        &recipients,
    )
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({
        "name": body.name,
        "recipients": recipients,
        "signed_by": identity.name(),
        "path": path.display().to_string(),
    })))
}

/// DELETE /api/secrets/{name} — remove a secret envelope.
async fn secret_remove(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    // Removing is a write and must be attributable the same way setting is.
    if state.sessions.resolve(session_token(&headers)).is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "no active session; sign in again".to_string(),
        ));
    }
    if ferryman_channel::secrets::remove_secret(&route, &name).map_err(internal)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "no such secret".to_string()))
    }
}

/// A short, still-identifiable prefix of a public key for display.
fn fingerprint(key: &str) -> String {
    let short: String = key.chars().take(16).collect();
    if key.len() > 16 {
        format!("{short}…")
    } else {
        short
    }
}

/// The human-readable content of a result payload: its `output` or `text` key,
/// or the whole payload as JSON when neither is present. A result's payload is
/// whatever the worker chose to put there, so this keeps the dashboard from
/// showing "(no output)" for a result that simply used a different key.
fn result_text(payload: &Value) -> Option<String> {
    if let Some(text) = payload
        .get("output")
        .or_else(|| payload.get("text"))
        .and_then(Value::as_str)
    {
        return Some(text.chars().take(4000).collect());
    }
    Some(serde_json::to_string_pretty(payload).unwrap_or_default())
}

/// GET /api/fleet — every machine on the network, every syncing device, and
/// every project this machine has a channel for. The whole fleet in one view,
/// not just the current project.
async fn fleet(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let machines = ferryman_channel::licensing::read_devices(&route)
        .map_err(internal)?
        .iter()
        .map(|device| {
            let behind = device.ferry_version.as_deref().is_some_and(|v| {
                ferryman_channel::licensing::version_is_older(v, env!("CARGO_PKG_VERSION"))
            });
            json!({
                "id": device.id,
                "kind": device.kind.as_str(),
                "operator_email": device.operator_email,
                "registered_at": device.registered_at.to_rfc3339(),
                "ferry_version": device.ferry_version,
                "behind": behind,
            })
        })
        .collect::<Vec<_>>();
    let devices = ferryman_channel::syncthing_peers()
        .unwrap_or_default()
        .iter()
        .map(|peer| json!({ "device_id": peer.device_id, "name": peer.name, "connected": peer.connected }))
        .collect::<Vec<_>>();
    let projects = discover_projects(&route).map_err(internal)?;
    Ok(Json(json!({
        "machines": machines,
        "devices": devices,
        "projects": projects,
        "current": route.project_id,
        "home": state.route.project_id,
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

/// Where sibling projects are looked for, when it is not simply the parent directory.
///
/// A fleet is usually kept as one folder of channels, and `ferry agent run --comms`
/// already takes that folder. The dashboard did not: launched from inside one channel it
/// scanned that channel's parent and found its siblings, and launched from a project
/// checkout elsewhere it found nothing at all and silently showed one project. Set by
/// `ferry dashboard --comms`.
static COMMS_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Point project discovery at a folder of channels. Call before `serve`.
pub fn discover_projects_in(root: PathBuf) {
    let _ = COMMS_ROOT.set(root);
}

/// Every project whose channel directory sits beside this workspace, or inside the
/// `--comms` folder when one was given. A directory is a project exactly when it has a
/// channel on disk; there is no registry to keep in sync, so a project appears the moment
/// its channel is there.
fn discover_projects(route: &ProjectRoute) -> anyhow::Result<Vec<Value>> {
    let Some(parent) = COMMS_ROOT
        .get()
        .map(PathBuf::as_path)
        .or_else(|| route.workspace.parent())
    else {
        return Ok(Vec::new());
    };
    let mut projects: Vec<(String, String, usize, usize, usize)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    // The manifest first: what a person deliberately filed, which is the most reliable
    // answer there is.
    if let Some(root) = ferryman_channel::ferry::find_root() {
        for entry in root.projects() {
            let start = entry.repo.clone().unwrap_or_else(|| entry.channel.clone());
            let Ok(child) = ferryman_channel::route_for(&start) else {
                continue;
            };
            if seen.contains(&child.project_id) {
                continue;
            }
            let tasks = ferryman_channel::list_tasks(&child).unwrap_or_default();
            let open = tasks
                .iter()
                .filter(|task| !matches!(task.state(), TaskState::Accepted | TaskState::Done))
                .count();
            seen.push(child.project_id.clone());
            projects.push((
                child.project_id,
                child.workspace.display().to_string(),
                tasks.len(),
                open,
                tasks.len() - open,
            ));
        }
    }

    // Then what this machine has actually used, wherever it lives - the half that finds
    // a fleet the scan below cannot reach.
    for project in ferryman_channel::known::known() {
        let Ok(child) = ferryman_channel::route_for(&project.workspace) else {
            continue;
        };
        if seen.contains(&child.project_id) {
            continue;
        }
        let tasks = ferryman_channel::list_tasks(&child).unwrap_or_default();
        let open = tasks
            .iter()
            .filter(|task| !matches!(task.state(), TaskState::Accepted | TaskState::Done))
            .count();
        seen.push(child.project_id.clone());
        projects.push((
            child.project_id,
            child.workspace.display().to_string(),
            tasks.len(),
            open,
            tasks.len() - open,
        ));
    }

    if parent.is_dir() {
        // One unreadable entry must not empty the whole list. The parent of a project is
        // often a drive root, and a drive root has `System Volume Information` and
        // `Program Files` on it - one permission error there took the picker down to
        // nothing, on the one machine with the most projects to pick from.
        for entry in std::fs::read_dir(parent)?.flatten() {
            let path = entry.path();
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let Ok(child) = ferryman_channel::route_for(&path) else {
                continue;
            };
            if seen.contains(&child.project_id) {
                continue;
            }
            let tasks = ferryman_channel::list_tasks(&child).unwrap_or_default();
            let open = tasks
                .iter()
                .filter(|task| !matches!(task.state(), TaskState::Accepted | TaskState::Done))
                .count();
            projects.push((
                child.project_id,
                child.workspace.display().to_string(),
                tasks.len(),
                open,
                tasks.len() - open,
            ));
        }
    }
    projects.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(projects
        .into_iter()
        .map(|(project_id, path, tasks, open, done)| {
            json!({
                "project_id": project_id,
                "path": path,
                "tasks": tasks,
                "open": open,
                "done": done,
            })
        })
        .collect())
}

/// GET /api/release — the release waiting for a person, if there is one.
async fn release(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let Some(request) = ferryman_channel::release::pending(&route) else {
        return Ok(Json(json!({ "pending": null })));
    };
    // Matched on version AND commit, because that is what an approval means.
    //
    // Matching on version alone was a dead end with no way out: an approval of v0.5.6 at
    // one commit made the page report v0.5.6 as approved, render the "approved by" panel,
    // and hide the buttons - for a request at a DIFFERENT commit that `may_sign` was
    // correctly refusing. The gate and the page disagreed, and the half that disagreed was
    // the half with the controls on it. The operator could not approve the release and
    // could not see why.
    let approved = ferryman_channel::release::list_approvals(&route)
        .into_iter()
        .find(|a| a.version == request.version && a.commit == request.commit);
    // An approval of this version at an older commit is worth showing - it is why the
    // commit pin exists and it explains the state - but it is not consent to this one.
    let superseded = ferryman_channel::release::list_approvals(&route)
        .into_iter()
        .find(|a| a.version == request.version && a.commit != request.commit);
    let denied = ferryman_channel::release::list_denials(&route)
        .into_iter()
        .find(|d| d.version == request.version);
    let roster = roster_now(&route);
    let now = chrono::Utc::now();
    // Asked at the commit the request itself names, which is what a person on this page
    // is being asked about.
    let verdict = ferryman_channel::release::may_sign(&route, &request, &request.commit);
    Ok(Json(json!({
        "pending": {
            "version": request.version,
            "commit": request.commit,
            "prepared_by": request.prepared_by,
            "prepared_at": request.prepared_at.to_rfc3339(),
            "age_minutes": request.age_minutes(now),
            "stale": request.is_stale(now),
            "ci_green": request.ci_green,
            "ci_summary": request.ci_summary,
            "notes": request.notes,
            "signature": sig(&ferryman_channel::release::verify_request(&request, &roster)),
        },
        "approval": approved.map(|a| json!({
            "version": a.version,
            "commit": a.commit,
            "approved_by": a.approved_by,
            "approved_at": a.approved_at.to_rfc3339(),
            "via": a.via,
            "signature": sig(&ferryman_channel::release::verify_approval(&a, &roster)),
        })),
        "superseded_approval": superseded.map(|a| json!({
            "commit": a.commit,
            "approved_by": a.approved_by,
            "approved_at": a.approved_at.to_rfc3339(),
        })),
        "denial": denied.map(|d| json!({
            "version": d.version,
            "commit": d.commit,
            "denied_by": d.denied_by,
            "denied_at": d.denied_at.to_rfc3339(),
            "reason": d.reason,
            "via": d.via,
            "signature": sig(&ferryman_channel::release::verify_denial(&d, &roster)),
        })),
        // The same verdict the signing path computes, from the same function.
        //
        // It used to be absent, and `may_sign` had exactly one caller: `ferry release
        // status`, at a terminal. So this page could offer an Approve button for a
        // request the gate would refuse, and the person found out later, elsewhere, if
        // they went looking. Two answers to one question, with the reassuring one in
        // front of the human. One gate, both callers.
        "would_authorise": match &verdict {
            Ok(_) => json!({ "ok": true }),
            Err(refusal) => json!({ "ok": false, "because": refusal.to_string() }),
        },
    })))
}

#[derive(Deserialize)]
struct ApproveBody {
    /// Repeated back by the page deliberately. If what the operator was looking at is
    /// not what the channel now holds, the approval must not silently attach to the
    /// newer thing - that is the substitution the whole design exists to refuse.
    commit: String,
}

/// POST /api/release/{version}/approve — a person says yes to one commit.
///
/// # Why the session is the whole gate
///
/// The operator's signing key is sealed at rest with their password and is not in this
/// process until they sign in (see `operators.rs`). So the fleet cannot reach this: an
/// orchestrator, a worker, or a compromised bridge has no session and therefore no key.
/// What authorises a release is a person having typed their password, which is exactly
/// the property the old "type a passphrase at the machine" arrangement had.
async fn approve_release(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    headers: HeaderMap,
    Path(version): Path<String>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;

    let request = ferryman_channel::release::pending(&route).ok_or((
        StatusCode::CONFLICT,
        "there is no release waiting to be approved".to_string(),
    ))?;
    if request.version != version {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "the release waiting is {}, not {version}. Reload and look at what is \
                 actually on the table.",
                request.version
            ),
        ));
    }
    // The page tells us which commit the person was looking at. If the channel has moved
    // under them, their yes was about something else.
    if request.commit != body.commit {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "this release is now at {} and you were shown {}. Reload and look again \
                 before approving.",
                request.commit, body.commit
            ),
        ));
    }
    if !request.ci_green {
        return Err((
            StatusCode::CONFLICT,
            "the tests did not pass; this gate is for judgement, not for overriding the \
             machine"
                .to_string(),
        ));
    }
    if request.is_stale(chrono::Utc::now()) {
        return Err((
            StatusCode::CONFLICT,
            "this request has gone stale; have it prepared again so you are approving \
             what is actually there"
                .to_string(),
        ));
    }

    let approval = ferryman_channel::release::ReleaseApproval {
        version: request.version.clone(),
        commit: request.commit.clone(),
        approved_by: identity.name().to_string(),
        approved_at: chrono::Utc::now(),
        via: "dashboard".to_string(),
        signed_by: None,
        signature: None,
    };
    let path = ferryman_channel::release::write_approval(&route, &approval, &identity)
        .map_err(internal)?;
    Ok(Json(json!({
        "version": approval.version,
        "commit": approval.commit,
        "approved_by": approval.approved_by,
        "path": path.display().to_string(),
    })))
}

#[derive(Deserialize)]
struct DenyBody {
    commit: String,
    #[serde(default)]
    reason: String,
}

/// POST /api/release/{version}/deny - a person says no to one commit, and why.
///
/// # Why saying no needs a signature too
///
/// Before this existed the store could only hold approvals, so a person who read a
/// request and decided against it had nowhere to put that: silence and refusal were
/// recorded identically, and "did anybody actually look at this" - the one question a
/// judgement surface exists to answer - could not be answered from the channel.
///
/// A denial is signed by the same key an approval is, unsealed by the same password. An
/// unsigned refusal would be a denial of service any peer could write into the synced
/// folder, and `may_sign` ignores one for that reason.
async fn deny_release(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    headers: HeaderMap,
    Path(version): Path<String>,
    Json(body): Json<DenyBody>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let request = ferryman_channel::release::pending(&route).ok_or((
        StatusCode::CONFLICT,
        "there is no release waiting to be decided".to_string(),
    ))?;
    if request.version != version {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "the release waiting is {}, not {version}. Reload and look at what is \
                 actually on the table.",
                request.version
            ),
        ));
    }
    // The same substitution check approving does. A no about one commit is not a no
    // about whatever has replaced it since the page was drawn.
    if request.commit != body.commit {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "this release is now at {} and you were shown {}. Reload and look again \
                 before deciding.",
                request.commit, body.commit
            ),
        ));
    }
    // Deliberately no CI or staleness gate here. Those refuse a *release*; they must not
    // refuse a person's refusal. Being unable to record "no" on a stale request would be
    // the original hole in a smaller shape.
    let denial = ferryman_channel::release::ReleaseDenial {
        version: request.version.clone(),
        commit: request.commit.clone(),
        denied_by: identity.name().to_string(),
        denied_at: chrono::Utc::now(),
        reason: body.reason.clone(),
        via: "dashboard".to_string(),
        signed_by: None,
        signature: None,
    };
    let path =
        ferryman_channel::release::write_denial(&route, &denial, &identity).map_err(internal)?;
    Ok(Json(json!({
        "version": denial.version,
        "commit": denial.commit,
        "denied_by": denial.denied_by,
        "reason": denial.reason,
        "path": path.display().to_string(),
    })))
}

/// Where the conversations live: the memory bank, which Syncthing carries - so what is
/// said here is said in the channel, not in the dashboard.
fn conversation_bank(route: &ProjectRoute) -> std::path::PathBuf {
    route.communications.join("memory-bank")
}

/// One line of a conversation file, parsed back out of the shape `append_turn` writes.
///
/// The file is Markdown on purpose - people read it, and agents' prompts are built from
/// it - so this parses rather than owning a format. A line it cannot read comes back
/// whole under an empty speaker rather than being dropped: silently swallowing a line of
/// somebody's conversation is worse than showing it plainly.
fn parse_turn(line: &str) -> Value {
    let rest = line.trim_start().trim_start_matches("- ");
    if let Some((at, tail)) = rest.split_once(' ')
        && let Some(said) = tail.strip_prefix("**")
        && let Some((who, body)) = said.split_once("**: ")
    {
        return json!({ "at": at, "who": who, "said": body });
    }
    json!({ "at": "", "who": "", "said": rest })
}

/// GET /api/conversations - every topic, with its last line and whether it verifies.
async fn conversations(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let bank = conversation_bank(&route);
    let dir = ferryman_channel::conversation::conversations_dir(&bank);
    let roster = roster_now(&route);
    let mut topics = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let Some(topic) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let lines: Vec<&str> = text
                .lines()
                .filter(|line| line.trim_start().starts_with("- "))
                .collect();
            let last = lines.last().map(|line| parse_turn(line));
            let check = ferryman_channel::conversation::verify_conversation(&bank, topic, &roster);
            topics.push(json!({
                "topic": topic,
                "turns": lines.len(),
                "last": last,
                "signature": sig(&check),
            }));
        }
    }
    // Most recently spoken in, first. A conversation nobody has touched for a week must
    // not sit above the one that is happening now.
    topics.sort_by(|a, b| {
        let key = |v: &Value| v["last"]["at"].as_str().unwrap_or_default().to_string();
        key(b).cmp(&key(a))
    });
    Ok(Json(json!({ "conversations": topics })))
}

/// GET /api/conversations/{topic} - the thread.
async fn conversation(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    Path(topic): Path<String>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let bank = conversation_bank(&route);
    let check =
        ferryman_channel::conversation::verify_conversation(&bank, &topic, &roster_now(&route));
    let text = ferryman_channel::conversation::load_conversation(&bank, &topic).unwrap_or_default();
    let turns: Vec<Value> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("- "))
        .map(parse_turn)
        .collect();
    Ok(Json(json!({
        "topic": topic,
        "turns": turns,
        "signature": sig(&check),
    })))
}

#[derive(Deserialize)]
struct SaidBody {
    said: String,
}

/// POST /api/conversations/{topic} - say something, signed by whoever is signed in.
///
/// # Why this writes to the channel rather than to the dashboard
///
/// The dashboard is a view over the synced channel, never a second channel. What the
/// operator types here and what they type into Telegram land in the same signed file and
/// are indistinguishable afterwards, which is the whole point. A message that existed
/// only in the dashboard would be invisible to every agent and would vanish when this
/// process stopped - and the project's claim is that there is no server in the middle.
async fn say(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(topic): Path<String>,
    Json(body): Json<SaidBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;
    let said = body.said.trim();
    if said.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "nothing to say".to_string()));
    }
    // A browser will happily post a megabyte, and this file is carried to every machine
    // in the fleet and read into agents' prompts.
    if said.len() > 8_000 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "that is too long for one turn; say it in a few".to_string(),
        ));
    }
    let bank = conversation_bank(&state.route);
    ferryman_channel::conversation::append_turn(&bank, &topic, identity.name(), said, &identity)
        .map_err(|e| internal(e.into()))?;
    // Each turn signed on its own as well. The conversation file is signed whole, by
    // whoever wrote last, so one line in it proves nothing about who said it - and a
    // person's plain words are how they name a head agent. Best-effort: the turn is
    // already said.
    let _ = ferryman_channel::head::record_said(
        &state.route.communications,
        &state.route.project_id,
        &identity,
        said,
    );
    Ok(Json(json!({ "topic": topic, "who": identity.name() })))
}

/// GET /api/memory — the project's shared memory bank, plus the knowledge graph
/// if graphify has exported one. Best-effort: an unreadable file is skipped, and
/// a missing graph simply returns `graph: null`.
async fn memory(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let mut files = Vec::new();
    let memory_dir = route.communications.join("memory-bank");
    if memory_dir.is_dir() {
        for entry in std::fs::read_dir(&memory_dir).map_err(|e| internal(e.into()))? {
            let entry = entry.map_err(|e| internal(e.into()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            files.push(json!({ "name": name, "content": content }));
        }
    }
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(json!({ "files": files, "graph": load_graph() })))
}

/// The graphify knowledge graph, if one can be found: `FERRYMAN_GRAPH_JSON`
/// first, then the conventional graphify output location. Returns the nodes
/// (label, type, community, summary) and a link count rather than the raw
/// geometry, which is a local build artifact.
fn load_graph() -> Option<Value> {
    let path = std::env::var("FERRYMAN_GRAPH_JSON")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            ["/srv/cline/projects/ferryman/graphify-out/graph.json"]
                .iter()
                .map(std::path::PathBuf::from)
                .find(|path| path.is_file())
        })?;
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let nodes = value
        .get("nodes")
        .and_then(Value::as_array)
        .map(|nodes| {
            nodes
                .iter()
                .map(|node| {
                    json!({
                        "id": node.get("id").and_then(Value::as_str).unwrap_or(""),
                        "label": node.get("label").and_then(Value::as_str).unwrap_or(""),
                        "type": node.get("type").and_then(Value::as_str).unwrap_or(""),
                        "community": node.get("community"),
                        "summary": node.get("summary").and_then(Value::as_str).unwrap_or(""),
                        "file": node.get("file").and_then(Value::as_str).unwrap_or(""),
                        "file_type": node.get("file_type").and_then(Value::as_str).unwrap_or(""),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let links = value
        .get("links")
        .and_then(Value::as_array)
        .map(|links| {
            links
                .iter()
                .map(|link| {
                    json!({
                        "source": link.get("source").and_then(Value::as_str).unwrap_or(""),
                        "target": link.get("target").and_then(Value::as_str).unwrap_or(""),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(json!({ "nodes": nodes, "links": links }))
}

#[derive(Deserialize)]
struct ReviewBody {
    accept: bool,
    #[serde(default)]
    notes: Option<String>,
}

/// POST /api/tasks/{id}/review — accept a result, or send it back with notes.
///
/// This is the write action the CLI exposes as `ferry channel review`, and it
/// uses the exact same path: load the latest result, enforce the contract, sign
/// the verdict with the *session's* operator identity, and hand it to
/// `submit_review`, whose own rules (an agent cannot approve its own work;
/// approval-gated orders need the master) still bind the web surface. Guarded
/// by the session token so a cross-origin page cannot drive it and so the
/// verdict is attributable to the human who signed in.
async fn review_task(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<Value>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;

    let task = ferryman_channel::read_task(&route, &id).map_err(internal)?;
    let revision = task.latest_revision().ok_or((
        StatusCode::CONFLICT,
        "there is no result to review yet".to_string(),
    ))?;
    if body.accept
        && let Some(missing) = task.contract_violations_in(&with_current_roster(&route))
        && !missing.is_empty()
    {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "result does not satisfy the order's contract: {}",
                missing.join("; ")
            ),
        ));
    }

    let mut verdict = ferryman_channel::Review {
        order_id: id.clone(),
        revision,
        reviewer: identity.name().to_string(),
        reviewed_at: chrono::Utc::now(),
        accepted: body.accept,
        notes: body.notes.clone(),
        signed_by: None,
        signature: None,
    };
    identity.sign_review(&mut verdict);
    let path = ferryman_channel::submit_review(&route, &verdict)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({
        "order_id": id,
        "revision": revision,
        "accepted": body.accept,
        "reviewer": verdict.reviewer,
        "path": path.display().to_string(),
    })))
}

/// GET / — the single-page app, with the project id and mode injected so the
/// browser knows how to behave. The session token is never embedded: it only
/// exists after the operator signs in, and it stays in the tab's memory.
async fn index(State(state): State<DashboardState>) -> Html<String> {
    let html = DASHBOARD_HTML
        .replace("__PROJECT__", &state.route.project_id)
        .replace(
            "__READONLY__",
            if state.read_only { "true" } else { "false" },
        )
        .replace(
            "__ANY_OPERATORS__",
            if state.operators.any() {
                "true"
            } else {
                "false"
            },
        );
    Html(html)
}

/// JSON representation of a task state. The shape is intentionally flat and
/// strings are used for state names so the dashboard stays stable as the
/// channel's internal types evolve.
fn state_value(state: &TaskState) -> Value {
    match state {
        TaskState::Open => json!({ "status": "open" }),
        TaskState::Offered { to } => json!({ "status": "offered", "to": to }),
        TaskState::Claimed { by } => json!({ "status": "claimed", "by": by }),
        TaskState::Stale { by, since } => {
            json!({ "status": "stale", "by": by, "since": since.to_rfc3339() })
        }
        TaskState::AwaitingReview { by, revision } => {
            json!({ "status": "awaiting_review", "by": by, "revision": revision })
        }
        TaskState::ChangesRequested { revision } => {
            json!({ "status": "changes_requested", "revision": revision })
        }
        TaskState::Accepted => json!({ "status": "accepted" }),
        TaskState::Done => json!({ "status": "done" }),
        TaskState::Refuted { by, revision } => {
            json!({ "status": "refuted", "by": by, "revision": revision })
        }
        TaskState::Killed { by, at } => {
            json!({ "status": "killed", "by": by, "at": at.to_rfc3339() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use chrono::Utc;
    use ferryman_channel::{AgentRoute, Order, TaskResult};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn order(id: &str) -> Order {
        Order {
            id: id.to_string(),
            project_id: "ferryman".to_string(),
            issued_by: "orchestrator".to_string(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "test": true }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            allow_overlap: false,
        }
    }

    fn state(route: &Arc<ProjectRoute>, read_only: bool) -> DashboardState {
        DashboardState::new(
            route.clone(),
            crate::operators::test_store(&route.attachment),
            read_only,
            Duration::from_secs(900),
        )
    }

    /// A session-carrying GET, decoded. Every read endpoint is behind the session guard,
    /// so a test that forgets the header gets a 401 and an unhelpful panic.
    async fn get_json(app: &Router, uri: &str, token: Option<&str>) -> Value {
        let mut builder = Request::builder().uri(uri);
        if let Some(token) = token {
            builder = builder.header("x-ferryman-dashboard-token", token);
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    async fn post(
        app: &Router,
        uri: &str,
        body: &str,
        token: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-ferryman-dashboard-token", token);
        }
        app.clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    /// POST carrying the one-time setup token, for bootstrap paths.
    async fn post_with_setup(
        app: &Router,
        uri: &str,
        body: &str,
        setup: &str,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("x-ferryman-dashboard-setup", setup)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Sign in and return the session token, for tests that are about something else.
    async fn signed_in(app: &Router, state: &DashboardState) -> String {
        state.operators.create("alice", "hunter2-secret").unwrap();
        let response = post(
            app,
            "/api/auth/login",
            r#"{"name":"alice","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "test sign-in must work");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        value["token"].as_str().unwrap().to_string()
    }

    /// Every endpoint that is not on `PUBLIC_PATHS` refuses an anonymous caller.
    ///
    /// This is the test that did not exist. Authentication was per-handler and three
    /// handlers out of seventeen had it, so the fleet - order payloads, worker output, the
    /// memory bank, the ledger, and every device's operator email - answered anyone who
    /// could reach the port. Two tests actively asserted that anonymous reads returned
    /// `200`, which is how a hole stays open through a green suite.
    ///
    /// Written as a loop over the real route list rather than one case, so adding a route
    /// without opening it deliberately cannot regress this.
    #[tokio::test]
    async fn every_non_public_endpoint_refuses_an_anonymous_caller() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        ferryman_channel::issue_order(&route, &order("task-1")).unwrap();
        let app = router(state(&route, false));

        for path in [
            "/api/auth/whoami",
            "/api/team",
            "/api/tasks",
            "/api/tasks/task-1",
            "/api/stats",
            "/api/ledger",
            "/api/learnings",
            "/api/roster",
            "/api/fleet",
            "/api/memory",
            "/api/cost/rates",
            "/api/improve",
            "/api/engine-policy",
            "/api/engine-policy/team",
            "/api/improve/pending",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must require a session"
            );
        }

        // The write endpoints too, including the one that used to invent the author name
        // `"operator"` for an unauthenticated caller and append it to the SYNCED memory
        // bank - an anonymous write into the context every agent on every machine reads.
        for (path, body) in [
            ("/api/tasks/task-1/review", r#"{"accept":true}"#),
            ("/api/memory/suggest", r#"{"text":"anonymous"}"#),
            ("/api/cost/plan", r#"{"goal":"x"}"#),
            ("/api/engine-policy/team", "{}"),
            ("/api/engine-policy/settings", r#"{"width":{"build":9}}"#),
        ] {
            let response = post(&app, path, body, None).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must require a session"
            );
        }

        // And the page itself must stay reachable, or there is nowhere to sign in from.
        let index = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(index.status(), StatusCode::OK, "the sign-in page is public");
    }

    /// A read-only dashboard must still be openable.
    ///
    /// Requiring a session on reads while `--read-only` refused sign-in would have made
    /// the flag mean "unusable" rather than "cannot write". This is the assertion that
    /// stops the two rules being reintroduced in isolation from each other.
    #[tokio::test]
    async fn a_read_only_dashboard_can_still_be_signed_into_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        ferryman_channel::issue_order(&route, &order("task-1")).unwrap();

        // The operator is created out of band, as `ferry enable --dashboard` does: a
        // read-only dashboard still refuses to create one over HTTP.
        let state = state(&route, true);
        state.operators.create("alice", "hunter2-secret").unwrap();
        let app = router(state);

        let login = post(
            &app,
            "/api/auth/login",
            r#"{"name":"alice","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(
            login.status(),
            StatusCode::OK,
            "read-only must not mean unopenable"
        );
        let body = login.into_body().collect().await.unwrap().to_bytes();
        let token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        let read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
                    .header("x-ferryman-dashboard-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK, "reads work when signed in");

        // Writing still does not.
        let write = post(
            &app,
            "/api/tasks/task-1/review",
            r#"{"accept":true}"#,
            Some(&token),
        )
        .await;
        assert_eq!(
            write.status(),
            StatusCode::FORBIDDEN,
            "read-only must still refuse a write"
        );
    }

    #[tokio::test]
    async fn api_team_separates_remote_humans_from_agents_without_inventing_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        ferryman_channel::register_expected_agent(&route, "john", "operator", &[]).unwrap();
        ferryman_channel::register_expected_agent(&route, "builder", "worker", &[]).unwrap();

        let state = state(&route, false);
        let app = router(state.clone());
        let token = signed_in(&app, &state).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/team")
                    .header("x-ferryman-dashboard-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let team: Value = serde_json::from_slice(&body).unwrap();
        let teammates = team["teammates"].as_array().unwrap();
        let agents = team["agents"].as_array().unwrap();
        assert!(teammates.iter().any(|person| person["name"] == "alice"));
        assert!(
            teammates
                .iter()
                .any(|person| { person["name"] == "john" && person["scope"] == "channel" })
        );
        assert!(!agents.iter().any(|agent| agent["name"] == "john"));
        let builder = agents
            .iter()
            .find(|agent| agent["name"] == "builder")
            .expect("worker appears as an agent");
        assert!(builder["owner"].is_null());
        assert_eq!(builder["access"], "unconfigured");
    }

    #[tokio::test]
    async fn api_tasks_lists_channel_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        ferryman_channel::issue_order(&route, &order("task-1")).unwrap();
        ferryman_channel::claim_order(&route, "task-1", "alice").unwrap();

        let state = state(&route, false);
        let app = router(state.clone());
        let token = signed_in(&app, &state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
                    .header("x-ferryman-dashboard-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let tasks: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["id"], "task-1");
        assert_eq!(tasks[0]["holder"], "alice");
        assert_eq!(tasks[0]["result_count"], 0);
        assert_eq!(tasks[0]["state"]["status"], "claimed");
        assert_eq!(tasks[0]["state"]["by"], "alice");
    }

    /// A named host gets in; everything else still does not.
    ///
    /// The point of naming them rather than switching the guard off: a rebinding attacker
    /// controls the `Host` header, so "allow any host" would hand them the fleet. They
    /// cannot make the operator type their domain into `--allow-host`.
    #[test]
    fn only_hosts_the_operator_named_are_admitted_beyond_loopback() {
        allow_hosts(vec![
            "beastly.tail1234.ts.net".into(),
            "  FLEET.example  ".into(),
        ]);

        // Loopback, always.
        assert!(host_is_allowed("127.0.0.1"));
        assert!(host_is_allowed("localhost"));

        // The names the operator gave, case- and space-insensitively.
        assert!(host_is_allowed("beastly.tail1234.ts.net"));
        assert!(host_is_allowed("BEASTLY.tail1234.TS.NET"));
        assert!(host_is_allowed("fleet.example"));

        // And nothing else - including the rebinding shapes.
        assert!(!host_is_allowed("attacker.example"));
        assert!(!host_is_allowed("127.0.0.1.evil.com"));
        assert!(!host_is_allowed("beastly.tail1234.ts.net.evil.com"));
        assert!(!host_is_allowed("evil.beastly.tail1234.ts.net"));
    }

    /// The cases a prefix test gets wrong.
    ///
    /// The bug this replaces passed every test that existed, because the only hostile
    /// input tried was `attacker.example` - a name that looks nothing like a loopback
    /// address. The bypass looks exactly like one. That asymmetry is the lesson: a guard
    /// is only tested by inputs shaped like the thing it is meant to let through.
    #[test]
    fn a_hostname_that_merely_starts_with_a_loopback_address_is_not_loopback() {
        for hostile in [
            // The bypass. A registrable domain, prefixed to look local.
            "127.0.0.1.evil.com",
            "127.0.0.1.nip.io",
            // Same trick without the dot boundary.
            "127.0.0.1evil.com",
            // The other half of the old test: a plain name is not a loopback address.
            "attacker.example",
            "localhost.evil.com",
            "notlocalhost",
            // Neither is a public address that happens to be near the range.
            "128.0.0.1",
            "12.7.0.1",
            // Or an empty header.
            "",
        ] {
            assert!(
                !is_loopback_host(hostile),
                "{hostile} must not be treated as loopback"
            );
        }

        for genuine in [
            "127.0.0.1",
            // The rest of 127.0.0.0/8, which the prefix test did get right and which a
            // naive equality-only fix would break.
            "127.0.0.2",
            "127.1.2.3",
            "localhost",
            "LocalHost",
            "::1",
            // The v6 loopback written out, which no string test would ever have matched.
            "0:0:0:0:0:0:0:1",
        ] {
            assert!(is_loopback_host(genuine), "{genuine} is loopback");
        }
    }

    #[tokio::test]
    async fn rejects_a_non_loopback_host_header() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let app = router(state(&route, false));

        // Aimed at a PUBLIC path on purpose. The point is to prove the Host guard alone
        // decides these two outcomes: against an authenticated path, a 403 would be
        // indistinguishable from the session layer's 401 and the test would pass whether
        // or not the guard existed.
        //
        // It also pins the layer ORDER. The guard is the outer layer, so a rebinding
        // attempt is refused before its credentials are examined at all - a 401 here would
        // mean the session check ran first and told an origin we should not be talking to
        // that it merely needed to sign in.
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);

        // The bypass this guard was rewritten for: a registrable domain prefixed to look
        // local. It must be refused exactly like any other foreign host.
        let rebound = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "127.0.0.1.evil.com:8788")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rebound.status(), StatusCode::FORBIDDEN);

        // A genuine loopback request (and one with no Host at all) still works.
        let good = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "127.0.0.1:8788")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(good.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_create_publishes_the_identity_to_the_roster() {
        let dir = tempfile::tempdir().unwrap();
        // Keep the machine-wide fleet roster inside the tempdir, so this test
        // does not publish a random key into the real operator's fleet dir.
        // Per-thread, not the plain override: the plain one is FIRST CALL WINS, so with
        // four tests each asking for their own directory, three of them silently got the
        // first one's - already populated, with an operator in it. Whether a test that
        // needs a virgin machine passed came down to which test the scheduler started
        // first. It won that race on one maintainer's machine and lost it on CI, and the
        // suite was red on every platform for weeks while passing locally.
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));
        let state = state(&route, false);
        let setup = state
            .bootstrap_token()
            .expect("a store with no operators mints a setup token");
        let app = router(state);

        // Without the token, no operator can be created - the hole this closes. Anyone who
        // could reach the port used to get a roster identity the whole fleet trusts.
        let refused = post(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(
            refused.status(),
            StatusCode::UNAUTHORIZED,
            "creating the first operator must need the terminal's setup token"
        );

        // A wrong token is no better than none.
        let wrong = post_with_setup(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            &"0".repeat(setup.len()),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let created = post_with_setup(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            &setup,
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK);

        // The public half is published to the project channel exactly like a
        // joining agent, so the operator's reviews will verify.
        let roster_file = route.communications.join("agents").join("operator1.json");
        assert!(roster_file.exists(), "roster entry should exist");
        let entry: AgentRoute =
            serde_json::from_str(&std::fs::read_to_string(&roster_file).unwrap()).unwrap();
        assert_eq!(entry.name, "operator1");
        assert!(entry.public_key.is_some());

        // Single-use: the same token cannot mint a second operator. Otherwise a token that
        // leaked from a scrollback would stay a standing key to the fleet.
        let replayed = post_with_setup(
            &app,
            "/api/auth/create",
            r#"{"name":"operator2","password":"hunter2-secret"}"#,
            &setup,
        )
        .await;
        assert_eq!(
            replayed.status(),
            StatusCode::UNAUTHORIZED,
            "the setup token must be consumed by its first use"
        );

        // And with an operator now in place, creating another is an authenticated action.
        let second = post(
            &app,
            "/api/auth/create",
            r#"{"name":"operator2","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);

        // The same name cannot be created again - checked through the authenticated path,
        // since the bootstrap route is now closed.
        let login = post(
            &app,
            "/api/auth/login",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);
        let body = login.into_body().collect().await.unwrap().to_bytes();
        let token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        let dup = post(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(dup.status(), StatusCode::CONFLICT);
    }

    /// The first-run create path creates the machine seed, returns its phrase exactly once,
    /// and the operator it mints is the seed's operator identity (ADR 0016).
    #[tokio::test]
    async fn first_run_create_returns_a_phrase_and_derives_from_the_seed() {
        let dir = tempfile::tempdir().unwrap();
        // Per-thread, not the plain override: the plain one is FIRST CALL WINS, so with
        // four tests each asking for their own directory, three of them silently got the
        // first one's - already populated, with an operator in it. Whether a test that
        // needs a virgin machine passed came down to which test the scheduler started
        // first. It won that race on one maintainer's machine and lost it on CI, and the
        // suite was red on every platform for weeks while passing locally.
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));
        let state = state(&route, false);
        let setup = state
            .bootstrap_token()
            .expect("no operators -> setup token");
        let app = router(state);

        let created = post_with_setup(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            &setup,
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK);
        let body = created.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();

        // The phrase is returned once, on the request that created the seed.
        let phrase = value["phrase"]
            .as_str()
            .expect("the first operator creation returns the recovery phrase");
        assert_eq!(phrase.split_whitespace().count(), 24);

        // The operator's key is the seed's operator fingerprint - not a second random key.
        let seed = ferryman_channel::seed::OperatorSeed::load(&route.attachment.join("machine"))
            .unwrap()
            .expect("the first run wrote a seed");
        assert_eq!(
            value["fingerprint"].as_str().unwrap(),
            seed.operator_identity_for("operator1")
                .unwrap()
                .public_key_hex()
        );

        // And the phrase round-trips to exactly that seed.
        assert_eq!(
            ferryman_channel::seed::phrase_to_seed(phrase).unwrap(),
            seed.expose_bytes()
        );
    }

    /// Every route the router serves is in the published OpenAPI spec.
    ///
    /// The spec had eleven paths while the router had thirty-one. Twenty endpoints -
    /// including everything that approves a release, grants a teammate access, or writes
    /// a secret - existed and were undocumented, and nothing anywhere would ever have
    /// said so. A spec that drifts silently is worse than no spec: it is consulted, and
    /// it is wrong.
    ///
    /// Reading the source rather than the router because axum's `Router` does not expose
    /// its paths. Crude, and it holds: a route added without a line in the spec fails
    /// here, which is the whole job.
    #[test]
    fn every_route_is_in_the_openapi_spec() {
        const SOURCE: &str = include_str!("dashboard.rs");
        const SPEC: &str = include_str!("../../../openapi/dashboard.yaml");

        let mut missing = Vec::new();
        for line in SOURCE.lines() {
            let Some(rest) = line.trim().strip_prefix(".route(\"") else {
                continue;
            };
            let Some(path) = rest.split('"').next() else {
                continue;
            };
            // The dashboard page itself is not an API endpoint.
            if path == "/" {
                continue;
            }
            if !SPEC.contains(&format!("\n  {path}:")) {
                missing.push(path.to_string());
            }
        }
        assert!(
            missing.is_empty(),
            "these routes are served but absent from openapi/dashboard.yaml: {missing:#?}"
        );
    }

    /// Recovering a name the CHANNEL already publishes needs no console token, because
    /// the phrase has to derive that exact published key - which only its owner can do.
    ///
    /// The token still guards creating a new name out of nothing, and the test below this
    /// one holds that line. This is the day somebody has lost their identity and is
    /// holding the one thing that restores it; if the dashboard runs as a service, or in
    /// a window they never saw, demanding a console secret strands them for no gain.
    #[tokio::test]
    async fn a_published_identity_is_recovered_by_its_phrase_alone() {
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));

        // The channel knows this operator: their public key is in the roster, exactly as
        // it would be after they set themselves up on a machine that has since lost the
        // sealed half.
        let seed_bytes = [0x5b; 32];
        let seed = ferryman_channel::seed::OperatorSeed::from_bytes(seed_bytes);
        let published = seed.operator_identity_for("josh").unwrap();
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "josh".into(),
                role: "operator".into(),
                capabilities: vec!["messages.receive".into()],
                public_key: Some(published.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();

        let state = state(&route, false);
        assert_eq!(
            state.orphaned_operators(),
            vec!["josh".to_string()],
            "the channel knows josh and this machine does not - that is the whole situation"
        );
        let app = router(state);

        let phrase = ferryman_channel::seed::seed_to_phrase(seed_bytes).unwrap();
        let recovered = post(
            &app,
            "/api/auth/recover",
            &serde_json::json!({
                "phrase": phrase,
                "name": "josh",
                "password": "hunter2-secret",
            })
            .to_string(),
            None, // no session, and deliberately no setup token
        )
        .await;
        assert_eq!(
            recovered.status(),
            StatusCode::OK,
            "the phrase derives the published key, which is proof enough"
        );
        let body = recovered.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["fingerprint"].as_str().unwrap(),
            published.public_key_hex(),
            "recovery must reconstruct the SAME key, or every past signature reads as forged"
        );
    }

    /// The other half: a phrase that reconstructs nothing this channel publishes is
    /// creating a new identity, whatever it is called, and still needs the token.
    ///
    /// Without this the gate would be gone entirely - anyone reaching the port could pick
    /// their own phrase, seed the machine, and be an operator of a fleet they were never
    /// let into.
    #[tokio::test]
    async fn a_phrase_for_an_unknown_name_still_needs_the_setup_token() {
        let dir = tempfile::tempdir().unwrap();
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));
        let seed_bytes = [0x5b; 32];
        let seed = ferryman_channel::seed::OperatorSeed::from_bytes(seed_bytes);
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "josh".into(),
                role: "operator".into(),
                capabilities: vec!["messages.receive".into()],
                public_key: Some(seed.operator_identity_for("josh").unwrap().public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        let app = router(state(&route, false));

        // An attacker's own phrase, under a name nobody has published.
        let mine = ferryman_channel::seed::seed_to_phrase([0x11; 32]).unwrap();
        let refused = post(
            &app,
            "/api/auth/recover",
            &serde_json::json!({
                "phrase": mine,
                "name": "intruder",
                "password": "hunter2-secret",
            })
            .to_string(),
            None,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

        // And the right phrase under the WRONG name is not a shortcut either: the name is
        // part of the derivation, so it derives a different key and proves nothing.
        let right_phrase_wrong_name = post(
            &app,
            "/api/auth/recover",
            &serde_json::json!({
                "phrase": ferryman_channel::seed::seed_to_phrase(seed_bytes).unwrap(),
                "name": "someone-else",
                "password": "hunter2-secret",
            })
            .to_string(),
            None,
        )
        .await;
        assert_eq!(right_phrase_wrong_name.status(), StatusCode::UNAUTHORIZED);
    }

    /// Recovery pastes the 24 words on a new machine and restores the same identity, and a
    /// second, different phrase is refused rather than silently re-keying the machine.
    #[tokio::test]
    async fn recovery_restores_the_identity_from_the_phrase() {
        let dir = tempfile::tempdir().unwrap();
        // Per-thread, not the plain override: the plain one is FIRST CALL WINS, so with
        // four tests each asking for their own directory, three of them silently got the
        // first one's - already populated, with an operator in it. Whether a test that
        // needs a virgin machine passed came down to which test the scheduler started
        // first. It won that race on one maintainer's machine and lost it on CI, and the
        // suite was red on every platform for weeks while passing locally.
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));
        let state = state(&route, false);
        let setup = state
            .bootstrap_token()
            .expect("no operators -> setup token");
        let app = router(state);

        let seed_bytes = [0x2a; 32];
        let phrase = ferryman_channel::seed::seed_to_phrase(seed_bytes).unwrap();

        // A phrase is not a credential: on a machine with no seed the caller chooses it.
        // Recovery is the same act as creation and carries the same gate.
        let unauthorised = post(
            &app,
            "/api/auth/recover",
            &serde_json::json!({
                "phrase": phrase,
                "name": "intruder",
                "password": "hunter2-secret",
            })
            .to_string(),
            None,
        )
        .await;
        assert_eq!(
            unauthorised.status(),
            StatusCode::UNAUTHORIZED,
            "recovery without the console token must not seed the machine"
        );

        let recovered = post_with_setup(
            &app,
            "/api/auth/recover",
            &serde_json::json!({
                "phrase": phrase,
                "name": "operator1",
                "password": "hunter2-secret",
            })
            .to_string(),
            &setup,
        )
        .await;
        assert_eq!(recovered.status(), StatusCode::OK);
        let body = recovered.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();

        let seed = ferryman_channel::seed::OperatorSeed::load(&route.attachment.join("machine"))
            .unwrap()
            .expect("recovery wrote the seed");
        assert_eq!(seed.expose_bytes(), seed_bytes);
        assert_eq!(
            value["fingerprint"].as_str().unwrap(),
            seed.operator_identity_for("operator1")
                .unwrap()
                .public_key_hex()
        );

        // A different phrase must not replace the seed that was just restored - checked
        // through the authenticated path, since the bootstrap token is now spent.
        let login = post(
            &app,
            "/api/auth/login",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);
        let body = login.into_body().collect().await.unwrap().to_bytes();
        let token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        let other = ferryman_channel::seed::seed_to_phrase([0x33; 32]).unwrap();
        let conflict = post(
            &app,
            "/api/auth/recover",
            &serde_json::json!({
                "phrase": other,
                "name": "operator2",
                "password": "hunter2-secret",
            })
            .to_string(),
            Some(&token),
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
    }

    /// Two operators created through the dashboard on one machine must not share a key.
    ///
    /// The end-to-end shape of the derivation regression: both were published to the
    /// roster, under two names, carrying one public key.
    #[tokio::test]
    async fn two_dashboard_operators_do_not_share_a_key() {
        let dir = tempfile::tempdir().unwrap();
        // Per-thread, not the plain override: the plain one is FIRST CALL WINS, so with
        // four tests each asking for their own directory, three of them silently got the
        // first one's - already populated, with an operator in it. Whether a test that
        // needs a virgin machine passed came down to which test the scheduler started
        // first. It won that race on one maintainer's machine and lost it on CI, and the
        // suite was red on every platform for weeks while passing locally.
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));
        let state = state(&route, false);
        let setup = state
            .bootstrap_token()
            .expect("no operators -> setup token");
        let app = router(state);

        let first = post_with_setup(
            &app,
            "/api/auth/create",
            r#"{"name":"ada","password":"hunter2-secret"}"#,
            &setup,
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let body = first.into_body().collect().await.unwrap().to_bytes();
        let first: Value = serde_json::from_slice(&body).unwrap();
        let token = first["token"].as_str().unwrap().to_string();

        let second = post(
            &app,
            "/api/auth/create",
            r#"{"name":"grace","password":"another-secret"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
        let body = second.into_body().collect().await.unwrap().to_bytes();
        let second: Value = serde_json::from_slice(&body).unwrap();

        assert_ne!(
            first["public_key"].as_str().unwrap(),
            second["public_key"].as_str().unwrap(),
            "two operators on one machine must not publish one key under two names"
        );
    }

    #[tokio::test]
    async fn login_is_rate_limited_per_operator_name() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let app = router(state(&route, false));

        // Five attempts are allowed; the sixth is refused. The operator does
        // not exist, so the first five 401 and the sixth is a 429.
        for _ in 0..5 {
            let response = post(
                &app,
                "/api/auth/login",
                r#"{"name":"alice","password":"wrong"}"#,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let limited = post(
            &app,
            "/api/auth/login",
            r#"{"name":"alice","password":"wrong"}"#,
            None,
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different operator name is not locked out by alice's failures.
        let other = post(
            &app,
            "/api/auth/login",
            r#"{"name":"bob","password":"wrong"}"#,
            None,
        )
        .await;
        assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn review_requires_a_session_and_signs_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        // The channel verifies signatures at read time, so the result and the
        // verdict must both be signed by identities whose public keys the roster
        // knows. The worker is minted from a fixed seed; the operator comes from
        // the password-sealed operator store.
        let alice = AgentIdentity::from_seed("alice", [1u8; 32]);

        let mut route = test_route(dir.path());
        let reviewer = crate::operators::test_store(&route.attachment)
            .create("reviewer", "hunter2-secret")
            .unwrap();
        route.agents.push(AgentRoute {
            name: "alice".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(alice.public_key_hex()),
            encryption_key: None,
        });
        route.agents.push(AgentRoute {
            name: "reviewer".into(),
            role: "master".into(),
            capabilities: Vec::new(),
            public_key: Some(reviewer.public_key_hex()),
            encryption_key: None,
        });
        let route = Arc::new(route);

        ferryman_channel::issue_order(&route, &order("task-1")).unwrap();
        ferryman_channel::claim_order(&route, "task-1", "alice").unwrap();
        let mut result = TaskResult {
            order_id: "task-1".into(),
            agent: "alice".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "done" }),
            signed_by: None,
            signature: None,
        };
        alice.sign_result(&mut result);
        ferryman_channel::submit_result(&route, &result).unwrap();

        let app = router(state(&route, false));

        // Signing in yields a session token.
        let login = post(
            &app,
            "/api/auth/login",
            r#"{"name":"reviewer","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);
        let body = login.into_body().collect().await.unwrap().to_bytes();
        let login: Value = serde_json::from_slice(&body).unwrap();
        let token = login["token"].as_str().unwrap();

        // Without a token, and with a bogus one, the review is refused.
        let denied = post(&app, "/api/tasks/task-1/review", r#"{"accept":true}"#, None).await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let denied = post(
            &app,
            "/api/tasks/task-1/review",
            r#"{"accept":true}"#,
            Some("bogus"),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        // With the token, the review lands signed by the operator.
        let accepted = post(
            &app,
            "/api/tasks/task-1/review",
            r#"{"accept":true}"#,
            Some(token),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK, "body: {:?}", {
            let body = accepted.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8_lossy(&body).to_string()
        });

        let task = ferryman_channel::read_task(&route, "task-1").unwrap();
        assert_eq!(task.reviews.len(), 1);
        assert!(task.reviews[0].accepted);
        assert_eq!(task.reviews[0].reviewer, "reviewer");
        assert!(
            task.reviews[0].signature.is_some(),
            "the verdict must be signed"
        );
    }

    /// The engine policy from the browser: auto until the master signs one, what auto
    /// recommends and why, accept and edit for the master only, and back to auto.
    #[tokio::test]
    async fn only_the_master_sets_the_engine_policy_from_the_browser() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;

        let before = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(before["auto"], true, "{before}");
        assert_eq!(before["may_set"], false, "nobody is master yet");
        assert_eq!(before["policy"]["protect_subscriptions"], true);
        assert!(before["recommended"]["reasons"].is_array(), "{before}");
        let refused = post(&app, "/api/engine-policy/accept", "{}", Some(&token)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "not the master");

        let claimed = post(&app, "/api/master/init", "{}", Some(&token)).await;
        assert_eq!(claimed.status(), StatusCode::OK);
        let accepted = post(&app, "/api/engine-policy/accept", "{}", Some(&token)).await;
        assert_eq!(accepted.status(), StatusCode::OK);
        let after = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(after["auto"], false, "{after}");
        assert_eq!(after["may_set"], true);
        assert_eq!(after["set_by"], "alice");

        let edit = r#"{"policy":{"prefer":{"build":["nemotron","deepseek"]},"never":["claude"],"where":["grouchly"]}}"#;
        let set = post(&app, "/api/engine-policy", edit, Some(&token)).await;
        assert_eq!(set.status(), StatusCode::OK);
        let (policy, setting) =
            ferryman_channel::policy::effective(&route.communications, &route.project_id);
        assert_eq!(setting.unwrap().set_by(), "alice");
        assert_eq!(policy.never, ["claude"]);
        assert_eq!(policy.machines, ["grouchly"]);
        assert!(policy.protect_subscriptions, "on unless said otherwise");
        assert_eq!(
            policy.preferences(ferryman_channel::policy::Role::Build),
            ["nemotron", "deepseek"]
        );
        let nonsense = post(
            &app,
            "/api/engine-policy",
            r#"{"policy":{"prefer":{"dance":["x"]}}}"#,
            Some(&token),
        )
        .await;
        assert_eq!(nonsense.status(), StatusCode::BAD_REQUEST);

        let cleared = post(
            &app,
            "/api/engine-policy",
            r#"{"policy":null}"#,
            Some(&token),
        )
        .await;
        assert_eq!(cleared.status(), StatusCode::OK);
        let back = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(back["auto"], true, "{back}");
    }

    /// The team preset from the browser: proposed with reasons to anyone signed in,
    /// tried with other widths, efforts and subscription roles, signed only by the master;
    /// and effort, width and subscription roles set one role at a time.
    #[tokio::test]
    async fn the_team_preset_and_the_per_role_settings_are_signed_only_by_the_master() {
        use ferryman_channel::policy::{Effort, Role};
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;

        let view = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(view["team"]["policy"]["effort"]["plan"], "high", "{view}");
        assert_eq!(view["team"]["policy"]["width"]["build"], 3);
        assert_eq!(view["team"]["policy"]["width"]["chore"], 4);
        assert!(view["team"]["reasons"].is_array(), "{view}");
        assert_eq!(view["effective"]["roles"]["build"]["effort"], "medium");
        assert_eq!(view["effective"]["roles"]["chore"]["effort"], "low");
        assert_eq!(view["warnings"].as_array().unwrap().len(), 0);

        // Other choices, tried without signing anything.
        let tried = get_json(
            &app,
            "/api/engine-policy/team?width=build=5&effort=build:high&subscription_roles=build,chore",
            Some(&token),
        )
        .await;
        assert_eq!(tried["policy"]["width"]["build"], 5, "{tried}");
        assert_eq!(tried["policy"]["effort"]["build"], "high");
        assert_eq!(
            tried["policy"]["subscription_roles"],
            json!(["build", "chore"])
        );
        assert!(
            tried["warnings"][0]
                .as_str()
                .unwrap()
                .contains("weekly_requests"),
            "no capped subscription is published: {tried}"
        );
        for bad in [
            "width=build=0",
            "width=build=lots",
            "effort=build=extreme",
            "subscription_roles=builder",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/engine-policy/team?{bad}"))
                        .header("x-ferryman-dashboard-token", &token)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
        }
        assert!(
            ferryman_channel::policy::setting(&route.communications, &route.project_id).is_none(),
            "proposing signs nothing"
        );

        // Nobody is master yet: refused.
        let team_body = r#"{"width":{"build":4},"subscription_roles":["build"]}"#;
        let refused = post(&app, "/api/engine-policy/team", team_body, Some(&token)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let refused = post(
            &app,
            "/api/engine-policy/settings",
            r#"{"effort":{"build":"high"}}"#,
            Some(&token),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let claimed = post(&app, "/api/master/init", "{}", Some(&token)).await;
        assert_eq!(claimed.status(), StatusCode::OK);
        let zero = post(
            &app,
            "/api/engine-policy/team",
            r#"{"width":{"build":0}}"#,
            Some(&token),
        )
        .await;
        assert_eq!(zero.status(), StatusCode::BAD_REQUEST);
        let signed = post(&app, "/api/engine-policy/team", team_body, Some(&token)).await;
        assert_eq!(signed.status(), StatusCode::OK);
        let (policy, setting) =
            ferryman_channel::policy::effective(&route.communications, &route.project_id);
        assert_eq!(setting.unwrap().set_by(), "alice");
        assert_eq!(policy.width_for(Role::Build), Some(4));
        assert_eq!(policy.width_for(Role::Chore), Some(4));
        assert_eq!(policy.effort_for(Role::Plan), Effort::High);
        assert_eq!(policy.subscription_roles, [Role::Build]);

        // Per-role settings change only what they name.
        let set = post(
            &app,
            "/api/engine-policy/settings",
            r#"{"effort":{"chore":"medium"},"width":{"build":null,"plan":2},"subscription_roles":[]}"#,
            Some(&token),
        )
        .await;
        assert_eq!(set.status(), StatusCode::OK);
        let (policy, _) =
            ferryman_channel::policy::effective(&route.communications, &route.project_id);
        assert_eq!(policy.effort_for(Role::Chore), Effort::Medium);
        assert_eq!(policy.effort_for(Role::Plan), Effort::High, "kept");
        assert_eq!(policy.width_for(Role::Build), None, "null removes the cap");
        assert_eq!(policy.width_for(Role::Plan), Some(2));
        assert_eq!(policy.width_for(Role::Chore), Some(4), "kept");
        assert!(policy.subscription_roles.is_empty());
        for bad in [
            "{}",
            r#"{"width":{"build":0}}"#,
            r#"{"effort":{"build":"extreme"}}"#,
            r#"{"width":{"builder":2}}"#,
        ] {
            let response = post(&app, "/api/engine-policy/settings", bad, Some(&token)).await;
            assert!(
                response.status().is_client_error(),
                "{bad}: {}",
                response.status()
            );
        }
        let view = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(view["effective"]["roles"]["plan"]["width"], 2, "{view}");
    }

    /// The simple choice from the browser, and the improvements waiting for the master:
    /// approving one the review engine has not reviewed is refused.
    #[tokio::test]
    async fn the_master_picks_engines_and_cannot_approve_before_the_review_engine() {
        let dir = tempfile::tempdir().unwrap();
        // The worker is on the route's roster, so its signed result is read.
        let wisp = ferryman_channel::AgentIdentity::from_seed("wisp", [5; 32]);
        let mut known = test_route(dir.path());
        known.agents.push(ferryman_channel::AgentRoute {
            name: "wisp".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(wisp.public_key_hex()),
            encryption_key: None,
        });
        let route = Arc::new(known);
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;
        // alice, signed in, is the channel's master, by the key her session signs with.
        let alice = dashboard_state.sessions.resolve(&token).unwrap();
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "alice".into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(alice.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        ferryman_channel::master::initialize_master(&route, &alice, "alice").unwrap();

        let chosen = post(
            &app,
            "/api/engine-policy/choose",
            r#"{"improve":"name:nemotron","review":"name:deepseek"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(chosen.status(), StatusCode::OK);
        let view = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(
            view["choices"]["current"]["improve"], "name:nemotron",
            "{view}"
        );
        assert_eq!(view["choices"]["current"]["review"], "name:deepseek");
        let empty = post(&app, "/api/engine-policy/choose", "{}", Some(&token)).await;
        assert_eq!(empty.status(), StatusCode::BAD_REQUEST);

        let mut improvement = order("improve-2026-w40-1");
        improvement.payload = json!({ "task": "better", "tags": ["improvement"], "improvement": { "title": "Better errors" } });
        improvement.requires_review = true;
        ferryman_channel::issue_order(&route, &improvement).unwrap();
        ferryman_channel::claim_order(&route, "improve-2026-w40-1", "wisp").unwrap();
        let mut result = TaskResult {
            order_id: "improve-2026-w40-1".into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "done", "evidence": { "recorded_by": "worker", "git": true, "commits": ["abc1234 better"], "diff_stat": "2 files changed" } }),
            signed_by: None,
            signature: None,
        };
        wisp.sign_result(&mut result);
        ferryman_channel::submit_result(&route, &result).unwrap();

        let pending = get_json(&app, "/api/improve/pending", Some(&token)).await;
        assert_eq!(pending["may_decide"], true, "{pending}");
        let waiting = &pending["waiting"][0];
        assert_eq!(waiting["order_id"], "improve-2026-w40-1", "{pending}");
        assert_eq!(waiting["ready_for_you"], false);
        assert_eq!(waiting["diff_stat"], "2 files changed");

        let early = post(
            &app,
            "/api/improve/decide",
            r#"{"order":"improve-2026-w40-1","accept":true}"#,
            Some(&token),
        )
        .await;
        assert_eq!(early.status(), StatusCode::FORBIDDEN);
        let body = early.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).contains("review engine has not reviewed it"),
            "{}",
            String::from_utf8_lossy(&body)
        );
        let task = ferryman_channel::read_task(&route, "improve-2026-w40-1").unwrap();
        assert!(!ferryman_channel::gate::approved_for_live(&route, &task));
    }

    /// Self-improve is off until the master switches it on, from the browser, and
    /// nobody else can.
    #[tokio::test]
    async fn only_the_master_switches_self_improve_from_the_browser() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;

        let before = get_json(&app, "/api/improve", Some(&token)).await;
        assert_eq!(before["enabled"], false, "off by default: {before}");
        assert_eq!(before["may_set"], false, "nobody is master yet");

        let refused = post(&app, "/api/improve", r#"{"enabled":true}"#, Some(&token)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "not the master");

        let claimed = post(&app, "/api/master/init", "{}", Some(&token)).await;
        assert_eq!(claimed.status(), StatusCode::OK);
        let on = post(&app, "/api/improve", r#"{"enabled":true}"#, Some(&token)).await;
        assert_eq!(on.status(), StatusCode::OK);

        let after = get_json(&app, "/api/improve", Some(&token)).await;
        assert_eq!(after["enabled"], true, "{after}");
        assert_eq!(after["may_set"], true);
        assert_eq!(after["set_by"], "alice");
        assert!(ferryman_channel::ferry::self_improve_enabled(
            &route.communications,
            &route.project_id
        ));
    }

    /// The Contracts page: a proposed contract is listed with its shapes and the orders on
    /// each side, only the master can lock it, a locked contract cannot be decided again,
    /// and the order cards carry the interface, the files and the overlap warning.
    #[tokio::test]
    async fn the_master_locks_a_contract_from_the_browser_and_nobody_else_can() {
        use ferryman_channel::interface::{self, InterfaceRef, Side};
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;
        assert_eq!(
            post(&app, "/api/contracts/user-api@1/lock", "", None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&app, "/api/master/init", "{}", Some(&token))
                .await
                .status(),
            StatusCode::OK
        );
        let alice = dashboard_state.sessions.resolve(&token).unwrap();
        let fresh = with_current_roster(&route);

        // Nothing proposed: an empty page for the master, and honest 404 / 400s.
        let none = get_json(&app, "/api/contracts", Some(&token)).await;
        assert_eq!(none["contracts"].as_array().unwrap().len(), 0, "{none}");
        assert_eq!(none["may_decide"], true);
        assert_eq!(none["master"], "alice");
        assert_eq!(
            post(&app, "/api/contracts/user-api@1/lock", "", Some(&token))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post(&app, "/api/contracts/nonsense/lock", "", Some(&token))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let response = ferryman_channel::contract::Shape::parse(&json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "integer" } }
        }))
        .unwrap();
        interface::propose(
            &fresh,
            &alice,
            "user-api",
            "1",
            "GET /users/:id",
            None,
            response,
        )
        .unwrap();
        for (id, side, touches) in [
            ("t-api", Side::Provides, vec!["src/api/**"]),
            ("t-ui", Side::Consumes, vec!["src/**"]),
        ] {
            let mut order = order(id);
            order.issued_by = "alice".into();
            order.interface = Some(InterfaceRef {
                name: "user-api".into(),
                version: "1".into(),
                side,
            });
            order.touches = touches.into_iter().map(String::from).collect();
            alice.sign_order(&mut order);
            ferryman_channel::issue_order(&fresh, &order).unwrap();
        }
        ferryman_channel::hold::record(
            &fresh,
            &alice,
            "t-ui",
            "waiting for contract user-api@1 to be locked",
        )
        .unwrap();

        let page = get_json(&app, "/api/contracts", Some(&token)).await;
        let contract = &page["contracts"][0];
        assert_eq!(contract["reference"], "user-api@1", "{page}");
        assert_eq!(contract["status"], "proposed");
        assert_eq!(contract["proposed_by"], "alice");
        assert_eq!(contract["response"]["required"][0], "id");
        // The page names the contract by its digest, so a lock lands on what it showed.
        let digest = contract["digest"].as_str().unwrap().to_string();
        assert_eq!(
            digest,
            interface::current_digest(&fresh, "user-api", "1").unwrap(),
            "{page}"
        );
        assert_eq!(contract["finding_digest"], "none", "{page}");
        assert_eq!(contract["providers"][0]["id"], "t-api");
        assert_eq!(contract["consumers"][0]["id"], "t-ui");
        assert!(
            contract["consumers"][0]["holds"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("waiting for contract user-api@1"),
            "{page}"
        );

        // The order cards say what they build to, the files they touch, and who they
        // would collide with.
        let tasks = get_json(&app, "/api/tasks", Some(&token)).await;
        let card = |id: &str| -> Value {
            tasks
                .as_array()
                .unwrap()
                .iter()
                .find(|task| task["id"] == id)
                .cloned()
                .unwrap_or_else(|| panic!("no card for {id}: {tasks}"))
        };
        assert_eq!(card("t-api")["interface"]["side"], "provides");
        assert_eq!(card("t-ui")["touches"][0], "src/**");
        assert_eq!(card("t-api")["overlaps"][0]["order_id"], "t-ui", "{tasks}");
        assert_eq!(card("t-ui")["holds"][0]["agent"], "alice");
        let detail = get_json(&app, "/api/tasks/t-ui", Some(&token)).await;
        assert_eq!(detail["order"]["interface"]["name"], "user-api", "{detail}");
        assert_eq!(detail["overlaps"][0]["order_id"], "t-api");

        // Someone who is not the master gets a page without a button and a 403.
        dashboard_state
            .operators
            .create("bob", "bobs-secret-pass")
            .unwrap();
        let login = post(
            &app,
            "/api/auth/login",
            r#"{"name":"bob","password":"bobs-secret-pass"}"#,
            None,
        )
        .await;
        let body = login.into_body().collect().await.unwrap().to_bytes();
        let bob: Value = serde_json::from_slice(&body).unwrap();
        let bob = bob["token"].as_str().unwrap();
        let theirs = get_json(&app, "/api/contracts", Some(bob)).await;
        assert_eq!(theirs["may_decide"], false, "{theirs}");
        let named = json!({ "digest": digest }).to_string();
        assert_eq!(
            post(&app, "/api/contracts/user-api@1/lock", &named, Some(bob))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(&app, "/api/contracts/user-api@1/reject", "", Some(bob))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert!(interface::locked(&fresh, "user-api", "1").is_none());

        // The master locks it; the question that asked is answered; it cannot be decided
        // again, either way.
        // A lock that does not say what it locks is refused, and so is one that names a
        // contract that is not the one on screen; neither locks anything.
        let unnamed = post(&app, "/api/contracts/user-api@1/lock", "", Some(&token)).await;
        assert_eq!(unnamed.status(), StatusCode::BAD_REQUEST);
        let short = post(
            &app,
            "/api/contracts/user-api@1/lock",
            r#"{"digest":"abc"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(short.status(), StatusCode::BAD_REQUEST);
        let stale = post(
            &app,
            "/api/contracts/user-api@1/lock",
            r#"{"digest":"0000000000000000"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::FORBIDDEN);
        let body = stale.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).contains("changed since you looked"),
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(interface::locked(&fresh, "user-api", "1").is_none());
        let locked = post(&app, "/api/contracts/user-api@1/lock", &named, Some(&token)).await;
        assert_eq!(locked.status(), StatusCode::OK);
        assert!(interface::locked(&fresh, "user-api", "1").is_some());
        assert!(ferryman_channel::questions::pending(&fresh).is_empty());
        let page = get_json(&app, "/api/contracts", Some(&token)).await;
        assert_eq!(page["contracts"][0]["status"], "locked");
        assert_eq!(page["contracts"][0]["locked_by"], "alice");
        for verb in ["lock", "reject"] {
            assert_eq!(
                post(
                    &app,
                    &format!("/api/contracts/user-api@1/{verb}"),
                    "",
                    Some(&token)
                )
                .await
                .status(),
                StatusCode::CONFLICT,
                "{verb}"
            );
        }
    }

    /// The adversary from the browser: the policy choice sets its engine and mode, a Block
    /// is listed beside the contract, `blocking` refuses Lock until the master overrides
    /// (by the endpoint or in the same call), and `off` hides it all.
    #[tokio::test]
    async fn the_adversary_is_chosen_read_and_overridden_from_the_browser() {
        use ferryman_channel::adversary::{AdversaryFinding, Issue, Severity, Trigger, Verdict};
        use ferryman_channel::interface;
        let dir = tempfile::tempdir().unwrap();
        let wisp = ferryman_channel::AgentIdentity::from_seed("wisp", [5; 32]);
        let mut known = test_route(dir.path());
        known.agents.push(ferryman_channel::AgentRoute {
            name: "wisp".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(wisp.public_key_hex()),
            encryption_key: None,
        });
        let route = Arc::new(known);
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;
        // alice, signed in, is the channel's master, by the key her session signs with.
        let alice = dashboard_state.sessions.resolve(&token).unwrap();
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "alice".into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(alice.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        ferryman_channel::master::initialize_master(&route, &alice, "alice").unwrap();
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "wisp".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(wisp.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        let fresh = with_current_roster(&route);
        // What makes wisp an adversary whose word counts: a signed inventory that lists the
        // engine it challenged with.
        let publish_inventory = || {
            ferryman_channel::receipts::refresh_engines(
                &fresh,
                &wisp,
                "grouchly",
                "0.0.0",
                vec![ferryman_channel::receipts::EngineReport {
                    name: "deepseek".into(),
                    kind: "http".into(),
                    model: None,
                    tier: "judge".into(),
                    paid: "prepaid".into(),
                    state: "up".into(),
                    until: None,
                    reason: None,
                    latency_ms: None,
                    balance: None,
                    checked_at: None,
                    trust: None,
                    billing: None,
                    class: None,
                }],
                Utc::now(),
            )
            .unwrap();
        };
        let finding = |subject: &str| AdversaryFinding {
            order_id: subject.split('@').next().unwrap_or_default().to_string(),
            revision: 0,
            trigger: Trigger::ContractLock,
            subject: subject.to_string(),
            engine: "deepseek".into(),
            model: None,
            machine: "grouchly".into(),
            same_engine: false,
            verdict: Verdict::Block,
            findings: vec![Issue {
                severity: Severity::High,
                title: "the consumer reads `name`, the provider sends `username`".into(),
                detail: "the two halves disagree".into(),
                location: None,
            }],
            created_at: Utc::now(),
            result_digest: String::new(),
            signed_by: String::new(),
            signature: String::new(),
        };
        let propose = |version: &str| {
            let shape = ferryman_channel::contract::Shape::parse(&json!({
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "integer" } }
            }))
            .unwrap();
            interface::propose(&fresh, &alice, "user-api", version, "users", None, shape).unwrap();
        };

        // Advisory is the default; the choice sets the engine and the mode, and refuses a
        // mode that means nothing.
        let view = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(view["adversary_mode"], "advisory", "{view}");
        let nonsense = post(
            &app,
            "/api/engine-policy/choose",
            r#"{"adversary":"sometimes"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(nonsense.status(), StatusCode::BAD_REQUEST);
        let chosen = post(
            &app,
            "/api/engine-policy/choose",
            r#"{"adversary_engine":"name:deepseek","adversary":"blocking"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(chosen.status(), StatusCode::OK);
        let view = get_json(&app, "/api/engine-policy", Some(&token)).await;
        assert_eq!(view["adversary_mode"], "blocking", "{view}");
        assert_eq!(view["choices"]["current"]["adversary"], "name:deepseek");
        assert_eq!(view["choices"]["current"]["adversary_mode"], "blocking");

        // A Block from an agent with no signed engine inventory does not count: the page
        // lists it as ignored, and blocking mode holds the lock for want of any finding that
        // does - it is not a way past the adversary either.
        propose("1");
        ferryman_channel::adversary::record(&fresh, &wisp, finding("user-api@1")).unwrap();
        let page = get_json(&app, "/api/contracts", Some(&token)).await;
        let contract = &page["contracts"][0];
        assert_eq!(contract["adversary"].as_array().unwrap().len(), 0, "{page}");
        assert_eq!(contract["finding_digest"], "none", "{page}");
        assert!(contract["lock_refusal"].is_string(), "{page}");
        let listed = get_json(&app, "/api/adversary", Some(&token)).await;
        assert_eq!(listed["findings"].as_array().unwrap().len(), 0, "{listed}");
        assert_eq!(listed["ignored"][0]["subject"], "user-api@1", "{listed}");
        assert!(
            listed["ignored"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("inventory"),
            "{listed}"
        );

        // With the inventory published, the same finding counts: the Block is shown, and
        // Lock is refused with the reason.
        publish_inventory();
        let page = get_json(&app, "/api/contracts", Some(&token)).await;
        assert_eq!(page["adversary_mode"], "blocking", "{page}");
        let contract = &page["contracts"][0];
        let digest = contract["digest"].as_str().unwrap().to_string();
        let seen = contract["finding_digest"].as_str().unwrap().to_string();
        assert_ne!(seen, "none", "{page}");
        let named = json!({ "digest": digest }).to_string();
        assert_eq!(contract["adversary"][0]["verdict"], "block", "{page}");
        assert_eq!(contract["adversary"][0]["unresolved_block"], true);
        assert!(
            contract["lock_refusal"]
                .as_str()
                .unwrap()
                .contains("blocks locking user-api@1"),
            "{page}"
        );
        let refused = post(&app, "/api/contracts/user-api@1/lock", &named, Some(&token)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let body = refused.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).contains("adversary"),
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(interface::locked(&fresh, "user-api", "1").is_none());

        // The override endpoint: a trigger that means nothing, a contract the adversary has
        // not read, then the real thing - after which Lock goes through.
        let bad = post(
            &app,
            "/api/adversary/override",
            r#"{"subject":"user-api@1","trigger":"whenever"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let unread = post(
            &app,
            "/api/adversary/override",
            r#"{"subject":"other-api@1","trigger":"contract-lock","finding":"none"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(unread.status(), StatusCode::NOT_FOUND);
        // An override has to name the finding the master read: none at all, or one that is
        // not what stands (the adversary said something else since), is refused.
        let unnamed = post(
            &app,
            "/api/adversary/override",
            r#"{"subject":"user-api@1","trigger":"contract-lock"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(unnamed.status(), StatusCode::BAD_REQUEST);
        let stale = post(
            &app,
            "/api/adversary/override",
            r#"{"subject":"user-api@1","trigger":"contract-lock","finding":"0000000000000000"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::FORBIDDEN);
        let blocked = post(
            &app,
            "/api/contracts/user-api@1/lock",
            &json!({ "digest": digest, "override": true, "finding": "0000000000000000" })
                .to_string(),
            Some(&token),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        assert!(interface::locked(&fresh, "user-api", "1").is_none());
        let overridden = post(
            &app,
            "/api/adversary/override",
            &json!({
                "subject": "user-api@1",
                "trigger": "contract-lock",
                "reason": "the consumer is being fixed",
                "finding": seen,
            })
            .to_string(),
            Some(&token),
        )
        .await;
        assert_eq!(overridden.status(), StatusCode::OK);
        let listed = get_json(&app, "/api/adversary", Some(&token)).await;
        assert_eq!(listed["mode"], "blocking", "{listed}");
        assert_eq!(listed["engine"], "name:deepseek");
        assert_eq!(listed["may_override"], true);
        assert_eq!(listed["findings"][0]["subject"], "user-api@1");
        assert_eq!(listed["findings"][0]["unresolved_block"], false, "{listed}");
        assert_eq!(
            listed["findings"][0]["override"]["reason"],
            "the consumer is being fixed"
        );
        let locked = post(&app, "/api/contracts/user-api@1/lock", &named, Some(&token)).await;
        assert_eq!(locked.status(), StatusCode::OK);

        // Or in one step: lock with an override.
        propose("2");
        ferryman_channel::adversary::record(&fresh, &wisp, finding("user-api@2")).unwrap();
        let page = get_json(&app, "/api/contracts", Some(&token)).await;
        let second = page["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["reference"] == "user-api@2")
            .unwrap();
        let named = json!({ "digest": second["digest"] }).to_string();
        let refused = post(&app, "/api/contracts/user-api@2/lock", &named, Some(&token)).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        // The override without the finding it overrides is not accepted.
        let unnamed = post(
            &app,
            "/api/contracts/user-api@2/lock",
            &json!({ "digest": second["digest"], "override": true, "reason": "ship it" })
                .to_string(),
            Some(&token),
        )
        .await;
        assert_eq!(unnamed.status(), StatusCode::BAD_REQUEST);
        let locked = post(
            &app,
            "/api/contracts/user-api@2/lock",
            &json!({
                "digest": second["digest"],
                "override": true,
                "finding": second["finding_digest"],
                "reason": "ship it",
            })
            .to_string(),
            Some(&token),
        )
        .await;
        assert_eq!(locked.status(), StatusCode::OK);
        assert!(interface::locked(&fresh, "user-api", "2").is_some());

        // Off shows nothing and refuses nothing.
        propose("3");
        ferryman_channel::adversary::record(&fresh, &wisp, finding("user-api@3")).unwrap();
        let off = post(
            &app,
            "/api/engine-policy/choose",
            r#"{"adversary":"off"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(off.status(), StatusCode::OK);
        let page = get_json(&app, "/api/contracts", Some(&token)).await;
        let third = page["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["reference"] == "user-api@3")
            .unwrap();
        assert_eq!(third["adversary"].as_array().unwrap().len(), 0, "{page}");
        assert!(third["lock_refusal"].is_null());
        let named = json!({ "digest": third["digest"] }).to_string();
        let locked = post(&app, "/api/contracts/user-api@3/lock", &named, Some(&token)).await;
        assert_eq!(locked.status(), StatusCode::OK);
    }

    /// "On for all my repos" passes over an archived project: the loop leaves finished
    /// work alone, and the page says why.
    #[tokio::test]
    async fn on_for_all_leaves_an_archived_project_alone() {
        let dir = tempfile::tempdir().unwrap();
        // Its own machine, so "all my repos" is this project and not a real ferry root.
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            dir.path().join("machine-state"),
        );
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;
        let claimed = post(&app, "/api/master/init", "{}", Some(&token)).await;
        assert_eq!(claimed.status(), StatusCode::OK);
        let alice = dashboard_state.sessions.resolve(&token).unwrap();
        assert!(
            ferryman_channel::ferry::set_archived(
                &route.communications,
                &route.project_id,
                true,
                &alice
            )
            .unwrap()
        );

        let all = post(
            &app,
            "/api/improve/all",
            r#"{"enabled":true}"#,
            Some(&token),
        )
        .await;
        assert_eq!(all.status(), StatusCode::OK);
        let body = axum::body::to_bytes(all.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["switched"], 0, "{body}");
        assert_eq!(body["projects"][0]["outcome"], "archived", "{body}");
        assert!(!ferryman_channel::ferry::self_improve_enabled(
            &route.communications,
            &route.project_id
        ));
    }

    /// The master lets the Telegram bridge act for them from the browser, the delegation
    /// counts, and revoking it from the browser ends it. Nobody else can do either.
    #[tokio::test]
    async fn the_master_delegates_to_the_bridge_from_the_browser_and_revokes_it() {
        use ferryman_channel::delegation::{ORDERS, authority};
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;
        let bridge = ferryman_channel::AgentIdentity::from_seed("telegram-grouchly", [4; 32]);
        ferryman_channel::register_agent(
            &route,
            &ferryman_channel::AgentRoute {
                name: "telegram-grouchly".into(),
                role: "delegate".into(),
                capabilities: Vec::new(),
                public_key: Some(bridge.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        let body = r#"{"delegate":"telegram-grouchly","scopes":["orders","review"]}"#;
        assert_eq!(
            post(&app, "/api/delegations", body, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&app, "/api/delegations", body, Some(&token))
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "nobody is master yet"
        );
        assert_eq!(
            post(&app, "/api/master/init", "{}", Some(&token))
                .await
                .status(),
            StatusCode::OK
        );
        let listed = get_json(&app, "/api/delegations", Some(&token)).await;
        assert_eq!(listed["may_set"], true);
        assert_eq!(listed["candidates"][0], "telegram-grouchly", "{listed}");

        assert_eq!(
            post(&app, "/api/delegations", body, Some(&token))
                .await
                .status(),
            StatusCode::OK
        );
        let listed = get_json(&app, "/api/delegations", Some(&token)).await;
        assert_eq!(listed["delegations"][0]["standing"], "active", "{listed}");
        assert_eq!(listed["delegations"][0]["principal"], "alice");
        let now = chrono::Utc::now();
        assert!(
            authority(
                &route.communications,
                &route.project_id,
                "alice",
                "telegram-grouchly",
                ORDERS,
                now
            )
            .allowed()
        );

        let revoke = r#"{"delegate":"telegram-grouchly"}"#;
        assert_eq!(
            post(&app, "/api/delegations/revoke", revoke, Some(&token))
                .await
                .status(),
            StatusCode::OK
        );
        assert!(
            !authority(
                &route.communications,
                &route.project_id,
                "alice",
                "telegram-grouchly",
                ORDERS,
                now
            )
            .allowed()
        );
    }

    /// Setting a secret from the dashboard is signed by the operator, not the
    /// machine, and lands in the project's channel as ciphertext.
    /// The property the whole chat surface rests on: the dashboard is a VIEW over the
    /// channel, not a second place to talk. What is typed in the browser must land in the
    /// same signed file the Telegram bridge appends to, and be indistinguishable from it
    /// afterwards - otherwise a message exists only here, no agent can see it, and it
    /// dies with the process.
    #[tokio::test]
    async fn saying_something_in_the_browser_writes_the_channel_the_bridge_reads() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;

        // Nobody signed in gets nowhere: what the fleet is saying is not public just
        // because the port is reachable.
        let denied = post(
            &app,
            "/api/conversations/launch",
            r#"{"said":"hello"}"#,
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let said = post(
            &app,
            "/api/conversations/launch",
            r#"{"said":"cutting the release now"}"#,
            Some(&token),
        )
        .await;
        assert_eq!(said.status(), StatusCode::OK);

        // It is in the channel, in the file the bridge and every agent prompt read.
        let bank = route.communications.join("memory-bank");
        let on_disk = ferryman_channel::conversation::load_conversation(&bank, "launch").unwrap();
        assert!(on_disk.contains("cutting the release now"), "{on_disk}");

        // And it is signed, so `recent_turns` will hand it to a prompt rather than
        // refusing it.
        let (turns, check) =
            ferryman_channel::conversation::recent_turns(&bank, "launch", 10, &route.agents);
        assert!(turns.contains("cutting the release now"));
        assert_ne!(check, SignatureCheck::Unsigned);

        // The API reads back what was written, parsed into turns.
        let body = get_json(&app, "/api/conversations/launch", Some(&token)).await;
        assert_eq!(body["turns"][0]["said"], "cutting the release now");
        assert!(
            body["turns"][0]["who"]
                .as_str()
                .is_some_and(|w| !w.is_empty()),
            "a turn with no speaker is not attributable: {body}"
        );

        // And the topic shows up in the list, with its last line.
        let list = get_json(&app, "/api/conversations", Some(&token)).await;
        assert_eq!(list["conversations"][0]["topic"], "launch");
        assert_eq!(list["conversations"][0]["turns"], 1);
    }

    /// An empty turn is not a message, and a megabyte is not one either. The file is
    /// carried to every machine in the fleet and read into agents' prompts.
    #[tokio::test]
    async fn an_empty_or_enormous_turn_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;

        let empty = post(
            &app,
            "/api/conversations/launch",
            r#"{"said":"   "}"#,
            Some(&token),
        )
        .await;
        assert_eq!(empty.status(), StatusCode::BAD_REQUEST);

        let huge = format!(r#"{{"said":"{}"}}"#, "x".repeat(9_000));
        let refused = post(&app, "/api/conversations/launch", &huge, Some(&token)).await;
        assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn secret_set_is_signed_by_the_operator_and_written_to_the_channel() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        std::fs::create_dir_all(route.communications.join("agents")).unwrap();
        // A recipient agent with a published encryption key.
        let recipient =
            ferryman_channel::secrets::EncryptionIdentity::from_seed("harbor", [1_u8; 32]);
        let roster = AgentRoute {
            name: "harbor".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: Some(recipient.public_key_hex()),
        };
        std::fs::write(
            route.communications.join("agents").join("harbor.json"),
            serde_json::to_vec_pretty(&roster).unwrap(),
        )
        .unwrap();
        let route = Arc::new(route);
        let dashboard_state = state(&route, false);
        let app = router(dashboard_state.clone());
        let token = signed_in(&app, &dashboard_state).await;

        let denied = post(
            &app,
            "/api/secrets",
            r#"{"name":"GH_TOKEN","value":"x","recipients":["harbor"]}"#,
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let created = post(
            &app,
            "/api/secrets",
            r#"{"name":"GH_TOKEN","value":"ghp_secret","recipients":["harbor"]}"#,
            Some(&token),
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK, "body: {:?}", {
            let body = created.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8_lossy(&body).to_string()
        });

        let path = route.communications.join("secrets").join("GH_TOKEN.json");
        assert!(path.is_file(), "envelope must be written to the channel");
        let envelope: ferryman_channel::secrets::SecretEnvelope =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(envelope.signed_by.as_deref(), Some("alice"));
        // The value never appears in the envelope.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("ghp_secret"), "value leaked into the channel");
    }

    #[test]
    fn sessions_expire_when_idle() {
        let sessions = Sessions::new(Duration::from_millis(20));
        let identity = AgentIdentity::from_seed("op", [9u8; 32]);
        let token = sessions.insert(identity);
        assert!(sessions.resolve(&token).is_some());
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            sessions.resolve(&token).is_none(),
            "idle session must expire"
        );
    }
}

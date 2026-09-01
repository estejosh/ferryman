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
        .route("/api/conversations", get(conversations))
        .route("/api/conversations/{topic}", get(conversation).post(say))
        .route("/api/memory", get(memory))
        .route("/api/memory/suggest", post(suggest))
        .route("/api/secrets", get(secrets_list))
        .route("/api/secrets", post(secret_set))
        .route("/api/secrets/{name}", delete(secret_remove))
        .route("/api/cost/rates", get(cost_rates))
        .route("/api/cost/plan", post(cost_plan))
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
        println!("\nNo operator exists for this project yet.");
        println!("To create the first one, the dashboard needs this single-use setup token:");
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
fn roster_now(state: &DashboardState) -> Vec<ferryman_channel::AgentRoute> {
    ferryman_channel::read_agent_roster(&state.route.communications)
        .unwrap_or_else(|_| state.route.agents.clone())
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

    let public_key = identity.public_key_hex();
    let token = state.sessions.insert(identity);
    Ok(Json(json!({
        "token": token,
        "name": &name,
        "public_key": &public_key,
        "fingerprint": &public_key,
        "phrase": phrase,
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
    if state.operators.any() {
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
            "recovering onto this machine needs the setup token printed in the terminal \
             running the dashboard; pass it as x-ferryman-dashboard-setup"
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
) -> Result<Json<Value>, DashboardError> {
    let current = state
        .sessions
        .resolve(session_token(&headers))
        .ok_or((StatusCode::UNAUTHORIZED, "no active session".to_string()))?;
    let mut names = state.operators.names().map_err(internal)?;
    let roster =
        ferryman_channel::read_agent_roster(&state.route.communications).map_err(internal)?;
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
    let master = ferryman_channel::master::read_master(&state.route)
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
            json!({
                "name": name,
                "role": role,
                "current": is_current,
                "scope": scope,
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
    Ok(Json(json!({
        "current": current.name(),
        "master": master,
        "teammates": teammates,
        "agents": agents,
    })))
}

/// GET /api/tasks — a summary of every task, with signature status.
async fn tasks(
    State(state): State<DashboardState>,
    Query(params): Query<ProjectParam>,
) -> Result<Json<Vec<Value>>, DashboardError> {
    let route = state.route_for(params.project.as_deref());
    let tasks = ferryman_channel::list_tasks(&route).map_err(internal)?;
    let items = tasks
        .iter()
        .map(|task| {
            json!({
                "id": task.order.id,
                "state": state_value(&task.state()),
                "holder": task.holder(),
                "result_count": task.results.len(),
                "sig": sig(&ferryman_channel::verify_order(&task.order, &route.agents)),
                "requires_review": task.order.requires_review,
                "requires_approval": task.order.requires_approval,
                "task": task.order.payload.get("task").and_then(Value::as_str).unwrap_or(""),
                "depends_on": task.order.depends_on,
                "contract_missing": task.contract_violations().unwrap_or_default(),
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
            "payload": task.order.payload,
            "sig": sig(&ferryman_channel::verify_order(&task.order, &route.agents)),
        },
        "claims": task.claims.iter().map(|c| json!({ "agent": c.agent, "at": c.claimed_at.to_rfc3339() })).collect::<Vec<_>>(),
        "results": results,
        "reviews": reviews,
        "contract_missing": task.contract_violations().unwrap_or_default(),
    })))
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
    Json(body): Json<PlanBody>,
) -> Result<Json<Value>, DashboardError> {
    let (tasks, prompt_tokens, completion_tokens) =
        ferryman_channel::cost::estimate_project_tokens(&body.prompt, body.tasks);
    let route = state.route.as_ref();
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
    let items = agents
        .iter()
        .map(|agent| {
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
    headers: HeaderMap,
    Json(body): Json<Suggestion>,
) -> Result<StatusCode, DashboardError> {
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
    let dir = state.route.communications.join("memory-bank");
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
    headers: HeaderMap,
    Json(body): Json<SecretBody>,
) -> Result<Json<Value>, DashboardError> {
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
        &state.route,
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
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, DashboardError> {
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
    if ferryman_channel::secrets::remove_secret(&state.route, &name).map_err(internal)? {
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
async fn fleet(State(state): State<DashboardState>) -> Result<Json<Value>, DashboardError> {
    let machines = ferryman_channel::licensing::read_devices(&state.route)
        .map_err(internal)?
        .iter()
        .map(|device| {
            json!({
                "id": device.id,
                "kind": device.kind.as_str(),
                "operator_email": device.operator_email,
                "registered_at": device.registered_at.to_rfc3339(),
            })
        })
        .collect::<Vec<_>>();
    let devices = ferryman_channel::syncthing_peers()
        .unwrap_or_default()
        .iter()
        .map(|peer| json!({ "device_id": peer.device_id, "name": peer.name }))
        .collect::<Vec<_>>();
    let projects = discover_projects(&state.route).map_err(internal)?;
    Ok(Json(
        json!({ "machines": machines, "devices": devices, "projects": projects }),
    ))
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
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_dir() {
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
async fn release(State(state): State<DashboardState>) -> Result<Json<Value>, DashboardError> {
    let Some(request) = ferryman_channel::release::pending(&state.route) else {
        return Ok(Json(json!({ "pending": null })));
    };
    let approved = ferryman_channel::release::list_approvals(&state.route)
        .into_iter()
        .find(|a| a.version == request.version);
    let roster = roster_now(&state);
    let now = chrono::Utc::now();
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
    headers: HeaderMap,
    Path(version): Path<String>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;

    let request = ferryman_channel::release::pending(&state.route).ok_or((
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
    let path = ferryman_channel::release::write_approval(&state.route, &approval, &identity)
        .map_err(internal)?;
    Ok(Json(json!({
        "version": approval.version,
        "commit": approval.commit,
        "approved_by": approval.approved_by,
        "path": path.display().to_string(),
    })))
}

/// Where the conversations live: the memory bank, which Syncthing carries - so what is
/// said here is said in the channel, not in the dashboard.
fn conversation_bank(state: &DashboardState) -> std::path::PathBuf {
    state.route.communications.join("memory-bank")
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
async fn conversations(State(state): State<DashboardState>) -> Result<Json<Value>, DashboardError> {
    let bank = conversation_bank(&state);
    let dir = ferryman_channel::conversation::conversations_dir(&bank);
    let roster = roster_now(&state);
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
    Path(topic): Path<String>,
) -> Result<Json<Value>, DashboardError> {
    let bank = conversation_bank(&state);
    let check =
        ferryman_channel::conversation::verify_conversation(&bank, &topic, &roster_now(&state));
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
    let bank = conversation_bank(&state);
    ferryman_channel::conversation::append_turn(&bank, &topic, identity.name(), said, &identity)
        .map_err(|e| internal(e.into()))?;
    Ok(Json(json!({ "topic": topic, "who": identity.name() })))
}

/// GET /api/memory — the project's shared memory bank, plus the knowledge graph
/// if graphify has exported one. Best-effort: an unreadable file is skipped, and
/// a missing graph simply returns `graph: null`.
async fn memory(State(state): State<DashboardState>) -> Result<Json<Value>, DashboardError> {
    let mut files = Vec::new();
    let memory_dir = state.route.communications.join("memory-bank");
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
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
    let identity = state.sessions.resolve(session_token(&headers)).ok_or((
        StatusCode::UNAUTHORIZED,
        "no active session; sign in again".to_string(),
    ))?;

    let task = ferryman_channel::read_task(&state.route, &id).map_err(internal)?;
    let revision = task.latest_revision().ok_or((
        StatusCode::CONFLICT,
        "there is no result to review yet".to_string(),
    ))?;
    if body.accept
        && let Some(missing) = task.contract_violations()
        && !missing.is_empty()
    {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "result does not satisfy the order's contract; missing keys: {}",
                missing.join(", ")
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
    let path = ferryman_channel::submit_review(&state.route, &verdict)
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

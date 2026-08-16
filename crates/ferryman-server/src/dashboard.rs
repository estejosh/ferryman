//! Web dashboard over the channel: tasks, ledger, engine stats, and learnings
//! in one interactive pane, plus (when not run read-only) the review action an
//! operator needs to accept or send back work. Operators sign in with a
//! password-protected identity and hold a short-lived, idle-expiring session.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Error, bail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
};
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
}

impl DashboardState {
    pub fn new(
        route: Arc<ProjectRoute>,
        operators: OperatorStore,
        read_only: bool,
        timeout: Duration,
    ) -> Self {
        Self {
            route,
            operators,
            sessions: Sessions::new(timeout),
            read_only,
            login_rate: RateLimiter::new(5, Duration::from_secs(60)),
            create_rate: RateLimiter::new(10, Duration::from_secs(3600)),
        }
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
    let parent = current.workspace.parent()?;
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
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
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
        .route("/api/tasks", get(tasks))
        .route("/api/tasks/{id}", get(task_detail))
        .route("/api/tasks/{id}/review", post(review_task))
        .route("/api/stats", get(stats))
        .route("/api/ledger", get(ledger))
        .route("/api/learnings", get(learnings))
        .route("/api/roster", get(roster))
        .route("/api/fleet", get(fleet))
        .route("/api/memory", get(memory))
        .route("/api/memory/suggest", post(suggest))
        .route("/api/cost/rates", get(cost_rates))
        .route("/api/cost/estimate", post(cost_estimate))
        .layer(axum::middleware::from_fn(loopback_host_guard))
        .with_state(state)
}

/// Reject requests whose `Host` header is not a loopback name/IP.
///
/// A raw loopback bind is not a defense against DNS rebinding: a browser can
/// resolve `attacker.example` to 127.0.0.1 and reach the dashboard as
/// "same-origin", reading the fleet and driving the write endpoints. Requiring
/// a loopback `Host` blocks that. Requests with no `Host` at all (non-browser
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
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.")
        })
        .unwrap_or(true);
    if host_ok {
        next.run(request).await
    } else {
        use axum::response::IntoResponse;
        (
            StatusCode::FORBIDDEN,
            "host not allowed on loopback dashboard",
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

#[derive(Deserialize)]
struct Credentials {
    name: String,
    password: String,
}

/// POST /api/auth/create — mint a password-sealed operator identity and publish
/// its public key to the roster, so the fleet can verify what this human signs.
async fn create_operator(
    State(state): State<DashboardState>,
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
    let identity = crate::operators::create_operator_identity(
        &state.route,
        &credentials.name,
        &credentials.password,
    )
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({
        "name": identity.name(),
        "public_key": identity.public_key_hex(),
    })))
}

/// POST /api/auth/login — unlock an operator identity and start a session.
async fn login(
    State(state): State<DashboardState>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<Value>, DashboardError> {
    if state.read_only {
        return Err((StatusCode::FORBIDDEN, "dashboard is read-only".to_string()));
    }
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

/// POST /api/cost/estimate — price one prompt against one engine. A rough
/// estimate (about four characters per input token), not a vendor's exact count.
#[derive(Deserialize)]
struct EstimateBody {
    engine: String,
    prompt: String,
    #[serde(default = "default_output_tokens")]
    output_tokens: u64,
}

fn default_output_tokens() -> u64 {
    500
}

async fn cost_estimate(
    State(state): State<DashboardState>,
    Json(body): Json<EstimateBody>,
) -> Result<Json<Value>, DashboardError> {
    let engine = body.engine.trim();
    if engine.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "engine is empty".to_string()));
    }
    let rates = ferryman_channel::cost::Rates::load(state.route.as_ref());
    let input_tokens = ferryman_channel::cost::estimate_tokens(&body.prompt);
    let estimated_cost_usd = ferryman_channel::cost::estimate_prompt_cost(
        &rates,
        engine,
        &body.prompt,
        body.output_tokens,
    );
    Ok(Json(json!({
        "engine": engine,
        "input_tokens": input_tokens,
        "output_tokens": body.output_tokens,
        "estimated_cost_usd": estimated_cost_usd,
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
                "key": agent.public_key.as_deref().map(fingerprint).unwrap_or_default(),
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
    let author = state
        .sessions
        .resolve(session_token(&headers))
        .map(|identity| identity.name().to_string())
        .unwrap_or_else(|| "operator".to_string());
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

/// Every project whose channel directory sits beside this workspace. A sibling
/// directory is a project exactly when it has a `.ferryman/bridge.toml`; there
/// is no registry to keep in sync, so a project appears the moment its channel
/// is on disk.
fn discover_projects(route: &ProjectRoute) -> anyhow::Result<Vec<Value>> {
    let Some(parent) = route.workspace.parent() else {
        return Ok(Vec::new());
    };
    let mut projects: Vec<(String, String, usize, usize, usize)> = Vec::new();
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
            ["/mnt/nvme-storage/cline/projects/ferryman/graphify-out/graph.json"]
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
        TaskState::Claimed { by } => json!({ "status": "claimed", "by": by }),
        TaskState::AwaitingReview { by, revision } => {
            json!({ "status": "awaiting_review", "by": by, "revision": revision })
        }
        TaskState::ChangesRequested { revision } => {
            json!({ "status": "changes_requested", "revision": revision })
        }
        TaskState::Accepted => json!({ "status": "accepted" }),
        TaskState::Done => json!({ "status": "done" }),
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
            OperatorStore::new(&route.attachment),
            read_only,
            Duration::from_secs(900),
        )
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

    #[tokio::test]
    async fn api_tasks_lists_channel_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        ferryman_channel::issue_order(&route, &order("task-1")).unwrap();
        ferryman_channel::claim_order(&route, "task-1", "alice").unwrap();

        let response = router(state(&route, false))
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
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

    #[tokio::test]
    async fn rejects_a_non_loopback_host_header() {
        let dir = tempfile::tempdir().unwrap();
        let route = Arc::new(test_route(dir.path()));
        let app = router(state(&route, false));

        // A DNS-rebinding attacker resolves their domain to 127.0.0.1; the Host
        // header betrays that and the request is refused.
        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
                    .header("host", "attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);

        // A genuine loopback request (and one with no Host at all) still works.
        let good = app
            .oneshot(
                Request::builder()
                    .uri("/api/tasks")
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
        ferryman_channel::licensing::use_machine_state_dir(dir.path().join("machine-state"));
        let route = Arc::new(test_route(dir.path()));
        let app = router(state(&route, false));

        let created = post(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            None,
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

        // The same name cannot be created again.
        let dup = post(
            &app,
            "/api/auth/create",
            r#"{"name":"operator1","password":"hunter2-secret"}"#,
            None,
        )
        .await;
        assert_eq!(dup.status(), StatusCode::CONFLICT);
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
        let reviewer = OperatorStore::new(&route.attachment)
            .create("reviewer", "hunter2-secret")
            .unwrap();
        route.agents.push(AgentRoute {
            name: "alice".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(alice.public_key_hex()),
        });
        route.agents.push(AgentRoute {
            name: "reviewer".into(),
            role: "master".into(),
            capabilities: Vec::new(),
            public_key: Some(reviewer.public_key_hex()),
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

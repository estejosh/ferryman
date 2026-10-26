//! `ferry mcp serve --http`: MCP over Streamable HTTP with its own authorization server
//! (ADR 0031, revised 2026-10-25: login and MCP live on the user's own machine).
//!
//! One process, one `/mcp` endpoint, plus the OAuth endpoints a cloud app needs
//! (`/.well-known/*`, `/register`, `/authorize`, `/token`, `/revoke`). The listener is plain
//! HTTP: put it behind TLS (the edge/ACME step, or a tunnel you control). It answers only to
//! the one `Host` named by `--public-url`, and every `/mcp` request is checked for a live
//! access token for that exact resource before its body is read.
//!
//! Every app that logs in becomes its own agent (`ferryman_channel::apps`): the pairing code
//! lets it ask, the owner approves on this machine (`ferry mcp apps approve`, or the dashboard),
//! and only then does the browser get its authorization code. A token speaks as its app and
//! nobody else, and revoking the app ends every token at the next request.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use ferryman_channel::apps;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use serde_json::{Value, json};

use crate::mcp::{HTTP_PROTOCOLS, MAX_LINE_BYTES, Server, handle_line};
use crate::mcp_agent::RouteSource;
use crate::mcp_oauth::{self as oauth, CodeRequest, OAuthError, Store};

/// What `--http` was started with.
#[derive(Clone, Debug)]
pub struct HttpOptions {
    pub addr: SocketAddr,
    /// `--public-url`: where the app reaches this server, through whatever TLS sits in front.
    pub public_url: Option<String>,
    /// Where tokens and pairing codes are kept. Defaults to the machine state directory.
    pub state_dir: Option<PathBuf>,
}

/// Request bodies other than `/mcp` are tiny forms and JSON.
const SMALL_BODY: usize = 16 * 1024;

/// The fixed names this server answers to.
#[derive(Clone, Debug)]
pub struct Config {
    /// `https://mcp.example.com`: the issuer.
    pub origin: String,
    /// `https://mcp.example.com/mcp`: the connector URL and the OAuth resource.
    pub resource: String,
    /// The only `Host` header accepted.
    pub host: String,
    pub state_dir: PathBuf,
}

impl Config {
    pub fn new(addr: SocketAddr, public_url: Option<&str>, state_dir: PathBuf) -> Result<Self> {
        let raw = match public_url {
            Some(url) => url.to_string(),
            None if addr.ip().is_loopback() => format!("http://{addr}"),
            None => bail!("--public-url is required when --http is not a loopback address"),
        };
        let url = url::Url::parse(&raw).context("--public-url is not a URL")?;
        let loopback = match url.host() {
            Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            bail!("--public-url must be https (plain http only for a loopback address)");
        }
        if url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/" | "/mcp")
        {
            bail!("--public-url is the site, like https://mcp.example.com (or ending /mcp)");
        }
        let name = url.host_str().context("--public-url has no host")?;
        let host = match url.port() {
            Some(port) => format!("{name}:{port}"),
            None => name.to_string(),
        }
        .to_ascii_lowercase();
        let origin = format!("{}://{host}", url.scheme());
        Ok(Self {
            resource: format!("{origin}/mcp"),
            origin,
            host,
            state_dir,
        })
    }

    fn prm_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource/mcp", self.origin)
    }
}

/// The machine-local directory for tokens and pairing codes.
pub fn default_state_dir() -> Result<PathBuf> {
    apps::default_state_dir().context("no per-user state directory on this machine")
}

pub struct App {
    cfg: Config,
    /// The live projects, asked again on every use.
    source: RouteSource,
    store: Mutex<Store>,
    /// Times of recent wrong pairing codes.
    failures: Mutex<Vec<i64>>,
    /// Logins that passed the pairing code and wait for the owner, by wait token.
    waiting: Mutex<HashMap<String, Waiting>>,
}

/// A login held between the pairing code and the owner's decision.
struct Waiting {
    app: String,
    client_id: String,
    redirect_uri: String,
    challenge: String,
    state: Option<String>,
    created: i64,
}

/// Who a request's token speaks as, set by [`require_token`].
#[derive(Clone)]
struct Caller(String);

impl App {
    pub fn new(cfg: Config, source: RouteSource) -> Result<Arc<Self>> {
        let store = Store::open(&cfg.state_dir)?;
        Ok(Arc::new(Self {
            cfg,
            source,
            store: Mutex::new(store),
            failures: Mutex::new(Vec::new()),
            waiting: Mutex::new(HashMap::new()),
        }))
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn waiting(&self) -> std::sync::MutexGuard<'_, HashMap<String, Waiting>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn server_for(&self, agent: &str) -> Result<Server> {
        Server::for_app(
            agent,
            self.source.clone(),
            apps::keys_dir(&self.cfg.state_dir),
        )
    }

    /// The projects `agent` would see, and at which level.
    async fn projects(
        self: &Arc<Self>,
        agent: &str,
    ) -> Vec<(String, ferryman_channel::access::Level)> {
        let (app, agent) = (self.clone(), agent.to_string());
        tokio::task::spawn_blocking(move || {
            app.server_for(&agent)
                .map(|server| server.remote_projects())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }

    /// End the tokens of every app the owner has revoked (from the CLI or the dashboard,
    /// which cannot reach this process's memory).
    fn sweep(&self) {
        let revoked = apps::revoked_agents(&self.cfg.state_dir);
        if revoked.is_empty() {
            return;
        }
        let mut store = self.store();
        for agent in revoked {
            store.revoke_agent(&agent);
        }
    }
}

pub fn router(app: Arc<App>) -> Router {
    let small = || DefaultBodyLimit::max(SMALL_BODY);
    Router::new()
        .route(
            "/mcp",
            any(mcp)
                .layer(DefaultBodyLimit::max(MAX_LINE_BYTES))
                .layer(middleware::from_fn_with_state(app.clone(), require_token)),
        )
        .route("/.well-known/oauth-protected-resource", get(prm))
        .route("/.well-known/oauth-protected-resource/mcp", get(prm))
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route("/register", post(register).layer(small()))
        .route(
            "/authorize",
            get(authorize_page).post(authorize_submit).layer(small()),
        )
        .route("/authorize/wait", get(authorize_wait))
        .route("/token", post(token).layer(small()))
        .route("/revoke", post(revoke).layer(small()))
        .layer(middleware::from_fn_with_state(app.clone(), host_guard))
        .with_state(app)
}

/// Serve on an already bound listener until the task is dropped.
pub async fn serve_listener(listener: tokio::net::TcpListener, app: Arc<App>) -> Result<()> {
    axum::serve(listener, router(app))
        .await
        .context("http server stopped")
}

/// `ferry mcp serve --http`: bind, print how to connect, and serve until killed.
pub fn run(options: &HttpOptions) -> Result<()> {
    let state_dir = match &options.state_dir {
        Some(dir) => dir.clone(),
        None => default_state_dir()?,
    };
    let cfg = Config::new(options.addr, options.public_url.as_deref(), state_dir)?;
    let live = crate::mcp_agent::root_routes();
    if live.is_empty() {
        bail!("there is no live project in the ferry root here, so there is nothing to serve");
    }
    let app = App::new(cfg.clone(), Arc::new(crate::mcp_agent::root_routes))?;
    let addr = options.addr;
    eprintln!("ferry mcp: connector URL {}", cfg.resource);
    eprintln!(
        "ferry mcp: serving {} project(s) on http://{addr} (plain HTTP: keep it behind TLS)",
        live.len()
    );
    eprintln!("ferry mcp: run `ferry mcp pair` for a one-time code to connect an app");
    eprintln!(
        "ferry mcp: each app gets its own identity once you approve it: `ferry mcp apps approve <id>`, or the dashboard"
    );
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("start the runtime")?
            .block_on(async move {
                let listener = tokio::net::TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("bind {addr}"))?;
                serve_listener(listener, app).await
            })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("the http server thread panicked"))?
}

// ---------------------------------------------------------------------------------------
// Responses

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    let mut response = (status, value.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    no_store(response)
}

fn oauth_failure(error: &OAuthError) -> Response {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({ "error": error.code, "error_description": error.description }),
    )
}

fn plain(status: StatusCode, text: &'static str) -> Response {
    no_store((status, text).into_response())
}

fn html(status: StatusCode, body: &str) -> Response {
    let mut response = (status, body.to_string()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    no_store(response)
}

fn unauthorized(app: &App, error: Option<&str>) -> Response {
    let mut challenge = format!("Bearer resource_metadata=\"{}\"", app.cfg.prm_url());
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    let mut response = json_response(
        StatusCode::UNAUTHORIZED,
        &json!({ "error": error.unwrap_or("unauthorized") }),
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn form(bytes: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(bytes).into_owned().collect()
}

// ---------------------------------------------------------------------------------------
// Middleware

/// Only the configured `Host` gets an answer (DNS rebinding, stray vhosts).
async fn host_guard(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    if host.as_deref() != Some(app.cfg.host.as_str()) {
        return plain(StatusCode::MISDIRECTED_REQUEST, "unknown host");
    }
    next.run(request).await
}

/// Auth before any parsing of the body: a live access token for this resource, held by an
/// app the owner still has approved, and an identity that still has a seat.
async fn require_token(State(app): State<Arc<App>>, mut request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);
    let Some(token) = token else {
        return unauthorized(&app, None);
    };
    app.sweep();
    let now = oauth::unix_now();
    let agent = app.store().access_agent(token, &app.cfg.resource, now);
    let Some(agent) = agent.filter(|agent| apps::is_live(&app.cfg.state_dir, agent)) else {
        return unauthorized(&app, Some("invalid_token"));
    };
    if app.projects(&agent).await.is_empty() {
        return plain(
            StatusCode::FORBIDDEN,
            "this app is not seated as a Worker or Member in any live project",
        );
    }
    apps::record_use(&app.cfg.state_dir, &agent, now);
    request.extensions_mut().insert(Caller(agent));
    next.run(request).await
}

// ---------------------------------------------------------------------------------------
// Metadata

async fn prm(State(app): State<Arc<App>>) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "resource": app.cfg.resource,
            "authorization_servers": [app.cfg.origin],
            "scopes_supported": [oauth::SCOPE_READ, oauth::SCOPE_WRITE, "offline_access"],
            "bearer_methods_supported": ["header"],
            "resource_name": "Ferryman",
        }),
    )
}

async fn as_metadata(State(app): State<Arc<App>>) -> Response {
    let o = &app.cfg.origin;
    json_response(
        StatusCode::OK,
        &json!({
            "issuer": o,
            "authorization_endpoint": format!("{o}/authorize"),
            "token_endpoint": format!("{o}/token"),
            "registration_endpoint": format!("{o}/register"),
            "revocation_endpoint": format!("{o}/revoke"),
            "revocation_endpoint_auth_methods_supported": ["none"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [oauth::SCOPE_READ, oauth::SCOPE_WRITE, "offline_access"],
            // Client ID Metadata Documents are not fetched in this slice: apps register (DCR).
            "client_id_metadata_document_supported": false,
        }),
    )
}

// ---------------------------------------------------------------------------------------
// Registration

async fn register(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return oauth_failure(&OAuthError {
            code: "invalid_client_metadata",
            description: "body must be JSON".into(),
        });
    };
    let result = app.store().register(&value, oauth::unix_now());
    match result {
        Ok(client) => json_response(StatusCode::CREATED, &client),
        Err(error) => oauth_failure(&error),
    }
}

// ---------------------------------------------------------------------------------------
// Authorize

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Why an authorization request cannot go ahead.
enum Refused {
    /// The client or redirect address cannot be trusted: say so here, redirect nowhere.
    Page(&'static str),
    /// Tell the client, at its registered redirect address.
    Redirect {
        uri: String,
        state: Option<String>,
        error: &'static str,
        description: &'static str,
    },
}

/// A request that passed every check except the pairing code.
struct Valid {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    redirect_host: String,
    challenge: String,
    state: Option<String>,
    /// The live projects an approved app may be seated in.
    projects: Vec<String>,
}

async fn validate(app: &Arc<App>, p: &HashMap<String, String>) -> Result<Valid, Refused> {
    let get = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
    let (client_id, redirect_uri) = (get("client_id"), get("redirect_uri"));
    let client_name = {
        let store = app.store();
        if !store.redirect_ok(client_id, redirect_uri) {
            return Err(Refused::Page(
                "This app is not registered, or its return address is not the one it registered.",
            ));
        }
        store.client_name(client_id).unwrap_or_default()
    };
    let state = p.get("state").cloned();
    let fail = |error, description| Refused::Redirect {
        uri: redirect_uri.to_string(),
        state: state.clone(),
        error,
        description,
    };
    if get("response_type") != "code" {
        return Err(fail("unsupported_response_type", "only response_type=code"));
    }
    let challenge = get("code_challenge");
    if get("code_challenge_method") != "S256" || challenge.len() != 43 {
        return Err(fail("invalid_request", "PKCE with S256 is required"));
    }
    if let Some(resource) = p.get("resource")
        && *resource != app.cfg.resource
    {
        return Err(fail("invalid_target", "resource is not this server"));
    }
    let source = app.source.clone();
    let projects: Vec<String> = tokio::task::spawn_blocking(move || {
        source().into_iter().map(|route| route.project_id).collect()
    })
    .await
    .unwrap_or_default();
    if projects.is_empty() {
        return Err(Refused::Page("This Ferryman has no live project to share."));
    }
    let redirect_host = url::Url::parse(redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();
    Ok(Valid {
        client_id: client_id.into(),
        client_name,
        redirect_uri: redirect_uri.into(),
        redirect_host,
        challenge: challenge.into(),
        state,
        projects,
    })
}

fn refused_response(refused: Refused) -> Response {
    match refused {
        Refused::Page(why) => html(
            StatusCode::BAD_REQUEST,
            &page(&format!("<h1>Cannot connect</h1><p>{}</p>", escape(why))),
        ),
        Refused::Redirect {
            uri,
            state,
            error,
            description,
        } => {
            let mut pairs = vec![("error", error), ("error_description", description)];
            if let Some(state) = &state {
                pairs.push(("state", state));
            }
            redirect(&uri, &pairs)
        }
    }
}

fn redirect(base: &str, pairs: &[(&str, &str)]) -> Response {
    let Ok(mut target) = url::Url::parse(base) else {
        return plain(StatusCode::BAD_REQUEST, "bad redirect");
    };
    {
        let mut query = target.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    match HeaderValue::from_str(target.as_str()) {
        Ok(location) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, location);
            no_store(response)
        }
        Err(_) => plain(StatusCode::BAD_REQUEST, "bad redirect"),
    }
}

fn page(body: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Connect to Ferryman</title>\
         <style>body{{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem}}\
         code{{background:#8881;padding:.1rem .3rem;border-radius:.2rem}}input{{font:inherit;padding:.4rem;width:100%;box-sizing:border-box}}\
         button{{font:inherit;padding:.5rem 1rem;margin-top:.8rem}}.err{{color:#b00020}}.small{{font-size:.85rem;opacity:.8}}</style>{body}"
    )
}

fn consent(valid: &Valid, p: &HashMap<String, String>, error: Option<&str>) -> String {
    let seats: String = valid
        .projects
        .iter()
        .map(|project| format!("<li><code>{}</code></li>", escape(project)))
        .collect();
    let hidden: String = [
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "state",
        "resource",
        "scope",
    ]
    .iter()
    .filter_map(|k| p.get(*k).map(|v| (k, v)))
    .map(|(k, v)| format!("<input type=hidden name=\"{k}\" value=\"{}\">", escape(v)))
    .collect();
    let error = error
        .map(|e| format!("<p class=err>{}</p>", escape(e)))
        .unwrap_or_default();
    page(&format!(
        "<h1>Connect an app to Ferryman</h1>\
         <p><b>{name}</b> wants to connect. After you enter the code and approve it on this machine, it is sent to <b>{host}</b>.</p>\
         <p>It will get an identity of its own. By default that is a Worker: it can read the channel and ask you, and cannot write into it. You can make it a Member when you approve. It can only be seated in:</p><ul>{seats}</ul>\
         <p class=small>The app, and the company behind it, will receive everything it reads through this connection. You can revoke it at any time.</p>\
         {error}\
         <form method=post action=/authorize>{hidden}\
         <label>Pairing code<input name=pairing_code autocomplete=off autofocus required></label>\
         <button>Connect</button></form>\
         <p class=small>Get a code by running <code>ferry mcp pair</code> on this machine. It works once, for ten minutes.</p>",
        name = escape(&valid.client_name),
        host = escape(&valid.redirect_host),
    ))
}

/// "Waiting for the owner", which reloads itself until the owner has decided.
fn waiting_page(app: &apps::App, wait: &str) -> Response {
    let body = format!(
        "<meta http-equiv=refresh content=\"3;url=/authorize/wait?w={wait}\">\
         <h1>Waiting for your approval</h1>\
         <p><b>{name}</b> will act as <code>{agent}</code>. Approve it on the machine that runs Ferryman:</p>\
         <p><code>ferry mcp apps approve {id}</code></p>\
         <p>or open the dashboard, Connected apps. This page continues by itself once you have. It gives up in ten minutes.</p>",
        name = escape(&app.client_name),
        agent = escape(&app.agent),
        id = escape(&app.id),
    );
    html(StatusCode::OK, &page(&body))
}

async fn authorize_page(State(app): State<Arc<App>>, uri: Uri) -> Response {
    let params = form(uri.query().unwrap_or("").as_bytes());
    match validate(&app, &params).await {
        Ok(valid) => html(StatusCode::OK, &consent(&valid, &params, None)),
        Err(refused) => refused_response(refused),
    }
}

async fn authorize_submit(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let params = form(&body);
    let valid = match validate(&app, &params).await {
        Ok(valid) => valid,
        Err(refused) => return refused_response(refused),
    };
    let now = oauth::unix_now();
    {
        let mut failures = app.failures.lock().unwrap_or_else(PoisonError::into_inner);
        failures.retain(|t| *t + oauth::LOCKOUT_SECS > now);
        if failures.len() >= oauth::LOCKOUT_FAILURES {
            return html(
                StatusCode::TOO_MANY_REQUESTS,
                &page(
                    "<h1>Locked</h1><p>Too many wrong codes. Wait ten minutes, then run <code>ferry mcp pair</code> again.</p>",
                ),
            );
        }
    }
    let entered = params.get("pairing_code").map(String::as_str).unwrap_or("");
    if !oauth::consume_pairing_code(&app.cfg.state_dir, entered, now) {
        app.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(now);
        return html(
            StatusCode::FORBIDDEN,
            &consent(&valid, &params, Some("That code is wrong or has expired.")),
        );
    }
    // The code opened the door; it does not make an identity. Ask for one and wait for the
    // owner, who decides on this machine.
    let (source, state_dir) = (app.source.clone(), app.cfg.state_dir.clone());
    let (name, host) = (valid.client_name.clone(), valid.redirect_host.clone());
    let asked = tokio::task::spawn_blocking(move || {
        apps::request(
            &state_dir,
            &source(),
            &apps::Request {
                client_name: &name,
                redirect_host: &host,
            },
            now,
        )
    })
    .await;
    let record = match asked {
        Ok(Ok(record)) => record,
        Ok(Err(error)) => {
            return html(
                StatusCode::SERVICE_UNAVAILABLE,
                &page(&format!(
                    "<h1>Not now</h1><p>{}</p>",
                    escape(&format!("{error:#}"))
                )),
            );
        }
        Err(_) => return plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let wait = oauth::random_hex(16);
    {
        let mut held = app.waiting();
        held.retain(|_, w| w.created + apps::PENDING_SECS + 60 > now);
        held.insert(
            wait.clone(),
            Waiting {
                app: record.id.clone(),
                client_id: valid.client_id,
                redirect_uri: valid.redirect_uri,
                challenge: valid.challenge,
                state: valid.state,
                created: now,
            },
        );
    }
    waiting_page(&record, &wait)
}

/// The page the browser reloads while the owner decides. Approved: the authorization code
/// goes to the app's registered return address. Refused or too slow: `access_denied`.
async fn authorize_wait(State(app): State<Arc<App>>, uri: Uri) -> Response {
    let params = form(uri.query().unwrap_or("").as_bytes());
    let wait = params.get("w").cloned().unwrap_or_default();
    let now = oauth::unix_now();
    let held = {
        let held = app.waiting();
        held.get(&wait).map(|w| {
            (
                w.app.clone(),
                w.client_id.clone(),
                w.redirect_uri.clone(),
                w.challenge.clone(),
                w.state.clone(),
                w.created,
            )
        })
    };
    let Some((app_id, client_id, redirect_uri, challenge, state, created)) = held else {
        return html(
            StatusCode::BAD_REQUEST,
            &page("<h1>Expired</h1><p>This sign-in is over. Start again from the app.</p>"),
        );
    };
    let (source, state_dir) = (app.source.clone(), app.cfg.state_dir.clone());
    let decided = tokio::task::spawn_blocking(move || -> anyhow::Result<apps::App> {
        let mut record = apps::find(&state_dir, &app_id)?;
        // A grant the master signed elsewhere counts, with no one at this machine.
        apps::settle(&state_dir, &mut record, &source(), now)?;
        if record.state == apps::State::Pending && created + apps::PENDING_SECS <= now {
            apps::deny(&state_dir, &mut record, now)?;
        }
        Ok(record)
    })
    .await;
    let Ok(Ok(record)) = decided else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let code;
    match record.state {
        apps::State::Pending => return waiting_page(&record, &wait),
        apps::State::Approved => {
            let scope = if record.level == Some(ferryman_channel::access::Level::Member) {
                format!("{} {}", oauth::SCOPE_READ, oauth::SCOPE_WRITE)
            } else {
                oauth::SCOPE_READ.to_string()
            };
            code = app.store().issue_code(
                &CodeRequest {
                    client_id: &client_id,
                    redirect_uri: &redirect_uri,
                    challenge: &challenge,
                    audience: &app.cfg.resource,
                    scope: &scope,
                    agent: &record.agent,
                },
                now,
            );
            pairs.push(("code", &code));
        }
        apps::State::Denied | apps::State::Revoked => {
            pairs.push(("error", "access_denied"));
            pairs.push(("error_description", "the owner did not approve this app"));
        }
    }
    app.waiting().remove(&wait);
    if let Some(state) = &state {
        pairs.push(("state", state));
    }
    redirect(&redirect_uri, &pairs)
}

// ---------------------------------------------------------------------------------------
// Token

async fn token(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let params = form(&body);
    let now = oauth::unix_now();
    app.sweep();
    let result = {
        let mut store = app.store();
        match params.get("grant_type").map(String::as_str) {
            Some("authorization_code") => store.exchange_code(&params, &app.cfg.resource, now),
            Some("refresh_token") => store.refresh(&params, &app.cfg.resource, now),
            _ => Err(oauth::oauth_error(
                "unsupported_grant_type",
                "authorization_code and refresh_token only",
            )),
        }
    };
    match result {
        Ok(tokens) => json_response(StatusCode::OK, &tokens),
        Err(error) => oauth_failure(&error),
    }
}

/// RFC 7009: the app ends its own session. Every token of the grant dies; when that was the
/// app's last grant the app itself is revoked (its key deleted, its seat signed away where
/// this machine holds the master key), so a disconnect leaves no identity behind.
async fn revoke(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let params = form(&body);
    let get = |k: &str| params.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let (Some(token), Some(client_id)) = (get("token"), get("client_id")) else {
        return oauth_failure(&OAuthError {
            code: "invalid_request",
            description: "token and client_id are required".into(),
        });
    };
    let now = oauth::unix_now();
    let ended = app.store().revoke_token(token, client_id);
    let agent = match ended {
        Ok(agent) => agent,
        Err(error) => return oauth_failure(&error),
    };
    if let Some(agent) = agent
        && app.store().live_grants(&agent, now) == 0
    {
        let (source, state_dir) = (app.source.clone(), app.cfg.state_dir.clone());
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(mut record) = apps::by_agent(&state_dir, &agent)
                && record.state != apps::State::Revoked
            {
                let _ = apps::revoke(
                    &state_dir,
                    &mut record,
                    &source(),
                    &apps::master_key_here,
                    now,
                );
            }
        })
        .await;
    }
    no_store(StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------------------
// MCP

fn rpc_failure(status: StatusCode, code: i64, message: &str) -> Response {
    json_response(
        status,
        &json!({ "jsonrpc": "2.0", "id": null, "error": { "code": code, "message": message } }),
    )
}

async fn mcp(
    State(app): State<Arc<App>>,
    Extension(Caller(agent)): Extension<Caller>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        // No server-initiated stream and no sessions to end.
        let mut response = plain(StatusCode::METHOD_NOT_ALLOWED, "POST only");
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return response;
    }
    if let Some(version) = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        && !HTTP_PROTOCOLS.contains(&version)
    {
        return rpc_failure(
            StatusCode::BAD_REQUEST,
            -32600,
            "unsupported MCP-Protocol-Version",
        );
    }
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return rpc_failure(StatusCode::BAD_REQUEST, -32700, "parse error");
    };
    if !message.is_object() {
        return rpc_failure(StatusCode::BAD_REQUEST, -32600, "send one JSON-RPC message");
    }
    let line = message.to_string();
    let worker = app.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let mut server = worker.server_for(&agent)?;
        anyhow::Ok(handle_line(&mut server, &line))
    })
    .await;
    match reply {
        Ok(Ok(Some(text))) => {
            let mut response = (StatusCode::OK, text).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            no_store(response)
        }
        Ok(Ok(None)) => StatusCode::ACCEPTED.into_response(),
        Ok(Err(_)) | Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

#[cfg(test)]
#[path = "mcp_http_tests.rs"]
mod tests;

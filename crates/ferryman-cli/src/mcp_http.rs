//! `ferry mcp serve --http`: MCP over Streamable HTTP with its own authorization server
//! (ADR 0031, revised 2026-10-25: login and MCP live on the user's own machine).
//!
//! One process, one `/mcp` endpoint, plus the OAuth endpoints a cloud app needs
//! (`/.well-known/*`, `/register`, `/authorize`, `/token`). The listener is plain HTTP:
//! put it behind TLS (the edge/ACME step, or a tunnel you control). It answers only to the
//! one `Host` named by `--public-url`, and every `/mcp` request is checked for a live
//! access token for that exact resource before its body is read.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use serde_json::{Value, json};

use crate::mcp::{HTTP_PROTOCOLS, MAX_LINE_BYTES, Server, handle_line};
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
    /// The agent identity every app is bound to.
    pub agent: String,
    pub state_dir: PathBuf,
}

impl Config {
    pub fn new(
        addr: SocketAddr,
        public_url: Option<&str>,
        agent: &str,
        state_dir: PathBuf,
    ) -> Result<Self> {
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
            agent: ferryman_channel::canonical_agent_name(agent),
            state_dir,
        })
    }

    fn prm_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource/mcp", self.origin)
    }
}

/// The machine-local directory for tokens and pairing codes.
pub fn default_state_dir() -> Result<PathBuf> {
    ferryman_channel::licensing::machine_state_dir()
        .map(|dir| dir.join("mcp-http"))
        .context("no per-user state directory on this machine")
}

pub struct App {
    cfg: Config,
    server: Mutex<Server>,
    store: Mutex<Store>,
    /// Times of recent wrong pairing codes.
    failures: Mutex<Vec<i64>>,
}

impl App {
    pub fn new(server: Server, cfg: Config) -> Result<Arc<Self>> {
        let store = Store::open(&cfg.state_dir)?;
        Ok(Arc::new(Self {
            cfg,
            server: Mutex::new(server),
            store: Mutex::new(store),
            failures: Mutex::new(Vec::new()),
        }))
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The projects a remote app would see, and at which level.
    async fn projects(self: &Arc<Self>) -> Vec<(String, ferryman_channel::access::Level)> {
        let app = self.clone();
        tokio::task::spawn_blocking(move || {
            app.server
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remote_projects()
        })
        .await
        .unwrap_or_default()
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
        .route("/token", post(token).layer(small()))
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
pub fn run(server: Server, options: &HttpOptions, agent: &str) -> Result<()> {
    let state_dir = match &options.state_dir {
        Some(dir) => dir.clone(),
        None => default_state_dir()?,
    };
    let cfg = Config::new(
        options.addr,
        options.public_url.as_deref(),
        agent,
        state_dir,
    )?;
    let eligible = server.remote_projects();
    if eligible.is_empty() {
        bail!(
            "'{}' is not seated as a Worker or Member in any live project here, so there is nothing to serve. \
             Seat it first (ferry channel join --as {0}); Orchestrators and the master identity are never served over HTTP",
            cfg.agent
        );
    }
    let app = App::new(server, cfg.clone())?;
    let addr = options.addr;
    eprintln!("ferry mcp: connector URL {}", cfg.resource);
    eprintln!(
        "ferry mcp: serving {} project(s) as '{}' on http://{addr} (plain HTTP: keep it behind TLS)",
        eligible.len(),
        cfg.agent
    );
    eprintln!("ferry mcp: run `ferry mcp pair` for a one-time code to connect an app");
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

/// Auth before any parsing of the body: a live access token for this resource and this
/// identity, and an identity that is still eligible.
async fn require_token(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
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
    let valid =
        app.store()
            .verify_access(token, &app.cfg.resource, &app.cfg.agent, oauth::unix_now());
    if !valid {
        return unauthorized(&app, Some("invalid_token"));
    }
    if app.projects().await.is_empty() {
        return plain(
            StatusCode::FORBIDDEN,
            "this identity is not seated as a Worker or Member in any live project",
        );
    }
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
    challenge: String,
    state: Option<String>,
    scope: String,
    agent: String,
    projects: Vec<(String, ferryman_channel::access::Level)>,
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
    let projects = app.projects().await;
    if projects.is_empty() {
        return Err(Refused::Page(
            "This Ferryman has no identity it may share: it must be seated as a Worker or Member in a live project.",
        ));
    }
    let scope = if projects
        .iter()
        .any(|(_, level)| *level == ferryman_channel::access::Level::Member)
    {
        format!("{} {}", oauth::SCOPE_READ, oauth::SCOPE_WRITE)
    } else {
        oauth::SCOPE_READ.to_string()
    };
    Ok(Valid {
        client_id: client_id.into(),
        client_name,
        redirect_uri: redirect_uri.into(),
        challenge: challenge.into(),
        state,
        scope,
        agent: app.cfg.agent.clone(),
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
    let host = url::Url::parse(&valid.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();
    let seats: String = valid
        .projects
        .iter()
        .map(|(project, level)| {
            format!(
                "<li><code>{}</code> as {}</li>",
                escape(project),
                level.as_str()
            )
        })
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
         <p><b>{name}</b> wants to connect. After you enter the code, it is sent to <b>{host}</b>.</p>\
         <p>It will act as <code>{agent}</code> and see:</p><ul>{seats}</ul>\
         <p class=small>The app, and the company behind it, will receive everything it reads through this connection.</p>\
         {error}\
         <form method=post action=/authorize>{hidden}\
         <label>Pairing code<input name=pairing_code autocomplete=off autofocus required></label>\
         <button>Connect</button></form>\
         <p class=small>Get a code by running <code>ferry mcp pair</code> on this machine. It works once, for ten minutes.</p>",
        name = escape(&valid.client_name),
        host = escape(&host),
        agent = escape(&valid.agent),
    ))
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
    let code = app.store().issue_code(
        &CodeRequest {
            client_id: &valid.client_id,
            redirect_uri: &valid.redirect_uri,
            challenge: &valid.challenge,
            audience: &app.cfg.resource,
            scope: &valid.scope,
            agent: &app.cfg.agent,
        },
        now,
    );
    let mut pairs = vec![("code", code.as_str())];
    if let Some(state) = &valid.state {
        pairs.push(("state", state));
    }
    redirect(&valid.redirect_uri, &pairs)
}

// ---------------------------------------------------------------------------------------
// Token

async fn token(State(app): State<Arc<App>>, body: Bytes) -> Response {
    let params = form(&body);
    let now = oauth::unix_now();
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
        let mut server = worker.server.lock().unwrap_or_else(PoisonError::into_inner);
        handle_line(&mut server, &line)
    })
    .await;
    match reply {
        Ok(Some(text)) => {
            let mut response = (StatusCode::OK, text).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            no_store(response)
        }
        Ok(None) => StatusCode::ACCEPTED.into_response(),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

#[cfg(test)]
#[path = "mcp_http_tests.rs"]
mod tests;

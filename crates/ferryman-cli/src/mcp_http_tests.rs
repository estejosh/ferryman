//! Tests for `--all-projects`, the layout guard and the HTTP transport with its OAuth login.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::mcp::Server;
use crate::mcp_agent::{self, AllProjects};
use crate::mcp_oauth::{self as oauth, CLAUDE_CALLBACK};
use ferryman_channel::access::{self, Level};
use ferryman_channel::apps;
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};

const APP: &str = "claude-ai";
const MASTER: &str = "josh";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Fleet {
    dir: tempfile::TempDir,
    routes: Vec<ProjectRoute>,
}

/// Three projects; APP is a Worker in alpha, a Member in beta and an Orchestrator in gamma.
fn fleet() -> Fleet {
    let dir = tempfile::tempdir().unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
    let mut routes = Vec::new();
    for (project, level) in [
        ("alpha", Level::Worker),
        ("beta", Level::Member),
        ("gamma", Level::Orchestrator),
    ] {
        let workspace = dir.path().join(project).join("workspace");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: project.into(),
            workspace,
            attachment: attachment.clone(),
            communications: communications.clone(),
            shared_remote: format!("{project}-ferryman"),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for (name, role) in [(MASTER, "operator"), (APP, "worker")] {
            let identity = AgentIdentity::load_or_create(name, &attachment).unwrap();
            ferryman_channel::register_agent(
                &route,
                &AgentRoute {
                    name: name.into(),
                    role: role.into(),
                    capabilities: Vec::new(),
                    public_key: Some(identity.public_key_hex()),
                    encryption_key: None,
                },
            )
            .unwrap();
        }
        route.agents = ferryman_channel::read_agent_roster(&communications).unwrap();
        let master = AgentIdentity::load_existing(MASTER, &attachment)
            .unwrap()
            .unwrap();
        ferryman_channel::master::initialize_master(&route, &master, MASTER).unwrap();
        access::set_level(&route, &master, APP, level).unwrap();
        routes.push(route);
    }
    Fleet { dir, routes }
}

fn all(fleet: &Fleet, remote: bool) -> AllProjects {
    let routes = fleet.routes.clone();
    AllProjects::new(APP, false, remote, Arc::new(move || routes.clone())).unwrap()
}

fn levels(result: &Value) -> Vec<(String, String)> {
    result["structuredContent"]["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["project"].as_str().unwrap().to_string(),
                p["level"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

#[test]
fn all_projects_join_lists_the_seats_with_their_level() {
    let fleet = fleet();
    let local = all(&fleet, false);
    let joined = local.call("ferry_join", &json!({}));
    assert_eq!(joined["isError"], false, "{joined}");
    assert_eq!(
        levels(&joined),
        [
            pair("alpha", "worker"),
            pair("beta", "member"),
            pair("gamma", "orchestrator")
        ]
    );
    // Over HTTP an Orchestrator seat is never offered.
    let remote = all(&fleet, true).call("ferry_join", &json!({}));
    assert_eq!(
        levels(&remote),
        [pair("alpha", "worker"), pair("beta", "member")]
    );
    // With a project, join is that project's own join.
    let one = local.call("ferry_join", &json!({ "project": "beta" }));
    assert_eq!(one["structuredContent"]["project"], "beta");
    assert_eq!(one["structuredContent"]["level"], "member");
}

#[test]
fn all_projects_calls_need_a_project_and_keep_the_per_project_checks() {
    let fleet = fleet();
    let local = all(&fleet, false);
    let missing = local.call("ferry_catchup", &json!({}));
    assert_eq!(missing["isError"], true);
    assert!(
        missing["structuredContent"]["reason"]
            .as_str()
            .unwrap()
            .contains("pass project")
    );
    let unknown = local.call("ferry_catchup", &json!({ "project": "nope" }));
    assert_eq!(unknown["isError"], true);
    // A worker in alpha still cannot post; a member in beta can.
    let worker = local.call(
        "ferry_talk",
        &json!({ "project": "alpha", "action": "post", "to": "josh", "text": "hello" }),
    );
    assert_eq!(worker["isError"], true, "{worker}");
    assert_eq!(worker["structuredContent"]["error"], "denied");
    let member = local.call(
        "ferry_talk",
        &json!({ "project": "beta", "action": "post", "to": "josh", "text": "hello" }),
    );
    assert_eq!(member["isError"], false, "{member}");
    // The master identity is refused outright.
    let master = AllProjects::new(
        MASTER,
        false,
        false,
        Arc::new({
            let routes = fleet.routes.clone();
            move || routes.clone()
        }),
    )
    .unwrap();
    assert!(master.open().is_empty());
}

#[test]
fn the_tool_list_adds_a_project_argument_and_stays_byte_stable() {
    let fleet = fleet();
    let server = Server::with_all(all(&fleet, true), true);
    let first = serde_json::to_string(&server.tools()).unwrap();
    let again = serde_json::to_string(&Server::with_all(all(&fleet, true), true).tools()).unwrap();
    assert_eq!(first, again);
    for tool in server.tools() {
        assert_eq!(
            tool["inputSchema"]["properties"]["project"]["type"],
            "string"
        );
    }
    assert!(!first.contains("alpha") && !first.contains(APP));
    let tokens = mcp_agent::est_tokens(first.len());
    assert!(
        tokens <= 1500,
        "all-projects tools/list is {tokens} tokens, cap 1500"
    );
}

#[test]
fn no_tool_changes_the_folder_layout() {
    let fleet = fleet();
    let all = all(&fleet, false);
    for (tool, args) in [
        ("ferry_migrate", json!({ "project": "beta" })),
        ("ferry_layout", json!({ "project": "beta" })),
        (
            "ferry_orders",
            json!({ "project": "beta", "action": "migrate" }),
        ),
        (
            "ferry_primary",
            json!({ "project": "beta", "action": "relocate" }),
        ),
    ] {
        let result = all.call(tool, &args);
        assert_eq!(result["isError"], true, "{tool}: {result}");
        assert_eq!(result["structuredContent"]["error"], "denied");
        let why = result["structuredContent"]["reason"].as_str().unwrap();
        assert!(
            why.contains("fleet order") && why.contains("signed by the master"),
            "{why}"
        );
    }
    // Single-project agents say the same.
    let agent = mcp_agent::Agent::new(fleet.routes[1].clone(), APP, false).unwrap();
    let refused = agent.call("ferry_orders", &json!({ "action": "migrate" }));
    assert_eq!(refused["structuredContent"]["error"], "denied");
    // And no definition offers one.
    let defs = serde_json::to_string(&mcp_agent::core_tools())
        .unwrap()
        .to_lowercase();
    for word in ["migrate", "layout", "relocate"] {
        assert!(!defs.contains(word), "a tool definition mentions {word}");
    }
}

#[test]
fn the_instructions_and_join_say_how_ferryman_works() {
    let fleet = fleet();
    let mut server = Server::with_all(all(&fleet, false), false);
    let init = crate::mcp::handle_line(
        &mut server,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    )
    .unwrap();
    let init: Value = serde_json::from_str(&init).unwrap();
    let text = init["result"]["instructions"].as_str().unwrap();
    for needle in [
        "iroh",
        "fallback",
        "never handle transport",
        "fleet order migrate",
        "master-signed",
        "pass project",
    ] {
        assert!(text.contains(needle), "instructions lack '{needle}'");
    }
    let tokens = mcp_agent::est_tokens(text.len());
    assert!(
        tokens <= 360,
        "all-projects instructions are {tokens} tokens, cap 360"
    );
    let joined = all(&fleet, false).call("ferry_join", &json!({}));
    let how = joined["structuredContent"]["how"].as_str().unwrap();
    assert!(
        how.contains("iroh")
            && how.contains("fleet order migrate")
            && how.contains("No tool here changes the layout")
    );
    // Single-project join says it too.
    let single = mcp_agent::Agent::new(fleet.routes[0].clone(), APP, false).unwrap();
    assert_eq!(
        single.call("ferry_join", &json!({}))["structuredContent"]["how"],
        how
    );
}

#[test]
fn http_serves_only_worker_and_member_seats() {
    let fleet = fleet();
    let server = Server::with_all(all(&fleet, true), true);
    assert_eq!(
        server.remote_projects(),
        [
            ("alpha".to_string(), Level::Worker),
            ("beta".to_string(), Level::Member)
        ]
    );
    let boss = mcp_agent::Agent::new(fleet.routes[2].clone(), APP, false).unwrap();
    let alone = Server::with(fleet.routes[2].clone(), Some(boss), false);
    assert!(alone.remote_projects().is_empty());
}

#[test]
fn the_public_url_fixes_the_host_and_the_resource() {
    let loopback: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    let cfg = Config::new(loopback, Some("https://Mcp.Example.com/"), PathBuf::new()).unwrap();
    assert_eq!(cfg.resource, "https://mcp.example.com/mcp");
    assert_eq!(cfg.host, "mcp.example.com");
    let cfg = Config::new(
        loopback,
        Some("https://mcp.example.com:8443/mcp"),
        PathBuf::new(),
    )
    .unwrap();
    assert_eq!(
        (cfg.host.as_str(), cfg.resource.as_str()),
        ("mcp.example.com:8443", "https://mcp.example.com:8443/mcp")
    );
    assert!(Config::new(loopback, Some("http://mcp.example.com"), PathBuf::new()).is_err());
    assert!(
        Config::new(
            loopback,
            Some("https://mcp.example.com/other"),
            PathBuf::new()
        )
        .is_err()
    );
    let public: SocketAddr = "0.0.0.0:8787".parse().unwrap();
    assert!(Config::new(public, None, PathBuf::new()).is_err());
    assert_eq!(
        Config::new(loopback, None, PathBuf::new()).unwrap().host,
        "127.0.0.1:8787"
    );
}

// -- the HTTP server ---------------------------------------------------------------------

struct Live {
    app: Arc<App>,
    fleet: Fleet,
    base: String,
    cfg: Config,
    http: reqwest::Client,
}

async fn start() -> Live {
    let fleet = fleet();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = fleet.dir.path().join("mcp-state");
    let cfg = Config::new(addr, None, state).unwrap();
    let routes = fleet.routes.clone();
    let app = App::new(cfg.clone(), Arc::new(move || routes.clone())).unwrap();
    tokio::spawn(serve_listener(listener, app.clone()));
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Live {
        app,
        fleet,
        base: format!("http://{addr}"),
        cfg,
        http,
    }
}

fn encode(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// The query of a redirect `Location`.
fn query_of(response: &reqwest::Response) -> std::collections::HashMap<String, String> {
    let location = response.headers()["location"].to_str().unwrap();
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

const LOOPBACK: &str = "http://127.0.0.1:53211/callback";

impl Live {
    async fn form(&self, path: &str, pairs: &[(&str, &str)]) -> reqwest::Response {
        self.http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(encode(pairs))
            .send()
            .await
            .unwrap()
    }

    async fn register_as(&self, name: &str, redirect: &str) -> String {
        let response = self
            .http
            .post(format!("{}/register", self.base))
            .json(&json!({ "client_name": name, "redirect_uris": [redirect], "token_endpoint_auth_method": "none" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        response.json::<Value>().await.unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn register(&self) -> String {
        self.register_as("Claude", CLAUDE_CALLBACK).await
    }

    fn authorize_pairs<'a>(
        &'a self,
        client: &'a str,
        challenge: &'a str,
        resource: &'a str,
        code: &'a str,
    ) -> Vec<(&'a str, &'a str)> {
        vec![
            ("response_type", "code"),
            ("client_id", client),
            ("redirect_uri", CLAUDE_CALLBACK),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", "st4te"),
            ("resource", resource),
            ("pairing_code", code),
        ]
    }

    /// Log in with a fresh pairing code. The app is not given a code: it waits for the
    /// owner. Returns the wait token and the app's id.
    async fn login_to(&self, client: &str, redirect: &str) -> (String, String) {
        let pairing = oauth::mint_pairing_code(&self.cfg.state_dir, oauth::unix_now()).unwrap();
        let challenge = oauth::s256(VERIFIER);
        let mut pairs = self.authorize_pairs(client, &challenge, &self.cfg.resource, &pairing);
        pairs.iter_mut().for_each(|(k, v)| {
            if *k == "redirect_uri" {
                *v = redirect;
            }
        });
        let response = self.form("/authorize", &pairs).await;
        assert_eq!(response.status(), 200);
        let page = response.text().await.unwrap();
        assert!(page.contains("Waiting for your approval"), "{page}");
        assert!(!page.contains("fmcp_code"));
        let wait = page
            .split("url=/authorize/wait?w=")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string();
        let id = page
            .split("ferry mcp apps approve ")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_string();
        (wait, id)
    }

    async fn login(&self, client: &str) -> (String, String) {
        self.login_to(client, CLAUDE_CALLBACK).await
    }

    async fn wait(&self, wait: &str) -> reqwest::Response {
        self.http
            .get(format!("{}/authorize/wait?w={wait}", self.base))
            .send()
            .await
            .unwrap()
    }

    /// What the owner does at the terminal: sign the app in, here as the master.
    fn approve(&self, id: &str, level: Level, only: &[String]) -> apps::App {
        let mut app = apps::find(&self.cfg.state_dir, id).unwrap();
        apps::approve(
            &self.cfg.state_dir,
            &mut app,
            level,
            only,
            &self.fleet.routes,
            &apps::master_key_here,
            oauth::unix_now(),
        )
        .unwrap();
        app
    }

    /// Log in, get approved as a Worker everywhere, and take the authorization code.
    async fn authorize(&self, client: &str) -> String {
        let (wait, id) = self.login(client).await;
        self.approve(&id, Level::Worker, &[]);
        let response = self.wait(&wait).await;
        assert_eq!(response.status(), 302);
        let location = response.headers()["location"].to_str().unwrap();
        assert!(location.starts_with(CLAUDE_CALLBACK));
        let query = query_of(&response);
        assert_eq!(query["state"], "st4te");
        query["code"].clone()
    }

    async fn tokens_for(&self, client: &str, code: &str, redirect: &str) -> Value {
        let response = self
            .form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", client),
                    ("redirect_uri", redirect),
                    ("code_verifier", VERIFIER),
                    ("resource", &self.cfg.resource),
                ],
            )
            .await;
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }

    async fn tokens(&self, client: &str, code: &str) -> Value {
        self.tokens_for(client, code, CLAUDE_CALLBACK).await
    }

    async fn rpc(&self, token: Option<&str>, body: Value) -> reqwest::Response {
        let mut request = self.http.post(format!("{}/mcp", self.base)).json(&body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().await.unwrap()
    }

    async fn call(&self, token: &str, tool: &str, arguments: Value) -> Value {
        let body = json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": { "name": tool, "arguments": arguments } });
        let reply: Value = self.rpc(Some(token), body).await.json().await.unwrap();
        reply["result"].clone()
    }

    async fn ping(&self, token: &str) -> u16 {
        self.rpc(
            Some(token),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
        )
        .await
        .status()
        .as_u16()
    }
}

#[tokio::test]
async fn the_oauth_flow_works_end_to_end() {
    let live = start().await;

    // No token: 401 that points at the resource metadata.
    let denied = live
        .rpc(
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        )
        .await;
    assert_eq!(denied.status(), 401);
    let challenge = denied.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        challenge.starts_with("Bearer resource_metadata=\""),
        "{challenge}"
    );
    assert!(challenge.contains("/.well-known/oauth-protected-resource/mcp"));

    // Discovery: the resource is the connector URL, the AS is this origin, PKCE S256 only,
    // and token revocation is offered.
    let prm: Value = live
        .http
        .get(format!(
            "{}/.well-known/oauth-protected-resource",
            live.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["resource"], live.cfg.resource);
    assert_eq!(prm["authorization_servers"], json!([live.cfg.origin]));
    let meta: Value = live
        .http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            live.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(
        meta["registration_endpoint"],
        format!("{}/register", live.cfg.origin)
    );
    assert_eq!(
        meta["revocation_endpoint"],
        format!("{}/revoke", live.cfg.origin)
    );

    // Only the fixed Host is answered.
    let stray = live
        .http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            live.base
        ))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(stray.status(), 421);

    // Registration: a foreign redirect is refused, claude.ai's is accepted.
    let foreign = live
        .http
        .post(format!("{}/register", live.base))
        .json(&json!({ "redirect_uris": ["https://evil.example/cb"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), 400);
    assert_eq!(
        foreign.json::<Value>().await.unwrap()["error"],
        "invalid_redirect_uri"
    );
    let client = live.register().await;

    // The sign-in page names the redirect host and issues nothing.
    let challenge = oauth::s256(VERIFIER);
    let query = encode(&[
        ("response_type", "code"),
        ("client_id", &client),
        ("redirect_uri", CLAUDE_CALLBACK),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", "st4te"),
        ("resource", &live.cfg.resource),
    ]);
    let page = live
        .http
        .get(format!("{}/authorize?{query}", live.base))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let page = page.text().await.unwrap();
    assert!(
        page.contains("claude.ai")
            && page.contains("pairing_code")
            && page.contains("alpha")
            && page.contains("Worker")
            && !page.contains("fmcp_code")
    );

    // A wrong audience is refused at authorize, with no pairing code needed to learn it.
    let wrong = live
        .form(
            "/authorize",
            &live.authorize_pairs(&client, &challenge, "https://other.example/mcp", "X"),
        )
        .await;
    assert_eq!(wrong.status(), 302);
    assert!(
        wrong.headers()["location"]
            .to_str()
            .unwrap()
            .contains("error=invalid_target")
    );
    // A wrong pairing code is refused, and makes no identity.
    let bad = live
        .form(
            "/authorize",
            &live.authorize_pairs(&client, &challenge, &live.cfg.resource, "AAAAA-AAAAA"),
        )
        .await;
    assert_eq!(bad.status(), 403);
    assert!(apps::list(&live.cfg.state_dir).is_empty());
    let code = live.authorize(&client).await;

    // The token endpoint checks PKCE and the audience, then issues.
    let wrong_verifier = live
        .form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client),
                ("redirect_uri", CLAUDE_CALLBACK),
                ("code_verifier", &"v".repeat(50)),
            ],
        )
        .await;
    assert_eq!(wrong_verifier.status(), 400);
    assert_eq!(
        wrong_verifier.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
    let code = live.authorize(&client).await;
    let wrong_resource = live
        .form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &client),
                ("redirect_uri", CLAUDE_CALLBACK),
                ("code_verifier", VERIFIER),
                ("resource", "https://other.example/mcp"),
            ],
        )
        .await;
    assert_eq!(
        wrong_resource.json::<Value>().await.unwrap()["error"],
        "invalid_target"
    );
    let code = live.authorize(&client).await;
    let issued = live.tokens(&client, &code).await;
    assert_eq!(issued["token_type"], "Bearer");
    // A Worker app is offered read scope only.
    assert_eq!(issued["scope"], "ferry:read");
    let access = issued["access_token"].as_str().unwrap().to_string();
    let refresh = issued["refresh_token"].as_str().unwrap().to_string();

    // The token opens /mcp: initialize negotiates 2025-06-18, tools/list has the project
    // argument, ferry_join names the app's own identity and its seats.
    let init = live.rpc(Some(&access), json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } })).await;
    assert_eq!(init.status(), 200);
    let init: Value = init.json().await.unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("iroh")
    );
    let note = live
        .rpc(
            Some(&access),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
    assert_eq!(note.status(), 202);
    let list: Value = live
        .rpc(
            Some(&access),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        )
        .await
        .json()
        .await
        .unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(
        |t| t["name"] == "ferry_join" && t["inputSchema"]["properties"]["project"].is_object()
    ));
    let join = live.call(&access, "ferry_join", json!({})).await;
    assert_eq!(join["structuredContent"]["agent"], "claude-ai-josh-3");
    assert_eq!(
        levels(&join),
        [
            pair("alpha", "worker"),
            pair("beta", "worker"),
            pair("gamma", "worker")
        ]
    );

    // GET is not offered, and a body over the cap is refused.
    assert_eq!(
        live.http
            .get(format!("{}/mcp", live.base))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    // The server answers 413 without reading the body and closes; on some platforms the
    // client sees that as a reset while it is still writing, which is a refusal too.
    let big = live
        .http
        .post(format!("{}/mcp", live.base))
        .bearer_auth(&access)
        .body(vec![b' '; 2 << 20])
        .send()
        .await;
    match big {
        Ok(response) => assert_eq!(response.status(), 413),
        Err(error) => assert!(error.is_request(), "{error}"),
    }

    // Refresh rotates.
    let rotated = live
        .form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client),
            ],
        )
        .await;
    assert_eq!(rotated.status(), 200);
    let rotated: Value = rotated.json().await.unwrap();
    let (access2, refresh2) = (
        rotated["access_token"].as_str().unwrap().to_string(),
        rotated["refresh_token"].as_str().unwrap().to_string(),
    );
    assert_ne!(refresh, refresh2);
    assert_eq!(live.ping(&access2).await, 200);

    // Replaying the spent refresh token is invalid_grant and kills the whole grant.
    let replay = live
        .form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client),
            ],
        )
        .await;
    assert_eq!(replay.status(), 400);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
    assert_eq!(live.ping(&access2).await, 401);
    let dead = live
        .form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh2),
                ("client_id", &client),
            ],
        )
        .await;
    assert_eq!(
        dead.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn an_app_waits_for_the_owner_and_gets_no_code_until_approved() {
    let live = start().await;
    let client = live.register().await;
    let (wait, id) = live.login(&client).await;
    // Pending: a request exists, signed by its own key, with nothing granted anywhere.
    let app = apps::find(&live.cfg.state_dir, &id).unwrap();
    assert_eq!(
        (app.state, app.agent.as_str()),
        (apps::State::Pending, "claude-ai-josh")
    );
    for route in &live.fleet.routes {
        let roster = ferryman_channel::read_agent_roster(&route.communications).unwrap();
        assert!(!roster.iter().any(|a| a.name == app.agent));
    }
    // The page keeps waiting, and says how to approve.
    for _ in 0..2 {
        let still = live.wait(&wait).await;
        assert_eq!(still.status(), 200);
        let body = still.text().await.unwrap();
        assert!(body.contains("ferry mcp apps approve") && !body.contains("fmcp_code"));
    }
    // Garbage and spent wait tokens lead nowhere.
    assert_eq!(live.wait("nope").await.status(), 400);
    // The owner refuses: the app is sent access_denied and holds no key.
    let mut record = apps::find(&live.cfg.state_dir, &id).unwrap();
    apps::deny(&live.cfg.state_dir, &mut record, oauth::unix_now()).unwrap();
    let refused = live.wait(&wait).await;
    assert_eq!(refused.status(), 302);
    let query = query_of(&refused);
    assert_eq!(query["error"], "access_denied");
    assert_eq!(query["state"], "st4te");
    assert!(!query.contains_key("code"));
    assert!(apps::load_key(&live.cfg.state_dir, &app.agent).is_none());
    assert_eq!(live.wait(&wait).await.status(), 400);

    // Too slow: a login nobody approved in ten minutes is refused, not left open.
    let (late, id) = live.login(&client).await;
    live.app.waiting().get_mut(&late).unwrap().created -= apps::PENDING_SECS + 1;
    let slow = live.wait(&late).await;
    assert_eq!(slow.status(), 302);
    assert_eq!(query_of(&slow)["error"], "access_denied");
    assert_eq!(
        apps::find(&live.cfg.state_dir, &id).unwrap().state,
        apps::State::Denied
    );
}

#[tokio::test]
async fn each_app_speaks_as_its_own_identity_with_its_own_level() {
    let live = start().await;
    let claude = live.register().await;
    let chatgpt = live.register_as("ChatGPT", LOOPBACK).await;

    // Claude is approved as a Worker everywhere; ChatGPT as a Member in beta only.
    let (wait, id) = live.login(&claude).await;
    live.approve(&id, Level::Worker, &[]);
    let code = query_of(&live.wait(&wait).await)["code"].clone();
    let worker = live.tokens(&claude, &code).await;
    let (wait, id) = live.login_to(&chatgpt, LOOPBACK).await;
    live.approve(&id, Level::Member, &["beta".to_string()]);
    let code = query_of(&live.wait(&wait).await)["code"].clone();
    let member = live.tokens_for(&chatgpt, &code, LOOPBACK).await;
    assert_eq!(worker["scope"], "ferry:read");
    assert_eq!(member["scope"], "ferry:read ferry:write");
    let (worker, member) = (
        worker["access_token"].as_str().unwrap().to_string(),
        member["access_token"].as_str().unwrap().to_string(),
    );

    // Two identities, two names, two keys that are not the machine's.
    let a = live.call(&worker, "ferry_join", json!({})).await;
    let b = live.call(&member, "ferry_join", json!({})).await;
    assert_eq!(a["structuredContent"]["agent"], "claude-ai-josh");
    assert_eq!(b["structuredContent"]["agent"], "chatgpt-josh");
    assert_eq!(
        levels(&a),
        [
            pair("alpha", "worker"),
            pair("beta", "worker"),
            pair("gamma", "worker")
        ]
    );
    // Only where the master signed it: ChatGPT sees beta and nothing else.
    assert_eq!(levels(&b), [pair("beta", "member")]);
    let apps_now = apps::list(&live.cfg.state_dir);
    assert_eq!(apps_now.len(), 2);
    assert_ne!(apps_now[0].public_key, apps_now[1].public_key);
    assert!(
        apps_now
            .iter()
            .all(|a| a.level != Some(Level::Orchestrator))
    );

    // The levels hold at the tools: the Worker cannot post, the Member can, signed as itself.
    let post = |project: &str| json!({ "project": project, "action": "post", "to": "josh", "text": "hello" });
    let refused = live.call(&worker, "ferry_talk", post("beta")).await;
    assert_eq!(refused["isError"], true, "{refused}");
    assert_eq!(refused["structuredContent"]["error"], "denied");
    let sent = live.call(&member, "ferry_talk", post("beta")).await;
    assert_eq!(sent["isError"], false, "{sent}");
    let elsewhere = live.call(&member, "ferry_talk", post("alpha")).await;
    assert_eq!(elsewhere["isError"], true);
    // The app that took a seat in beta is who the ledger names.
    let beta = &live.fleet.routes[1];
    let messages = ferryman_channel::list_messages(beta).unwrap_or_default();
    assert!(
        messages.iter().any(|m| m.sender == "chatgpt-josh"),
        "{messages:?}"
    );

    // Usage is counted per app.
    let seen = apps_now
        .iter()
        .find(|a| a.agent == "chatgpt-josh")
        .map(|a| apps::usage(&live.cfg.state_dir, &a.id))
        .unwrap();
    assert!(seen.calls >= 3 && seen.last_used > 0, "{seen:?}");
}

#[tokio::test]
async fn revoking_an_app_ends_every_token_at_once_and_removes_everything() {
    let live = start().await;
    let client = live.register().await;
    let code = live.authorize(&client).await;
    let first = live.tokens(&client, &code).await;
    let (access, refresh) = (
        first["access_token"].as_str().unwrap().to_string(),
        first["refresh_token"].as_str().unwrap().to_string(),
    );
    // A second session of the same login, so there is more than one token to kill.
    let rotated = live
        .form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    let (access2, refresh2) = (
        rotated["access_token"].as_str().unwrap().to_string(),
        rotated["refresh_token"].as_str().unwrap().to_string(),
    );
    assert_eq!(live.ping(&access).await, 200);
    assert_eq!(live.ping(&access2).await, 200);
    let app = apps::list(&live.cfg.state_dir).remove(0);
    assert!(apps::load_key(&live.cfg.state_dir, &app.agent).is_some());

    // The owner revokes it from the terminal (the dashboard calls the same function).
    let mut record = apps::find(&live.cfg.state_dir, &app.id).unwrap();
    let done = apps::revoke(
        &live.cfg.state_dir,
        &mut record,
        &live.fleet.routes,
        &apps::master_key_here,
        oauth::unix_now(),
    )
    .unwrap();
    assert!(done.key_deleted);
    assert_eq!(done.signed, ["alpha", "beta", "gamma"]);

    // The server needs no restart: every token is dead at its next request.
    assert_eq!(live.ping(&access).await, 401);
    assert_eq!(live.ping(&access2).await, 401);
    let again = live
        .form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh2),
                ("client_id", &client),
            ],
        )
        .await;
    assert_eq!(again.status(), 400);
    assert_eq!(
        again.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
    // Key gone, grant signed down, revocation recorded by the master.
    assert!(apps::load_key(&live.cfg.state_dir, &app.agent).is_none());
    for route in &live.fleet.routes {
        assert_eq!(
            access::level_of(&route.communications, &route.project_id, &app.agent),
            Level::Worker
        );
        assert!(ferryman_channel::master::is_revoked(route, &app.agent).unwrap());
    }
    // And it cannot come back by itself: the same login makes a new identity.
    let (_, id) = live.login(&client).await;
    assert_ne!(
        apps::find(&live.cfg.state_dir, &id).unwrap().agent,
        app.agent
    );
}

#[tokio::test]
async fn the_revoke_endpoint_follows_rfc_7009() {
    let live = start().await;
    let client = live.register().await;
    let other = live.register().await;
    let code = live.authorize(&client).await;
    let issued = live.tokens(&client, &code).await;
    let (access, refresh) = (
        issued["access_token"].as_str().unwrap().to_string(),
        issued["refresh_token"].as_str().unwrap().to_string(),
    );
    let app = apps::list(&live.cfg.state_dir).remove(0);

    // Missing pieces are invalid_request; another client's token is invalid_client and
    // survives; an unknown token is a plain 200.
    let missing = live.form("/revoke", &[("client_id", &client)]).await;
    assert_eq!(missing.status(), 400);
    assert_eq!(
        missing.json::<Value>().await.unwrap()["error"],
        "invalid_request"
    );
    let stolen = live
        .form("/revoke", &[("token", &refresh), ("client_id", &other)])
        .await;
    assert_eq!(stolen.status(), 400);
    assert_eq!(
        stolen.json::<Value>().await.unwrap()["error"],
        "invalid_client"
    );
    assert_eq!(live.ping(&access).await, 200);
    let unknown = live
        .form(
            "/revoke",
            &[("token", "fmcp_rt_nothing"), ("client_id", &client)],
        )
        .await;
    assert_eq!(unknown.status(), 200);
    assert_eq!(live.ping(&access).await, 200);

    // Revoking the refresh token ends the session, the access token with it, and (it being
    // the app's only session) the app: its key is deleted and the owner's list says revoked.
    let ended = live
        .form(
            "/revoke",
            &[
                ("token", &refresh),
                ("client_id", &client),
                ("token_type_hint", "refresh_token"),
            ],
        )
        .await;
    assert_eq!(ended.status(), 200);
    assert_eq!(live.ping(&access).await, 401);
    let after = apps::find(&live.cfg.state_dir, &app.id).unwrap();
    assert_eq!(after.state, apps::State::Revoked);
    assert!(apps::load_key(&live.cfg.state_dir, &app.agent).is_none());
    for route in &live.fleet.routes {
        assert!(ferryman_channel::master::is_revoked(route, &app.agent).unwrap());
    }
    // Revoking again is still a success.
    let twice = live
        .form("/revoke", &[("token", &refresh), ("client_id", &client)])
        .await;
    assert_eq!(twice.status(), 200);
}

#[tokio::test]
async fn without_the_master_key_here_the_app_waits_for_a_grant_signed_elsewhere() {
    let live = start().await;
    let client = live.register().await;
    let (wait, id) = live.login(&client).await;
    // This machine cannot sign: the approval signs nothing and the request stays signed.
    let mut app = apps::find(&live.cfg.state_dir, &id).unwrap();
    let report = apps::approve(
        &live.cfg.state_dir,
        &mut app,
        Level::Worker,
        &[],
        &live.fleet.routes,
        &|_: &ProjectRoute| None,
        oauth::unix_now(),
    )
    .unwrap();
    assert!(report.signed.is_empty());
    assert_eq!(live.wait(&wait).await.status(), 200);
    // The master, on another machine, takes the request and signs the grant, which syncs back.
    let there = tempfile::tempdir().unwrap();
    let mut taken =
        apps::import(there.path(), &apps::request_file(&live.cfg.state_dir, &id)).unwrap();
    apps::approve(
        there.path(),
        &mut taken,
        Level::Worker,
        &[],
        &live.fleet.routes,
        &apps::master_key_here,
        oauth::unix_now(),
    )
    .unwrap();
    // The waiting browser now gets its code, with nothing done at this machine's terminal.
    let released = live.wait(&wait).await;
    assert_eq!(released.status(), 302);
    let code = query_of(&released)["code"].clone();
    let issued = live.tokens(&client, &code).await;
    assert_eq!(
        live.ping(issued["access_token"].as_str().unwrap()).await,
        200
    );
}

#[tokio::test]
async fn a_token_for_another_audience_is_not_accepted() {
    let live = start().await;
    let client = live.register().await;
    let code = live.authorize(&client).await;
    let issued = live.tokens(&client, &code).await;
    let access = issued["access_token"].as_str().unwrap();
    assert_eq!(live.ping(access).await, 200);
    // The same server restarted under a different public name does not honour it: the
    // grant's audience no longer equals the resource.
    let other = Config::new(
        format!("127.0.0.1:{}", live.cfg.host.rsplit(':').next().unwrap())
            .parse()
            .unwrap(),
        Some("https://elsewhere.example"),
        live.cfg.state_dir.clone(),
    )
    .unwrap();
    let store = oauth::Store::open(&other.state_dir).unwrap();
    let now = oauth::unix_now();
    assert_eq!(
        store
            .access_agent(access, &live.cfg.resource, now)
            .as_deref(),
        Some("claude-ai-josh")
    );
    assert_eq!(store.access_agent(access, &other.resource, now), None);
    // A garbage token is 401, and a token only speaks as the app it was issued to.
    assert_eq!(live.ping("fmcp_at_nope").await, 401);
    assert!(!store.verify_access(access, &live.cfg.resource, "someone-else", now));
}

#[tokio::test]
async fn five_wrong_pairing_codes_lock_the_login() {
    let live = start().await;
    let client = live.register().await;
    let challenge = oauth::s256(VERIFIER);
    for _ in 0..oauth::LOCKOUT_FAILURES {
        let wrong = live
            .form(
                "/authorize",
                &live.authorize_pairs(&client, &challenge, &live.cfg.resource, "ZZZZZ-ZZZZZ"),
            )
            .await;
        assert_eq!(wrong.status(), 403);
    }
    let pairing = oauth::mint_pairing_code(&live.cfg.state_dir, oauth::unix_now()).unwrap();
    let locked = live
        .form(
            "/authorize",
            &live.authorize_pairs(&client, &challenge, &live.cfg.resource, &pairing),
        )
        .await;
    assert_eq!(locked.status(), 429);
}

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
    let cfg = Config::new(
        loopback,
        Some("https://Mcp.Example.com/"),
        APP,
        PathBuf::new(),
    )
    .unwrap();
    assert_eq!(cfg.resource, "https://mcp.example.com/mcp");
    assert_eq!(cfg.host, "mcp.example.com");
    let cfg = Config::new(
        loopback,
        Some("https://mcp.example.com:8443/mcp"),
        APP,
        PathBuf::new(),
    )
    .unwrap();
    assert_eq!(
        (cfg.host.as_str(), cfg.resource.as_str()),
        ("mcp.example.com:8443", "https://mcp.example.com:8443/mcp")
    );
    assert!(
        Config::new(
            loopback,
            Some("http://mcp.example.com"),
            APP,
            PathBuf::new()
        )
        .is_err()
    );
    assert!(
        Config::new(
            loopback,
            Some("https://mcp.example.com/other"),
            APP,
            PathBuf::new()
        )
        .is_err()
    );
    let public: SocketAddr = "0.0.0.0:8787".parse().unwrap();
    assert!(Config::new(public, None, APP, PathBuf::new()).is_err());
    assert_eq!(
        Config::new(loopback, None, APP, PathBuf::new())
            .unwrap()
            .host,
        "127.0.0.1:8787"
    );
}

// -- the HTTP server ---------------------------------------------------------------------

struct Live {
    _fleet: Fleet,
    base: String,
    cfg: Config,
    http: reqwest::Client,
}

async fn start() -> Live {
    let fleet = fleet();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = fleet.dir.path().join("mcp-state");
    let cfg = Config::new(addr, None, APP, state).unwrap();
    let app = App::new(Server::with_all(all(&fleet, true), true), cfg.clone()).unwrap();
    tokio::spawn(serve_listener(listener, app));
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Live {
        _fleet: fleet,
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

    async fn register(&self) -> String {
        let response = self
            .http
            .post(format!("{}/register", self.base))
            .json(&json!({ "client_name": "Claude", "redirect_uris": [CLAUDE_CALLBACK], "token_endpoint_auth_method": "none" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        response.json::<Value>().await.unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_string()
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

    /// Run authorize with a fresh pairing code and return the authorization code.
    async fn authorize(&self, client: &str) -> String {
        let pairing = oauth::mint_pairing_code(&self.cfg.state_dir, oauth::unix_now()).unwrap();
        let challenge = oauth::s256(VERIFIER);
        let response = self
            .form(
                "/authorize",
                &self.authorize_pairs(client, &challenge, &self.cfg.resource, &pairing),
            )
            .await;
        assert_eq!(response.status(), 302);
        let location = response.headers()["location"].to_str().unwrap().to_string();
        let target = url::Url::parse(&location).unwrap();
        assert!(location.starts_with(CLAUDE_CALLBACK));
        let query: std::collections::HashMap<_, _> = target.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "st4te");
        query["code"].clone()
    }

    async fn tokens(&self, client: &str, code: &str) -> Value {
        let response = self
            .form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", client),
                    ("redirect_uri", CLAUDE_CALLBACK),
                    ("code_verifier", VERIFIER),
                    ("resource", &self.cfg.resource),
                ],
            )
            .await;
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }

    async fn rpc(&self, token: Option<&str>, body: Value) -> reqwest::Response {
        let mut request = self.http.post(format!("{}/mcp", self.base)).json(&body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().await.unwrap()
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

    // Discovery: the resource is the connector URL, the AS is this origin, PKCE S256 only.
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
    // A wrong pairing code is refused; a right one works once.
    let bad = live
        .form(
            "/authorize",
            &live.authorize_pairs(&client, &challenge, &live.cfg.resource, "AAAAA-AAAAA"),
        )
        .await;
    assert_eq!(bad.status(), 403);
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
    assert_eq!(issued["scope"], "ferry:read ferry:write");
    let access = issued["access_token"].as_str().unwrap().to_string();
    let refresh = issued["refresh_token"].as_str().unwrap().to_string();

    // The token opens /mcp: initialize negotiates 2025-06-18, tools/list has the project
    // argument, ferry_join lists the two Worker/Member seats and not the Orchestrator one.
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
    let join: Value = live.rpc(Some(&access), json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "ferry_join", "arguments": {} } })).await.json().await.unwrap();
    assert_eq!(
        levels(&join["result"]),
        [pair("alpha", "worker"), pair("beta", "member")]
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
    let big = live
        .http
        .post(format!("{}/mcp", live.base))
        .bearer_auth(&access)
        .body(vec![b' '; 2 << 20])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status(), 413);

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
    let ping = live
        .rpc(
            Some(&access2),
            json!({ "jsonrpc": "2.0", "id": 4, "method": "ping" }),
        )
        .await;
    assert_eq!(ping.status(), 200);

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
    let after = live
        .rpc(
            Some(&access2),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" }),
        )
        .await;
    assert_eq!(after.status(), 401);
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
async fn a_token_for_another_audience_is_not_accepted() {
    let live = start().await;
    let client = live.register().await;
    let code = live.authorize(&client).await;
    let issued = live.tokens(&client, &code).await;
    let access = issued["access_token"].as_str().unwrap();
    assert_eq!(
        live.rpc(
            Some(access),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })
        )
        .await
        .status(),
        200
    );
    // The same server restarted under a different public name does not honour it: the
    // grant's audience no longer equals the resource.
    let other = Config::new(
        format!("127.0.0.1:{}", live.cfg.host.rsplit(':').next().unwrap())
            .parse()
            .unwrap(),
        Some("https://elsewhere.example"),
        APP,
        live.cfg.state_dir.clone(),
    )
    .unwrap();
    let store = oauth::Store::open(&other.state_dir).unwrap();
    assert!(store.verify_access(access, &live.cfg.resource, APP, oauth::unix_now()));
    assert!(!store.verify_access(access, &other.resource, APP, oauth::unix_now()));
    // A garbage token and a token for another identity are both 401.
    assert_eq!(
        live.rpc(
            Some("fmcp_at_nope"),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })
        )
        .await
        .status(),
        401
    );
    assert!(!store.verify_access(
        access,
        &live.cfg.resource,
        "someone-else",
        oauth::unix_now()
    ));
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

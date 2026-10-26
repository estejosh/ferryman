//! Zero-config MCP: a new user adds the server to a client and it works (order mcp-zero-config).
//! Every test builds a temporary ferry root of 25 projects and starts the server with no flags.

use super::*;
use crate::mcp_agent::{self, RouteSource};
use ferryman_channel::access::{self, Level};
use ferryman_channel::{AgentIdentity, AgentRoute, Order, Priority};

const MASTER: &str = "josh";
const MEMBER: &str = "fang";

struct Root {
    _dir: tempfile::TempDir,
    routes: Vec<ProjectRoute>,
    master: AgentIdentity,
}

impl Root {
    fn source(&self) -> RouteSource {
        let routes = self.routes.clone();
        std::sync::Arc::new(move || routes.clone())
    }

    fn server(&self) -> Server {
        Server::zero_config(self.source(), false)
    }
}

/// A ferry root of `count` projects, each with a master and one Member agent.
fn root(count: usize) -> Root {
    let dir = tempfile::tempdir().unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
    let mut routes = Vec::new();
    for n in 0..count {
        let workspace = dir.path().join(format!("p{n:02}")).join("workspace");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: format!("proj{n:02}"),
            workspace,
            attachment: attachment.clone(),
            communications: communications.clone(),
            shared_remote: format!("proj{n:02}-ferryman"),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for (name, role) in [(MASTER, "operator"), (MEMBER, "worker")] {
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
        routes.push(route);
    }
    let master = AgentIdentity::load_existing(MASTER, &routes[0].attachment)
        .unwrap()
        .unwrap();
    Root {
        _dir: dir,
        routes,
        master,
    }
}

fn open_order(root: &Root, route: &ProjectRoute, id: &str, title: &str) {
    let mut order = Order {
        id: id.into(),
        project_id: route.project_id.clone(),
        issued_by: MASTER.into(),
        assigned_to: None,
        created_at: chrono::Utc::now(),
        payload: json!({ "task": title }),
        requires_review: true,
        requires_approval: false,
        depends_on: Vec::new(),
        signed_by: None,
        signature: None,
        result_contract: None,
        interface: None,
        touches: Vec::new(),
        needs: None,
        allow_overlap: false,
        priority: None::<Priority>,
    };
    root.master.sign_order(&mut order);
    ferryman_channel::issue_order(route, &order).unwrap();
}

fn rpc(server: &mut Server, line: &str) -> Value {
    serde_json::from_str(&handle_line(server, line).unwrap()).unwrap()
}

fn initialize(server: &mut Server, client: &str) -> Value {
    rpc(
        server,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":client,"version":"1"}}})
        .to_string(),
    )
}

fn tool(server: &mut Server, name: &str, args: Value) -> Value {
    let v = rpc(
        server,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":args}})
            .to_string(),
    );
    v["result"].clone()
}

fn ok(result: &Value) -> &Value {
    assert_eq!(result["isError"], false, "{result}");
    &result["structuredContent"]
}

#[test]
fn a_fresh_machine_starts_with_no_flags_and_is_seated_as_a_worker_everywhere() {
    let root = root(25);
    let mut server = root.server();
    let init = initialize(&mut server, "codex");
    assert!(init["result"]["instructions"].is_string());
    let join = tool(&mut server, "ferry_join", json!({}));
    let data = ok(&join);
    assert_eq!(data["granted"], true);
    assert_eq!(data["level"], "worker");
    assert_eq!(data["agent"], mcp_agent::app_name(Some("codex")));
    assert_eq!(data["total"], 25);
    for route in &root.routes {
        assert_eq!(
            access::level_of(&route.communications, &route.project_id, data["agent"].as_str().unwrap()),
            Level::Worker
        );
    }
}

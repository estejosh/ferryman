//! Zero-config MCP: a new user adds the server to a client and it works (order mcp-zero-config).
//! Every test builds a temporary ferry root of projects and starts the server with no flags.

use super::*;
use crate::mcp_agent::{self, AllProjects, RouteSource};
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

    /// `ferry mcp serve` with no flags.
    fn server(&self) -> Server {
        Server::zero_config(self.source(), false)
    }

    /// A seated Member, `fang`, over the same projects.
    fn member(&self) -> Server {
        let all = AllProjects::new(MEMBER, false, false, self.source()).unwrap();
        Server::with_all(all, false)
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

fn refused<'a>(result: &'a Value, kind: &str) -> &'a str {
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(result["structuredContent"]["error"], kind, "{result}");
    result["structuredContent"]["reason"].as_str().unwrap()
}

fn ids(page: &Value) -> Vec<String> {
    page["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["project"].as_str().unwrap().to_string())
        .collect()
}

fn order_ids(list: &Value) -> Vec<String> {
    list["orders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_fresh_machine_starts_with_no_flags_and_is_seated_as_a_worker_in_25_projects_paged() {
    let root = root(25);
    let mut server = root.server();
    let init = initialize(&mut server, "codex");
    assert_eq!(init["result"]["instructions"], mcp_agent::INSTRUCTIONS);
    let me = mcp_agent::app_name(Some("codex"));

    let first = tool(&mut server, "ferry_join", json!({}));
    let page1 = ok(&first).clone();
    assert_eq!(page1["granted"], true);
    assert_eq!(page1["level"], "worker");
    assert_eq!(page1["agent"], me);
    assert_eq!(page1["total"], 25);
    assert!(page1["can"]["worker"].as_str().unwrap().contains("claim"));
    assert_eq!(page1["guide"], mcp_agent::INSTRUCTIONS);
    // Paged, never silent: what is not here is counted and has a cursor.
    let shown = page1["shown"].as_u64().unwrap() as usize;
    assert_eq!(ids(&page1).len(), shown);
    assert!(shown >= 1 && shown < 25);
    assert_eq!(page1["hidden"], 25 - shown as u64);
    let mut seen = ids(&page1);
    let mut next = page1["next"].as_str().unwrap().to_string();
    assert!(next.starts_with('o'));
    while next.starts_with('o') {
        let page = tool(&mut server, "ferry_join", json!({ "since": next }));
        let page = ok(&page).clone();
        assert!(page.get("guide").is_none(), "the guide goes out once");
        seen.extend(ids(&page));
        next = page["next"].as_str().unwrap().to_string();
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 25, "every project is on some page");

    // The roster says what it is, and the level follows from it, in every project.
    for route in &root.routes {
        let roster = ferryman_channel::read_agent_roster(&route.communications).unwrap();
        let entry = roster.iter().find(|a| a.name == me).unwrap();
        assert_eq!(entry.role, access::APP_ROLE);
        assert_eq!(
            access::level_of(&route.communications, &route.project_id, &me),
            Level::Worker
        );
    }
    // The guide again, whenever it is wanted.
    let help = tool(&mut server, "ferry_help", json!({}));
    assert_eq!(ok(&help)["guide"], mcp_agent::INSTRUCTIONS);
    assert_eq!(ok(&help)["levels"]["worker"], 25);
}

#[test]
fn the_zero_config_agent_runs_the_whole_loop_to_awaiting_review() {
    let root = root(25);
    let route = &root.routes[3];
    open_order(&root, route, "o-loop", "Fix the flaky login test");
    open_order(
        &root,
        &root.routes[4],
        "o-elsewhere",
        "Another project's work",
    );
    let mut server = root.server();
    initialize(&mut server, "claude-code");
    let with = |extra: Value| {
        let mut args = json!({ "project": route.project_id });
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        args
    };

    let catchup = tool(&mut server, "ferry_catchup", with(json!({})));
    assert_eq!(ok(&catchup)["open"][0]["id"], "o-loop");
    // The full title, not a "~" cut.
    assert_eq!(ok(&catchup)["open"][0]["title"], "Fix the flaky login test");

    let listed = tool(
        &mut server,
        "ferry_orders",
        with(json!({ "action": "list" })),
    );
    let data = ok(&listed);
    assert_eq!(data["scope"], "open");
    assert_eq!(data["total"], 1);
    assert_eq!(data["hidden"], 0);
    assert_eq!(data["orders"][0]["id"], "o-loop");

    let claimed = tool(
        &mut server,
        "ferry_orders",
        with(json!({ "action": "claim", "id": "o-loop" })),
    );
    assert_eq!(ok(&claimed)["ok"], true);
    let shown = tool(
        &mut server,
        "ferry_orders",
        with(json!({ "action": "show", "id": "o-loop" })),
    );
    assert!(
        ok(&shown)["work_repo"]
            .as_str()
            .unwrap()
            .contains("workspace")
    );
    ok(&tool(
        &mut server,
        "ferry_orders",
        with(json!({ "action": "progress", "id": "o-loop", "note": "reproduced it" })),
    ));
    let submitted = tool(
        &mut server,
        "ferry_orders",
        with(json!({ "action": "submit", "id": "o-loop", "ref": "abc1234", "note": "fixed, tests pass" })),
    );
    assert_eq!(ok(&submitted)["state"], "awaiting_review");
    // Read with the roster as it is now: the app joined it after `route` was made.
    let mut fresh = route.clone();
    fresh.agents = ferryman_channel::read_agent_roster(&route.communications).unwrap();
    let task = ferryman_channel::read_task(&fresh, "o-loop").unwrap();
    assert!(matches!(
        task.state(),
        ferryman_channel::TaskState::AwaitingReview { .. }
    ));
}

#[test]
fn a_member_creates_an_order_and_another_worker_sees_it_in_list_open() {
    let root = root(25);
    let route = &root.routes[5];
    let mut member = root.member();
    let created = tool(
        &mut member,
        "ferry_orders",
        json!({ "project": route.project_id, "action": "create", "title": "Write the install guide",
                "task": "Cover codex and claude code.", "kind": "docs", "size": "small", "priority": "high" }),
    );
    let id = ok(&created)["id"].as_str().unwrap().to_string();
    assert_eq!(ok(&created)["state"], "open");
    // A second order that waits on the first.
    let later = tool(
        &mut member,
        "ferry_orders",
        json!({ "project": route.project_id, "action": "create", "title": "Review the install guide",
                "depends_on": [id] }),
    );
    let later_id = ok(&later)["id"].as_str().unwrap().to_string();

    let mut worker = root.server();
    initialize(&mut worker, "cursor");
    let mut args = json!({ "project": route.project_id, "action": "list" });
    let open = tool(&mut worker, "ferry_orders", args.clone());
    let listed = order_ids(ok(&open));
    assert!(listed.contains(&id) && listed.contains(&later_id));
    // Claimable is what the worker could take right now: not the one that waits.
    args["scope"] = json!("claimable");
    let claimable = tool(&mut worker, "ferry_orders", args.clone());
    assert_eq!(order_ids(ok(&claimable)), [id.clone()]);
    assert_eq!(ok(&claimable)["scope"], "claimable");
    // Signed by the member, who is the issuer, and set to come back reviewed.
    let task = ferryman_channel::read_task(route, &id).unwrap();
    assert_eq!(task.order.issued_by, MEMBER);
    assert!(task.order.requires_review);
    args["scope"] = json!("sideways");
    refused(&tool(&mut worker, "ferry_orders", args), "bad_request");
}

#[test]
fn a_worker_cannot_create_an_order_and_is_told_whom_to_ask() {
    let root = root(3);
    let mut worker = root.server();
    initialize(&mut worker, "codex");
    let result = tool(
        &mut worker,
        "ferry_orders",
        json!({ "project": "proj00", "action": "create", "title": "Do a thing" }),
    );
    let why = refused(&result, "denied");
    assert!(
        why.contains("worker") && why.contains("ferry_talk") && why.contains(MASTER),
        "{why}"
    );
    assert_eq!(
        ferryman_channel::list_tasks(&root.routes[0]).unwrap().len(),
        0
    );
}

#[test]
fn agents_never_approve_and_a_missing_order_is_called_that() {
    let root = root(3);
    let route = &root.routes[0];
    open_order(&root, route, "o-plain", "plain");
    let mut gated = ferryman_channel::read_task(route, "o-plain")
        .unwrap()
        .order;
    gated.id = "o-gated".into();
    gated.requires_approval = true;
    root.master.sign_order(&mut gated);
    ferryman_channel::issue_order(route, &gated).unwrap();

    let mut worker = root.server();
    initialize(&mut worker, "codex");
    let mut member = root.member();
    let review =
        |id: &str| json!({ "project": "proj00", "action": "review", "id": id, "verdict": "accept" });

    let why = refused(&tool(&mut worker, "ferry_orders", review("o-plain")), "denied").to_string();
    assert!(
        why.contains("agents never approve") && why.contains("ferry_talk"),
        "{why}"
    );

    // A result on the gated order: a member is told to ask the human.
    for args in [
        json!({ "project": "proj00", "action": "claim", "id": "o-gated" }),
        json!({ "project": "proj00", "action": "submit", "id": "o-gated", "ref": "abc1234", "note": "ready" }),
    ] {
        ok(&tool(&mut worker, "ferry_orders", args));
    }
    let result = tool(&mut member, "ferry_orders", review("o-gated"));
    let why = refused(&result, "denied");
    assert!(
        why.contains("agents never approve") && why.contains("ferry_ask_human"),
        "{why}"
    );

    // A missing order is "no such order", for a worker and a member alike, never os error 2.
    for server in [&mut worker, &mut member] {
        for action in ["review", "show", "claim"] {
            let r = tool(
                server,
                "ferry_orders",
                json!({ "project": "proj00", "action": action, "id": "nope", "verdict": "accept" }),
            );
            let why = refused(&r, "bad_request");
            assert!(why.contains("no such order"), "{action}: {why}");
            assert!(!why.contains("os error"), "{why}");
        }
    }
}

#[test]
fn a_stale_primary_is_reported_and_exactly_one_ask_is_raised() {
    let root = root(3);
    let route = &root.routes[1];
    // A retired machine name holds the lead, and has been silent for 17 days.
    let old = AgentIdentity::load_or_create("beastly", &route.attachment).unwrap();
    ferryman_channel::register_agent(
        route,
        &AgentRoute {
            name: "beastly".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(old.public_key_hex()),
            encryption_key: None,
        },
    )
    .unwrap();
    access::set_level(route, &root.master, "beastly", Level::Orchestrator).unwrap();
    ferryman_channel::marvin::take(route, &old, "leading", false).unwrap();
    let mut holding = ferryman_channel::marvin::read_holding(route, "beastly")
        .unwrap()
        .unwrap();
    holding.touched_at = chrono::Utc::now() - chrono::Duration::days(17);
    std::fs::write(
        ferryman_channel::marvin::holding_path(route, "beastly"),
        serde_json::to_vec(&holding).unwrap(),
    )
    .unwrap();
    let asks = || {
        ferryman_channel::questions::list(route)
            .into_iter()
            .filter(|(q, _)| q.id.starts_with("ask-stale-primary"))
            .count()
    };

    // A worker is told, and cannot write the channel, so it raises nothing.
    let mut worker = root.server();
    initialize(&mut worker, "codex");
    let caught = tool(&mut worker, "ferry_catchup", json!({ "project": "proj01" }));
    let primary = &ok(&caught)["primary"];
    assert_eq!(primary["stale"], true);
    assert_eq!(primary["silent_for"], "17 days");
    assert!(primary["fix"].as_str().unwrap().contains("beastly"));
    assert_eq!(asks(), 0);

    // A member says so and raises one ask to the human, however often it looks.
    let mut member = root.member();
    for _ in 0..2 {
        let caught = tool(&mut member, "ferry_catchup", json!({ "project": "proj01" }));
        assert_eq!(ok(&caught)["primary"]["stale"], true);
    }
    let status = tool(
        &mut member,
        "ferry_primary",
        json!({ "project": "proj01", "action": "status" }),
    );
    assert_eq!(ok(&status)["stale"], true);
    assert!(ok(&status)["fix"].as_str().unwrap().contains("master"));
    assert_eq!(asks(), 1);
    // A project whose primary is heard from is not stale.
    let fine = tool(&mut member, "ferry_catchup", json!({ "project": "proj00" }));
    assert!(ok(&fine)["primary"].get("stale").is_none());
}

#[test]
fn join_says_when_a_newer_release_is_published() {
    let root = root(2);
    let approval = ferryman_channel::release::ReleaseApproval {
        version: "99.0.0".into(),
        commit: "c0ffee".into(),
        approved_by: MASTER.into(),
        approved_at: chrono::Utc::now(),
        via: "test".into(),
        artifacts: Default::default(),
        signed_by: None,
        signature: None,
    };
    ferryman_channel::release::write_approval(&root.routes[0], &approval, &root.master).unwrap();
    let mut server = root.server();
    initialize(&mut server, "codex");
    let joined = tool(&mut server, "ferry_join", json!({}));
    assert_eq!(ok(&joined)["update"]["latest"], "99.0.0");
    assert!(mcp_agent::INSTRUCTIONS.contains("tell the human; never update mid-order"));
}

//! Tests for the MCP agent surface (ADR 0028): the permission matrix, continuity, approvals,
//! cursors, the secret guard, updates, and the token budget (`mcp_budget`).

use super::*;
use crate::mcp::{Server, handle_line};
use ferryman_channel::release::{ReleaseApproval, write_approval};
use ferryman_channel::{Order, Priority};

struct World {
    _dir: tempfile::TempDir,
    route: ProjectRoute,
    master: AgentIdentity,
}

const WORKER: &str = "wisp";
const MEMBER: &str = "fang";
const BOSS: &str = "boss";
const BOSS2: &str = "boss-two";
const OLD_PRIMARY: &str = "josh";

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
    let workspace = dir.path().join("workspace");
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    std::fs::create_dir_all(&communications).unwrap();
    let mut route = ProjectRoute {
        project_id: "demo".into(),
        workspace,
        attachment: attachment.clone(),
        communications: communications.clone(),
        shared_remote: "demo-ferryman".into(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    for (name, role) in [
        (OLD_PRIMARY, "operator"),
        (WORKER, "worker"),
        (MEMBER, "worker"),
        (BOSS, "worker"),
        (BOSS2, "worker"),
    ] {
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
    let master = AgentIdentity::load_existing(OLD_PRIMARY, &attachment)
        .unwrap()
        .unwrap();
    ferryman_channel::master::initialize_master(&route, &master, OLD_PRIMARY).unwrap();
    access::set_level(&route, &master, WORKER, Level::Worker).unwrap();
    access::set_level(&route, &master, BOSS, Level::Orchestrator).unwrap();
    access::set_level(&route, &master, BOSS2, Level::Orchestrator).unwrap();
    World {
        _dir: dir,
        route,
        master,
    }
}

fn agent(w: &World, name: &str) -> Agent {
    let mut agent = Agent::new(w.route.clone(), name, true);
    agent.public_release = Box::new(|_| None);
    agent
}

fn core_agent(w: &World, name: &str) -> Agent {
    let mut agent = Agent::new(w.route.clone(), name, false);
    agent.public_release = Box::new(|_| None);
    agent
}

fn call(agent: &Agent, tool: &str, args: Value) -> Value {
    agent.call(tool, &args)
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

fn tokens(value: &Value) -> usize {
    value.to_string().len() / 4
}

fn order(w: &World, id: &str, title: &str) -> Order {
    let mut order = Order {
        id: id.into(),
        project_id: w.route.project_id.clone(),
        issued_by: OLD_PRIMARY.into(),
        assigned_to: None,
        created_at: Utc::now(),
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
    w.master.sign_order(&mut order);
    order
}

fn issue(w: &World, id: &str, title: &str) {
    ferryman_channel::issue_order(&w.route, &order(w, id, title)).unwrap();
}

fn age_holding(w: &World, who: &str, minutes: i64) {
    let mut holding = marvin::read_holding(&w.route, who).unwrap().unwrap();
    holding.touched_at = Utc::now() - chrono::Duration::minutes(minutes);
    std::fs::write(
        marvin::holding_path(&w.route, who),
        serde_json::to_vec(&holding).unwrap(),
    )
    .unwrap();
}

fn take_as(w: &World, name: &str) {
    let identity = AgentIdentity::load_existing(name, &w.route.attachment)
        .unwrap()
        .unwrap();
    marvin::take(&w.route, &identity, "test", false).unwrap();
}

// -- the permission matrix ----------------------------------------------------------------

#[test]
fn a_worker_reads_but_every_channel_write_is_denied_by_level() {
    let w = world();
    issue(&w, "o-w", "something");
    let worker = agent(&w, WORKER);
    assert_eq!(worker.level(), Level::Worker);

    // Reads work.
    for (tool, args) in [
        ("ferry_join", json!({})),
        ("ferry_catchup", json!({})),
        ("ferry_orders", json!({ "action": "list" })),
        ("ferry_orders", json!({ "action": "show", "id": "o-w" })),
        ("ferry_talk", json!({ "action": "read" })),
        ("ferry_primary", json!({ "action": "status" })),
        ("ferry_primary", json!({ "action": "standby" })),
        ("ferry_ask_human", json!({ "action": "status" })),
    ] {
        ok(&call(&worker, tool, args));
    }

    // Writes are refused with the level named.
    for (tool, args) in [
        ("ferry_orders", json!({ "action": "claim", "id": "o-w" })),
        (
            "ferry_orders",
            json!({ "action": "progress", "id": "o-w", "note": "x" }),
        ),
        (
            "ferry_orders",
            json!({ "action": "submit", "id": "o-w", "ref": "abc123", "note": "done" }),
        ),
        (
            "ferry_orders",
            json!({ "action": "review", "id": "o-w", "verdict": "accept" }),
        ),
        (
            "ferry_talk",
            json!({ "action": "post", "to": BOSS, "text": "hello" }),
        ),
        (
            "ferry_ask_human",
            json!({ "action": "raise", "title": "t", "recommendation": "r", "reasoning": "w" }),
        ),
        ("ferry_primary", json!({ "action": "release" })),
        ("ferry_primary", json!({ "action": "takeover" })),
    ] {
        let result = call(&worker, tool, args.clone());
        let why = refused(&result, "denied");
        assert!(why.contains("worker"), "{tool} {args}: {why}");
    }
}

#[test]
fn a_worker_cannot_post_and_is_told_to_hand_in_instead() {
    let w = world();
    let result = call(
        &agent(&w, WORKER),
        "ferry_talk",
        json!({ "action": "post", "to": BOSS, "text": "hi" }),
    );
    let why = refused(&result, "denied");
    assert!(why.contains("hand-in"), "{why}");
}

#[test]
fn a_member_works_an_order_end_to_end_and_cannot_take_over() {
    let w = world();
    issue(&w, "o-m", "build the thing");
    let member = agent(&w, MEMBER);
    assert_eq!(member.level(), Level::Member);

    let listed = call(&member, "ferry_orders", json!({ "action": "list" }));
    assert_eq!(ok(&listed)["orders"][0]["id"], "o-m");

    assert_eq!(
        ok(&call(
            &member,
            "ferry_orders",
            json!({ "action": "claim", "id": "o-m" })
        ))["ok"],
        true
    );
    ok(&call(
        &member,
        "ferry_orders",
        json!({ "action": "progress", "id": "o-m", "note": "halfway" }),
    ));

    // A result is a reference and a short summary, never the work.
    let no_ref = call(
        &member,
        "ferry_orders",
        json!({ "action": "submit", "id": "o-m", "note": "done" }),
    );
    refused(&no_ref, "bad_request");
    let work = call(
        &member,
        "ferry_orders",
        json!({ "action": "submit", "id": "o-m", "ref": "abc1234", "note": "```rust\nfn main() {}\n```" }),
    );
    assert!(refused(&work, "bad_request").contains("work content"));
    let submitted = call(
        &member,
        "ferry_orders",
        json!({ "action": "submit", "id": "o-m", "ref": "abc1234", "note": "tests pass" }),
    );
    assert_eq!(ok(&submitted)["revision"], 1);

    // The author cannot review their own result; another agent can.
    let own = call(
        &member,
        "ferry_orders",
        json!({ "action": "review", "id": "o-m", "verdict": "accept" }),
    );
    assert!(refused(&own, "denied").contains("another agent"));
    let boss = agent(&w, BOSS);
    let reviewed = call(
        &boss,
        "ferry_orders",
        json!({ "action": "review", "id": "o-m", "verdict": "accept" }),
    );
    assert_eq!(ok(&reviewed)["accepted"], true);

    // Not an Orchestrator: no takeover, even when nobody is primary.
    let result = call(&member, "ferry_primary", json!({ "action": "takeover" }));
    assert!(refused(&result, "denied").contains("Orchestrator"));
}

#[test]
fn an_agent_cannot_submit_or_progress_an_order_it_does_not_hold() {
    let w = world();
    issue(&w, "o-x", "someone else's");
    let boss = agent(&w, BOSS);
    ok(&call(
        &boss,
        "ferry_orders",
        json!({ "action": "claim", "id": "o-x" }),
    ));
    let member = agent(&w, MEMBER);
    let result = call(
        &member,
        "ferry_orders",
        json!({ "action": "submit", "id": "o-x", "ref": "abc1234", "note": "mine now" }),
    );
    assert!(refused(&result, "refused").contains("do not hold"));
    let result = call(
        &member,
        "ferry_orders",
        json!({ "action": "progress", "id": "o-x", "note": "mine" }),
    );
    refused(&result, "refused");
}

#[test]
fn an_order_that_needs_the_master_cannot_be_accepted_by_an_agent() {
    let w = world();
    let mut gated = order(&w, "o-gate", "ship it");
    gated.requires_approval = true;
    w.master.sign_order(&mut gated);
    ferryman_channel::issue_order(&w.route, &gated).unwrap();
    let member = agent(&w, MEMBER);
    ok(&call(
        &member,
        "ferry_orders",
        json!({ "action": "claim", "id": "o-gate" }),
    ));
    ok(&call(
        &member,
        "ferry_orders",
        json!({ "action": "submit", "id": "o-gate", "ref": "abc1234", "note": "ready" }),
    ));
    let boss = agent(&w, BOSS);
    let result = call(
        &boss,
        "ferry_orders",
        json!({ "action": "review", "id": "o-gate", "verdict": "accept" }),
    );
    assert!(refused(&result, "denied").contains("master"));
}

#[test]
fn an_agent_with_no_key_is_told_it_is_locked_and_does_nothing() {
    let w = world();
    let stranger = agent(&w, "stranger");
    let result = call(
        &stranger,
        "ferry_talk",
        json!({ "action": "post", "to": BOSS, "text": "hi" }),
    );
    assert!(refused(&result, "denied").contains("worker"));
}

// -- continuity ----------------------------------------------------------------------------

#[test]
fn another_agent_takes_over_only_after_the_primary_has_been_silent() {
    let w = world();
    take_as(&w, OLD_PRIMARY);
    let boss = agent(&w, BOSS);

    // Heard from just now.
    let status = call(&boss, "ferry_primary", json!({ "action": "status" }));
    assert_eq!(ok(&status)["state"], "alive");
    assert_eq!(ok(&status)["primary"], OLD_PRIMARY);
    let result = call(&boss, "ferry_primary", json!({ "action": "takeover" }));
    assert!(refused(&result, "refused").contains("takeover needs"));

    // Quiet (11 minutes) is still not silent.
    age_holding(&w, OLD_PRIMARY, 11);
    assert_eq!(
        ok(&call(&boss, "ferry_primary", json!({ "action": "status" })))["state"],
        "quiet"
    );
    refused(
        &call(&boss, "ferry_primary", json!({ "action": "takeover" })),
        "refused",
    );

    // Silent: the rule says so, and a Member still cannot.
    age_holding(
        &w,
        OLD_PRIMARY,
        marvin::HOLDING_GOES_QUIET_AFTER_MINUTES + 1,
    );
    let status = call(
        &agent(&w, MEMBER),
        "ferry_primary",
        json!({ "action": "status" }),
    );
    assert_eq!(ok(&status)["state"], "silent");
    assert!(
        ok(&status)["rule"]
            .as_str()
            .unwrap()
            .contains("may take over")
    );
    refused(
        &call(
            &agent(&w, MEMBER),
            "ferry_primary",
            json!({ "action": "takeover" }),
        ),
        "denied",
    );

    // The Orchestrator takes over, says so on the channel, and is primary.
    let taken = call(&boss, "ferry_primary", json!({ "action": "takeover" }));
    assert_eq!(ok(&taken)["primary"], BOSS);
    assert_eq!(ok(&taken)["next"], "ferry_catchup");
    assert_eq!(
        marvin::current_holder(&w.route).unwrap().unwrap().agent,
        BOSS
    );
    let said: Vec<String> = ferryman_channel::list_messages(&w.route)
        .unwrap()
        .iter()
        .map(message_text)
        .collect();
    assert!(
        said.iter().any(|t| t == "taking over from josh"),
        "{said:?}"
    );

    // A second Orchestrator cannot take it while the new primary is heard from.
    refused(
        &call(
            &agent(&w, BOSS2),
            "ferry_primary",
            json!({ "action": "takeover" }),
        ),
        "refused",
    );
}

#[test]
fn a_paused_machine_cannot_take_over() {
    let w = world();
    take_as(&w, OLD_PRIMARY);
    age_holding(
        &w,
        OLD_PRIMARY,
        marvin::HOLDING_GOES_QUIET_AFTER_MINUTES + 5,
    );
    let marker = ferryman_ops::governor::pause_marker().unwrap();
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, "paused for the test").unwrap();
    let result = call(
        &agent(&w, BOSS),
        "ferry_primary",
        json!({ "action": "takeover" }),
    );
    assert!(refused(&result, "denied").contains("paused"));
    // Lifting the pause lets it through.
    std::fs::remove_file(&marker).unwrap();
    ok(&call(
        &agent(&w, BOSS),
        "ferry_primary",
        json!({ "action": "takeover" }),
    ));
}

#[test]
fn nobody_primary_lets_an_orchestrator_take_it_and_release_hands_it_on() {
    let w = world();
    let boss = agent(&w, BOSS);
    assert_eq!(
        ok(&call(&boss, "ferry_primary", json!({ "action": "status" })))["state"],
        "none"
    );
    ok(&call(
        &boss,
        "ferry_primary",
        json!({ "action": "takeover" }),
    ));
    ok(&call(
        &boss,
        "ferry_primary",
        json!({ "action": "release" }),
    ));
    // Released: the next one does not wait out the quiet period.
    ok(&call(
        &agent(&w, BOSS2),
        "ferry_primary",
        json!({ "action": "takeover" }),
    ));
    assert_eq!(
        marvin::current_holder(&w.route).unwrap().unwrap().agent,
        BOSS2
    );
}

#[test]
fn catchup_gives_the_successor_the_brief_and_decisions_within_caps() {
    let w = world();
    take_as(&w, OLD_PRIMARY);
    let mut brief = marvin::Brief::new(OLD_PRIMARY, "ship the MCP beta");
    brief.constraints = "no secrets in the channel\nwork stays in the repo".into();
    brief.decided = "- use the facade\n- no new crate".into();
    marvin::write_brief(&w.route, &brief, &w.master).unwrap();
    issue(&w, "o-1", "first");
    let caught = call(&agent(&w, BOSS), "ferry_catchup", json!({}));
    let data = ok(&caught);
    assert_eq!(data["brief"]["objective"], "ship the MCP beta");
    assert_eq!(data["decisions"].as_array().unwrap().len(), 2);
    assert_eq!(data["primary"]["name"], OLD_PRIMARY);
    assert_eq!(data["open"][0]["id"], "o-1");
    assert!(tokens(&caught) <= 800);
}

#[test]
fn the_primary_staying_busy_keeps_it_from_looking_quiet() {
    let w = world();
    // The Orchestrator holds Marvin, goes ten minutes without a call, then catches up.
    take_as(&w, BOSS);
    age_holding(&w, BOSS, 12);
    let boss = agent(&w, BOSS);
    assert_eq!(
        ok(&call(&boss, "ferry_primary", json!({ "action": "status" })))["state"],
        "quiet"
    );
    ok(&call(&boss, "ferry_catchup", json!({})));
    assert_eq!(
        ok(&call(&boss, "ferry_primary", json!({ "action": "status" })))["state"],
        "alive"
    );
}

// -- approvals -----------------------------------------------------------------------------

#[test]
fn an_agent_can_ask_the_human_but_never_approve() {
    let w = world();
    let member = agent(&w, MEMBER);
    let raised = call(
        &member,
        "ferry_ask_human",
        json!({
            "action": "raise", "title": "Spend $40 on a license?",
            "recommendation": "yes", "reasoning": "The build needs it."
        }),
    );
    let id = ok(&raised)["id"].as_str().unwrap().to_string();
    assert_eq!(ok(&raised)["state"], "pending");
    assert_eq!(
        ok(&call(
            &member,
            "ferry_ask_human",
            json!({ "action": "status", "id": id })
        ))["state"],
        "pending"
    );

    // There is no approve action, and the raise tool offers none.
    let result = call(
        &member,
        "ferry_ask_human",
        json!({ "action": "approve", "id": id }),
    );
    refused(&result, "bad_request");

    // An answer nobody signed does not count.
    let forged = ferryman_channel::questions::Answer {
        question_id: id.clone(),
        project_id: "demo".into(),
        answer: "approve".into(),
        by: OLD_PRIMARY.into(),
        answered_at: Utc::now(),
        signed_by: MEMBER.into(),
        signature: "00".repeat(64),
    };
    let path = w
        .route
        .communications
        .join("questions")
        .join(format!("{id}.answer.json"));
    std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert_eq!(
        ok(&call(
            &member,
            "ferry_ask_human",
            json!({ "action": "status", "id": id })
        ))["state"],
        "pending"
    );
    std::fs::remove_file(&path).unwrap();

    // The human's signed answer is read, as approved.
    ferryman_channel::questions::answer(&w.route, &id, "approve", OLD_PRIMARY, &w.master).unwrap();
    assert_eq!(
        ok(&call(
            &member,
            "ferry_ask_human",
            json!({ "action": "status", "id": id })
        ))["state"],
        "approved"
    );
    let caught = call(&member, "ferry_catchup", json!({}));
    assert_eq!(ok(&caught)["asks"][0]["state"], "approved");
}

#[test]
fn a_rejection_and_a_send_back_come_through_with_the_note() {
    let w = world();
    let member = agent(&w, MEMBER);
    let args = |t: &str| json!({ "action": "raise", "title": t, "recommendation": "do it", "reasoning": "because" });
    let a = ok(&call(&member, "ferry_ask_human", args("a")))["id"]
        .as_str()
        .unwrap()
        .to_string();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let b = ok(&call(&member, "ferry_ask_human", args("b")))["id"]
        .as_str()
        .unwrap()
        .to_string();
    ferryman_channel::questions::answer(&w.route, &a, "reject", OLD_PRIMARY, &w.master).unwrap();
    ferryman_channel::questions::answer(
        &w.route,
        &b,
        "Use the smaller plan instead",
        OLD_PRIMARY,
        &w.master,
    )
    .unwrap();
    assert_eq!(
        ok(&call(
            &member,
            "ferry_ask_human",
            json!({ "action": "status", "id": a })
        ))["state"],
        "rejected"
    );
    let sent_back = call(
        &member,
        "ferry_ask_human",
        json!({ "action": "status", "id": b }),
    );
    assert_eq!(ok(&sent_back)["state"], "sent_back");
    assert_eq!(ok(&sent_back)["note"], "Use the smaller plan instead");
}

#[test]
fn asking_refuses_secrets_and_oversize_reasoning() {
    let w = world();
    let member = agent(&w, MEMBER);
    let result = call(
        &member,
        "ferry_ask_human",
        json!({
            "action": "raise", "title": "key", "recommendation": "use it",
            "reasoning": "the token is ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        }),
    );
    assert!(refused(&result, "secret").contains("ferry channel secret"));
    let long = "x ".repeat(700);
    let result = call(
        &member,
        "ferry_ask_human",
        json!({
            "action": "raise", "title": "t", "recommendation": "r", "reasoning": long
        }),
    );
    refused(&result, "bad_request");
}

// -- talk, cursors ---------------------------------------------------------------------------

#[test]
fn talk_read_returns_only_what_is_new_and_acknowledges_it() {
    let w = world();
    let member = agent(&w, MEMBER);
    let boss = agent(&w, BOSS);
    for text in ["one", "two", "three"] {
        ok(&call(
            &member,
            "ferry_talk",
            json!({ "action": "post", "to": BOSS, "text": text }),
        ));
        std::thread::sleep(std::time::Duration::from_millis(3));
    }
    let peeked = call(
        &boss,
        "ferry_talk",
        json!({ "action": "read", "peek": true }),
    );
    assert_eq!(ok(&peeked)["messages"].as_array().unwrap().len(), 3);
    // Peek acknowledged nothing, so the same call returns the same three.
    assert_eq!(
        ok(&call(
            &boss,
            "ferry_talk",
            json!({ "action": "read", "peek": true })
        ))["messages"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let first = call(&boss, "ferry_talk", json!({ "action": "read" }));
    let data = ok(&first);
    assert_eq!(data["messages"][0]["text"], "one");
    assert_eq!(data["messages"][2]["text"], "three");
    let cursor = data["next"].as_str().unwrap().to_string();
    // Acknowledged: nothing left without a cursor, and nothing after the cursor.
    assert_eq!(
        ok(&call(&boss, "ferry_talk", json!({ "action": "read" })))["messages"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        ok(&call(
            &boss,
            "ferry_talk",
            json!({ "action": "read", "since": cursor })
        ))["messages"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    std::thread::sleep(std::time::Duration::from_millis(5));
    ok(&call(
        &member,
        "ferry_talk",
        json!({ "action": "post", "to": BOSS, "text": "four" }),
    ));
    let after = call(
        &boss,
        "ferry_talk",
        json!({ "action": "read", "since": cursor }),
    );
    assert_eq!(ok(&after)["messages"].as_array().unwrap().len(), 1);
    assert_eq!(ok(&after)["messages"][0]["text"], "four");
    // A cursor from nowhere is refused, not guessed at.
    refused(
        &call(
            &boss,
            "ferry_talk",
            json!({ "action": "read", "since": "zzz" }),
        ),
        "bad_request",
    );
}

#[test]
fn long_messages_come_back_as_links_and_resources_read_them() {
    let w = world();
    let member = agent(&w, MEMBER);
    let long = format!("{} end", "word ".repeat(150));
    ok(&call(
        &member,
        "ferry_talk",
        json!({ "action": "post", "to": BOSS, "text": long }),
    ));
    let boss = agent(&w, BOSS);
    let read = call(
        &boss,
        "ferry_talk",
        json!({ "action": "read", "peek": true }),
    );
    let row = &ok(&read)["messages"][0];
    assert_eq!(row["more"], true);
    assert!(row["text"].as_str().unwrap().chars().count() <= 300);
    let link = &read["content"][1];
    assert_eq!(link["type"], "resource_link");
    let uri = link["uri"].as_str().unwrap();
    assert!(uri.starts_with("ferry://demo/msg/"));
    let body = boss.read_resource(uri).unwrap();
    assert!(
        body["contents"][0]["text"]
            .as_str()
            .unwrap()
            .ends_with("end")
    );
    // Someone else's message is not yours to read.
    let other = agent(&w, MEMBER);
    let id = uri.rsplit('/').next().unwrap();
    ok(&call(
        &boss,
        "ferry_talk",
        json!({ "action": "post", "to": BOSS2, "text": "private" }),
    ));
    let private = ferryman_channel::list_messages(&w.route)
        .unwrap()
        .into_iter()
        .find(|m| message_text(m) == "private")
        .unwrap();
    assert!(
        other
            .read_resource(&format!("ferry://demo/msg/{}", private.id))
            .is_err()
    );
    assert!(
        other
            .read_resource(&format!("ferry://demo/msg/{id}"))
            .is_ok()
    );
}

#[test]
fn posting_refuses_secrets_telegram_strangers_and_work_content() {
    let w = world();
    let member = agent(&w, MEMBER);
    for text in [
        "here: sk-abcdefghijklmnopqrstuvwxyz0123",
        "DEEPSEEK_API_KEY=abcd1234efgh5678",
        "-----BEGIN OPENSSH PRIVATE KEY----- abc -----END OPENSSH PRIVATE KEY-----",
        "password: hunter2hunter2",
    ] {
        let result = call(
            &member,
            "ferry_talk",
            json!({ "action": "post", "to": BOSS, "text": text }),
        );
        assert!(
            refused(&result, "secret").contains("ferry channel secret"),
            "{text}"
        );
    }
    refused(
        &call(
            &member,
            "ferry_talk",
            json!({ "action": "post", "to": "nobody", "text": "hi" }),
        ),
        "bad_request",
    );
    refused(
        &call(
            &member,
            "ferry_talk",
            json!({ "action": "post", "to": "telegram", "text": "hi" }),
        ),
        "bad_request",
    );
    refused(
        &call(
            &member,
            "ferry_talk",
            json!({ "action": "post", "to": BOSS, "text": "```\ncode\n```" }),
        ),
        "bad_request",
    );
    // A commit sha is fine.
    ok(&call(
        &member,
        "ferry_talk",
        json!({ "action": "post", "to": BOSS, "text": "pushed 9f2c1a7d3e5b4c6a8f0e1d2c3b4a5f6e7d8c9b0a" }),
    ));
}

#[test]
fn the_secret_shape_guard_catches_tokens_and_spares_ordinary_text() {
    for bad in [
        "ghp_abcdefghijklmnopqrstuvwxyz012345",
        "xoxb-1234567890-abcdef",
        "AKIAABCDEFGHIJKLMNOP",
        "export STRIPE_SECRET=sk_live_abcdefgh1234",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyAxMjM0NTY3ODk=",
        "passphrase: correct-horse-battery",
        "AGE-SECRET-KEY-1ABCDEF",
    ] {
        assert!(secret_shape(bad).is_some(), "{bad}");
    }
    for fine in [
        "claimed o-12, tests pass",
        "commit 9f2c1a7d3e5b4c6a8f0e1d2c3b4a5f6e7d8c9b0a is on mcp-design",
        "see docs/adr/0028-mcp-server.md and crates/ferryman-cli/src/mcp.rs",
        "the password flow lives in the vault; use ferry channel secret",
        "https://github.com/estejosh/ferryman/pull/108",
    ] {
        assert_eq!(secret_shape(fine), None, "{fine}");
    }
}

// -- orders, snifrig fields --------------------------------------------------------------------

#[test]
fn a_heavy_order_shows_its_hints_and_runs_direct_until_snifrig_is_agreed() {
    let w = world();
    let mut heavy = order(&w, "o-heavy", "render the thing");
    heavy.needs = Some(ferryman_channel::work::ExplicitNeeds {
        heavy: true,
        hints: Some(ferryman_channel::work::ResourceHints {
            cores: Some(8),
            ram_gb: Some(16),
            gpu_mem_gb: Some(8),
            expected_minutes: Some(45),
        }),
        ..Default::default()
    });
    w.master.sign_order(&mut heavy);
    ferryman_channel::issue_order(&w.route, &heavy).unwrap();
    let shown = call(
        &agent(&w, MEMBER),
        "ferry_orders",
        json!({ "action": "show", "id": "o-heavy" }),
    );
    let data = ok(&shown);
    assert_eq!(data["heavy"], true);
    assert_eq!(data["hints"]["cores"], 8);
    assert_eq!(data["hints"]["expected_minutes"], 45);
    assert_eq!(data["run_via"], "direct");
    assert_eq!(shown["content"][1]["uri"], "ferry://demo/order/o-heavy");

    // An order without the fields is unchanged: no heavy, no hints.
    issue(&w, "o-plain", "plain");
    let plain = call(
        &agent(&w, MEMBER),
        "ferry_orders",
        json!({ "action": "show", "id": "o-plain" }),
    );
    assert!(ok(&plain).get("heavy").is_none());
    assert!(ok(&plain).get("hints").is_none());
}

#[test]
fn orders_list_pages_with_a_cursor_and_never_passes_twenty() {
    let w = world();
    for n in 0..45 {
        issue(&w, &format!("o-{n:02}"), &format!("order number {n}"));
    }
    let member = agent(&w, MEMBER);
    let first = call(&member, "ferry_orders", json!({ "action": "list" }));
    let rows = ok(&first)["orders"].as_array().unwrap().len();
    assert!((1..=MAX_ITEMS).contains(&rows), "{rows}");
    assert_eq!(ok(&first)["truncated"], true);
    assert!(tokens(&first) <= cap_tokens("ferry_orders"));
    let mut seen = BTreeSet::new();
    let mut cursor: Option<String> = None;
    for _ in 0..60 {
        let args = match &cursor {
            Some(c) => json!({ "action": "list", "since": c }),
            None => json!({ "action": "list" }),
        };
        let page = call(&member, "ferry_orders", args);
        for row in ok(&page)["orders"].as_array().unwrap() {
            assert!(seen.insert(row["id"].as_str().unwrap().to_string()));
        }
        match ok(&page).get("next").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 45);
}

#[test]
fn resources_stay_inside_the_channel() {
    let w = world();
    issue(&w, "o-r", "read me");
    let member = agent(&w, MEMBER);
    let body = member.read_resource("ferry://demo/order/o-r").unwrap();
    assert!(
        body["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("read me")
    );
    for bad in [
        "ferry://other/order/o-r",
        "ferry://demo/order/../secrets",
        "ferry://demo/order/..%2Fsecrets",
        "ferry://demo/secrets/keys",
        "file:///etc/passwd",
        "ferry://demo/order",
    ] {
        assert!(member.read_resource(bad).is_err(), "{bad}");
    }
}

// -- updates ----------------------------------------------------------------------------------

fn approve(w: &World, version: &str, signer: &AgentIdentity, approver: &str) {
    let approval = ReleaseApproval {
        version: version.into(),
        commit: "c0ffee".into(),
        approved_by: approver.into(),
        approved_at: Utc::now(),
        via: "test".into(),
        signed_by: None,
        signature: None,
    };
    write_approval(&w.route, &approval, signer).unwrap();
}

#[test]
fn the_update_field_is_absent_when_current_and_present_when_a_signed_release_is_newer() {
    let w = world();
    let boss = agent(&w, BOSS);
    let joined = call(&boss, "ferry_join", json!({}));
    assert!(ok(&joined).get("update").is_none());
    assert!(
        ok(&call(&boss, "ferry_catchup", json!({})))
            .get("update")
            .is_none()
    );

    approve(&w, "99.0.0", &w.master, OLD_PRIMARY);
    let joined = call(&boss, "ferry_join", json!({}));
    let update = &ok(&joined)["update"];
    assert_eq!(update["latest"], "99.0.0");
    assert_eq!(update["current"], env!("CARGO_PKG_VERSION"));
    assert_eq!(update["auto"], false); // no worker config in the fixture
    assert!(
        update["how"]
            .as_str()
            .unwrap()
            .contains("github.com/estejosh/ferryman/releases")
    );
    // About 40 tokens at most.
    assert!(tokens(update) <= 45, "{}", tokens(update));
    // The catch-up header carries it too.
    assert_eq!(
        ok(&call(&boss, "ferry_catchup", json!({})))["update"]["latest"],
        "99.0.0"
    );

    // A fleet machine (it has a worker config) is told the one-line command, and whether
    // the worker will apply it.
    std::fs::write(
        w.route.attachment.join("agent.toml"),
        "command = \"claude\"\n",
    )
    .unwrap();
    let fleet = call(&boss, "ferry_join", json!({}));
    assert_eq!(ok(&fleet)["update"]["how"], "ferry update");
}

#[test]
fn an_unsigned_or_non_master_release_is_ignored() {
    let w = world();
    let boss = agent(&w, BOSS);

    // Unsigned: a file with no signature at all.
    let path = ferryman_channel::release::approval_path(&w.route, OLD_PRIMARY);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let unsigned = ReleaseApproval {
        version: "98.0.0".into(),
        commit: "c0ffee".into(),
        approved_by: OLD_PRIMARY.into(),
        approved_at: Utc::now(),
        via: "x".into(),
        signed_by: None,
        signature: None,
    };
    std::fs::write(&path, serde_json::to_vec(&unsigned).unwrap()).unwrap();
    assert!(
        ok(&call(&boss, "ferry_join", json!({})))
            .get("update")
            .is_none()
    );

    // Signed, but by an agent that is not the master.
    let fang = AgentIdentity::load_existing(MEMBER, &w.route.attachment)
        .unwrap()
        .unwrap();
    approve(&w, "97.0.0", &fang, MEMBER);
    assert!(
        ok(&call(&boss, "ferry_join", json!({})))
            .get("update")
            .is_none()
    );

    // Signed by the master, then edited afterwards: the signature no longer holds.
    approve(&w, "96.0.0", &w.master, OLD_PRIMARY);
    let mut tampered: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    tampered["version"] = json!("999.0.0");
    std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(
        ok(&call(&boss, "ferry_join", json!({})))
            .get("update")
            .is_none()
    );

    // A version that is not newer than what runs is not an update.
    approve(&w, "0.0.1", &w.master, OLD_PRIMARY);
    assert!(
        ok(&call(&boss, "ferry_join", json!({})))
            .get("update")
            .is_none()
    );
}

#[test]
fn the_public_source_counts_through_the_same_filter() {
    let w = world();
    let mut boss = agent(&w, BOSS);
    boss.public_release = Box::new(|_| Some("v98.1.0".to_string()));
    assert_eq!(
        ok(&call(&boss, "ferry_join", json!({})))["update"]["latest"],
        "98.1.0"
    );
    // The newest of the two sources wins.
    approve(&w, "99.5.0", &w.master, OLD_PRIMARY);
    assert_eq!(
        ok(&call(&boss, "ferry_join", json!({})))["update"]["latest"],
        "99.5.0"
    );
    // Older than what runs: not shown.
    boss.public_release = Box::new(|_| Some("v0.0.2".to_string()));
    std::fs::remove_file(ferryman_channel::release::approval_path(
        &w.route,
        OLD_PRIMARY,
    ))
    .unwrap();
    assert!(
        ok(&call(&boss, "ferry_join", json!({})))
            .get("update")
            .is_none()
    );
}

#[test]
fn applying_an_update_is_refused_below_orchestrator_and_check_is_read_only() {
    let w = world();
    approve(&w, "99.0.0", &w.master, OLD_PRIMARY);
    for name in [WORKER, MEMBER] {
        let a = agent(&w, name);
        let result = call(&a, "ferry_update", json!({ "action": "apply" }));
        let why = refused(&result, "denied");
        assert!(why.contains("Orchestrator"), "{name}: {why}");
        // Check works at any level.
        let checked = call(&a, "ferry_update", json!({ "action": "check" }));
        assert_eq!(ok(&checked)["available"], true);
        assert_eq!(ok(&checked)["latest"], "99.0.0");
    }
    // An Orchestrator with nothing newer is told it is current (no download attempted).
    std::fs::remove_file(ferryman_channel::release::approval_path(
        &w.route,
        OLD_PRIMARY,
    ))
    .unwrap();
    let applied = call(
        &agent(&w, BOSS),
        "ferry_update",
        json!({ "action": "apply" }),
    );
    assert_eq!(ok(&applied)["available"], false);
}

#[test]
fn the_update_tool_exists_only_in_the_admin_group() {
    let w = world();
    let mut plain = Agent::new(w.route.clone(), BOSS, false);
    plain.public_release = Box::new(|_| None);
    refused(
        &call(&plain, "ferry_update", json!({ "action": "check" })),
        "bad_request",
    );
    let names: Vec<String> = admin_tools()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        ["ferry_get", "ferry_search", "ferry_status", "ferry_update"]
    );
    assert!(!core_tools().iter().any(|t| t["name"] == "ferry_update"));
}

// -- join ------------------------------------------------------------------------------------------

#[test]
fn join_says_who_you_are_and_who_is_primary_and_seats_a_new_agent() {
    let w = world();
    take_as(&w, OLD_PRIMARY);
    let boss = agent(&w, BOSS);
    let joined = call(&boss, "ferry_join", json!({}));
    let data = ok(&joined);
    assert_eq!(data["level"], "orchestrator");
    assert_eq!(data["granted"], true);
    assert_eq!(data["primary"]["name"], OLD_PRIMARY);
    assert_eq!(data["next"], "ferry_catchup");
    assert!(
        joined["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("Ferryman MCP (beta)")
    );

    // An app that has never been here gets a key, and takes its name on the roster.
    let newcomer = agent(&w, "claude-desktop-test");
    let joined = call(&newcomer, "ferry_join", json!({}));
    assert_eq!(ok(&joined)["granted"], true, "{joined}");
    assert_eq!(ok(&joined)["level"], "worker");
    assert!(
        ferryman_channel::read_agent_roster(&w.route.communications)
            .unwrap()
            .iter()
            .any(|a| a.name == "claude-desktop-test" && a.public_key.is_some())
    );
    // And it did not claim to be the fleet's MCP gateway.
    assert!(
        !ferryman_channel::read_agent_roster(&w.route.communications)
            .unwrap()
            .iter()
            .any(ferryman_channel::discovery::is_mcp)
    );
    // Joining again is the same answer.
    assert_eq!(
        ok(&call(&newcomer, "ferry_join", json!({})))["granted"],
        true
    );
}

// -- the server ------------------------------------------------------------------------------------

fn rpc(server: &mut Server, line: &Value) -> Value {
    serde_json::from_str(&handle_line(server, &line.to_string()).unwrap()).unwrap()
}

#[test]
fn a_scripted_session_runs_end_to_end_over_json_rpc() {
    let w = world();
    issue(&w, "o-e2e", "end to end");
    let mut server = Server::with(w.route.clone(), Some(core_agent(&w, MEMBER)), false);

    let init = rpc(
        &mut server,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
    );
    assert!(
        init["result"]["serverInfo"]["version"]
            .as_str()
            .unwrap()
            .ends_with("-beta")
    );
    assert_eq!(init["result"]["instructions"], INSTRUCTIONS);
    assert!(init["result"]["capabilities"]["resources"].is_object());
    assert!(
        handle_line(
            &mut server,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .is_none()
    );

    let listed = rpc(
        &mut server,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "ferry_ask_human",
            "ferry_catchup",
            "ferry_join",
            "ferry_orders",
            "ferry_primary",
            "ferry_talk"
        ]
    );
    for tool in listed["result"]["tools"].as_array().unwrap() {
        assert!(tool["outputSchema"].is_object());
        assert!(tool["inputSchema"].is_object());
    }

    let mut id = 10;
    let mut tool = |server: &mut Server, name: &str, args: Value| {
        id += 1;
        rpc(server, &json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": args } }))["result"].clone()
    };
    let joined = tool(&mut server, "ferry_join", json!({}));
    assert_eq!(joined["structuredContent"]["agent"], MEMBER);
    let caught = tool(&mut server, "ferry_catchup", json!({}));
    assert_eq!(caught["structuredContent"]["open"][0]["id"], "o-e2e");
    // A repeat with the cursor is one line.
    let cursor = caught["structuredContent"]["next"]
        .as_str()
        .unwrap()
        .to_string();
    let again = tool(&mut server, "ferry_catchup", json!({ "since": cursor }));
    assert_eq!(again["structuredContent"]["unchanged"], true);
    assert_eq!(
        tool(
            &mut server,
            "ferry_orders",
            json!({ "action": "claim", "id": "o-e2e" })
        )["structuredContent"]["ok"],
        true
    );
    let submitted = tool(
        &mut server,
        "ferry_orders",
        json!({ "action": "submit", "id": "o-e2e", "ref": "deadbeef", "note": "done" }),
    );
    assert_eq!(submitted["structuredContent"]["revision"], 1);
    let posted = tool(
        &mut server,
        "ferry_talk",
        json!({ "action": "post", "to": BOSS, "text": "submitted o-e2e" }),
    );
    assert_eq!(posted["isError"], false);
    // The next catch-up differs: the cursor moved.
    let changed = tool(&mut server, "ferry_catchup", json!({ "since": cursor }));
    assert!(changed["structuredContent"].get("unchanged").is_none());

    // A tool the group does not carry is an error, not a guess.
    let admin = tool(&mut server, "ferry_status", json!({}));
    assert_eq!(admin["isError"], true);
    let legacy = tool(&mut server, "channel_status", json!({}));
    assert_eq!(legacy["isError"], true);

    let read = rpc(
        &mut server,
        &json!({ "jsonrpc": "2.0", "id": 99, "method": "resources/read", "params": { "uri": "ferry://demo/order/o-e2e" } }),
    );
    assert!(
        read["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("end to end")
    );
    let bad = rpc(
        &mut server,
        &json!({ "jsonrpc": "2.0", "id": 100, "method": "resources/read", "params": { "uri": "ferry://demo/order/../../x" } }),
    );
    assert!(bad["error"].is_object());
}

#[test]
fn the_groups_add_tools_and_read_only_serves_only_the_old_ones() {
    let w = world();
    let core_only = Server::with(w.route.clone(), Some(core_agent(&w, MEMBER)), false);
    assert_eq!(core_only.tools().len(), 6);
    // Admin and legacy are opt-in; asked for, they are appended after the core six.
    let mut admin = Agent::new(w.route.clone(), MEMBER, true);
    admin.public_release = Box::new(|_| None);
    let with_both = Server::with(w.route.clone(), Some(admin), true);
    let names: Vec<String> = with_both
        .tools()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names.len(), 6 + 4 + 8);
    assert!(
        names.contains(&"ferry_update".to_string()) && names.contains(&"list_ledger".to_string())
    );
    // --read-only: the stranger surface, with no agent tools at all.
    let mut read_only = Server::with(w.route.clone(), None, true);
    assert_eq!(read_only.tools().len(), 8);
    let result = rpc(
        &mut read_only,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "ferry_talk", "arguments": { "action": "post" } } }),
    );
    assert_eq!(result["result"]["isError"], true);
    // The agent group's tools are not even described to a read-only client.
    assert!(
        !read_only
            .tools()
            .iter()
            .any(|t| t["name"].as_str().unwrap().starts_with("ferry_"))
    );
}

// -- the token budget (T1-T10) ----------------------------------------------------------------

/// Round up to the next ten so a stray timestamp digit cannot flip a snapshot.
fn bucket(n: usize) -> usize {
    n.div_ceil(10) * 10
}

#[test]
fn mcp_budget() {
    let w = world();
    let boss = agent(&w, BOSS);

    // T1: the core tool list.
    let core = core_tools();
    let core_tokens = serde_json::to_string(&core).unwrap().len() / 4;
    assert!(
        core_tokens <= 1500,
        "core tools/list is {core_tokens} tokens, cap 1500"
    );
    let mut per_tool = BTreeMap::new();
    for tool in &core {
        per_tool.insert(
            tool["name"].as_str().unwrap().to_string(),
            bucket(tokens(tool)),
        );
    }

    // T3: instructions.
    let instructions = INSTRUCTIONS.len() / 4;
    assert!(
        instructions <= 250,
        "instructions are {instructions} tokens, cap 250"
    );

    // T8: byte-stable. Different agent, different time, different project state: the same
    // bytes, sorted, with no version, time or agent name inside a definition.
    let first = serde_json::to_string(
        &Server::with(w.route.clone(), Some(core_agent(&w, BOSS)), false).tools(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    issue(&w, "o-bytes", "changes the channel");
    let second = serde_json::to_string(
        &Server::with(w.route.clone(), Some(core_agent(&w, MEMBER)), false).tools(),
    )
    .unwrap();
    assert_eq!(
        first, second,
        "tools/list must not depend on time, agent or channel state"
    );
    assert!(!first.contains(env!("CARGO_PKG_VERSION")));
    for name in [BOSS, MEMBER, "demo"] {
        assert!(!first.contains(name), "a definition carries '{name}'");
    }
    let names: Vec<&str> = core.iter().map(|t| t["name"].as_str().unwrap()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    // T9: every tool has an output schema.
    assert!(core.iter().all(|t| t["outputSchema"]["type"] == "object"));
    // T2: the opt-in groups cost nothing by default.
    assert!(!first.contains("ferry_search") && !first.contains("list_ledger"));

    // T6/T10: catch-up on a busy channel: 200 ledger entries, 40 open orders.
    take_as(&w, OLD_PRIMARY);
    let mut brief = marvin::Brief::new(
        OLD_PRIMARY,
        "Make the fleet ship the MCP beta without anyone babysitting the machines or reading the whole history",
    );
    brief.constraints = (1..=8)
        .map(|n| {
            format!("constraint {n}: keep the secrets out of the channel and the work in the repo")
        })
        .collect::<Vec<_>>()
        .join("\n");
    brief.decided = (1..=25).map(|n| format!("- decision {n}: we agreed to do the thing in this particular way because of the reasons discussed")).collect::<Vec<_>>().join("\n");
    marvin::write_brief(&w.route, &brief, &w.master).unwrap();
    for n in 0..40 {
        issue(
            &w,
            &format!("order-{n:03}"),
            &format!(
                "Implement part {n} of the long running feature with a deliberately lengthy title"
            ),
        );
    }
    for n in 0..5 {
        let _ = boss.call(
            "ferry_orders",
            &json!({ "action": "claim", "id": format!("order-{n:03}") }),
        );
    }
    for n in 0..200 {
        ferryman_channel::ledger::append_ledger_entry(
            &w.route,
            &w.master,
            "note",
            OLD_PRIMARY,
            &format!("ledger entry {n} with a summary of some length to be realistic"),
            None,
        )
        .unwrap();
    }
    for n in 0..12 {
        ok(&call(
            &agent(&w, MEMBER),
            "ferry_talk",
            json!({ "action": "post", "to": BOSS, "text": format!("message {n}: please look at order-{n:03}, I need a decision on the approach") }),
        ));
    }
    let caught = call(&boss, "ferry_catchup", json!({}));
    let catchup = tokens(&caught);
    assert!(
        catchup <= 800,
        "catch-up is {catchup} tokens on the busy fixture, cap 800"
    );
    assert!(
        ok(&caught)["open"].as_array().unwrap().len() >= 5,
        "the digest should still say something"
    );
    let detailed = call(&boss, "ferry_catchup", json!({ "detail": true }));
    assert!(tokens(&detailed) <= 800);
    assert!(serde_json::to_string(ok(&detailed)).unwrap().len() <= MAX_CHARS);

    // Typical responses against their caps.
    let mut typical = BTreeMap::new();
    let mut check = |label: &str, tool: &str, result: Value| {
        let t = tokens(&result);
        assert!(
            t <= cap_tokens(tool),
            "{label} is {t} tokens, cap {}",
            cap_tokens(tool)
        );
        assert!(
            serde_json::to_string(&result["structuredContent"])
                .unwrap()
                .len()
                <= MAX_CHARS
        );
        for value in result["structuredContent"].as_object().unwrap().values() {
            if let Some(items) = value.as_array() {
                assert!(
                    items.len() <= MAX_ITEMS,
                    "{label}: more than {MAX_ITEMS} items"
                );
            }
        }
        typical.insert(label.to_string(), bucket(t));
    };
    check(
        "ferry_join",
        "ferry_join",
        call(&boss, "ferry_join", json!({})),
    );
    check("ferry_catchup", "ferry_catchup", caught.clone());
    check(
        "ferry_orders list",
        "ferry_orders",
        call(&boss, "ferry_orders", json!({ "action": "list" })),
    );
    check(
        "ferry_orders show",
        "ferry_orders",
        call(
            &boss,
            "ferry_orders",
            json!({ "action": "show", "id": "order-010" }),
        ),
    );
    check(
        "ferry_orders claim",
        "ferry_orders",
        call(
            &boss,
            "ferry_orders",
            json!({ "action": "claim", "id": "order-020" }),
        ),
    );
    check(
        "ferry_talk read",
        "ferry_talk",
        call(
            &boss,
            "ferry_talk",
            json!({ "action": "read", "peek": true }),
        ),
    );
    check(
        "ferry_talk post",
        "ferry_talk",
        call(
            &boss,
            "ferry_talk",
            json!({ "action": "post", "to": MEMBER, "text": "ack" }),
        ),
    );
    check(
        "ferry_primary status",
        "ferry_primary",
        call(&boss, "ferry_primary", json!({ "action": "status" })),
    );
    let asked = call(
        &boss,
        "ferry_ask_human",
        json!({ "action": "raise", "title": "Pick a plan", "recommendation": "plan B", "reasoning": "cheaper and just as fast" }),
    );
    check("ferry_ask_human raise", "ferry_ask_human", asked.clone());
    check(
        "ferry_ask_human status",
        "ferry_ask_human",
        call(
            &boss,
            "ferry_ask_human",
            json!({ "action": "status", "id": asked["structuredContent"]["id"] }),
        ),
    );

    // The unconditional caps hold even for a flood of messages: 60 long messages in.
    for n in 0..60 {
        ok(&call(
            &agent(&w, MEMBER),
            "ferry_talk",
            json!({ "action": "post", "to": BOSS2, "text": format!("flood {n} {}", "lorem ipsum ".repeat(60)) }),
        ));
    }
    let flood = call(
        &agent(&w, BOSS2),
        "ferry_talk",
        json!({ "action": "read", "peek": true }),
    );
    check("ferry_talk read flood", "ferry_talk", flood.clone());
    assert_eq!(ok(&flood)["truncated"], true);

    // A committed snapshot makes growth visible in review. UPDATE_MCP_BUDGET=1 rewrites it.
    let snapshot = json!({
        "note": "Estimated tokens (chars / 4), rounded up to ten. Regenerate with UPDATE_MCP_BUDGET=1 cargo test -p ferryman-cli mcp_budget",
        "caps": { "core_tools_list": 1500, "instructions": 250, "catchup_busy": 800 },
        "core_tools_list": bucket(core_tokens),
        "instructions": bucket(instructions),
        "catchup_busy": bucket(catchup),
        "tool_definitions": per_tool,
        "typical_responses": typical,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mcp_budget.json");
    let rendered = serde_json::to_string_pretty(&snapshot).unwrap() + "\n";
    if std::env::var("UPDATE_MCP_BUDGET").is_ok_and(|v| v == "1") {
        std::fs::write(&path, &rendered).unwrap();
    } else {
        let committed = std::fs::read_to_string(&path).expect("tests/mcp_budget.json is committed");
        assert_eq!(
            committed.replace("\r\n", "\n"),
            rendered,
            "the MCP token budget changed; if that is intended, regenerate tests/mcp_budget.json with UPDATE_MCP_BUDGET=1"
        );
    }
}

use std::collections::BTreeMap;

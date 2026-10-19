//! The read cache: what it saves, and what it must never hide.

use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use chrono::Utc;
use ferryman_channel::{
    AgentIdentity, AgentRoute, Order, ProjectRoute, TaskResult, list_tasks, read_task,
    readcache::remembered_under,
};
use serde_json::json;

fn agent(identity: &AgentIdentity, role: &str) -> AgentRoute {
    AgentRoute {
        name: identity.name().to_string(),
        role: role.to_string(),
        capabilities: Vec::new(),
        public_key: Some(identity.public_key_hex()),
        encryption_key: None,
    }
}

fn route(dir: &Path, wisp: &AgentIdentity, boss: &AgentIdentity) -> ProjectRoute {
    let workspace = dir.join("workspace");
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    std::fs::create_dir_all(communications.join("tasks")).unwrap();
    ProjectRoute {
        project_id: "cache".into(),
        workspace,
        attachment,
        communications,
        shared_remote: "cache-ferryman".into(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: vec![agent(wisp, "worker"), agent(boss, "operator")],
    }
}

fn write(path: &Path, value: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn order(route: &ProjectRoute, boss: &AgentIdentity, id: &str) {
    let dir = route.communications.join("tasks").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    let mut order = Order {
        id: id.into(),
        project_id: route.project_id.clone(),
        issued_by: "boss".into(),
        assigned_to: Some("wisp".into()),
        created_at: Utc::now(),
        payload: json!({ "task": "write the report" }),
        requires_review: false,
        requires_approval: false,
        depends_on: Vec::new(),
        signed_by: None,
        signature: None,
        result_contract: None,
        interface: None,
        touches: Vec::new(),
        needs: None,
        allow_overlap: false,
        priority: None,
    };
    boss.sign_order(&mut order);
    write(&dir.join("order.json"), &order);
}

fn result(route: &ProjectRoute, wisp: &AgentIdentity, id: &str, revision: u32) {
    let mut result = TaskResult {
        order_id: id.into(),
        agent: "wisp".into(),
        revision,
        submitted_at: Utc::now(),
        payload: json!({ "output": "done" }),
        signed_by: None,
        signature: None,
    };
    wisp.sign_result(&mut result);
    write(
        &route
            .communications
            .join("tasks")
            .join(id)
            .join(format!("result.wisp.{revision:03}.json")),
        &result,
    );
}

fn settle() {
    sleep(Duration::from_millis(2300));
}

#[test]
fn a_task_that_has_not_changed_is_not_read_again_and_one_that_has_is() {
    let dir = tempfile::tempdir().unwrap();
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let route = route(dir.path(), &wisp, &boss);
    order(&route, &boss, "t-1");
    result(&route, &wisp, "t-1", 1);

    // Written a moment ago: not yet believed, so not remembered.
    assert_eq!(list_tasks(&route).unwrap()[0].results.len(), 1);
    assert_eq!(remembered_under(&route.communications), 0);

    settle();
    assert_eq!(list_tasks(&route).unwrap()[0].results.len(), 1);
    assert_eq!(remembered_under(&route.communications), 1);
    assert_eq!(list_tasks(&route).unwrap()[0].results.len(), 1);

    // A new file in the folder is seen on the next read.
    result(&route, &wisp, "t-1", 2);
    assert_eq!(read_task(&route, "t-1").unwrap().results.len(), 2);
}

#[test]
fn a_file_swapped_for_one_of_the_same_size_is_seen() {
    let dir = tempfile::tempdir().unwrap();
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let route = route(dir.path(), &wisp, &boss);
    order(&route, &boss, "t-1");
    result(&route, &wisp, "t-1", 1);
    settle();
    assert_eq!(list_tasks(&route).unwrap()[0].results.len(), 1);
    assert_eq!(remembered_under(&route.communications), 1);

    // Same name and same length, but forged: signed by someone the roster does not know.
    let forger = AgentIdentity::from_seed("wisp", [8; 32]);
    result(&route, &forger, "t-1", 1);
    assert!(list_tasks(&route).unwrap()[0].results.is_empty());
}

#[test]
fn a_roster_or_key_change_judges_every_signature_again() {
    let dir = tempfile::tempdir().unwrap();
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let mut route = route(dir.path(), &wisp, &boss);
    order(&route, &boss, "t-1");
    result(&route, &wisp, "t-1", 1);
    settle();
    assert_eq!(list_tasks(&route).unwrap()[0].results.len(), 1);
    assert_eq!(remembered_under(&route.communications), 1);

    // The agent leaves the roster: its result no longer counts.
    let before = route.agents.clone();
    route.agents.retain(|a| a.name != "wisp");
    assert!(list_tasks(&route).unwrap()[0].results.is_empty());

    // A key rotation (a revocation of the old one) does the same.
    route.agents = before.clone();
    route.agents[0].public_key = Some(AgentIdentity::from_seed("wisp", [1; 32]).public_key_hex());
    assert!(list_tasks(&route).unwrap()[0].results.is_empty());

    // And putting it back is believed again.
    route.agents = before;
    assert_eq!(list_tasks(&route).unwrap()[0].results.len(), 1);
}

#[test]
fn a_task_that_has_gone_is_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let route = route(dir.path(), &wisp, &boss);
    order(&route, &boss, "t-1");
    order(&route, &boss, "t-2");
    settle();
    assert_eq!(list_tasks(&route).unwrap().len(), 2);
    assert_eq!(remembered_under(&route.communications), 2);
    std::fs::remove_dir_all(route.communications.join("tasks/t-2")).unwrap();
    assert_eq!(list_tasks(&route).unwrap().len(), 1);
    assert_eq!(remembered_under(&route.communications), 1);
}

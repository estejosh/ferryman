//! Order priority: signed, defaulted by who issued it, and the order a worker takes work in.

use std::path::Path;

use chrono::{Duration, Utc};
use ferryman_channel::{
    AgentIdentity, AgentRoute, Order, Priority, ProjectRoute, SignatureCheck, claim_order,
    issue_order, verify_order, work_for,
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

struct Rig {
    _dir: tempfile::TempDir,
    route: ProjectRoute,
    boss: AgentIdentity,
    bot: AgentIdentity,
    wisp: AgentIdentity,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
    let boss = AgentIdentity::from_seed("boss", [9; 32]);
    let bot = AgentIdentity::from_seed("bot", [3; 32]);
    let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
    let workspace = dir.path().join("workspace");
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    std::fs::create_dir_all(communications.join("tasks")).unwrap();
    let route = ProjectRoute {
        project_id: "prio".into(),
        workspace,
        attachment,
        communications,
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: vec![
            agent(&boss, "operator"),
            agent(&bot, "worker"),
            agent(&wisp, "worker"),
        ],
    };
    for who in [&boss, &bot, &wisp] {
        let role = route
            .agents
            .iter()
            .find(|a| a.name == who.name())
            .unwrap()
            .clone();
        ferryman_channel::register_agent(&route, &role).unwrap();
    }
    Rig {
        _dir: dir,
        route,
        boss,
        bot,
        wisp,
    }
}

fn order(id: &str, by: &str, age_minutes: i64, priority: Option<Priority>) -> Order {
    Order {
        id: id.into(),
        project_id: "prio".into(),
        issued_by: by.into(),
        assigned_to: None,
        created_at: Utc::now() - Duration::minutes(age_minutes),
        payload: json!({ "task": id }),
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
        priority,
    }
}

fn issue(rig: &Rig, mut order: Order) {
    match order.issued_by.as_str() {
        "boss" => rig.boss.sign_order(&mut order),
        _ => rig.bot.sign_order(&mut order),
    }
    issue_order(&rig.route, &order).unwrap();
}

fn queue(rig: &Rig, who: &str) -> Vec<String> {
    work_for(&rig.route, who)
        .unwrap()
        .into_iter()
        .map(|task| task.order.id)
        .collect()
}

#[test]
fn an_order_without_the_field_reads_as_normal_and_keeps_its_bytes() {
    let rig = rig();
    let mut old = order("old", "boss", 0, None);
    rig.boss.sign_order(&mut old);
    // Written as it always was: no field at all.
    let text = serde_json::to_string(&old).unwrap();
    assert!(!text.contains("priority"), "{text}");
    let read: Order = serde_json::from_str(&text).unwrap();
    assert_eq!(read.priority, None);
    assert_eq!(read.priority(), Priority::Normal);
    assert_eq!(
        verify_order(&read, &rig.route.agents),
        SignatureCheck::Valid
    );
}

#[test]
fn the_priority_is_signed_and_cannot_be_changed_after() {
    let rig = rig();
    let mut high = order("hi", "boss", 0, Some(Priority::High));
    rig.boss.sign_order(&mut high);
    assert_eq!(
        verify_order(&high, &rig.route.agents),
        SignatureCheck::Valid
    );
    // Bumped, lowered or stripped after signing: not the order that was signed.
    for changed in [Some(Priority::Low), Some(Priority::Normal), None] {
        let mut forged = high.clone();
        forged.priority = changed;
        assert_eq!(
            verify_order(&forged, &rig.route.agents),
            SignatureCheck::Invalid,
            "{changed:?}"
        );
    }
    // And one signed without it cannot be promoted.
    let mut plain = order("plain", "boss", 0, None);
    rig.boss.sign_order(&mut plain);
    plain.priority = Some(Priority::High);
    assert_eq!(
        verify_order(&plain, &rig.route.agents),
        SignatureCheck::Invalid
    );
}

#[test]
fn a_priority_this_version_does_not_know_does_not_make_the_order_unreadable() {
    let rig = rig();
    let mut order = order("future", "boss", 0, Some(Priority::High));
    rig.boss.sign_order(&mut order);
    let mut value = serde_json::to_value(&order).unwrap();
    value["priority"] = json!("urgent");
    let read: Order = serde_json::from_value(value).unwrap();
    assert_eq!(read.priority, None);
    // It was signed as something else, so it is refused rather than run at a guess.
    assert_eq!(
        verify_order(&read, &rig.route.agents),
        SignatureCheck::Invalid
    );
}

#[test]
fn an_order_without_a_priority_is_worked_at_its_issuers_default() {
    let rig = rig();
    let people = ferryman_channel::people(&rig.route);
    assert!(people.contains("boss") && !people.contains("bot"));
    let by = |who: &str| {
        let mut order = order("d", who, 0, None);
        match who {
            "boss" => rig.boss.sign_order(&mut order),
            _ => rig.bot.sign_order(&mut order),
        }
        order
    };
    // A person's order that names no priority is high, an agent's is normal, and nothing
    // was written into either.
    assert_eq!(by("boss").effective_priority(&people), Priority::High);
    assert_eq!(by("bot").effective_priority(&people), Priority::Normal);
    assert_eq!(by("boss").priority, None);
    // An order nobody signed gets the person default.
    assert_eq!(
        order("u", "bot", 0, None).effective_priority(&people),
        Priority::High
    );
    // A signed priority wins over the role.
    let mut low = order("l", "boss", 0, Some(Priority::Low));
    rig.boss.sign_order(&mut low);
    assert_eq!(low.effective_priority(&people), Priority::Low);
    assert_eq!(Priority::parse("HIGH").unwrap(), Priority::High);
    assert!(Priority::parse("urgent").is_err());
}
#[test]
fn a_worker_takes_the_highest_priority_first_then_the_oldest() {
    let rig = rig();
    issue(&rig, order("a-normal-old", "bot", 50, None));
    issue(&rig, order("b-low-oldest", "boss", 90, Some(Priority::Low)));
    issue(&rig, order("c-high-new", "boss", 5, Some(Priority::High)));
    issue(
        &rig,
        order("d-high-older", "boss", 30, Some(Priority::High)),
    );
    issue(
        &rig,
        order("e-normal-new", "bot", 10, Some(Priority::Normal)),
    );
    assert_eq!(
        queue(&rig, "wisp"),
        [
            "d-high-older",
            "c-high-new",
            "a-normal-old",
            "e-normal-new",
            "b-low-oldest"
        ]
    );
    // A person's order that names no priority is worked ahead of an agent's older one.
    issue(&rig, order("f-person-default", "boss", 1, None));
    assert_eq!(queue(&rig, "wisp")[2], "f-person-default");
}

#[test]
fn a_new_high_priority_order_never_displaces_work_already_held() {
    let rig = rig();
    issue(&rig, order("held-low", "boss", 60, Some(Priority::Low)));
    claim_order(&rig.route, "held-low", rig.wisp.name()).unwrap();
    issue(&rig, order("urgent", "boss", 1, Some(Priority::High)));
    // What is in hand comes first; the new order is next, not ahead.
    assert_eq!(queue(&rig, "wisp"), ["held-low", "urgent"]);
    let _ = Path::new("");
}

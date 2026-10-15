use super::*;
use chrono::Utc;
use ferryman_channel::{AgentIdentity, AgentRoute, Order, ProjectRoute};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn hermetic() {
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-orders-selftest-{}", std::process::id())),
    );
}

fn josh() -> AgentIdentity {
    AgentIdentity::from_seed("josh", [7u8; 32])
}

fn mallory() -> AgentIdentity {
    AgentIdentity::from_seed("mallory", [9u8; 32])
}

fn task_dir(route: &ProjectRoute, id: &str) -> PathBuf {
    route.communications.join("tasks").join(id)
}

fn channel_of(root: &Root, id: &str) -> PathBuf {
    let channel = root.comms_home(id);
    fs::create_dir_all(&channel).unwrap();
    let master = josh();
    let route = ProjectRoute {
        project_id: id.into(),
        workspace: channel.clone(),
        attachment: channel.clone(),
        communications: channel.clone(),
        shared_remote: format!("{id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    for (name, key) in [
        ("josh", master.public_key_hex()),
        ("mallory", mallory().public_key_hex()),
    ] {
        ferryman_channel::register_agent(
            &route,
            &AgentRoute {
                name: name.into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(key),
                encryption_key: None,
            },
        )
        .unwrap();
    }
    let route = ProjectRoute {
        agents: ferryman_channel::read_agent_roster(&channel).unwrap(),
        ..route
    };
    ferryman_channel::master::initialize_master(&route, &master, "josh").unwrap();
    root.adopt(id, &channel, None).unwrap();
    channel
}

fn route_of(root: &Root, id: &str) -> ProjectRoute {
    let entry = entry_of(root, id).unwrap();
    entry.route(root).unwrap().0
}

fn issue(route: &ProjectRoute, id: &str, to: Option<&str>) {
    let mut order = Order {
        id: id.into(),
        project_id: route.project_id.clone(),
        issued_by: "josh".into(),
        assigned_to: to.map(str::to_owned),
        created_at: Utc::now(),
        payload: json!({ "task": "do the thing" }),
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
    };
    josh().sign_order(&mut order);
    ferryman_channel::issue_order(route, &order).unwrap();
}

fn world() -> (tempfile::TempDir, Root, ProjectRoute) {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    channel_of(&root, "quantly");
    let route = route_of(&root, "quantly");
    (dir, root, route)
}

fn as_josh() -> impl FnMut(&Entry, &str) -> Result<AgentIdentity> {
    |_entry, name| {
        if name.eq_ignore_ascii_case("josh") {
            Ok(josh())
        } else {
            bail!("no key for {name}")
        }
    }
}

fn order_file(route: &ProjectRoute, id: &str) -> Vec<u8> {
    for entry in fs::read_dir(task_dir(route, id)).unwrap().flatten() {
        if entry.file_name().to_string_lossy().starts_with("order.") {
            return fs::read(entry.path()).unwrap();
        }
    }
    panic!("no order file");
}

fn claim(route: &ProjectRoute, order: &str, by: &str) {
    ferryman_channel::claim_order(route, order, by).unwrap();
}

#[test]
fn an_order_addressed_to_a_retired_identity_is_reoffered_without_editing_it() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", Some("old-swarm"));
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1")
            .unwrap()
            .assignee(),
        Some("old-swarm")
    );
    let before = order_file(&route, "t-1");

    let offer = reoffer(
        &root,
        "quantly",
        "t-1",
        Some("new-swarm"),
        "old-swarm retired",
        None,
        &mut as_josh(),
    )
    .unwrap();
    assert_eq!(offer.offered_by, "josh");
    assert_eq!(offer.from.as_deref(), Some("old-swarm"));

    let task = ferryman_channel::read_task(&route, "t-1").unwrap();
    assert_eq!(task.assignee(), Some("new-swarm"));
    assert_eq!(task.holder(), Some("new-swarm"));
    assert_eq!(
        order_file(&route, "t-1"),
        before,
        "the signed order is untouched"
    );
    let files: Vec<String> = fs::read_dir(task_dir(&route, "t-1"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        files.iter().any(|f| f.starts_with("offer.josh.")),
        "{files:?}"
    );
    let ledger = ferryman_channel::ledger::read_ledger(&route).unwrap();
    assert!(
        ledger
            .entries
            .iter()
            .any(|line| line.summary.contains("re-offered t-1")),
        "history keeps the hand-over"
    );
}

#[test]
fn a_later_reoffer_wins_and_an_offer_to_nobody_returns_the_order_to_the_queue() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", Some("old-swarm"));
    reoffer(
        &root,
        "quantly",
        "t-1",
        Some("a-swarm"),
        "one",
        None,
        &mut as_josh(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    reoffer(&root, "quantly", "t-1", None, "two", None, &mut as_josh()).unwrap();
    let task = ferryman_channel::read_task(&route, "t-1").unwrap();
    assert_eq!(task.assignee(), None);
    assert_eq!(task.state(), ferryman_channel::TaskState::Open);
}

#[test]
fn only_the_issuer_or_the_master_may_reoffer() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", Some("old-swarm"));
    let mut as_mallory = |_: &Entry, _: &str| Ok(mallory());
    let refused = reoffer(
        &root,
        "quantly",
        "t-1",
        Some("mallory"),
        "mine now",
        Some("mallory"),
        &mut as_mallory,
    );
    assert!(refused.is_err());
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1")
            .unwrap()
            .assignee(),
        Some("old-swarm")
    );
}

#[test]
fn a_forged_offer_file_is_ignored_when_it_is_read() {
    let (_dir, _root, route) = world();
    issue(&route, "t-1", Some("old-swarm"));
    // A peer who can write the channel writes an offer file under their own name. Their key
    // is on the roster, so the signature verifies; they are neither issuer nor master.
    let offer = signed_offer(
        &route,
        "t-1",
        "mallory",
        &mallory(),
        Some("mallory"),
        Utc::now(),
    );
    // The signature is good (the payload is built exactly as the channel builds it): it is
    // refused only because mallory is neither the issuer nor the master.
    assert_eq!(
        ferryman_channel::offer::verify(&offer, &route.agents),
        ferryman_channel::SignatureCheck::Valid
    );
    write_offer(&route, "t-1", "mallory.1", &offer);
    let task = ferryman_channel::read_task(&route, "t-1").unwrap();
    assert!(task.offers.is_empty(), "{:?}", task.offers);
    assert_eq!(task.assignee(), Some("old-swarm"));
}

/// An offer built and signed the way the channel does, for tests that need one the normal
/// command would not write.
fn signed_offer(
    route: &ProjectRoute,
    order: &str,
    by: &str,
    key: &AgentIdentity,
    to: Option<&str>,
    at: chrono::DateTime<Utc>,
) -> Offer {
    let mut offer = Offer {
        project_id: route.project_id.clone(),
        order_id: order.into(),
        to: to.map(str::to_owned),
        offered_by: by.into(),
        from: Some("old-swarm".into()),
        reason: "test".into(),
        at,
        signed_by: Some(by.into()),
        signature: None,
    };
    let payload = format!(
        "ferryman-offer-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        offer.project_id,
        offer.order_id,
        offer.to.as_deref().unwrap_or(""),
        offer.offered_by,
        offer.from.as_deref().unwrap_or(""),
        offer.reason,
        offer.at.to_rfc3339(),
    );
    offer.signature = Some(key.sign_bytes(payload.as_bytes()));
    offer
}

fn write_offer(route: &ProjectRoute, order: &str, name: &str, offer: &Offer) {
    fs::write(
        task_dir(route, order).join(format!("offer.{name}.json")),
        serde_json::to_string(offer).unwrap(),
    )
    .unwrap();
}

/// A signed offer is bound to its project: the master's offer for an order in one project
/// copied into another project's channel, where an order has the same id and the same master
/// signs, does nothing there.
#[test]
fn an_offer_copied_from_another_project_is_not_read() {
    hermetic();
    let dir = tempfile::tempdir().unwrap();
    let root = Root::create(&dir.path().join("ferry")).unwrap();
    channel_of(&root, "quantly");
    channel_of(&root, "fructly");
    let (quantly, fructly) = (route_of(&root, "quantly"), route_of(&root, "fructly"));
    issue(&quantly, "t-1", Some("old-swarm"));
    issue(&fructly, "t-1", Some("old-swarm"));
    reoffer(
        &root,
        "quantly",
        "t-1",
        Some("new-swarm"),
        "moved",
        None,
        &mut as_josh(),
    )
    .unwrap();
    assert_eq!(
        ferryman_channel::read_task(&quantly, "t-1")
            .unwrap()
            .assignee(),
        Some("new-swarm")
    );
    // Copy the file, byte for byte, into the other project's order.
    for entry in fs::read_dir(task_dir(&quantly, "t-1")).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("offer.josh.") {
            fs::copy(entry.path(), task_dir(&fructly, "t-1").join(&name)).unwrap();
        }
    }
    let task = ferryman_channel::read_task(&fructly, "t-1").unwrap();
    assert!(task.offers.is_empty(), "{:?}", task.offers);
    assert_eq!(task.assignee(), Some("old-swarm"));
}

/// The newest offer decides, and its date is the signer's own word. An offer dated far ahead
/// is not read, so an issuer cannot make theirs the newest for good and shut the master out.
#[test]
fn an_offer_dated_in_the_future_is_not_read() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", Some("old-swarm"));
    // josh is both issuer and master here; the point is the date, not who signs.
    let later = Utc::now() + chrono::Duration::days(3650);
    let offer = signed_offer(&route, "t-1", "josh", &josh(), Some("squatter"), later);
    write_offer(&route, "t-1", "josh.future", &offer);
    let task = ferryman_channel::read_task(&route, "t-1").unwrap();
    assert!(task.offers.is_empty(), "{:?}", task.offers);
    // So an honest offer afterwards is the newest, and takes.
    reoffer(
        &root,
        "quantly",
        "t-1",
        Some("new-swarm"),
        "now",
        None,
        &mut as_josh(),
    )
    .unwrap();
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1")
            .unwrap()
            .assignee(),
        Some("new-swarm")
    );
    // A little clock skew is allowed.
    let skew = Utc::now() + chrono::Duration::minutes(2);
    let near = signed_offer(&route, "t-1", "josh", &josh(), Some("skewed"), skew);
    write_offer(&route, "t-1", "josh.skew", &near);
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1")
            .unwrap()
            .assignee(),
        Some("skewed")
    );
}

#[test]
fn a_long_reason_is_cut_and_has_no_control_characters() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", Some("old-swarm"));
    let long = format!("why\n{}", "x".repeat(5000));
    let offer = reoffer(
        &root,
        "quantly",
        "t-1",
        Some("new-swarm"),
        &long,
        None,
        &mut as_josh(),
    )
    .unwrap();
    assert!(offer.reason.chars().count() <= ferryman_channel::offer::REASON_CAP);
    assert!(!offer.reason.contains('\n'));
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1")
            .unwrap()
            .offers
            .len(),
        1,
        "and it still verifies"
    );
}

#[test]
fn a_claim_held_by_a_retired_identity_is_released_by_the_master_and_nothing_is_deleted() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", None);
    claim(&route, "t-1", "old-swarm");
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1").unwrap().holder(),
        Some("old-swarm")
    );

    // A dry run says what it would do and signs nothing.
    let mut never =
        |_: &Entry, _: &str| -> Result<AgentIdentity> { bail!("asked for a key in a dry run") };
    let dry = release_held(&root, "old-swarm", "josh", "retired", true, &mut never);
    assert_eq!(dry, vec![("quantly".into(), "t-1".into(), Released::Done)]);
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1").unwrap().holder(),
        Some("old-swarm")
    );

    let done = release_held(&root, "old-swarm", "josh", "retired", false, &mut as_josh());
    assert_eq!(done, vec![("quantly".into(), "t-1".into(), Released::Done)]);
    let task = ferryman_channel::read_task(&route, "t-1").unwrap();
    assert_eq!(task.holder(), None, "back in the queue");
    assert_eq!(task.claims.len(), 1, "the claim stays as history");
    assert_eq!(task.releases.len(), 1);
    assert_eq!(task.releases[0].releaser, "josh");
    assert_eq!(task.releases[0].released, "old-swarm");

    // Again: nothing left to release.
    let again = release_held(&root, "old-swarm", "josh", "retired", false, &mut as_josh());
    assert!(again.is_empty(), "{again:?}");
}

#[test]
fn a_claim_whose_worker_is_alive_here_is_not_released() {
    let (dir, root, route) = world();
    issue(&route, "t-1", None);
    claim(&route, "t-1", "old-swarm");
    let repo = dir.path().join("clone");
    fs::create_dir_all(repo.join(".ferryman")).unwrap();
    fs::write(
        repo.join(".ferryman").join("worker-old-swarm.lock"),
        std::process::id().to_string(),
    )
    .unwrap();
    root.adopt("quantly", &root.comms_home("quantly"), Some(&repo))
        .unwrap();
    let rows = release_held(&root, "old-swarm", "josh", "retired", false, &mut as_josh());
    assert!(
        matches!(&rows[0].2, Released::Skipped(why) if why.contains("alive")),
        "{rows:?}"
    );
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1").unwrap().holder(),
        Some("old-swarm")
    );
}

#[test]
fn a_project_somebody_else_masters_is_left_alone() {
    let (_dir, root, route) = world();
    issue(&route, "t-1", None);
    claim(&route, "t-1", "old-swarm");
    let rows = release_held(&root, "old-swarm", "bob", "retired", false, &mut as_josh());
    assert!(
        matches!(&rows[0].2, Released::Skipped(why) if why.contains("master is josh")),
        "{rows:?}"
    );
    assert_eq!(
        ferryman_channel::read_task(&route, "t-1").unwrap().holder(),
        Some("old-swarm")
    );
}

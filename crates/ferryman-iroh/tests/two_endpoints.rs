//! Two endpoints in one process, connected directly (no relay), syncing real channel
//! folders whose trust comes from real signed TRANSPORTS records.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};
use ferryman_iroh::{ALPN, Lane, endpoint_hex};
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

fn route(base: &Path, project: &str) -> ProjectRoute {
    let workspace = base.join(project);
    let attachment = workspace.join(".ferryman");
    let communications = attachment.join("ferryman");
    fs::create_dir_all(&communications).unwrap();
    ProjectRoute {
        project_id: project.into(),
        workspace,
        attachment,
        communications,
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: "private".into(),
        agents: Vec::new(),
    }
}

fn enrol(route: &ProjectRoute, identity: &AgentIdentity) {
    ferryman_channel::register_agent(
        route,
        &AgentRoute {
            name: identity.name().into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        },
    )
    .unwrap();
}

async fn endpoint(key: SecretKey, lookup: &MemoryLookup) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .address_lookup(lookup.clone())
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

fn addr(endpoint: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(endpoint.id());
    for socket in endpoint.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/// Two machines, each with its own copy of the `demo` channel (as Syncthing would have
/// left them: same roster, same TRANSPORTS records), and a third channel only one has.
struct Pair {
    _dir: tempfile::TempDir,
    a: Arc<Lane>,
    b: Arc<Lane>,
    a_demo: ProjectRoute,
    b_demo: ProjectRoute,
    a_private: ProjectRoute,
    outside: std::path::PathBuf,
    /// A channel both machines serve and know the roster of, where neither holds the
    /// other's TRANSPORTS record: (A's copy, B's copy). Only with `pair_with(true)`.
    fresh: Option<(ProjectRoute, ProjectRoute)>,
}

async fn pair() -> Pair {
    pair_with(false).await
}

async fn pair_with(with_fresh: bool) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    // Fixed per process, not inside this test's own folder: the override is set once, and
    // another test's thread would otherwise keep its keys in a folder this one deletes.
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-iroh-tests-{}", std::process::id())),
    );
    let a_demo = route(&dir.path().join("a"), "demo");
    let b_demo = route(&dir.path().join("b"), "demo");
    let a_private = route(&dir.path().join("a"), "private");
    let fang = AgentIdentity::load_or_create("fang", &a_demo.attachment).unwrap();
    let wisp = AgentIdentity::load_or_create("wisp", &b_demo.attachment).unwrap();
    let (key_a, key_b) = (SecretKey::generate(), SecretKey::generate());
    let lookup = MemoryLookup::new();
    let a_end = endpoint(key_a.clone(), &lookup).await;
    let b_end = endpoint(key_b.clone(), &lookup).await;
    lookup.add_endpoint_info(addr(&a_end));
    lookup.add_endpoint_info(addr(&b_end));
    enrol(&a_demo, &fang);
    enrol(&a_demo, &wisp);
    ferryman_channel::transports::publish(&a_demo, &fang, &endpoint_hex(&key_a.public()), None)
        .unwrap();
    ferryman_channel::transports::publish(&a_demo, &wisp, &endpoint_hex(&key_b.public()), None)
        .unwrap();
    // What Syncthing would have done before the lane ever ran: B has the same records.
    copy_tree(&a_demo.communications, &b_demo.communications);
    // `private` names wisp too, but only on A's side: B does not serve it.
    enrol(&a_private, &fang);
    enrol(&a_private, &wisp);
    ferryman_channel::transports::publish(&a_private, &wisp, &endpoint_hex(&key_b.public()), None)
        .unwrap();
    let mut a_routes = vec![a_demo.clone(), a_private.clone()];
    let mut b_routes = vec![b_demo.clone()];
    let mut fresh = None;
    if with_fresh {
        let (a_fresh, b_fresh) = (
            route(&dir.path().join("a"), "fresh"),
            route(&dir.path().join("b"), "fresh"),
        );
        let mallory = AgentIdentity::load_or_create("mallory", &a_fresh.attachment).unwrap();
        // Both know who is in the project; each has published only its own record.
        for route in [&a_fresh, &b_fresh] {
            enrol(route, &fang);
            enrol(route, &wisp);
        }
        // Someone only A's roster knows.
        enrol(&a_fresh, &mallory);
        ferryman_channel::transports::publish(
            &a_fresh,
            &fang,
            &endpoint_hex(&key_a.public()),
            None,
        )
        .unwrap();
        ferryman_channel::transports::publish(
            &b_fresh,
            &wisp,
            &endpoint_hex(&key_b.public()),
            None,
        )
        .unwrap();
        ferryman_channel::transports::publish(
            &a_fresh,
            &mallory,
            &endpoint_hex(&SecretKey::generate().public()),
            None,
        )
        .unwrap();
        a_routes.push(a_fresh.clone());
        b_routes.push(b_fresh.clone());
        fresh = Some((a_fresh, b_fresh));
    }
    let a = Lane::new(a_end, a_routes, None, None);
    let b = Lane::new(b_end, b_routes, None, None);
    tokio::spawn(Arc::clone(&a).serve());
    tokio::spawn(Arc::clone(&b).serve());
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    Pair {
        _dir: dir,
        a,
        b,
        a_demo,
        b_demo,
        a_private,
        outside,
        fresh,
    }
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Every file anywhere under `dir` called `name`.
fn found(dir: &Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut hits = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            hits.extend(found(&entry.path(), name));
        } else if entry.file_name() == name {
            hits.push(entry.path());
        }
    }
    hits
}

fn write(route: &ProjectRoute, path: &str, text: &str) {
    let file = route.communications.join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, text).unwrap();
}

#[tokio::test]
async fn two_machines_sync_a_channel_both_ways_and_nothing_else() {
    let p = pair().await;
    write(&p.a_demo, "tasks/t-1/order.json", "{\"from\":\"a\"}");
    write(&p.b_demo, "messages/m-1.json", "{\"from\":\"b\"}");
    write(&p.a_demo, "tools/ferry.exe", "MZ");
    write(&p.a_demo, "keys/fang.key", "secret");
    write(&p.a_private, "secret-plan.json", "{}");

    p.a.round().await;

    let status = p.a.status();
    let peer = &status.peers[&endpoint_hex(&p.b.endpoint().id())];
    assert!(peer.last_error.is_none(), "{:?}", peer.last_error);
    assert_eq!((peer.received, peer.sent), (1, 1));
    // `private` is trusted on A's side only, and B does not serve it: not exchanged.
    assert_eq!(peer.projects, ["demo"]);
    assert_eq!(
        fs::read_to_string(p.b_demo.communications.join("tasks/t-1/order.json")).unwrap(),
        "{\"from\":\"a\"}"
    );
    assert_eq!(
        fs::read_to_string(p.a_demo.communications.join("messages/m-1.json")).unwrap(),
        "{\"from\":\"b\"}"
    );
    // Excluded on the way out, and a channel B does not serve is not offered to it.
    assert!(!p.b_demo.communications.join("tools/ferry.exe").exists());
    assert!(!p.b_demo.communications.join("keys/fang.key").exists());
    assert!(!p.b_demo.communications.join("secret-plan.json").exists());

    // B counted the same exchange from its side, and a round of its own has nothing
    // left to move.
    let a_id = endpoint_hex(&p.a.endpoint().id());
    let before = p.b.status().peers[&a_id].clone();
    assert_eq!((before.received, before.sent), (1, 1));
    p.b.round().await;
    let after = &p.b.status().peers[&a_id];
    assert!(after.last_error.is_none(), "{:?}", after.last_error);
    assert_eq!((after.received, after.sent), (1, 1));
}

#[tokio::test]
async fn an_endpoint_no_channel_vouches_for_is_refused() {
    let p = pair().await;
    write(&p.b_demo, "messages/m-1.json", "{}");
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(addr(p.b.endpoint()));
    let stranger = endpoint(SecretKey::generate(), &lookup).await;
    let lane = Lane::new(stranger, vec![route(&p.outside, "demo")], None, None);
    let peer = ferryman_iroh::lane::Peer {
        projects: ["demo".to_owned()].into(),
        ..Default::default()
    };
    let refused = lane.sync_peer(p.b.endpoint().id(), &peer).await;
    assert!(refused.is_err(), "a stranger was let in");
    assert!(!p.outside.join("demo/.ferryman/ferryman/messages").exists());
}

#[tokio::test]
async fn a_peer_that_names_paths_outside_the_channel_writes_nothing_there() {
    let p = pair().await;
    // A speaks the protocol by hand, as a hostile peer would: it offers files whose paths
    // climb out of the channel, then sends them whether or not they were asked for.
    let connection =
        p.a.endpoint()
            .connect(EndpointAddr::new(p.b.endpoint().id()), ALPN)
            .await
            .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let bytes = b"planted";
    let hash = blake3::hash(bytes).to_hex().to_string();
    let escapes = [
        "../../../outside/planted.json",
        "../escape.json",
        "a/../../x.json",
    ];
    let manifest: Vec<_> = escapes
        .iter()
        .map(
            |path| serde_json::json!({"path": path, "size": bytes.len(), "mtime": 1, "hash": hash}),
        )
        .collect();
    let hello =
        serde_json::to_vec(&serde_json::json!({"project_id": "demo", "manifest": manifest}))
            .unwrap();
    send.write_all(&u32::try_from(hello.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(&hello).await.unwrap();
    let mut length = [0_u8; 4];
    recv.read_exact(&mut length).await.unwrap();
    let mut reply = vec![0_u8; u32::from_be_bytes(length) as usize];
    recv.read_exact(&mut reply).await.unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["reply"], "plan");
    assert_eq!(reply["want"], serde_json::json!([]), "{reply}");
    // And the files anyway, unasked.
    for path in escapes {
        let item = serde_json::to_vec(
            &serde_json::json!({"path": path, "size": bytes.len(), "mtime": 1, "hash": hash}),
        )
        .unwrap();
        let _ = send
            .write_all(&u32::try_from(item.len()).unwrap().to_be_bytes())
            .await;
        let _ = send.write_all(&item).await;
        let _ = send.write_all(bytes).await;
    }
    let _ = send.finish();
    let _ = recv.read_to_end(1 << 20).await;
    connection.close(0u32.into(), b"done");

    let base = p.b_demo.workspace.parent().unwrap().parent().unwrap();
    for name in ["planted.json", "escape.json", "x.json"] {
        assert!(found(base, name).is_empty(), "{name} was written");
    }
}

// ---------------------------------------------------------------------------------------
// Layout 2 and access levels (ADR 0024): the hand-ins folder syncs beside the channel, a
// Worker's channel writes are refused where they arrive, and its own machine stays quiet.

fn v2_route(base: &Path, project: &str) -> ProjectRoute {
    let root = ferryman_channel::ferry::Root::create_with_layout(&base.join("ferry"), 2).unwrap();
    let communications = root.comms_home(project);
    let workspace = root.managed_clone(project);
    let attachment = workspace.join(".ferryman");
    fs::create_dir_all(&communications).unwrap();
    fs::create_dir_all(&attachment).unwrap();
    ProjectRoute {
        project_id: project.into(),
        workspace,
        attachment,
        communications,
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: "private".into(),
        agents: Vec::new(),
    }
}

/// fang (the master, so an Orchestrator) on A, and wisp (made a Worker) on B.
struct Levels {
    _dir: tempfile::TempDir,
    a: Arc<Lane>,
    b: Arc<Lane>,
    a_route: ProjectRoute,
    b_route: ProjectRoute,
    a_handins: std::path::PathBuf,
    b_handins: std::path::PathBuf,
}

async fn levels() -> Levels {
    let dir = tempfile::tempdir().unwrap();
    ferryman_channel::licensing::use_machine_state_dir_per_thread(
        std::env::temp_dir().join(format!("ferryman-iroh-tests-{}", std::process::id())),
    );
    let mut a_route = v2_route(&dir.path().join("a"), "demo");
    let b_route = v2_route(&dir.path().join("b"), "demo");
    let fang = AgentIdentity::load_or_create("fang", &a_route.attachment).unwrap();
    let wisp = AgentIdentity::load_or_create("wisp", &b_route.attachment).unwrap();
    let (key_a, key_b) = (SecretKey::generate(), SecretKey::generate());
    let lookup = MemoryLookup::new();
    let a_end = endpoint(key_a.clone(), &lookup).await;
    let b_end = endpoint(key_b.clone(), &lookup).await;
    lookup.add_endpoint_info(addr(&a_end));
    lookup.add_endpoint_info(addr(&b_end));
    enrol(&a_route, &fang);
    enrol(&a_route, &wisp);
    a_route.agents = ferryman_channel::read_agent_roster(&a_route.communications).unwrap();
    ferryman_channel::master::initialize_master(&a_route, &fang, "fang").unwrap();
    ferryman_channel::access::set_level(
        &a_route,
        &fang,
        "wisp",
        ferryman_channel::access::Level::Worker,
    )
    .unwrap();
    // wisp is a Worker now, so its record is written to its own hand-ins folder.
    ferryman_channel::transports::publish(&a_route, &fang, &endpoint_hex(&key_a.public()), None)
        .unwrap();
    ferryman_channel::transports::publish(&a_route, &wisp, &endpoint_hex(&key_b.public()), None)
        .unwrap();
    let a_handins = ferryman_channel::ferry::handins_dir_for(&a_route.communications, "demo");
    let b_handins = ferryman_channel::ferry::handins_dir_for(&b_route.communications, "demo");
    fs::create_dir_all(&a_handins).unwrap();
    fs::create_dir_all(&b_handins).unwrap();
    // What the first sync would have left on B.
    copy_tree(&a_route.communications, &b_route.communications);
    copy_tree(&a_handins, &b_handins);
    let a = Lane::new(a_end, vec![a_route.clone()], None, None);
    let b = Lane::new(b_end, vec![b_route.clone()], None, None);
    tokio::spawn(Arc::clone(&a).serve());
    tokio::spawn(Arc::clone(&b).serve());
    Levels {
        _dir: dir,
        a,
        b,
        a_route,
        b_route,
        a_handins,
        b_handins,
    }
}

fn put(dir: &Path, path: &str, text: &str) {
    let file = dir.join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, text).unwrap();
}

#[tokio::test]
async fn the_handins_folder_syncs_beside_the_channel_and_verdicts_come_from_the_head_only() {
    let l = levels().await;
    // The Worker hands work in; the head (fang, the master) writes a verdict beside it.
    put(
        &l.b_handins,
        "wisp/ord-1/handin.json",
        "{\"from\":\"wisp\"}",
    );
    put(
        &l.a_handins,
        "wisp/ord-1/accepted.json",
        "{\"by\":\"fang\"}",
    );
    // And the Worker writes a verdict of its own, which is not its to write.
    put(
        &l.b_handins,
        "wisp/ord-2/accepted.json",
        "{\"by\":\"wisp\"}",
    );

    l.a.round().await;

    let status = l.a.status();
    let peer = &status.peers[&endpoint_hex(&l.b.endpoint().id())];
    assert!(peer.last_error.is_none(), "{:?}", peer.last_error);
    assert!(peer.projects.contains(&"demo".to_owned()));
    assert!(
        peer.projects.contains(&"demo+handins".to_owned()),
        "{:?}",
        peer.projects
    );
    assert_eq!(
        fs::read_to_string(l.a_handins.join("wisp/ord-1/handin.json")).unwrap(),
        "{\"from\":\"wisp\"}",
        "the hand-in reached the head"
    );
    assert_eq!(
        fs::read_to_string(l.b_handins.join("wisp/ord-1/accepted.json")).unwrap(),
        "{\"by\":\"fang\"}",
        "the head's verdict reached the Worker"
    );
    assert!(
        !l.a_handins.join("wisp/ord-2/accepted.json").exists(),
        "a verdict from a peer that is not the head is not let in"
    );
    // Nothing of the hand-ins went into the channel.
    assert!(!l.a_route.communications.join("handins").exists());
    assert!(!l.a_route.communications.join("wisp").exists());
}

#[tokio::test]
async fn a_workers_channel_files_are_refused_on_arrival_by_name_and_by_content() {
    let l = levels().await;
    // The Worker's machine has put things in its channel copy that it should not have.
    put(&l.b_route.communications, "tasks/t-1/claim.wisp.json", "{}");
    put(&l.b_route.communications, "presence/wisp.json", "{}");
    put(
        &l.b_route.communications,
        "messages/demo/m-1.json",
        "{\"sender\":\"Wisp\",\"id\":\"m-1\"}",
    );
    // And something that is fine.
    put(&l.b_route.communications, "notes/readme.txt", "ok");

    // B does not know it is a Worker-only machine (no local agents set), so it offers all
    // of it: this is the receiving side's own refusal.
    l.a.round().await;

    let a = &l.a_route.communications;
    assert!(!a.join("tasks/t-1/claim.wisp.json").exists(), "by name");
    assert!(!a.join("presence/wisp.json").exists(), "by name");
    assert!(!a.join("messages/demo/m-1.json").exists(), "by content");
    // A knows B's agents are all Workers, so nothing B offers into the channel is let in,
    // innocent or not: its writes belong in its hand-ins, and a Worker that registered a
    // fresh name could not talk its way round the file-by-file rules.
    assert!(
        !a.join("notes/readme.txt").exists(),
        "a Worker-only peer writes nothing into the channel"
    );
}

#[tokio::test]
async fn a_workers_own_machine_listens_to_the_channel_and_publishes_none_of_it() {
    let l = levels().await;
    l.b.set_local_agents(vec!["wisp".to_owned()]);
    put(
        &l.a_route.communications,
        "tasks/t-9/order.json",
        "{\"from\":\"a\"}",
    );
    put(&l.b_route.communications, "notes/local.txt", "b only");

    // Either side may dial; the Worker's machine must give nothing from the channel.
    l.a.round().await;
    l.b.round().await;

    assert_eq!(
        fs::read_to_string(l.b_route.communications.join("tasks/t-9/order.json")).unwrap(),
        "{\"from\":\"a\"}",
        "it hears the fleet"
    );
    assert!(
        !l.a_route.communications.join("notes/local.txt").exists(),
        "and says nothing back through the channel"
    );
    // Its hand-ins still go out.
    put(&l.b_handins, "wisp/ord-3/handin.json", "{}");
    l.b.round().await;
    let status = l.b.status();
    let peer = &status.peers[&endpoint_hex(&l.a.endpoint().id())];
    assert!(peer.last_error.is_none(), "{:?}", peer.last_error);
    assert!(
        l.a_handins.join("wisp/ord-3/handin.json").is_file(),
        "{status:?} a={:?} b={:?} astat={:?}",
        found(&l.a_handins, "handin.json"),
        found(&l.b_handins, "handin.json"),
        l.a.status()
    );
}

#[tokio::test]
async fn first_contact_opens_only_the_transports_records_of_a_new_channel() {
    let p = pair_with(true).await;
    let (a_fresh, b_fresh) = p.fresh.clone().unwrap();
    // Work in A's copy of the new channel. It must not move before trust is there.
    write(&a_fresh, "tasks/t-9/order.json", "{\"from\":\"a\"}");
    write(&a_fresh, "messages/m-9.json", "{}");
    let (a_id, b_id) = (p.a.endpoint().id(), p.b.endpoint().id());

    // Today's rule: neither is trusted in `fresh`, because neither holds the other's record.
    assert!(!p.a.trusted()[&b_id].projects.contains("fresh"));
    assert!(!p.b.trusted()[&a_id].projects.contains("fresh"));
    // But each is offered it, because the other is trusted in `demo`.
    assert!(p.a.trusted()[&b_id].bootstrap.contains("fresh"));

    p.a.round().await;
    let status = p.a.status();
    let peer = &status.peers[&endpoint_hex(&b_id)];
    assert!(peer.last_error.is_none(), "{:?}", peer.last_error);

    // The records crossed, both ways.
    assert!(
        b_fresh
            .communications
            .join("transports/fang.json")
            .is_file()
    );
    assert!(
        a_fresh
            .communications
            .join("transports/wisp.json")
            .is_file()
    );
    // Nothing else did: not the work, not the messages.
    assert!(!b_fresh.communications.join("tasks").exists());
    assert!(!b_fresh.communications.join("messages").exists());
    // And a record from an agent B's roster does not know was not let in.
    assert!(
        !b_fresh
            .communications
            .join("transports/mallory.json")
            .exists()
    );

    // Now the ordinary rule applies: each holds the other's record, so each trusts the
    // other in `fresh`, and the next round carries the channel.
    assert!(p.a.trusted()[&b_id].projects.contains("fresh"));
    assert!(p.b.trusted()[&a_id].projects.contains("fresh"));
    p.a.round().await;
    assert_eq!(
        fs::read_to_string(b_fresh.communications.join("tasks/t-9/order.json")).unwrap(),
        "{\"from\":\"a\"}"
    );
}

#[tokio::test]
async fn first_contact_does_not_trust_a_peer_no_shared_channel_vouches_for() {
    let p = pair_with(true).await;
    let (_, b_fresh) = p.fresh.clone().unwrap();
    // A stranger holding the right project names but no endpoint any record vouches for.
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(addr(p.b.endpoint()));
    let stranger = endpoint(SecretKey::generate(), &lookup).await;
    let lane = Lane::new(stranger, vec![route(&p.outside, "fresh")], None, None);
    let peer = ferryman_iroh::lane::Peer {
        bootstrap: ["fresh".to_owned()].into(),
        ..Default::default()
    };
    assert!(lane.sync_peer(p.b.endpoint().id(), &peer).await.is_err());
    assert!(
        !b_fresh
            .communications
            .join("transports/mallory.json")
            .exists()
    );
    assert!(
        !p.outside
            .join("fresh/.ferryman/ferryman/transports")
            .exists()
    );
}

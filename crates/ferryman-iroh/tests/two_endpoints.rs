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
}

async fn pair() -> Pair {
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
    let a = Lane::new(a_end, vec![a_demo.clone(), a_private.clone()], None, None);
    let b = Lane::new(b_end, vec![b_demo.clone()], None, None);
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

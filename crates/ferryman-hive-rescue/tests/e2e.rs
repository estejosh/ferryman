//! End to end, in one process: two lanes whose usual relay is unreachable and whose direct
//! path is blocked cannot reach each other. The master posts to a (mock) Hive node, the
//! other machine reads it, and both reconnect through the rescue relay the record names.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use chrono::{Duration, Utc};
use common::{ACCOUNT, Fleet};
use ferryman_channel::{AgentIdentity, AgentRoute, ProjectRoute};
use ferryman_hive_rescue::rescuer::{cut_off_since, lane_info};
use ferryman_iroh::{ALPN, Lane, endpoint_hex};
use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};

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

/// An endpoint that can only use relays (no direct path at all), whose only relay is
/// `primary`. Returns the map it shares, which is where a rescue relay will be added.
async fn relay_only(key: SecretKey, primary: &RelayUrl) -> (Endpoint, RelayMap) {
    let map = RelayMap::from_iter([RelayConfig::from(primary.clone())]);
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Custom(map.clone()))
        .clear_ip_transports()
        // The test relay has a self-signed certificate.
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .unwrap();
    (endpoint, map)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cut_off_lanes_find_each_other_again_through_hive_and_the_rescue_relay() {
    let fleet = Fleet::new();
    let (beastly, grouchly) = (fleet.beastly.signer(), fleet.grouchly.signer());

    // The usual relay answers nobody. The rescue relay is a real one, elsewhere.
    let dead: RelayUrl = "https://127.0.0.1:9/".parse().unwrap();
    let (_rescue_map, rescue_url, _server) = iroh::test_utils::run_relay_server().await.unwrap();

    let (key_a, key_b) = (SecretKey::generate(), SecretKey::generate());
    let (a_end, a_map) = relay_only(key_a.clone(), &dead).await;
    let (b_end, b_map) = relay_only(key_b.clone(), &dead).await;

    // The channel both have (as Syncthing left it): a roster and each other's record,
    // which names the usual relay.
    let dir = tempfile::tempdir().unwrap();
    let a_demo = route(&dir.path().join("a"), "demo");
    let b_demo = route(&dir.path().join("b"), "demo");
    for who in [&beastly, &grouchly] {
        enrol(&a_demo, who);
    }
    for (who, key) in [(&beastly, &key_a), (&grouchly, &key_b)] {
        ferryman_channel::transports::publish(
            &a_demo,
            who,
            &endpoint_hex(&key.public()),
            Some(dead.as_str()),
        )
        .unwrap();
    }
    copy_tree(&a_demo.communications, &b_demo.communications);
    fs::create_dir_all(a_demo.communications.join("tasks/t-1")).unwrap();
    fs::write(
        a_demo.communications.join("tasks/t-1/order.json"),
        "{\"from\":\"beastly\"}",
    )
    .unwrap();

    let a = Lane::new(a_end, vec![a_demo.clone()], Some(dead.to_string()), None);
    let b = Lane::new(b_end, vec![b_demo.clone()], Some(dead.to_string()), None);
    a.configure_relays(true, None);
    b.configure_relays(true, None);
    tokio::spawn(Arc::clone(&a).serve());
    tokio::spawn(Arc::clone(&b).serve());

    // 1. Cut off: neither can reach the other, and neither relay is connected.
    let (first_a, first_b) = tokio::join!(a.round(), b.round());
    let _ = (first_a, first_b);
    let b_id = endpoint_hex(&b.endpoint().id());
    assert!(b.status().peers.values().all(|p| p.last_error.is_some()));
    assert!(!b_demo.communications.join("tasks/t-1/order.json").exists());
    let cut = cut_off_since(&b.status()).expect("grouchly is cut off");
    assert!(
        cut_off_since(&a.status()).is_some(),
        "beastly is cut off too"
    );

    // 2. Twenty minutes later (the tick takes the time, so the test does not wait): the
    // master posts one record to Hive, naming the rescue relay.
    let hive = common::start_mock().await;
    let (sa, sb) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let master = fleet.rescuer(&fleet.beastly, &hive.url(), sa.path(), true, |c| {
        c.rescue_relay = Some(rescue_url.to_string());
    });
    let reader = fleet.rescuer(&fleet.grouchly, &hive.url(), sb.path(), false, |_| {});
    master.attach(a.endpoint(), Some(a_map)).unwrap();
    reader.attach(b.endpoint(), Some(b_map)).unwrap();
    let now = cut.max(Utc::now()) + Duration::minutes(20);

    let posted = master
        .tick(&a.status(), &lane_info(&a, false), now)
        .await
        .posted
        .expect("the master posts");
    assert_eq!(hive.ops_for(ACCOUNT).len(), 1);
    assert_eq!(posted.record.body.at.id, endpoint_hex(&a.endpoint().id()));

    // 3. The other machine, cut off, reads Hive, verifies and feeds iroh.
    let report = reader.tick(&b.status(), &lane_info(&b, false), now).await;
    assert!(report.read.expect("read").applied);
    assert!(
        reader
            .lookup()
            .get_endpoint_info(a.endpoint().id())
            .is_some_and(|info| info.relay_urls().any(|u| *u == rescue_url)),
        "iroh learned where the master is"
    );

    // 4. They reconnect through the rescue relay: the file crosses, and the path says so.
    let mut done = false;
    for _ in 0..8 {
        b.round().await;
        let status = b.status();
        let peer = status.peers.values().next().unwrap();
        if peer.last_error.is_none() && peer.last_sync.is_some() {
            done = true;
            assert!(
                peer.path.as_deref().is_some_and(|p| p.starts_with("relay")),
                "went by {:?}",
                peer.path
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert!(
        done,
        "no sync after the rescue: {:?}",
        b.status().peers.get(&b_id)
    );
    assert_eq!(
        fs::read_to_string(b_demo.communications.join("tasks/t-1/order.json")).unwrap(),
        "{\"from\":\"beastly\"}"
    );
}

/// Seal `body` as `who` to the whole roster and put it in the mock's history.
fn post_as(
    hive: &ferryman_hive_rescue::mock::MockHive,
    fleet: &Fleet,
    who: &common::Machine,
    body: ferryman_hive_rescue::record::Body,
) {
    let view = fleet.view.lock().unwrap().clone();
    let signed = ferryman_hive_rescue::record::sign(body.clone(), &who.signer()).unwrap();
    let sealed = ferryman_hive_rescue::record::seal(
        &signed,
        &ferryman_hive_rescue::record::recipients(&view.roster, |_| false),
    )
    .unwrap();
    hive.inject(
        ACCOUNT,
        "ferryman-rescue",
        &ferryman_hive_rescue::record::op_json(&body.fleet, &sealed),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_masters_relays_join_the_shared_map_and_expiry_takes_them_back() {
    use ferryman_hive_rescue::record::{Body, Kind, RescueRelay, Where, fleet_tag};

    let fleet = Fleet::new();
    let hive = common::start_mock().await;
    let dead: RelayUrl = "https://127.0.0.1:9/".parse().unwrap();
    let (endpoint, map) = relay_only(SecretKey::generate(), &dead).await;
    let state = tempfile::tempdir().unwrap();
    let reader = fleet.rescuer(&fleet.grouchly, &hive.url(), state.path(), false, |c| {
        c.backup_agents = vec!["grouchly-ferry".into()];
    });
    reader.attach(&endpoint, Some(map.clone())).unwrap();

    let tag = fleet_tag(
        fleet.view.lock().unwrap().roster[0]
            .public_key
            .as_ref()
            .unwrap(),
    );
    let (master_id, backup_id) = (
        SecretKey::generate().public(),
        SecretKey::generate().public(),
    );
    // grouchly is known by its own endpoint, which the backup record points at.
    fleet.view.lock().unwrap().endpoints.insert(
        "grouchly-ferry".into(),
        std::collections::BTreeSet::from([endpoint_hex(&backup_id)]),
    );
    let now = Utc::now();
    let base = |kind, signer: &str, seq, id: &iroh::EndpointId, relay: &str| Body {
        v: 1,
        fleet: tag.clone(),
        kind,
        signer: signer.into(),
        seq,
        issued: now,
        expires: now + Duration::minutes(60),
        at: Where {
            id: endpoint_hex(id),
            relay_url: Some(relay.into()),
            direct: Vec::new(),
        },
        relay_list_version: None,
        rescue_relay: None,
        relays: None,
    };
    let mut master = base(
        Kind::Master,
        "beastly-ferry",
        1,
        &master_id,
        "https://master-home.example/",
    );
    master.rescue_relay = Some(RescueRelay {
        url: "https://rescue.example/".into(),
        cert_sha256: None,
    });
    let backup = base(
        Kind::Backup,
        "grouchly-ferry",
        1,
        &backup_id,
        "https://backup-home.example/",
    );
    post_as(&hive, &fleet, &fleet.beastly, master);
    post_as(&hive, &fleet, &fleet.grouchly, backup);

    assert!(reader.poll(now, true).await.unwrap().applied);
    let url = |u: &str| u.parse::<RelayUrl>().unwrap();
    // The master's relay and rescue relay joined the map every dial uses; the backup's did not.
    assert!(map.contains(&url("https://master-home.example/")));
    assert!(map.contains(&url("https://rescue.example/")));
    assert!(!map.contains(&url("https://backup-home.example/")));
    assert!(map.contains(&dead), "what was there before is untouched");
    // Both machines are still dialable, the backup by its own address only.
    let backup_info = reader
        .lookup()
        .get_endpoint_info(backup_id)
        .expect("backup address");
    assert!(
        backup_info
            .relay_urls()
            .any(|u| *u == url("https://backup-home.example/"))
    );
    assert!(reader.lookup().get_endpoint_info(master_id).is_some());

    // Past the records' expiry, what they taught is taken back; the relay that was
    // already there stays.
    reader.expire(now + Duration::minutes(61));
    assert!(!map.contains(&url("https://master-home.example/")));
    assert!(!map.contains(&url("https://rescue.example/")));
    assert!(map.contains(&dead));
    assert!(reader.lookup().get_endpoint_info(master_id).is_none());
    assert!(reader.lookup().get_endpoint_info(backup_id).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cached_record_is_checked_again_when_the_lane_starts() {
    use ferryman_hive_rescue::record::{Body, Kind, Where, fleet_tag};

    let fleet = Fleet::new();
    let hive = common::start_mock().await;
    let dead: RelayUrl = "https://127.0.0.1:9/".parse().unwrap();
    let state = tempfile::tempdir().unwrap();
    let tag = fleet_tag(
        fleet.view.lock().unwrap().roster[0]
            .public_key
            .as_ref()
            .unwrap(),
    );
    let master_id = SecretKey::generate().public();
    let now = Utc::now();
    post_as(
        &hive,
        &fleet,
        &fleet.beastly,
        Body {
            v: 1,
            fleet: tag,
            kind: Kind::Master,
            signer: "beastly-ferry".into(),
            seq: 1,
            issued: now,
            expires: now + Duration::minutes(60),
            at: Where {
                id: endpoint_hex(&master_id),
                relay_url: None,
                direct: Vec::new(),
            },
            relay_list_version: None,
            rescue_relay: None,
            relays: None,
        },
    );
    // A first run reads it and writes it to the state file.
    let first = fleet.rescuer(&fleet.grouchly, &hive.url(), state.path(), false, |_| {});
    assert!(first.poll(now, true).await.unwrap().applied);

    // A restart, the cache still good: it is applied at once.
    let (endpoint, map) = relay_only(SecretKey::generate(), &dead).await;
    let again = fleet.rescuer(&fleet.grouchly, &hive.url(), state.path(), false, |_| {});
    again.attach(&endpoint, Some(map.clone())).unwrap();
    assert!(again.lookup().get_endpoint_info(master_id).is_some());

    // A restart after the master was revoked: the cache is a file on disk, and the
    // fleet folder's word of today wins. Nothing is applied and the cache is dropped.
    fleet
        .view
        .lock()
        .unwrap()
        .revoked
        .insert("beastly-ferry".into());
    let (endpoint, map) = relay_only(SecretKey::generate(), &dead).await;
    let revoked = fleet.rescuer(&fleet.grouchly, &hive.url(), state.path(), false, |_| {});
    revoked.attach(&endpoint, Some(map)).unwrap();
    assert!(revoked.lookup().get_endpoint_info(master_id).is_none());
    assert!(revoked.snapshot().latest_master.is_none());
}

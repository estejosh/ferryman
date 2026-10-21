//! The rescue loop against a mock Hive node (a local HTTP server): when each machine posts
//! and reads, what an accepted record teaches iroh, and what is refused.

mod common;

use chrono::{DateTime, Utc};
use common::{ACCOUNT, Fleet, at};
use ferryman_hive_rescue::mock::MockHive;
use ferryman_hive_rescue::record::{self, Kind};
use ferryman_hive_rescue::rescuer::{LaneInfo, Verdict};
use ferryman_iroh::lane::{PeerStatus, Status};

/// A lane that has lost its relay and its one peer since `since`.
fn cut_off(since: DateTime<Utc>) -> Status {
    let mut status = Status {
        relay_expected: true,
        relay_connected: false,
        relay_down_since: Some(since),
        ..Status::default()
    };
    status.peers.insert(
        "ab".repeat(32),
        PeerStatus {
            failing_since: Some(since),
            last_error: Some("no answer".into()),
            ..PeerStatus::default()
        },
    );
    status
}

fn healthy() -> Status {
    let mut status = Status {
        relay_expected: true,
        relay_connected: true,
        ..Status::default()
    };
    status.peers.insert("ab".repeat(32), PeerStatus::default());
    status
}

fn info(relay: Option<&str>) -> LaneInfo {
    LaneInfo {
        endpoint_id: hex::encode(iroh::SecretKey::from_bytes(&[5; 32]).public().as_bytes()),
        home_relay: relay.map(str::to_owned),
        direct: Vec::new(),
    }
}

#[tokio::test]
async fn the_master_posts_once_after_the_cut_off_and_a_cut_off_machine_learns_from_it() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let master = fleet.rescuer(&fleet.beastly, &hive.url(), a.path(), true, |c| {
        c.rescue_relay = Some("https://rescue.example/".into());
    });
    let reader = fleet.rescuer(&fleet.grouchly, &hive.url(), b.path(), false, |_| {});
    let t0 = Utc::now();

    // Ten minutes cut off is not enough.
    let report = master.tick(&cut_off(t0), &info(None), at(t0, 10)).await;
    assert!(report.posted.is_none());
    assert_eq!(hive.broadcasts(), 0);

    // Sixteen is: one operation, under the fleet account, and nothing readable in it.
    let report = master.tick(&cut_off(t0), &info(None), at(t0, 16)).await;
    let posted = report.posted.expect("posted");
    assert_eq!(posted.kind, Kind::Master);
    assert_eq!(hive.broadcasts(), 1);
    let ops = hive.ops_for(ACCOUNT);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].0, "ferryman-rescue");
    assert!(!ops[0].1.contains("rescue.example"));
    assert!(!ops[0].1.contains(&info(None).endpoint_id));

    // Still cut off a minute later: no second post.
    let report = master.tick(&cut_off(t0), &info(None), at(t0, 17)).await;
    assert!(report.posted.is_none());
    assert_eq!(hive.broadcasts(), 1);

    // The other machine, cut off, reads it, verifies it and feeds iroh.
    let report = reader.tick(&cut_off(t0), &info(None), at(t0, 17)).await;
    let read = report.read.expect("read");
    assert_eq!(read.scanned, 1);
    assert!(matches!(
        read.records[0].verdict,
        Verdict::Valid { new: true, .. }
    ));
    assert!(read.applied);
    let id = iroh::SecretKey::from_bytes(&[5; 32]).public();
    let learned = reader
        .lookup()
        .get_endpoint_info(id)
        .expect("a dial address");
    let relays: Vec<String> = learned.relay_urls().map(ToString::to_string).collect();
    assert_eq!(relays, ["https://rescue.example/"]);
    assert_eq!(
        reader.snapshot().latest_master.unwrap().body.seq,
        posted.record.body.seq
    );

    // Not polled again before the interval (3 minutes) is up.
    let report = reader.tick(&cut_off(t0), &info(None), at(t0, 18)).await;
    assert!(report.read.is_none());
    // And once it is, the same record is "already seen", not applied again.
    let report = reader.tick(&cut_off(t0), &info(None), at(t0, 21)).await;
    let read = report.read.expect("read");
    assert!(matches!(
        read.records[0].verdict,
        Verdict::Valid { new: false, .. }
    ));
    assert!(!read.applied);
}

#[tokio::test]
async fn a_healthy_machine_reads_nothing_and_a_reader_without_a_key_never_posts() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc::now();
    let reader = fleet.rescuer(&fleet.grouchly, &hive.url(), dir.path(), false, |_| {});
    let report = reader.tick(&healthy(), &info(None), at(t0, 120)).await;
    assert!(report.read.is_none() && report.posted.is_none());

    // The master, cut off, but with no posting key: says so and posts nothing.
    let dir2 = tempfile::tempdir().unwrap();
    let keyless = fleet.rescuer(&fleet.beastly, &hive.url(), dir2.path(), false, |_| {});
    let report = keyless.tick(&cut_off(t0), &info(None), at(t0, 30)).await;
    assert!(report.posted.is_none());
    assert!(
        report.notes.iter().any(|n| n.contains("no posting key")),
        "{:?}",
        report.notes
    );
    assert_eq!(hive.broadcasts(), 0);
}

#[tokio::test]
async fn it_posts_again_while_still_cut_off_so_a_fresh_record_is_always_there() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let dir = tempfile::tempdir().unwrap();
    let master = fleet.rescuer(&fleet.beastly, &hive.url(), dir.path(), true, |_| {});
    let t0 = Utc::now();
    assert!(
        master
            .tick(&cut_off(t0), &info(None), at(t0, 16))
            .await
            .posted
            .is_some()
    );
    assert!(
        master
            .tick(&cut_off(t0), &info(None), at(t0, 50))
            .await
            .posted
            .is_none()
    );
    let again = master
        .tick(&cut_off(t0), &info(None), at(t0, 62))
        .await
        .posted
        .expect("refresh");
    assert!(again.reason.contains("refreshing"));
    // A new cut-off later is a new episode.
    let t1 = at(t0, 200);
    let later = master
        .tick(&cut_off(t1), &info(None), at(t1, 16))
        .await
        .posted
        .expect("new episode");
    assert!(later.record.body.seq > again.record.body.seq);
    assert_eq!(hive.broadcasts(), 3);
}

#[tokio::test]
async fn a_relay_change_is_posted_but_the_first_sighting_is_only_a_baseline() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let dir = tempfile::tempdir().unwrap();
    let master = fleet.rescuer(&fleet.beastly, &hive.url(), dir.path(), true, |_| {});
    let t0 = Utc::now();
    let relay_a = info(Some("https://relay-a.example/"));
    let relay_b = info(Some("https://relay-b.example/"));
    assert!(master.tick(&healthy(), &relay_a, t0).await.posted.is_none());
    assert!(
        master
            .tick(&healthy(), &relay_a, at(t0, 60))
            .await
            .posted
            .is_none()
    );
    assert_eq!(hive.broadcasts(), 0);

    // Something to compare against: a first post (cut off), then the relay moves.
    assert!(
        master
            .tick(&cut_off(at(t0, 70)), &relay_a, at(t0, 90))
            .await
            .posted
            .is_some()
    );
    let moved = master
        .tick(&healthy(), &relay_b, at(t0, 130))
        .await
        .posted
        .expect("relay change");
    assert!(moved.reason.contains("relay-b.example"), "{}", moved.reason);
    // Not again for the same relay.
    assert!(
        master
            .tick(&healthy(), &relay_b, at(t0, 200))
            .await
            .posted
            .is_none()
    );
}

#[tokio::test]
async fn the_backup_posts_only_when_cut_off_long_and_no_fresh_master_record_exists() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let (m, g) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let master = fleet.rescuer(&fleet.beastly, &hive.url(), m.path(), true, |_| {});
    let backup = fleet.rescuer(&fleet.grouchly, &hive.url(), g.path(), true, |c| {
        c.backup = true;
        c.backup_agents = vec!["grouchly-ferry".into()];
    });
    let t0 = Utc::now();

    // The master posted 30 minutes ago and is fine: the backup stays quiet at 61 minutes.
    assert!(
        master
            .tick(&cut_off(t0), &info(None), at(t0, 16))
            .await
            .posted
            .is_some()
    );
    let report = backup.tick(&cut_off(t0), &info(None), at(t0, 61)).await;
    assert!(report.posted.is_none());
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("fresh master record")),
        "{:?}",
        report.notes
    );

    // Not yet 60 minutes cut off: quiet whatever Hive says.
    let report = backup
        .tick(&cut_off(at(t0, 50)), &info(None), at(t0, 100))
        .await;
    assert!(report.posted.is_none());

    // 120 minutes in, the master's record is long stale: the backup posts, as a pointer.
    let t1 = at(t0, 120);
    let report = backup.tick(&cut_off(t0), &info(None), t1).await;
    let posted = report.posted.expect("backup post");
    assert_eq!(posted.kind, Kind::Backup);
    assert!(posted.record.body.rescue_relay.is_none() && posted.record.body.relays.is_none());

    // A reader accepts it only if it designates grouchly.
    let r = tempfile::tempdir().unwrap();
    let strict = fleet.rescuer(&fleet.beastly, &hive.url(), r.path(), false, |_| {});
    let read = strict.poll(t1, false).await.unwrap();
    assert!(
        read.records
            .iter()
            .any(|f| matches!(&f.verdict, Verdict::Refused(w) if w.contains("designated")))
    );
    let r2 = tempfile::tempdir().unwrap();
    let trusting = fleet.rescuer(&fleet.beastly, &hive.url(), r2.path(), false, |c| {
        c.backup_agents = vec!["grouchly-ferry".into()];
    });
    let read = trusting.poll(t1, false).await.unwrap();
    assert!(read.records.iter().any(|f| matches!(
        &f.verdict,
        Verdict::Valid {
            kind: Kind::Backup,
            ..
        }
    )));
}

#[tokio::test]
async fn forgeries_replays_and_other_fleets_on_the_chain_are_not_believed() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let dir = tempfile::tempdir().unwrap();
    let reader = fleet.rescuer(&fleet.grouchly, &hive.url(), dir.path(), false, |_| {});
    let t0 = Utc::now();

    // grouchly (not the master) signs a record as the master, sealed to the whole roster.
    let view = fleet.view.lock().unwrap().clone();
    let tag = record::fleet_tag(view.roster[0].public_key.as_ref().unwrap());
    let mut body = ferryman_hive_rescue::record::Body {
        v: 1,
        fleet: tag.clone(),
        kind: Kind::Master,
        signer: "beastly-ferry".into(),
        seq: 5,
        issued: t0,
        expires: at(t0, 60),
        at: ferryman_hive_rescue::record::Where {
            id: "cd".repeat(32),
            relay_url: Some("https://evil.example/".into()),
            direct: Vec::new(),
        },
        relay_list_version: None,
        rescue_relay: None,
        relays: None,
    };
    let forged = record::sign(body.clone(), &fleet.grouchly.signer()).unwrap();
    let sealed = record::seal(&forged, &record::recipients(&view.roster, |_| false)).unwrap();
    hive.inject(ACCOUNT, "ferryman-rescue", &record::op_json(&tag, &sealed));
    // Garbage, and another fleet's operation.
    hive.inject(ACCOUNT, "ferryman-rescue", "not json");
    hive.inject(
        ACCOUNT,
        "ferryman-rescue",
        &record::op_json("ffffffffffffffff", &[1, 2, 3]),
    );

    let read = reader.poll(at(t0, 1), true).await.unwrap();
    assert_eq!(read.scanned, 3);
    assert!(!read.applied);
    assert!(reader.snapshot().latest_master.is_none());
    assert!(
        read.records
            .iter()
            .any(|f| matches!(&f.verdict, Verdict::Refused(w) if w.contains("signature")))
    );
    assert!(
        read.records
            .iter()
            .all(|f| !matches!(f.verdict, Verdict::Valid { .. }))
    );

    // The real thing, then the same operation replayed by anyone with a posting key.
    body.at.relay_url = Some("https://relay.example/".into());
    let real = record::sign(body, &fleet.beastly.signer()).unwrap();
    let sealed = record::seal(&real, &record::recipients(&view.roster, |_| false)).unwrap();
    let json = record::op_json(&tag, &sealed);
    hive.inject(ACCOUNT, "ferryman-rescue", &json);
    assert!(reader.poll(at(t0, 2), true).await.unwrap().applied);
    hive.inject(ACCOUNT, "ferryman-rescue", &json);
    let read = reader.poll(at(t0, 3), true).await.unwrap();
    assert!(!read.applied);
    assert_eq!(reader.snapshot().latest_master.unwrap().body.seq, 5);

    // And after it expires, the same operation counts for nothing.
    let read = reader.poll(at(t0, 90), false).await.unwrap();
    assert!(
        read.records
            .iter()
            .filter(|f| matches!(&f.verdict, Verdict::Refused(w) if w == "expired"))
            .count()
            >= 2
    );
}

#[tokio::test]
async fn a_dead_node_costs_a_note_not_the_channel() {
    let hive = MockHive::start("127.0.0.1:0").await.unwrap();
    let fleet = Fleet::new();
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let master = fleet.rescuer(&fleet.beastly, &hive.url(), a.path(), true, |_| {});
    let t0 = Utc::now();
    assert!(
        master
            .tick(&cut_off(t0), &info(None), at(t0, 16))
            .await
            .posted
            .is_some()
    );

    // Two nodes configured: the first is down, the second works.
    let down = MockHive::start("127.0.0.1:0").await.unwrap();
    down.set_down(true);
    let reader = fleet.rescuer_nodes(
        &fleet.grouchly,
        &[down.url(), hive.url()],
        b.path(),
        false,
        |_| {},
    );
    let read = reader.poll(at(t0, 17), true).await.unwrap();
    assert_eq!(read.failed.len(), 1);
    assert_eq!(read.answered, [hive.url()]);
    assert!(read.applied);

    // Everything down: an error report, no panic.
    hive.set_down(true);
    let read = reader.poll(at(t0, 30), true).await.unwrap();
    assert!(read.answered.is_empty() && !read.applied);
}

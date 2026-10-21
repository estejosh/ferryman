//! Seal, sign, verify, replay and expiry of the rescue record.

mod common;

use chrono::{Duration, Utc};
use common::{Fleet, Machine};
use ferryman_hive_rescue::record::{
    self, Body, Kind, RescueRelay, Verifier, Where, fleet_tag, recipients,
};
use ferryman_hive_rescue::state::State;

fn body(fleet: &Fleet, signer: &str, kind: Kind, seq: u64) -> Body {
    let now = Utc::now();
    let master = fleet.view.lock().unwrap().roster[0]
        .public_key
        .clone()
        .unwrap();
    Body {
        v: 1,
        fleet: fleet_tag(&master),
        kind,
        signer: signer.into(),
        seq,
        issued: now,
        expires: now + Duration::minutes(60),
        at: Where {
            id: "ab".repeat(32),
            relay_url: Some("https://relay.example/".into()),
            direct: Vec::new(),
        },
        relay_list_version: None,
        rescue_relay: Some(RescueRelay {
            url: "https://rescue.example/".into(),
            cert_sha256: None,
        }),
        relays: None,
    }
}

fn verifier<'a>(
    fleet: &'a Fleet,
    tag: &'a str,
    roster: &'a [ferryman_channel::AgentRoute],
    backups: &'a [String],
) -> Verifier<'a> {
    let _ = fleet;
    Verifier {
        fleet: tag,
        roster,
        master: "beastly-ferry",
        backups,
        now: Utc::now(),
    }
}

fn roster(fleet: &Fleet) -> Vec<ferryman_channel::AgentRoute> {
    fleet.view.lock().unwrap().roster.clone()
}

#[test]
fn a_record_seals_to_the_roster_and_only_the_roster_opens_it() {
    let fleet = Fleet::new();
    let roster = roster(&fleet);
    let b = body(&fleet, "beastly-ferry", Kind::Master, 1);
    let tag = b.fleet.clone();
    let signed = record::sign(b, &fleet.beastly.signer()).unwrap();
    let sealed = record::seal(&signed, &recipients(&roster, |_| false)).unwrap();

    // Both roster members open it, and get the same signed record back.
    for who in [&fleet.beastly, &fleet.grouchly] {
        let opened = record::open(&sealed, &tag, &who.enc()).unwrap();
        assert_eq!(opened, signed);
    }
    // A stranger with an X25519 key of their own cannot.
    let stranger = Machine::new("stranger", 99);
    let error = format!(
        "{:#}",
        record::open(&sealed, &tag, &stranger.enc()).unwrap_err()
    );
    assert!(error.contains("not sealed to this machine"), "{error}");
    // Nothing readable is in the bytes.
    assert!(!String::from_utf8_lossy(&sealed).contains("relay.example"));
}

#[test]
fn a_member_left_out_cannot_open_and_tampering_is_caught() {
    let fleet = Fleet::new();
    let roster = roster(&fleet);
    let b = body(&fleet, "beastly-ferry", Kind::Master, 1);
    let tag = b.fleet.clone();
    let signed = record::sign(b, &fleet.beastly.signer()).unwrap();
    // grouchly revoked: not wrapped to.
    let sealed = record::seal(&signed, &recipients(&roster, |n| n == "grouchly-ferry")).unwrap();
    assert!(record::open(&sealed, &tag, &fleet.grouchly.enc()).is_err());
    assert!(record::open(&sealed, &tag, &fleet.beastly.enc()).is_ok());

    let mut flipped = sealed.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(record::open(&flipped, &tag, &fleet.beastly.enc()).is_err());
    // Bound to its fleet: another fleet's tag does not open it.
    assert!(record::open(&sealed, "0000000000000000", &fleet.beastly.enc()).is_err());
}

#[test]
fn the_master_signature_is_checked_against_the_roster() {
    let fleet = Fleet::new();
    let roster = roster(&fleet);
    let b = body(&fleet, "beastly-ferry", Kind::Master, 1);
    let tag = b.fleet.clone();
    let v = verifier(&fleet, &tag, &roster, &[]);

    let good = record::sign(b.clone(), &fleet.beastly.signer()).unwrap();
    v.check(&good).unwrap();

    // Signed by the wrong key while claiming to be the master.
    let forged = record::sign(b.clone(), &fleet.grouchly.signer()).unwrap();
    assert!(v.check(&forged).unwrap_err().0.contains("signature"));

    // A change after signing.
    let mut edited = good.clone();
    edited.body.at.id = "cd".repeat(32);
    assert!(v.check(&edited).unwrap_err().0.contains("signature"));

    // A roster member that is not the master cannot sign as the master.
    let mut as_master = b.clone();
    as_master.signer = "grouchly-ferry".into();
    let not_master = record::sign(as_master, &fleet.grouchly.signer()).unwrap();
    assert!(v.check(&not_master).unwrap_err().0.contains("not"));

    // A name that is not on the roster.
    let mut nobody = b.clone();
    nobody.signer = "mallory".into();
    let mallory = record::sign(nobody, &Machine::new("mallory", 5).signer()).unwrap();
    assert!(
        v.check(&mallory)
            .unwrap_err()
            .0
            .contains("not on the roster")
    );

    // Another fleet's record.
    let mut other = b.clone();
    other.fleet = "ffffffffffffffff".into();
    let other = record::sign(other, &fleet.beastly.signer()).unwrap();
    assert!(v.check(&other).unwrap_err().0.contains("another fleet"));
}

#[test]
fn an_expired_or_backdated_or_overlong_record_does_not_count() {
    let fleet = Fleet::new();
    let roster = roster(&fleet);
    let b = body(&fleet, "beastly-ferry", Kind::Master, 1);
    let tag = b.fleet.clone();
    let v = verifier(&fleet, &tag, &roster, &[]);
    let sign = |b: Body| record::sign(b, &fleet.beastly.signer()).unwrap();

    let mut expired = b.clone();
    expired.issued = Utc::now() - Duration::hours(3);
    expired.expires = Utc::now() - Duration::hours(2);
    assert_eq!(v.check(&sign(expired)).unwrap_err().0, "expired");

    let mut future = b.clone();
    future.issued = Utc::now() + Duration::hours(2);
    future.expires = future.issued + Duration::hours(1);
    assert!(v.check(&sign(future)).unwrap_err().0.contains("future"));

    let mut forever = b.clone();
    forever.expires = forever.issued + Duration::days(30);
    assert!(v.check(&sign(forever)).unwrap_err().0.contains("lifetime"));
}

#[test]
fn a_replayed_record_is_dropped_by_its_sequence_number() {
    let fleet = Fleet::new();
    let first = record::sign(
        body(&fleet, "beastly-ferry", Kind::Master, 10),
        &fleet.beastly.signer(),
    )
    .unwrap();
    let second = record::sign(
        body(&fleet, "beastly-ferry", Kind::Master, 11),
        &fleet.beastly.signer(),
    )
    .unwrap();
    let mut state = State::default();
    state.accept(&first).unwrap();
    state.accept(&second).unwrap();
    // The old one again, and the newest again: both are replays.
    assert!(state.accept(&first).unwrap_err().0.contains("replay"));
    assert!(state.accept(&second).unwrap_err().0.contains("replay"));
    assert_eq!(state.latest_master.as_ref().unwrap().body.seq, 11);
    // Another signer's numbers are its own.
    let other = record::sign(
        body(&fleet, "grouchly-ferry", Kind::Backup, 1),
        &fleet.grouchly.signer(),
    )
    .unwrap();
    state.accept(&other).unwrap();
}

#[test]
fn a_backup_record_counts_only_from_a_designated_machine_and_only_points_at_itself() {
    let fleet = Fleet::new();
    let roster = roster(&fleet);
    let mut b = body(&fleet, "grouchly-ferry", Kind::Backup, 1);
    let tag = b.fleet.clone();
    b.rescue_relay = None;
    let signed = record::sign(b.clone(), &fleet.grouchly.signer()).unwrap();

    assert!(
        verifier(&fleet, &tag, &roster, &[])
            .check(&signed)
            .unwrap_err()
            .0
            .contains("designated")
    );
    let designated = ["grouchly-ferry".to_owned()];
    verifier(&fleet, &tag, &roster, &designated)
        .check(&signed)
        .unwrap();

    // A backup cannot carry a rescue relay or a relay list.
    let mut greedy = b.clone();
    greedy.rescue_relay = Some(RescueRelay {
        url: "https://evil.example/".into(),
        cert_sha256: None,
    });
    let greedy = record::sign(greedy, &fleet.grouchly.signer()).unwrap();
    assert!(
        verifier(&fleet, &tag, &roster, &designated)
            .check(&greedy)
            .unwrap_err()
            .0
            .contains("only point")
    );
}

#[test]
fn nonsense_in_a_signed_record_is_refused() {
    let fleet = Fleet::new();
    let roster = roster(&fleet);
    let good = body(&fleet, "beastly-ferry", Kind::Master, 1);
    let tag = good.fleet.clone();
    let v = verifier(&fleet, &tag, &roster, &[]);
    let sign = |b: Body| record::sign(b, &fleet.beastly.signer()).unwrap();

    let mut b = good.clone();
    b.at.id = "xyz".into();
    assert!(v.check(&sign(b)).is_err());
    let mut b = good.clone();
    b.at.relay_url = Some("http://insecure.example/".into());
    assert!(v.check(&sign(b)).is_err());
    let mut b = good.clone();
    b.at.direct = vec!["not-an-address".into()];
    assert!(v.check(&sign(b)).is_err());
    let mut b = good.clone();
    b.rescue_relay = Some(RescueRelay {
        url: "https://r.example/".into(),
        cert_sha256: Some("zz".into()),
    });
    assert!(v.check(&sign(b)).is_err());
}

#[test]
fn a_fleet_of_dozens_fits_in_one_custom_json() {
    let fleet = Fleet::new();
    let mut roster = roster(&fleet);
    for i in 0..40_u8 {
        roster.push(Machine::new(&format!("machine-{i}"), 120 + i).route());
    }
    let b = body(&fleet, "beastly-ferry", Kind::Master, 1);
    let signed = record::sign(b, &fleet.beastly.signer()).unwrap();
    let sealed = record::seal(&signed, &recipients(&roster, |_| false)).unwrap();
    let json = record::op_json(&signed.body.fleet, &sealed);
    assert!(json.len() < 8192, "{} bytes for 42 recipients", json.len());
}

#[test]
fn the_operation_json_round_trips_and_ignores_other_fleets() {
    let sealed = vec![1_u8, 2, 3];
    let json = record::op_json("aaaa", &sealed);
    assert_eq!(record::parse_op_json(&json, "aaaa").unwrap(), sealed);
    assert!(record::parse_op_json(&json, "bbbb").is_err());
    assert!(record::parse_op_json("{}", "aaaa").is_err());
}

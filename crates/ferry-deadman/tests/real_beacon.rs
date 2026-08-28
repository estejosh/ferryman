//! Live-network validation against drand quicknet.
//!
//! These tests hit the public internet and are therefore `#[ignore]`d by
//! default. Run them explicitly once after changes that touch the beacon or
//! timelock layers:
//!
//! ```sh
//! cargo test --test real_beacon -- --ignored --nocapture
//! ```

use ferry_deadman::beacon::{self, Beacon};
use ferry_deadman::tlock;

const CHAIN: &str = beacon::QUICKNET_CHAIN_HASH;

#[test]
#[ignore]
fn real_chain_info_and_signature_verify_shape() {
    let (base, info) = Beacon::fetch_default_drand().expect("a mirror must answer");
    assert_eq!(info.hash.to_ascii_lowercase(), CHAIN.to_ascii_lowercase());
    assert!(info.scheme.contains("rfc9380"), "scheme: {}", info.scheme);
    assert_eq!(
        info.public_key.len(),
        192,
        "quicknet pk is a 96-byte G2 point"
    );
    println!(
        "mirror {base} serves quicknet: period={}s genesis={}",
        info.period, info.genesis_time
    );

    // A round several periods in the past is guaranteed published.
    let now = ferry_deadman::error::unix_now().unwrap();
    let b = Beacon::Drand(beacon::DrandParams {
        base_url: base,
        chain_hash: CHAIN.into(),
        info,
    });
    let past = b.round_at(now - b.period_secs() as i64 * 5);
    let sig = b
        .wait_for_signature(past, std::time::Duration::from_secs(30))
        .expect("past round signature must be fetchable");
    assert!(sig.len() == 48 || sig.len() == 96);
}

#[test]
#[ignore]
fn real_tlock_roundtrip_to_a_past_round() {
    let (base, info) = Beacon::fetch_default_drand().expect("a mirror must answer");
    let b = Beacon::Drand(beacon::DrandParams {
        base_url: base,
        chain_hash: CHAIN.into(),
        info,
    });
    let now = ferry_deadman::error::unix_now().unwrap();
    // Seal to a round ~15s in the past; its signature exists already.
    let past_round = b.round_at(now - 15);
    let (master, blob) = tlock::seal_master_key(&b, past_round).expect("seal");
    assert_eq!(blob[0], tlock::KEY_BLOB_TAG_DRAND);
    assert_eq!(blob.len(), 1 + 128);

    let sig = b
        .wait_for_signature(past_round, std::time::Duration::from_secs(30))
        .expect("fetch signature");
    let opened = tlock::open_master_key(&blob, &sig).expect("open");
    assert_eq!(master, opened, "real timelock roundtrip must be lossless");

    // The signature of any OTHER round must NOT open the blob.
    let other_sig = b
        .wait_for_signature(past_round - 1, std::time::Duration::from_secs(30))
        .expect("second signature");
    assert_ne!(
        sig, other_sig,
        "distinct rounds must have distinct signatures"
    );
    assert!(tlock::open_master_key(&blob, &other_sig).is_err());
}

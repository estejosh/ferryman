//! Hive transaction serialization, digest and signature against vectors made by the
//! reference implementation (`@hiveio/dhive` 1.3.2: `Types.Transaction`,
//! `cryptoUtils.transactionDigest`, `PrivateKey.sign`). `tests/data/gen_vectors.mjs` makes
//! `tests/data/hive_vectors.json`; its header says how to rerun it.

use ferryman_hive_rescue::tx::{
    CustomJson, MAINNET_CHAIN_ID, PostingKey, Transaction, parse_hive_time,
};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hive_vectors.json"
    ))
    .unwrap();
    serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap()
}

fn tx_of(v: &Value) -> Transaction {
    Transaction {
        ref_block_num: u16::try_from(v["ref_block_num"].as_u64().unwrap()).unwrap(),
        ref_block_prefix: u32::try_from(v["ref_block_prefix"].as_u64().unwrap()).unwrap(),
        expiration: parse_hive_time(v["expiration"].as_str().unwrap()).unwrap(),
        operations: vec![CustomJson {
            required_auths: v["required_auths"].as_array().map_or_else(Vec::new, |a| {
                a.iter().map(|x| x.as_str().unwrap().to_owned()).collect()
            }),
            required_posting_auths: vec![v["account"].as_str().unwrap().to_owned()],
            id: v["id"].as_str().unwrap_or("ferryman-rescue-v1").into(),
            json: v["json"].as_str().unwrap().to_owned(),
        }],
    }
}

#[test]
fn there_are_vectors() {
    assert!(vectors().len() >= 14);
}

/// The reference's signing loop retries until the signature is canonical; the vectors
/// include keys and transactions where it needed 2, 3 and more than 4 tries, so the
/// retry path (a fresh nonce each time) is checked against the reference, not just the
/// lucky first attempt.
#[test]
fn the_vectors_include_non_canonical_retries() {
    let attempts: Vec<u64> = vectors()
        .iter()
        .map(|v| v["attempts"].as_u64().unwrap())
        .collect();
    for wanted in [2, 3] {
        assert!(
            attempts.contains(&wanted),
            "no vector needing {wanted} tries"
        );
    }
    assert!(
        attempts.iter().any(|a| *a >= 4),
        "no vector needing 4+ tries"
    );
    assert!(attempts.contains(&1));
}

#[test]
fn the_wif_and_public_key_match_the_reference() {
    for v in vectors() {
        let key = PostingKey::from_wif(v["wif"].as_str().unwrap()).unwrap();
        let sealed = key.public_key_bytes();
        let stm = v["pub"].as_str().unwrap().strip_prefix("STM").unwrap();
        let decoded = bs58::decode(stm).into_vec().unwrap();
        assert_eq!(&decoded[..33], &sealed[..], "{}", v["seed"]);
    }
}

#[test]
fn serialization_matches_the_reference_byte_for_byte() {
    for v in vectors() {
        assert_eq!(
            hex::encode(tx_of(&v).serialize()),
            v["serialized_hex"].as_str().unwrap(),
            "{}",
            v["seed"]
        );
    }
}

#[test]
fn the_digest_matches_the_reference() {
    for v in vectors() {
        assert_eq!(
            hex::encode(tx_of(&v).digest(MAINNET_CHAIN_ID).unwrap()),
            v["digest_hex"].as_str().unwrap(),
            "{}",
            v["seed"]
        );
    }
}

#[test]
fn the_signature_matches_the_reference() {
    for v in vectors() {
        let key = PostingKey::from_wif(v["wif"].as_str().unwrap()).unwrap();
        assert_eq!(
            tx_of(&v).sign(&key, MAINNET_CHAIN_ID).unwrap(),
            v["signature"].as_str().unwrap(),
            "{}",
            v["seed"]
        );
    }
}

#[test]
fn a_signature_recovers_the_signing_key() {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    for v in vectors() {
        let key = PostingKey::from_wif(v["wif"].as_str().unwrap()).unwrap();
        let tx = tx_of(&v);
        let sig = hex::decode(tx.sign(&key, MAINNET_CHAIN_ID).unwrap()).unwrap();
        assert_eq!(sig.len(), 65);
        let recovered = VerifyingKey::recover_from_prehash(
            &tx.digest(MAINNET_CHAIN_ID).unwrap(),
            &Signature::from_slice(&sig[1..]).unwrap(),
            RecoveryId::from_byte(sig[0] - 31).unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(recovered.to_sec1_point(true).as_bytes()),
            key.public_key_hex()
        );
    }
}

#[test]
fn a_bad_wif_is_refused_without_echoing_it() {
    let good = "5K2r4ZRQ9HUu1Y1Sfon55LSe5jLwKiwcB7wAEi61cHKDjZ3LrGY";
    let mut bad = good.to_owned();
    bad.replace_range(10..11, if &good[10..11] == "Z" { "Y" } else { "Z" });
    let error = format!("{:#}", PostingKey::from_wif(&bad).unwrap_err());
    assert!(!error.contains(&bad));
    assert!(PostingKey::from_wif("not a key").is_err());
    assert_eq!(
        format!("{:?}", PostingKey::from_wif(good).unwrap()),
        "PostingKey(<redacted>)"
    );
}

#[test]
fn an_oversized_operation_is_refused_here_with_a_clear_message() {
    let op = CustomJson {
        required_auths: Vec::new(),
        required_posting_auths: vec!["a".into()],
        id: "ferryman-rescue".into(),
        json: "x".repeat(9000),
    };
    assert!(format!("{:#}", op.check().unwrap_err()).contains("carries under 8192"));
}

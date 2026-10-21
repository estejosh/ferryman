//! The one Hive transaction this crate ever makes: a `custom_json` operation, signed with
//! a posting key.
//!
//! No maintained Rust crate does Hive transaction signing (the Steem-era ones are
//! abandoned and pull in rust-secp256k1 C bindings), so this is the smallest thing that
//! works: the binary serialization of a transaction with one `custom_json` operation, the
//! chain-id-prefixed SHA-256 digest, and a canonical recoverable secp256k1 signature.
//! `tests/data/hive_vectors.json` holds vectors produced by the reference implementation
//! (`@hiveio/dhive` 1.3.2), and `tests/vectors.rs` checks serialization, digest and
//! signature byte for byte.
//!
//! Nothing here logs, prints or formats a key: [`PostingKey`]'s `Debug` is redacted.

use std::fmt;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDateTime, Utc};
use k256::ecdsa::SigningKey;
use k256::ecdsa::hazmat::SignPrimitive;
use k256::sha2::Sha256 as Sha256Old;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Hive mainnet's chain id.
pub const MAINNET_CHAIN_ID: &str =
    "beeab0de00000000000000000000000000000000000000000000000000000000";

/// `custom_json`'s operation number.
const CUSTOM_JSON: u8 = 18;

/// The longest `json` string a `custom_json` operation may carry.
pub const MAX_JSON: usize = 8192;
/// The longest operation id.
pub const MAX_ID: usize = 32;

/// A posting key. The secret never leaves this type except as a signature.
pub struct PostingKey(SigningKey);

impl fmt::Debug for PostingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostingKey(<redacted>)")
    }
}

impl PostingKey {
    /// Parse a WIF private key (`5...`, base58 of `0x80 || key || sha256d(..)[..4]`).
    ///
    /// # Errors
    /// Not base58, wrong length, wrong version byte, a bad checksum, or not a valid key.
    /// The error never includes the text.
    pub fn from_wif(wif: &str) -> Result<Self> {
        let raw = bs58::decode(wif.trim())
            .into_vec()
            .map_err(|_| anyhow::anyhow!("the posting key is not base58"))?;
        if raw.len() != 37 || raw[0] != 0x80 {
            bail!("the posting key is not a WIF private key");
        }
        let (body, check) = raw.split_at(33);
        let sum = Sha256::digest(Sha256::digest(body));
        if sum[..4] != *check {
            bail!("the posting key's checksum is wrong (mistyped?)");
        }
        let key = SigningKey::from_slice(&body[1..])
            .map_err(|_| anyhow::anyhow!("the posting key is not a valid secp256k1 key"))?;
        Ok(Self(key))
    }

    /// The compressed public key, hex (for tests and for comparing with an account).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_encoded_point(true).as_bytes())
    }

    /// Sign a 32-byte digest the way Hive nodes expect: low-S, recoverable, and canonical
    /// by the Steem rule, retrying with fresh nonce data until it is (as dhive does).
    ///
    /// Returns the 65-byte signature as hex: `31 + recovery id`, `r`, `s`.
    ///
    /// # Errors
    /// The signing primitive failed (never expected for a valid key).
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<String> {
        let scalar = self.0.as_nonzero_scalar();
        let z = k256::FieldBytes::from(*digest);
        for attempt in 1_u8..=255 {
            // dhive passes sha256(digest || attempt) as the RFC 6979 additional data on
            // every attempt, the first included.
            let mut extra = Vec::with_capacity(33);
            extra.extend_from_slice(digest);
            extra.push(attempt);
            let ad = Sha256::digest(&extra);
            let (signature, recovery) = scalar
                .try_sign_prehashed_rfc6979::<Sha256Old>(&z, &ad)
                .map_err(|_| anyhow::anyhow!("signing failed"))?;
            let Some(recovery) = recovery else {
                bail!("signing produced no recovery id");
            };
            let (signature, recovery) = match signature.normalize_s() {
                Some(low) => (
                    low,
                    k256::ecdsa::RecoveryId::new(!recovery.is_y_odd(), recovery.is_x_reduced()),
                ),
                None => (signature, recovery),
            };
            let compact = signature.to_bytes();
            if canonical(&compact) {
                let mut out = Vec::with_capacity(65);
                out.push(31 + recovery.to_byte());
                out.extend_from_slice(&compact);
                return Ok(hex::encode(out));
            }
        }
        bail!("no canonical signature in 255 attempts")
    }
}

/// The Steem/Hive "canonical signature" rule over `r || s`.
fn canonical(rs: &[u8]) -> bool {
    rs[0] & 0x80 == 0
        && !(rs[0] == 0 && rs[1] & 0x80 == 0)
        && rs[32] & 0x80 == 0
        && !(rs[32] == 0 && rs[33] & 0x80 == 0)
}

/// A `custom_json` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomJson {
    pub required_auths: Vec<String>,
    pub required_posting_auths: Vec<String>,
    pub id: String,
    pub json: String,
}

impl CustomJson {
    /// Whether the node would accept it, checked here so the error is ours and clear.
    ///
    /// # Errors
    /// The id or the json is too long, or there is no authority to post under.
    pub fn check(&self) -> Result<()> {
        if self.id.is_empty() || self.id.len() > MAX_ID {
            bail!("a custom_json id is 1 to {MAX_ID} characters");
        }
        if self.json.len() >= MAX_JSON {
            bail!(
                "the record is {} bytes; a custom_json operation carries under {MAX_JSON}. \
                 Fewer recipients (roster members with an encryption key) would fit",
                self.json.len()
            );
        }
        if self.required_auths.is_empty() && self.required_posting_auths.is_empty() {
            bail!("a custom_json operation needs an account to post under");
        }
        Ok(())
    }
}

/// A transaction of `custom_json` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub expiration: DateTime<Utc>,
    pub operations: Vec<CustomJson>,
}

fn varint(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn string(out: &mut Vec<u8>, text: &str) {
    varint(out, text.len());
    out.extend_from_slice(text.as_bytes());
}

/// Hive writes expirations as `YYYY-MM-DDTHH:MM:SS`, UTC, no zone.
#[must_use]
pub fn hive_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// Parse a node's time string (UTC, with or without a trailing `Z`).
///
/// # Errors
/// Not a Hive time.
pub fn parse_hive_time(text: &str) -> Result<DateTime<Utc>> {
    let text = text.trim_end_matches('Z');
    let naive = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
        .with_context(|| format!("'{text}' is not a Hive time"))?;
    Ok(naive.and_utc())
}

impl Transaction {
    /// The bytes Hive signs and hashes.
    ///
    /// # Panics
    /// Never in practice: a time before 1970 or past 2106 is clamped.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ref_block_num.to_le_bytes());
        out.extend_from_slice(&self.ref_block_prefix.to_le_bytes());
        let seconds = u32::try_from(self.expiration.timestamp().max(0)).unwrap_or(u32::MAX);
        out.extend_from_slice(&seconds.to_le_bytes());
        varint(&mut out, self.operations.len());
        for op in &self.operations {
            out.push(CUSTOM_JSON);
            varint(&mut out, op.required_auths.len());
            for account in &op.required_auths {
                string(&mut out, account);
            }
            varint(&mut out, op.required_posting_auths.len());
            for account in &op.required_posting_auths {
                string(&mut out, account);
            }
            string(&mut out, &op.id);
            string(&mut out, &op.json);
        }
        varint(&mut out, 0); // extensions
        out
    }

    /// `sha256(chain_id || serialized)`: what the key signs.
    ///
    /// # Errors
    /// `chain_id_hex` is not 64 hex characters.
    pub fn digest(&self, chain_id_hex: &str) -> Result<[u8; 32]> {
        let chain = hex::decode(chain_id_hex).context("the chain id is not hex")?;
        let mut hasher = Sha256::new();
        hasher.update(&chain);
        hasher.update(self.serialize());
        Ok(hasher.finalize().into())
    }

    /// The transaction id: the first 20 bytes of `sha256(serialized)`, hex.
    #[must_use]
    pub fn id(&self) -> String {
        hex::encode(&Sha256::digest(self.serialize())[..20])
    }

    /// Sign with `key`.
    ///
    /// # Errors
    /// A bad chain id, or the signing primitive failed.
    pub fn sign(&self, key: &PostingKey, chain_id_hex: &str) -> Result<String> {
        key.sign_digest(&self.digest(chain_id_hex)?)
    }

    /// The JSON form a node's `broadcast_transaction` takes.
    #[must_use]
    pub fn to_rpc(&self, signatures: &[String]) -> Value {
        json!({
            "ref_block_num": self.ref_block_num,
            "ref_block_prefix": self.ref_block_prefix,
            "expiration": hive_time(self.expiration),
            "operations": self.operations.iter().map(|op| json!([
                "custom_json",
                {
                    "required_auths": op.required_auths,
                    "required_posting_auths": op.required_posting_auths,
                    "id": op.id,
                    "json": op.json,
                }
            ])).collect::<Vec<_>>(),
            "extensions": [],
            "signatures": signatures,
        })
    }
}

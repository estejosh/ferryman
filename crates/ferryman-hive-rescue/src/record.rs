//! The rescue record: what the master says, how it is signed, sealed and checked.
//!
//! ```text
//! custom_json { id: "ferryman-rescue", json: {"v":1,"f":"<fleet tag>","s":"<hex sealed>"} }
//!   sealed = 0x01 || eph_pub(32) || nonce(12) || n(1) || n * (tag(4) || wrapped_key(48)) || body
//!   body   = ChaCha20-Poly1305(content_key, nonce, aad = "ferryman-rescue/v1" || fleet || eph_pub)
//!            of the JSON of a Signed record
//!   slot   = ChaCha20-Poly1305(wrap_key, zero nonce, aad = fleet) of content_key
//!   wrap_key = HKDF-SHA256(salt = eph_pub || recipient_pub, ikm = X25519(eph, recipient),
//!                          info = "ferryman-rescue/v1/wrap")
//! ```
//!
//! A fresh ephemeral key per record, the content key wrapped separately to each roster
//! member with an X25519 key: revoking a machine is not wrapping to it from then on, and a
//! leaked key opens only the records wrapped to it. The Hive chain keeps the ciphertext
//! forever; that is why the default record carries no direct IP addresses.
//!
//! What counts is checked after opening, never before and never from the chain's say-so
//! (see [`Verifier::check`]): the signature against the roster, the signer's standing,
//! expiry, and a sequence number higher than any seen from that signer. A record grants
//! nothing: the ordinary iroh checks still decide who is let in.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use ferryman_channel::fleethome::FleetRelay;
use ferryman_channel::secrets::EncryptionIdentity;
use ferryman_channel::{AgentIdentity, AgentRoute, canonical_agent_name};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// The record's format version.
pub const VERSION: u32 = 1;
const SEAL_VERSION: u8 = 1;
const WRAP_INFO: &[u8] = b"ferryman-rescue/v1/wrap";
const AAD: &[u8] = b"ferryman-rescue/v1";

/// How far ahead of this machine's clock a record may be dated.
pub const CLOCK_SKEW: Duration = Duration::minutes(10);
/// The longest a record may live, whatever it says.
pub const MAX_LIFETIME: Duration = Duration::hours(24);
/// Direct address candidates a record may carry.
pub const MAX_DIRECT: usize = 8;

/// Who signed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// The fleet's master: its addresses, the relay to use, the relay list.
    Master,
    /// A designated backup poster: a pointer to that machine only.
    Backup,
}

/// Where to reach the signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Where {
    /// The iroh endpoint id, 64 hex characters.
    pub id: String,
    /// The relay the endpoint is homed on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Direct socket addresses. Empty unless the fleet turned them on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct: Vec<String>,
}

/// A relay to use now, because the usual one is what is down.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RescueRelay {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

/// What is signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Body {
    pub v: u32,
    /// The fleet this is for (see [`fleet_tag`]).
    pub fleet: String,
    pub kind: Kind,
    /// The roster name that signed, inside the signature so it cannot be replayed under
    /// another name.
    pub signer: String,
    /// Higher than any this signer has sent.
    pub seq: u64,
    pub issued: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    #[serde(rename = "where")]
    pub at: Where,
    /// When the master wrote the relay list in the fleet folder: the list's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_list_version: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescue_relay: Option<RescueRelay>,
    /// The master's relay list at the time, so a cut-off machine learns of a move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<FleetRelay>>,
}

/// A body and the signature over it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signed {
    pub body: Body,
    pub sig: String,
}

/// A short, public tag for the fleet: the same on every machine that knows the master's
/// key, and not reversible to anything. It scopes records, so two fleets sharing a Hive
/// account do not read each other's.
#[must_use]
pub fn fleet_tag(master_public_key_hex: &str) -> String {
    let digest = Sha256::digest(format!("ferryman-rescue-fleet\n{master_public_key_hex}"));
    hex::encode(&digest[..8])
}

fn payload(body: &Body) -> Result<Vec<u8>> {
    let mut bytes = b"ferryman-rescue-v1\n".to_vec();
    bytes.extend_from_slice(serde_jcs::to_string(body)?.as_bytes());
    Ok(bytes)
}

/// Sign `body` as `identity`.
///
/// # Errors
/// The body cannot be canonicalised.
pub fn sign(body: Body, identity: &AgentIdentity) -> Result<Signed> {
    let sig = identity.sign_bytes(&payload(&body)?);
    Ok(Signed { body, sig })
}

/// One roster member the record is wrapped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub name: String,
    pub x25519: [u8; 32],
}

/// The members of `roster` that have an encryption key, parsed.
#[must_use]
pub fn recipients(roster: &[AgentRoute], skip: impl Fn(&str) -> bool) -> Vec<Recipient> {
    let mut seen = BTreeMap::new();
    for agent in roster {
        let name = canonical_agent_name(&agent.name);
        if skip(&name) {
            continue;
        }
        let Some(key) = agent
            .encryption_key
            .as_deref()
            .and_then(|k| hex::decode(k).ok())
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
        else {
            continue;
        };
        seen.insert(name.clone(), Recipient { name, x25519: key });
    }
    seen.into_values().collect()
}

fn tag_of(public: &[u8; 32]) -> [u8; 4] {
    let digest = Sha256::digest(public);
    [digest[0], digest[1], digest[2], digest[3]]
}

fn wrap_key(shared: &[u8; 32], eph: &[u8; 32], recipient: &[u8; 32]) -> Result<[u8; 32]> {
    let mut salt = [0_u8; 64];
    salt[..32].copy_from_slice(eph);
    salt[32..].copy_from_slice(recipient);
    let mut key = [0_u8; 32];
    Hkdf::<sha2::Sha256>::new(Some(&salt), shared)
        .expand(WRAP_INFO, &mut key)
        .map_err(|_| anyhow!("could not derive the wrap key"))?;
    Ok(key)
}

fn aead(key: &[u8; 32]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("bad key"))
}

fn body_aad(fleet: &str, eph: &[u8; 32]) -> Vec<u8> {
    let mut aad = AAD.to_vec();
    aad.extend_from_slice(fleet.as_bytes());
    aad.extend_from_slice(eph);
    aad
}

/// Seal a signed record to `recipients`.
///
/// # Errors
/// No recipients, more than 255, or the encryption failed.
pub fn seal(record: &Signed, recipients: &[Recipient]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("no roster member has an encryption key, so there is nobody to seal to");
    }
    let count = u8::try_from(recipients.len()).context("more than 255 recipients")?;
    let mut eph_bytes = [0_u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut eph_bytes);
    let ephemeral = StaticSecret::from(eph_bytes);
    let eph_pub = *PublicKey::from(&ephemeral).as_bytes();
    let mut content_key = [0_u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut content_key);
    let mut nonce = [0_u8; 12];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);

    let plaintext = serde_json::to_vec(record)?;
    let body = aead(&content_key)?
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &body_aad(&record.body.fleet, &eph_pub),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;

    let mut out = vec![SEAL_VERSION];
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&nonce);
    out.push(count);
    for recipient in recipients {
        let shared = ephemeral.diffie_hellman(&PublicKey::from(recipient.x25519));
        let wrap = wrap_key(shared.as_bytes(), &eph_pub, &recipient.x25519)?;
        let wrapped = aead(&wrap)?
            .encrypt(
                &Nonce::from([0_u8; 12]),
                Payload {
                    msg: &content_key,
                    aad: record.body.fleet.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        out.extend_from_slice(&tag_of(&recipient.x25519));
        out.extend_from_slice(&wrapped);
    }
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open a sealed record with this machine's encryption identity.
///
/// The result is NOT trusted: run it through [`Verifier::check`].
///
/// # Errors
/// Not a record of this format, not wrapped to this machine, or tampered with.
pub fn open(sealed: &[u8], fleet: &str, me: &EncryptionIdentity) -> Result<Signed> {
    const SLOT: usize = 4 + 48;
    if sealed.first() != Some(&SEAL_VERSION) || sealed.len() < 1 + 32 + 12 + 1 {
        bail!("not a rescue record");
    }
    let eph_pub: [u8; 32] = sealed[1..33].try_into()?;
    let nonce: [u8; 12] = sealed[33..45].try_into()?;
    let count = usize::from(sealed[45]);
    let slots_end = 46 + count * SLOT;
    if count == 0 || sealed.len() <= slots_end {
        bail!("the record is cut short");
    }
    let my_public = me.public_key_bytes();
    let my_tag = tag_of(&my_public);
    let shared = me.agree(&eph_pub);
    let wrap = wrap_key(&shared, &eph_pub, &my_public)?;
    let mut content_key = None;
    for slot in sealed[46..slots_end].chunks_exact(SLOT) {
        if slot[..4] != my_tag {
            continue;
        }
        if let Ok(key) = aead(&wrap)?.decrypt(
            &Nonce::from([0_u8; 12]),
            Payload {
                msg: &slot[4..],
                aad: fleet.as_bytes(),
            },
        ) {
            content_key = <[u8; 32]>::try_from(key.as_slice()).ok();
            break;
        }
    }
    let content_key =
        content_key.ok_or_else(|| anyhow!("the record is not sealed to this machine"))?;
    let plaintext = aead(&content_key)?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &sealed[slots_end..],
                aad: &body_aad(fleet, &eph_pub),
            },
        )
        .map_err(|_| anyhow!("the record failed its authentication"))?;
    serde_json::from_slice(&plaintext).context("the record's content is not a rescue record")
}

/// The `json` string of the `custom_json` operation for a sealed record.
#[must_use]
pub fn op_json(fleet: &str, sealed: &[u8]) -> String {
    serde_json::json!({ "v": VERSION, "f": fleet, "s": hex::encode(sealed) }).to_string()
}

/// Read a `custom_json` operation's `json` back into the sealed bytes, when it is for
/// `fleet`.
///
/// # Errors
/// Not a rescue operation, or for another fleet.
pub fn parse_op_json(json: &str, fleet: &str) -> Result<Vec<u8>> {
    #[derive(Deserialize)]
    struct Op {
        v: u32,
        f: String,
        s: String,
    }
    let op: Op = serde_json::from_str(json).context("not a rescue operation")?;
    if op.v != VERSION || op.f != fleet {
        bail!("an operation for another fleet or version");
    }
    hex::decode(op.s).context("the sealed part is not hex")
}

/// What decides whether an opened record counts.
pub struct Verifier<'a> {
    pub fleet: &'a str,
    pub roster: &'a [AgentRoute],
    /// The fleet's master, canonical.
    pub master: &'a str,
    /// Names whose backup records count.
    pub backups: &'a [String],
    pub now: DateTime<Utc>,
}

/// Why a record does not count. Shown by `ferry rescue hive read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(why: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(why.into()))
}

impl Verifier<'_> {
    /// Everything except the sequence number (the ledger's job, and only once the record
    /// is otherwise good, so a forged record cannot burn a sequence number).
    ///
    /// # Errors
    /// [`Refused`], with the reason.
    pub fn check(&self, record: &Signed) -> Result<(), Refused> {
        let body = &record.body;
        if body.v != VERSION {
            return refuse("a record of a version this build does not read");
        }
        if body.fleet != self.fleet {
            return refuse("a record for another fleet");
        }
        let signer = canonical_agent_name(&body.signer);
        let Some(agent) = self
            .roster
            .iter()
            .find(|a| canonical_agent_name(&a.name) == signer)
        else {
            return refuse(format!("'{}' is not on the roster", body.signer));
        };
        let Some(key) = agent
            .public_key
            .as_deref()
            .and_then(|k| hex::decode(k).ok())
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
            .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        else {
            return refuse(format!("'{}' has no usable key on the roster", body.signer));
        };
        let Some(sig) = hex::decode(&record.sig)
            .ok()
            .and_then(|s| <[u8; 64]>::try_from(s.as_slice()).ok())
        else {
            return refuse("the signature is malformed");
        };
        let Ok(bytes) = payload(body) else {
            return refuse("the record cannot be canonicalised");
        };
        if key
            .verify_strict(&bytes, &Signature::from_bytes(&sig))
            .is_err()
        {
            return refuse("the signature does not verify against the roster");
        }
        match body.kind {
            Kind::Master => {
                if signer != self.master {
                    return refuse(format!("'{}' signed as master but is not", body.signer));
                }
            }
            Kind::Backup => {
                if !self
                    .backups
                    .iter()
                    .any(|b| canonical_agent_name(b) == signer)
                {
                    return refuse(format!(
                        "'{}' is not a designated backup poster",
                        body.signer
                    ));
                }
                if body.relays.is_some()
                    || body.rescue_relay.is_some()
                    || body.relay_list_version.is_some()
                {
                    return refuse("a backup record may only point at its own machine");
                }
            }
        }
        if body.issued > self.now + CLOCK_SKEW {
            return refuse("dated in the future");
        }
        if body.expires <= self.now {
            return refuse("expired");
        }
        if body.expires - body.issued > MAX_LIFETIME || body.expires <= body.issued {
            return refuse("its lifetime is not sane");
        }
        if body.at.id.len() != 64 || !body.at.id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return refuse("the endpoint id is not 64 hex characters");
        }
        if let Some(url) = &body.at.relay_url
            && !relay_url_ok(url)
        {
            return refuse("the endpoint's relay is not an https address");
        }
        if body.at.direct.len() > MAX_DIRECT
            || body
                .at
                .direct
                .iter()
                .any(|a| a.parse::<std::net::SocketAddr>().is_err())
        {
            return refuse("a direct address that is not a socket address, or too many");
        }
        if let Some(relay) = &body.rescue_relay {
            let entry = FleetRelay {
                url: relay.url.clone(),
                cert_sha256: relay.cert_sha256.clone(),
                note: None,
            };
            if let Err(why) = entry.check() {
                return refuse(format!("the rescue relay: {why}"));
            }
        }
        if let Some(list) = &body.relays {
            if list.len() > ferryman_channel::fleethome::MAX_RELAYS {
                return refuse("too many relays");
            }
            if let Some(why) = list.iter().find_map(|r| r.check().err()) {
                return refuse(format!("the relay list: {why}"));
            }
        }
        Ok(())
    }
}

fn relay_url_ok(url: &str) -> bool {
    FleetRelay {
        url: url.to_owned(),
        cert_sha256: None,
        note: None,
    }
    .check()
    .is_ok()
}

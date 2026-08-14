//! Signed v2 portable envelopes — implementation gates 1 and 2 of
//! `PORTABLE_AUTHENTICATION.md`.
//!
//! v1 transport is unsigned. This module adds the v2 envelope: an `authentication`
//! block carrying an Ed25519 signature over the RFC 8785 canonical JSON of the
//! envelope, plus the outer, unsynchronized `trusted-signers.toml` that binds
//! signers to projects, roles, and capabilities.
//!
//! Gates covered here: (1) signing identity (signer id) and trust-store parsing,
//! (2) canonical v2 message/acknowledgement types and signature tests. Enforcing
//! these at the inbound boundary (gate 3) is a separate change.

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// v2 message envelope format marker.
pub const MESSAGE_FORMAT_V2: &str = "ferryman-message/v2";
/// v2 acknowledgement envelope format marker.
pub const ACKNOWLEDGEMENT_FORMAT_V2: &str = "ferryman-acknowledgement/v2";
const KIND_MESSAGE: &str = "message";
const KIND_ACKNOWLEDGEMENT: &str = "acknowledgement";
const ALGORITHM: &str = "ed25519";
const KEY_VERSION: u32 = 1;

/// A signer identity: `sha256:<hex SHA-256 of the Ed25519 public key>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignerId(String);

impl SignerId {
    /// Derive a signer id from an Ed25519 public key.
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(key.as_bytes()))
        ))
    }

    /// Parse and validate a signer id.
    pub fn parse(value: &str) -> Result<Self> {
        let rest = value
            .strip_prefix("sha256:")
            .context("signer id must start with 'sha256:'")?;
        if rest.len() != 64 || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("signer id must be 'sha256:' followed by 64 lowercase hex characters");
        }
        Ok(Self(value.to_owned()))
    }

    /// The full `sha256:<hex>` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The authentication block added to every v2 envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Authentication {
    pub algorithm: String,
    pub signer_id: String,
    pub key_version: u32,
    pub nonce: String,
    /// Hex signature over the canonical envelope; omitted while signing.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// A v2 message envelope: the v1 `Message` fields plus `authentication`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageV2 {
    pub format: String,
    pub id: String,
    pub project_id: String,
    pub sender: String,
    pub recipient: String,
    pub created_at: DateTime<Utc>,
    pub acknowledgement_deadline: DateTime<Utc>,
    pub payload_reference: String,
    pub payload: Value,
    pub reply_required: bool,
    pub idempotency_key: String,
    pub authentication: Authentication,
}

/// A v2 acknowledgement envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgementV2 {
    pub format: String,
    pub message_id: String,
    /// SHA-256 of the canonical signed message envelope this acknowledges.
    pub message_digest: String,
    pub project_id: String,
    pub recipient: String,
    pub processed_at: DateTime<Utc>,
    pub idempotency_key: String,
    pub authentication: Authentication,
}

/// One trusted signer and its project/role/capability grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerGrant {
    /// Hex-encoded Ed25519 public key (32 bytes).
    pub public_key: String,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl SignerGrant {
    /// The signer id derived from this grant's public key.
    pub fn signer_id(&self) -> Result<SignerId> {
        Ok(SignerId::from_verifying_key(&self.verifying_key()?))
    }

    /// Parse the public key into a verifying key.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes =
            hex::decode(&self.public_key).context("trusted signer public key is not hex")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("trusted signer public key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).context("trusted signer public key is invalid")
    }
}

/// The outer, unsynchronized trust store (`trusted-signers.toml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustedSigners {
    #[serde(default)]
    pub signers: Vec<SignerGrant>,
}

impl TrustedSigners {
    /// Load the trust store from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read trust store {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse trust store {}", path.display()))
    }

    /// The grant whose derived signer id matches `signer_id`, if trusted.
    pub fn grant_for(&self, signer_id: &str) -> Option<&SignerGrant> {
        self.signers
            .iter()
            .find(|grant| grant.signer_id().is_ok_and(|id| id.as_str() == signer_id))
    }
}

/// RFC 8785 canonical JSON of `value`, as bytes.
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let canonical = serde_jcs::to_string(&value)?;
    Ok(canonical.into_bytes())
}

/// The signing domain separator: `ferryman-portable-envelope/v2\0<kind>\0`.
fn domain_separator(kind: &str) -> Vec<u8> {
    format!("ferryman-portable-envelope/v2\0{kind}\0").into_bytes()
}

/// A fresh 128-bit nonce, hex-encoded.
fn new_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    hex::encode(bytes)
}

/// Sign `canonical` bytes over the domain separator, hex-encoding the signature.
fn sign_bytes(signing: &SigningKey, kind: &str, canonical: &[u8]) -> String {
    let mut message = domain_separator(kind);
    message.extend_from_slice(canonical);
    hex::encode(signing.sign(&message).to_bytes())
}

/// Verify `signature` over `canonical` bytes and the domain separator.
fn verify_bytes(key: &VerifyingKey, kind: &str, canonical: &[u8], signature: &str) -> Result<()> {
    let bytes = hex::decode(signature).context("signature is not hex")?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&bytes);
    let mut message = domain_separator(kind);
    message.extend_from_slice(canonical);
    key.verify_strict(&message, &signature)
        .context("signature verification failed")
}

impl MessageV2 {
    /// Build an unsigned v2 message.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        payload_reference: impl Into<String>,
        payload: Value,
        reply_required: bool,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now();
        Self {
            format: MESSAGE_FORMAT_V2.into(),
            idempotency_key: id.clone(),
            id,
            project_id: project_id.into(),
            sender: sender.into(),
            recipient: recipient.into(),
            created_at,
            acknowledgement_deadline: created_at + chrono::Duration::seconds(30),
            payload_reference: payload_reference.into(),
            payload,
            reply_required,
            authentication: Authentication {
                algorithm: ALGORITHM.into(),
                signer_id: String::new(),
                key_version: KEY_VERSION,
                nonce: String::new(),
                signature: String::new(),
            },
        }
    }

    /// Sign in place: fills the authentication block and the signature.
    pub fn sign(&mut self, signing: &SigningKey) -> Result<()> {
        self.format = MESSAGE_FORMAT_V2.into();
        self.authentication = Authentication {
            algorithm: ALGORITHM.into(),
            signer_id: SignerId::from_verifying_key(&signing.verifying_key())
                .as_str()
                .into(),
            key_version: KEY_VERSION,
            nonce: new_nonce(),
            signature: String::new(),
        };
        let canonical = canonical_bytes(self)?;
        self.authentication.signature = sign_bytes(signing, KIND_MESSAGE, &canonical);
        Ok(())
    }

    /// Verify the signature and that the signer is trusted; returns the signer id.
    pub fn verify(&self, trusted: &TrustedSigners) -> Result<SignerId> {
        let grant = trusted
            .grant_for(&self.authentication.signer_id)
            .context("signer is not trusted")?;
        let key = grant.verifying_key()?;
        let mut copy = self.clone();
        copy.authentication.signature = String::new();
        let canonical = canonical_bytes(&copy)?;
        verify_bytes(
            &key,
            KIND_MESSAGE,
            &canonical,
            &self.authentication.signature,
        )?;
        SignerId::parse(&self.authentication.signer_id)
    }
}

impl AcknowledgementV2 {
    /// Build an unsigned v2 acknowledgement for `message`.
    pub fn new(message: &MessageV2) -> Result<Self> {
        Ok(Self {
            format: ACKNOWLEDGEMENT_FORMAT_V2.into(),
            message_id: message.id.clone(),
            message_digest: hex::encode(Sha256::digest(canonical_bytes(message)?)),
            project_id: message.project_id.clone(),
            recipient: message.recipient.clone(),
            processed_at: Utc::now(),
            idempotency_key: message.idempotency_key.clone(),
            authentication: Authentication {
                algorithm: ALGORITHM.into(),
                signer_id: String::new(),
                key_version: KEY_VERSION,
                nonce: String::new(),
                signature: String::new(),
            },
        })
    }

    /// Sign in place.
    pub fn sign(&mut self, signing: &SigningKey) -> Result<()> {
        self.authentication = Authentication {
            algorithm: ALGORITHM.into(),
            signer_id: SignerId::from_verifying_key(&signing.verifying_key())
                .as_str()
                .into(),
            key_version: KEY_VERSION,
            nonce: new_nonce(),
            signature: String::new(),
        };
        let canonical = canonical_bytes(self)?;
        self.authentication.signature = sign_bytes(signing, KIND_ACKNOWLEDGEMENT, &canonical);
        Ok(())
    }

    /// Verify the signature and that the signer is trusted.
    pub fn verify(&self, trusted: &TrustedSigners) -> Result<SignerId> {
        let grant = trusted
            .grant_for(&self.authentication.signer_id)
            .context("signer is not trusted")?;
        let key = grant.verifying_key()?;
        let mut copy = self.clone();
        copy.authentication.signature = String::new();
        let canonical = canonical_bytes(&copy)?;
        verify_bytes(
            &key,
            KIND_ACKNOWLEDGEMENT,
            &canonical,
            &self.authentication.signature,
        )?;
        SignerId::parse(&self.authentication.signer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn trust_for(key: &SigningKey) -> TrustedSigners {
        TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(key.verifying_key().as_bytes()),
                projects: vec!["ferryman".into()],
                roles: vec!["orchestrator".into()],
                capabilities: vec!["issue".into(), "acknowledge".into()],
            }],
        }
    }

    #[test]
    fn signer_id_derives_and_parses() {
        let key = key();
        let id = SignerId::from_verifying_key(&key.verifying_key());
        assert_eq!(SignerId::parse(id.as_str()).unwrap(), id);
        assert!(SignerId::parse("sha256:zz").is_err());
        assert!(SignerId::parse("nope").is_err());
    }

    #[test]
    fn message_signs_and_verifies() {
        let signing = key();
        let trusted = trust_for(&signing);
        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({"hi": 1}),
            true,
        );
        message.sign(&signing).unwrap();
        let id = message.verify(&trusted).unwrap();
        assert_eq!(id, SignerId::from_verifying_key(&signing.verifying_key()));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let signing = key();
        let trusted = trust_for(&signing);
        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({"a": 1}),
            true,
        );
        message.sign(&signing).unwrap();
        message.payload = serde_json::json!({"a": 2});
        assert!(message.verify(&trusted).is_err());
    }

    #[test]
    fn untrusted_signer_fails() {
        let signing = key();
        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();
        assert!(message.verify(&TrustedSigners::default()).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let signing = key();
        let other = key();
        let mut message = MessageV2::new(
            "ferryman",
            "orchestrator",
            "worker",
            "r",
            serde_json::json!({}),
            true,
        );
        message.sign(&signing).unwrap();
        assert!(message.verify(&trust_for(&other)).is_err());
    }

    #[test]
    fn nonces_differ() {
        let signing = key();
        let mut a = MessageV2::new("p", "s", "r", "x", serde_json::json!({}), true);
        let mut b = MessageV2::new("p", "s", "r", "x", serde_json::json!({}), true);
        a.sign(&signing).unwrap();
        b.sign(&signing).unwrap();
        assert_ne!(a.authentication.nonce, b.authentication.nonce);
    }

    #[test]
    fn acknowledgement_signs_and_verifies() {
        let signing = key();
        let trusted = trust_for(&signing);
        let mut message = MessageV2::new("p", "s", "r", "x", serde_json::json!({}), true);
        message.sign(&signing).unwrap();
        let mut ack = AcknowledgementV2::new(&message).unwrap();
        ack.sign(&signing).unwrap();
        ack.verify(&trusted).unwrap();
        let mut bad = ack.clone();
        bad.message_id = "not-the-message".into();
        assert!(bad.verify(&trusted).is_err());
    }

    #[test]
    fn trust_store_roundtrips_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trusted-signers.toml");
        let signing = key();
        std::fs::write(
            &path,
            format!(
                "[[signers]]\npublic_key = \"{}\"\nprojects = [\"ferryman\"]\nroles = [\"orchestrator\"]\ncapabilities = [\"issue\"]\n",
                hex::encode(signing.verifying_key().as_bytes())
            ),
        )
        .unwrap();
        let store = TrustedSigners::load(&path).unwrap();
        assert_eq!(store.signers.len(), 1);
        let id = SignerId::from_verifying_key(&signing.verifying_key());
        assert_eq!(
            store.grant_for(id.as_str()).unwrap().roles,
            vec!["orchestrator"]
        );
    }
}

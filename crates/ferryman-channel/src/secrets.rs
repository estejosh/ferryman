//! Sealed secrets through the channel.
//!
//! A secret is set ONCE and reaches exactly the machines that should have it,
//! without touching those machines. The value never travels as plaintext: it is
//! sealed per recipient with XChaCha20-Poly1305 under a shared secret derived by
//! X25519 ECDH, the secret's name and project id are bound in as associated
//! data, and the whole envelope is signed by whoever set it and verified against
//! the roster on read.
//!
//! # Why a second keypair
//!
//! The signing key (ed25519) attributes statements; the encryption key (X25519)
//! grants decryption. They are different curves doing different jobs, and a
//! signing-key compromise must not by itself expose ciphertext. The private half
//! lives beside the signing key, owner-only, and is never synced; only the
//! public half is published in the roster.
//!
//! # Why the envelope is signed
//!
//! agenix documents that its encrypted files are NOT authenticated: anyone with
//! write access to the repository can replace them. The signed envelope is the
//! thing Ferryman adds over that - a tampered envelope fails signature
//! verification before it is ever opened.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, SharedSecret, StaticSecret};

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck};

const SECRET_FORMAT: &str = "ferryman-secret/v1";

/// A per-agent X25519 keypair used only to decrypt sealed secrets.
///
/// The key lives in `<attachment>/keys/<name>.enc.key`, owner-only, and is
/// never synced. Only the public half is published, as `AgentRoute::encryption_key`.
pub struct EncryptionIdentity {
    name: String,
    secret: StaticSecret,
}

impl std::fmt::Debug for EncryptionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionIdentity")
            .field("name", &self.name)
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl EncryptionIdentity {
    /// Load this agent's encryption key, creating one the first time it runs.
    ///
    /// Mirrors [`AgentIdentity::load_or_create`]: the key is machine-wide so an
    /// agent is the same recipient in every project, and a machine that already
    /// has a key under this name keeps it.
    pub fn load_or_create(name: &str, state_dir: &Path) -> Result<Self> {
        Self::load_or_create_in(name, state_dir, crate::licensing::machine_state_dir())
    }

    /// The same, with the machine directory given rather than discovered, so a
    /// test can construct an identity belonging to a different machine.
    pub(crate) fn load_or_create_in(
        name: &str,
        state_dir: &Path,
        machine_dir: Option<PathBuf>,
    ) -> Result<Self> {
        if !crate::is_safe_component(name) {
            bail!("agent name must be a path-safe identifier")
        }
        let name = crate::canonical_agent_name(name);
        if let Some(existing) = Self::from_state_file(&name, state_dir)? {
            if let Some(dir) = &machine_dir
                && Self::from_state_file(&name, dir)?.is_none()
            {
                Self::write_state_file(&name, dir, &existing.secret)?;
            }
            return Ok(existing);
        }
        if let Some(dir) = &machine_dir
            && let Some(existing) = Self::from_state_file(&name, dir)?
        {
            Self::write_state_file(&name, state_dir, &existing.secret)?;
            return Ok(existing);
        }

        let mut seed = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let secret = StaticSecret::from(seed);
        if let Some(dir) = &machine_dir {
            Self::write_state_file(&name, dir, &secret)?;
        }
        Self::write_state_file(&name, state_dir, &secret)?;
        Ok(Self { name, secret })
    }
    /// Load an existing encryption key, and do NOT create one.
    ///
    /// The distinction matters the same way it does for the signing key: a
    /// reader that cannot decrypt must fail loudly, never mint a fresh key under
    /// a name the roster may not know.
    pub fn load_existing(name: &str, state_dir: &Path) -> Result<Option<Self>> {
        let name = crate::canonical_agent_name(name);
        Self::from_state_file(&name, state_dir)
    }

    fn from_state_file(name: &str, state_dir: &Path) -> Result<Option<Self>> {
        let path = Self::key_path(name, state_dir);
        if !path.is_file() {
            return Ok(None);
        }
        let encoded = fs_read(&path)?;
        let bytes = hex::decode(encoded.trim())
            .with_context(|| format!("{} is not a valid encryption key", path.display()))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("{} is not a 32-byte key", path.display()))?;
        Ok(Some(Self {
            name: name.to_string(),
            secret: StaticSecret::from(bytes),
        }))
    }

    fn write_state_file(name: &str, state_dir: &Path, secret: &StaticSecret) -> Result<()> {
        let path = Self::key_path(name, state_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, hex::encode(secret.to_bytes()))?;
        crate::restrict_to_owner(&path)?;
        Ok(())
    }

    fn key_path(name: &str, state_dir: &Path) -> PathBuf {
        state_dir.join("keys").join(format!("{name}.enc.key"))
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reconstruct an encryption identity from a raw 32-byte X25519 seed, for
    /// tests and embedding. Mirrors `AgentIdentity::from_seed`.
    #[must_use]
    pub fn from_seed(name: &str, seed: [u8; 32]) -> Self {
        Self {
            name: crate::canonical_agent_name(name),
            secret: StaticSecret::from(seed),
        }
    }

    /// The half that is safe to publish.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public().as_bytes())
    }

    fn public(&self) -> XPublicKey {
        XPublicKey::from(&self.secret)
    }
}

fn fs_read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

/// One recipient's slot: the ciphertext and everything a reader needs to open it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientSlot {
    /// The recipient's roster name.
    pub recipient: String,
    /// The setter's ephemeral X25519 public key for THIS recipient.
    pub ephemeral_public_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// A sealed secret as written to the channel. Ciphertext only: the value never
/// appears here in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEnvelope {
    pub format: String,
    pub name: String,
    pub project_id: String,
    pub recipients: Vec<RecipientSlot>,
    #[serde(default)]
    pub signed_by: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl SecretEnvelope {
    /// The bytes a signature covers: every field that decides what this envelope
    /// IS and who it is for. Deliberately explicit rather than "serialise the
    /// struct", for the same reason the message payloads are.
    fn payload(&self) -> String {
        let mut payload = format!(
            "{}\n{}\n{}\n{}\n",
            self.format,
            self.name,
            self.project_id,
            self.created_at.to_rfc3339()
        );
        for slot in &self.recipients {
            payload.push_str(&format!(
                "{}\n{}\n{}\n{}\n",
                slot.recipient, slot.ephemeral_public_hex, slot.nonce_hex, slot.ciphertext_hex
            ));
        }
        payload
    }
}

/// A summary of a stored secret, safe to show in a list. Never the value.
#[derive(Debug, Clone, Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub recipients: Vec<String>,
    pub signed_by: Option<String>,
    pub created_at: String,
    pub signature: &'static str,
}

/// A stable label for a signature check, so a summary can be serialized without
/// carrying the whole enum.
fn signature_label(check: &SignatureCheck) -> &'static str {
    match check {
        SignatureCheck::Valid => "valid",
        SignatureCheck::Unsigned => "unsigned",
        SignatureCheck::Invalid => "invalid",
        SignatureCheck::UnknownSigner => "unknown",
        SignatureCheck::KeyChanged { .. } => "key_changed",
    }
}

fn secrets_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("secrets")
}

fn envelope_path(route: &ProjectRoute, name: &str) -> PathBuf {
    secrets_dir(route).join(format!("{name}.json"))
}

/// The associated data bound into every AEAD seal: the secret's name, its
/// project, and the recipient. A ciphertext cannot be replayed under a
/// different name, moved into another project, or swapped between recipient
/// slots and still decrypt.
fn associated_data(name: &str, project_id: &str, recipient: &str) -> Vec<u8> {
    format!("{SECRET_FORMAT}\n{name}\n{project_id}\n{recipient}").into_bytes()
}

/// The cipher for one recipient slot, keyed by a KDF over the shared secret.
///
/// # Why the Diffie-Hellman output is not used as a key directly
///
/// It was. `XChaCha20Poly1305::new_from_slice(shared.as_bytes())` reads like the obvious
/// thing and is the one place this design hand-rolled something: an X25519 output is a
/// curve point's x-coordinate, not thirty-two uniformly random bytes. RFC 7748 says to
/// hash it before use, and every construction this is modelled on does - NaCl's
/// `crypto_box` runs it through HSalsa20, `age` and HPKE use HKDF-SHA256 keyed with the
/// public keys.
///
/// The practical risk in this envelope was small, because the envelope is signed and an
/// attacker cannot inject an ephemeral key to be multiplied against. The argument for
/// fixing it is not the attack; it is that ADR 0010 rests on "no new curve math or AEAD
/// construction is hand-written", and this line was the exception to its own rule. An
/// auditor comparing this to `age` finds it immediately, and the answer "it is probably
/// fine" is worth less than not having to give it.
///
/// Both public keys go in the salt, as `age` does. That binds the key to this exact pair
/// rather than to the shared secret alone, so a slot's key cannot be reused in a context
/// where one side differs.
fn slot_cipher(
    shared: &SharedSecret,
    ephemeral_public: &XPublicKey,
    recipient_public: &XPublicKey,
) -> Result<XChaCha20Poly1305> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(recipient_public.as_bytes());
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(SECRET_FORMAT.as_bytes(), &mut key)
        .map_err(|_| anyhow!("could not derive the slot key"))?;
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid derived key"))
}

/// Seal `value` to one recipient using an ephemeral X25519 keypair.
fn seal_value(
    ephemeral: &StaticSecret,
    recipient_public: &XPublicKey,
    name: &str,
    project_id: &str,
    recipient: &str,
    value: &str,
) -> Result<RecipientSlot> {
    let shared = ephemeral.diffie_hellman(recipient_public);
    let cipher = slot_cipher(&shared, &XPublicKey::from(ephemeral), recipient_public)?;
    let mut nonce = [0_u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: value.as_bytes(),
                aad: &associated_data(name, project_id, recipient),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(RecipientSlot {
        recipient: recipient.to_string(),
        ephemeral_public_hex: hex::encode(XPublicKey::from(ephemeral).as_bytes()),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Set a secret: seal it to `recipients` and write the signed envelope into this
/// project's channel. `signer` is the roster identity on the record for it.
pub fn set_secret(
    route: &ProjectRoute,
    signer: &AgentIdentity,
    name: &str,
    value: &str,
    recipients: &[String],
) -> Result<PathBuf> {
    if !crate::is_safe_component(name) {
        bail!("secret name must contain only letters, digits, '.', '-', or '_'")
    }
    if recipients.is_empty() {
        bail!("a secret needs at least one recipient (--to or the form's recipients)")
    }
    let roster = crate::read_agent_roster(&route.communications)?;
    let mut slots = Vec::with_capacity(recipients.len());
    for raw in recipients {
        let recipient = crate::canonical_agent_name(raw);
        let Some(agent) = roster.iter().find(|a| a.name == recipient) else {
            bail!("recipient '{recipient}' is not in this project's roster")
        };
        let Some(enc) = agent.encryption_key.as_ref().filter(|k| !k.is_empty()) else {
            bail!(
                "recipient '{recipient}' has not published an encryption key yet; \
                 run 'ferry channel join' on that machine first"
            )
        };
        let public = XPublicKey::from(hex_decode_32(enc)?);
        let mut ephemeral_seed = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut ephemeral_seed);
        let ephemeral = StaticSecret::from(ephemeral_seed);
        slots.push(seal_value(
            &ephemeral,
            &public,
            name,
            &route.project_id,
            &recipient,
            value,
        )?);
    }

    let mut envelope = SecretEnvelope {
        format: SECRET_FORMAT.to_string(),
        name: name.to_string(),
        project_id: route.project_id.clone(),
        recipients: slots,
        signed_by: None,
        signature: None,
        created_at: chrono::Utc::now(),
    };
    let payload = envelope.payload();
    envelope.signed_by = Some(signer.name().to_string());
    envelope.signature = Some(signer.sign_bytes(payload.as_bytes()));

    let path = envelope_path(route, name);
    crate::atomic_json(&path, &envelope)?;
    Ok(path)
}

/// List stored secrets as summaries. Values are never returned.
pub fn list_secrets(route: &ProjectRoute) -> Result<Vec<SecretSummary>> {
    let dir = secrets_dir(route);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let roster = crate::read_agent_roster(&route.communications).unwrap_or_default();
    let mut summaries = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(".sync-conflict-"))
        {
            continue;
        }
        let Ok(envelope) = read_envelope(&path) else {
            continue;
        };
        let signature = verify_envelope(&envelope, &roster);
        summaries.push(SecretSummary {
            name: envelope.name,
            recipients: envelope
                .recipients
                .iter()
                .map(|slot| slot.recipient.clone())
                .collect(),
            signed_by: envelope.signed_by,
            created_at: envelope.created_at.to_rfc3339(),
            signature: signature_label(&signature),
        });
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(summaries)
}

fn read_envelope(path: &Path) -> Result<SecretEnvelope> {
    let envelope: SecretEnvelope = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    if envelope.format != SECRET_FORMAT {
        bail!("{} is not a ferryman secret envelope", path.display());
    }
    Ok(envelope)
}

/// Verify a secret envelope's signature against the roster.
#[must_use]
pub fn verify_envelope(envelope: &SecretEnvelope, roster: &[AgentRoute]) -> SignatureCheck {
    crate::check_signature(
        envelope.signed_by.as_ref(),
        envelope.signature.as_ref(),
        &envelope.payload(),
        roster,
    )
}

/// Decrypt a secret for this machine's agent. Refuses - loudly and specifically -
/// when the signature is bad, the name is unknown, this agent is not a
/// recipient, or the local key cannot open it. It never returns an empty value.
pub fn open_secret(
    route: &ProjectRoute,
    name: &str,
    identity: &EncryptionIdentity,
) -> Result<String> {
    let path = envelope_path(route, name);
    let envelope = read_envelope(&path)?;
    let roster = crate::read_agent_roster(&route.communications)?;
    if verify_envelope(&envelope, &roster) != SignatureCheck::Valid {
        bail!("secret '{name}' is not signed by a roster identity; refusing to open it");
    }
    let slot = envelope
        .recipients
        .iter()
        .find(|slot| slot.recipient.eq_ignore_ascii_case(identity.name()))
        .ok_or_else(|| {
            anyhow!(
                "this machine's agent ('{}') is not a recipient of secret '{name}'",
                identity.name()
            )
        })?;

    let ephemeral = XPublicKey::from(hex_decode_32(&slot.ephemeral_public_hex)?);
    let shared = identity.secret.diffie_hellman(&ephemeral);
    let cipher = slot_cipher(&shared, &ephemeral, &identity.public())?;
    let nonce = hex::decode(&slot.nonce_hex).context("secret nonce is not valid hex")?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| anyhow!("secret nonce is the wrong length"))?;
    let ciphertext =
        hex::decode(&slot.ciphertext_hex).context("secret ciphertext is not valid hex")?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &associated_data(&envelope.name, &envelope.project_id, &slot.recipient),
            },
        )
        .map_err(|_| anyhow!("secret '{name}' could not be decrypted (key does not match)"))?;
    String::from_utf8(plaintext).context("secret value is not valid UTF-8")
}

/// Remove a secret envelope. Returns `true` when it existed.
pub fn remove_secret(route: &ProjectRoute, name: &str) -> Result<bool> {
    let path = envelope_path(route, name);
    if !path.is_file() {
        return Ok(false);
    }
    std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

/// Resolve `secret:<name>` references in a credentials map.
///
/// The rule is precise: `secret:<name>` is a reference only when `<name>` names
/// an envelope this agent can decrypt, and then it resolves to the decrypted
/// value. If `<name>` names an envelope this agent cannot decrypt (not a
/// recipient, no local key, bad signature), this fails loudly - never an empty
/// string, never the literal `secret:<name>`. A value that happens to begin with
/// `secret:` but names no envelope is a literal and passes through untouched, so
/// no escaping is needed.
pub fn resolve_credentials(
    route: &ProjectRoute,
    credentials: HashMap<String, String>,
    identity: Option<&EncryptionIdentity>,
) -> Result<HashMap<String, String>> {
    let mut resolved = HashMap::with_capacity(credentials.len());
    for (key, value) in credentials {
        let Some(name) = value.strip_prefix("secret:") else {
            resolved.insert(key, value);
            continue;
        };
        if name.is_empty() {
            resolved.insert(key, value);
            continue;
        }
        if !envelope_path(route, name).is_file() {
            // No envelope named this: the value is a literal that happens to
            // start with "secret:". Keep it as-is.
            resolved.insert(key, value);
            continue;
        }
        let Some(identity) = identity else {
            bail!(
                "credential '{key}' references secret '{name}', but this machine's agent has \
                 no encryption key; run 'ferry channel join' on this machine first"
            );
        };
        let decrypted = open_secret(route, name, identity).map_err(|error| {
            anyhow!(
                "credential '{key}' references secret '{name}', which could not be decrypted: {error}"
            )
        })?;
        resolved.insert(key, decrypted);
    }
    Ok(resolved)
}

fn hex_decode_32(encoded: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(encoded).context("key is not valid hex")?;
    bytes.try_into().map_err(|_| anyhow!("key is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentIdentity;
    use std::collections::HashMap;
    use std::path::Path;

    fn test_route(dir: &Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "acme".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "acme-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn signer() -> AgentIdentity {
        AgentIdentity::from_seed("op", [7_u8; 32])
    }

    fn recipient(dir: &Path, state: &str) -> EncryptionIdentity {
        EncryptionIdentity::load_or_create_in(
            "beastly",
            &dir.join(state),
            Some(dir.join(format!("{state}-machine"))),
        )
        .unwrap()
    }

    fn roster_with(recipient: &EncryptionIdentity) -> Vec<AgentRoute> {
        vec![
            AgentRoute {
                name: "op".into(),
                role: "operator".into(),
                capabilities: vec!["messages.receive".into()],
                public_key: Some(signer().public_key_hex()),
                encryption_key: None,
            },
            AgentRoute {
                name: "beastly".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: None,
                encryption_key: Some(recipient.public_key_hex()),
            },
        ]
    }

    fn write_roster(route: &ProjectRoute, roster: &[AgentRoute]) {
        std::fs::create_dir_all(route.communications.join("agents")).unwrap();
        for agent in roster {
            crate::write_roster_entry(&route.communications.join("agents"), agent).unwrap();
        }
    }

    #[test]
    fn the_slot_key_is_derived_and_is_not_the_raw_diffie_hellman_output() {
        // The one place this design hand-rolled something. An X25519 output is a curve
        // point's x-coordinate, not thirty-two uniformly random bytes: RFC 7748 says to
        // hash it, and NaCl, age and HPKE all do. Using it directly was the exception to
        // ADR 0010's own "no hand-written construction" rule.
        //
        // Proved by what the key is NOT: a ciphertext sealed with the derived key must not
        // open under the raw shared secret.
        let dir = tempfile::tempdir().unwrap();
        let them = recipient(dir.path(), "them");
        let ephemeral = StaticSecret::from([3_u8; 32]);
        let slot = seal_value(
            &ephemeral,
            &them.public(),
            "token",
            "ferryman",
            "them",
            "hunter2",
        )
        .unwrap();

        let raw = ephemeral.diffie_hellman(&them.public());
        let naive = XChaCha20Poly1305::new_from_slice(raw.as_bytes()).unwrap();
        let nonce = hex::decode(&slot.nonce_hex).unwrap();
        let ciphertext = hex::decode(&slot.ciphertext_hex).unwrap();
        assert!(
            naive
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &associated_data("token", "ferryman", "them"),
                    },
                )
                .is_err(),
            "the raw shared secret still opens the slot, so no derivation happened"
        );
    }

    #[test]
    fn both_public_keys_are_bound_into_the_derivation() {
        // The salt is ephemeral || recipient, as age does, so a slot key belongs to one
        // exact pair rather than to the shared secret alone.
        let dir = tempfile::tempdir().unwrap();
        let them = recipient(dir.path(), "them");
        let ephemeral = StaticSecret::from([3_u8; 32]);
        let shared = ephemeral.diffie_hellman(&them.public());
        let mine = XPublicKey::from(&ephemeral);

        let right = slot_cipher(&shared, &mine, &them.public()).unwrap();
        let swapped = slot_cipher(&shared, &them.public(), &mine).unwrap();

        let nonce = [7_u8; 24];
        let sealed = right
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: b"x",
                    aad: b"",
                },
            )
            .unwrap();
        assert!(
            swapped
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &sealed,
                        aad: b""
                    },
                )
                .is_err(),
            "the order of the public keys in the salt does not affect the key"
        );
    }

    #[test]
    fn seal_then_open_round_trips_for_the_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));

        let path = set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();
        assert!(path.is_file());

        let opened = open_secret(&route, "GH_TOKEN", &recipient).unwrap();
        assert_eq!(opened, "ghp_supersecret");
    }

    #[test]
    fn a_non_recipient_cannot_open() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        let outsider =
            EncryptionIdentity::load_or_create_in("outsider", &dir.path().join("other"), None)
                .unwrap();
        let err = open_secret(&route, "GH_TOKEN", &outsider)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a recipient"), "got: {err}");
    }

    #[test]
    fn sealing_refuses_a_recipient_without_an_encryption_key() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let roster = vec![AgentRoute {
            name: "oldagent".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(AgentIdentity::from_seed("oldagent", [3_u8; 32]).public_key_hex()),
            encryption_key: None,
        }];
        write_roster(&route, &roster);

        let err = set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["oldagent".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("encryption key"), "got: {err}");
    }

    #[test]
    fn tampering_with_the_envelope_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        let path = set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        let mut envelope: SecretEnvelope =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let last = envelope.recipients[0].ciphertext_hex.len() - 1;
        let flipped = if envelope.recipients[0].ciphertext_hex.as_bytes()[last] == b'0' {
            "1"
        } else {
            "0"
        };
        envelope.recipients[0]
            .ciphertext_hex
            .replace_range(last.., flipped);
        crate::atomic_json(&path, &envelope).unwrap();

        let err = open_secret(&route, "GH_TOKEN", &recipient)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not signed"),
            "tampering must fail signature verification first: {err}"
        );
    }

    #[test]
    fn decryption_fails_when_the_recipient_key_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        // Same NAME, different key material - the signature still verifies, but
        // the AEAD seal cannot be opened by a key it was not made for.
        let wrong_key =
            EncryptionIdentity::load_or_create_in("beastly", &dir.path().join("other"), None)
                .unwrap();
        let err = open_secret(&route, "GH_TOKEN", &wrong_key)
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not be decrypted"), "got: {err}");
    }

    #[test]
    fn a_forged_signature_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        let path = set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        let mut envelope: SecretEnvelope =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let impostor = AgentIdentity::from_seed("impostor", [9_u8; 32]);
        envelope.signed_by = Some("impostor".into());
        envelope.signature = Some(impostor.sign_bytes(envelope.payload().as_bytes()));
        crate::atomic_json(&path, &envelope).unwrap();

        let err = open_secret(&route, "GH_TOKEN", &recipient)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not signed"), "got: {err}");
    }

    #[test]
    fn resolve_credentials_distinguishes_reference_from_literal() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        let credentials = HashMap::from([
            ("GH_TOKEN".to_string(), "secret:GH_TOKEN".to_string()),
            (
                "LITERAL".to_string(),
                "secret:not-a-real-secret".to_string(),
            ),
            ("PLAIN".to_string(), "plain-value".to_string()),
        ]);
        let resolved = resolve_credentials(&route, credentials, Some(&recipient)).unwrap();
        assert_eq!(resolved["GH_TOKEN"], "ghp_supersecret");
        assert_eq!(resolved["LITERAL"], "secret:not-a-real-secret");
        assert_eq!(resolved["PLAIN"], "plain-value");
    }

    #[test]
    fn resolve_credentials_fails_loudly_for_an_undecryptable_reference() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        let outsider =
            EncryptionIdentity::load_or_create_in("outsider", &dir.path().join("other2"), None)
                .unwrap();
        let credentials = HashMap::from([("GH_TOKEN".to_string(), "secret:GH_TOKEN".to_string())]);
        let err = resolve_credentials(&route, credentials, Some(&outsider))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a recipient"), "got: {err}");
    }

    #[test]
    fn list_never_leaks_values_and_reports_signature() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let signer = signer();
        let recipient = recipient(dir.path(), "state");
        write_roster(&route, &roster_with(&recipient));
        set_secret(
            &route,
            &signer,
            "GH_TOKEN",
            "ghp_supersecret",
            &["beastly".into()],
        )
        .unwrap();

        let summaries = list_secrets(&route).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "GH_TOKEN");
        assert_eq!(summaries[0].recipients, vec!["beastly".to_string()]);
        assert_eq!(summaries[0].signed_by.as_deref(), Some("op"));
        assert_eq!(summaries[0].signature, "valid");
        let json = serde_json::to_string(&summaries[0]).unwrap();
        assert!(!json.contains("supersecret"), "leaked value: {json}");
        assert!(!json.contains("ciphertext"), "leaked slot: {json}");
    }
}

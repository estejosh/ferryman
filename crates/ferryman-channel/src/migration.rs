//! v1 -> v2 migration tooling (portable-authentication gate 5).
//!
//! There is deliberately no permissive mixed-mode receiver. New sends switch to
//! v2 once a signing identity exists, but v1 files already on disk need an
//! explicit migration step. This module inventories those files and converts
//! only the subset whose origin this machine can prove.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::portable_auth::{MESSAGE_FORMAT_V2, MessageV2};
use crate::{AgentIdentity, Message, ProjectRoute};

/// One v1 message found by [`inventory_v1`], classified for migration.
#[derive(Debug, Clone, PartialEq)]
pub enum MigrationEntry {
    /// A v1 message this machine can prove it created locally.
    Convertible { message: Message },
    /// A v1 message that needs a human decision before it is rewritten.
    OperatorReview { message: Message, reason: String },
}

impl MigrationEntry {
    /// The v1 message this entry describes.
    pub fn message(&self) -> &Message {
        match self {
            MigrationEntry::Convertible { message }
            | MigrationEntry::OperatorReview { message, .. } => message,
        }
    }

    /// A short, human-readable classification.
    pub fn kind(&self) -> &'static str {
        match self {
            MigrationEntry::Convertible { .. } => "convertible",
            MigrationEntry::OperatorReview { .. } => "operator-review",
        }
    }

    /// The reason an entry is not automatically convertible.
    pub fn reason(&self) -> Option<&str> {
        match self {
            MigrationEntry::Convertible { .. } => None,
            MigrationEntry::OperatorReview { reason, .. } => Some(reason),
        }
    }
}

/// The result of converting one v1 message into a signed v2 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvertOutcome {
    pub message_id: String,
    pub project_id: String,
    pub old_format: String,
    pub new_format: String,
    /// SHA-256 of the canonical JSON of the v1 message before conversion.
    pub old_digest: String,
    /// SHA-256 of the canonical JSON of the signed v2 envelope after conversion.
    pub new_digest: String,
    /// The canonical message path a non-dry-run conversion wrote (or would write).
    pub path: PathBuf,
    /// True when nothing was written to disk.
    pub dry_run: bool,
}

/// Scan the portable message directory and the local outbox for v1 messages and
/// classify each one.
///
/// A message is `Convertible` only when an immutable delivery-attempt record
/// exists under `attachment/runtime/delivery-attempts/<message-id>/`. The
/// transport location alone is not proof of origin: a v1 file synced in from a
/// peer has no local delivery-attempt record and must be operator-reviewed.
pub fn inventory_v1(route: &ProjectRoute) -> Result<Vec<MigrationEntry>> {
    route.validate()?;

    let messages_dir = route
        .communications
        .join("messages")
        .join(&route.project_id);
    let outbox_dir = route.attachment.join("runtime").join("outbox");

    // A previous migration writes the v2 envelope into the canonical message
    // directory but deliberately leaves the transport outbox alone. Do not
    // re-convert those ids when the stale v1 outbox entry is scanned again.
    let already_v2 = read_v2_message_ids(&messages_dir)?;

    let mut by_id: BTreeMap<String, Message> = BTreeMap::new();

    // The canonical message directory wins when the same id exists in both places.
    for message in read_v1_messages(&messages_dir, &route.project_id)? {
        by_id.insert(message.id.clone(), message);
    }
    for message in read_v1_messages(&outbox_dir, &route.project_id)? {
        if already_v2.contains(&message.id) {
            continue;
        }
        by_id.entry(message.id.clone()).or_insert(message);
    }

    let mut entries = Vec::with_capacity(by_id.len());
    for (_, message) in by_id {
        let attempt_dir = delivery_attempt_dir(route, &message.id);
        let locally_created = has_delivery_attempt_record(&attempt_dir)?;
        if locally_created {
            entries.push(MigrationEntry::Convertible { message });
        } else {
            entries.push(MigrationEntry::OperatorReview {
                reason: format!(
                    "no immutable delivery-attempt record at {}",
                    attempt_dir.display()
                ),
                message,
            });
        }
    }

    Ok(entries)
}

/// Convert a v1 message into a signed v2 envelope.
///
/// The original message id and idempotency key are preserved; the v2 envelope
/// gets fresh `created_at`/`acknowledgement_deadline` values (the v1 values are
/// intentionally not copied). When `dry_run` is false the signed envelope is
/// written over the canonical `communications/messages/<project_id>/<id>.json`
/// path. When `dry_run` is true the outcome is computed and returned without
/// touching the filesystem.
pub fn convert_v1_to_v2(
    route: &ProjectRoute,
    message: &Message,
    signing: &SigningKey,
    dry_run: bool,
) -> Result<ConvertOutcome> {
    route.validate()?;
    if message.project_id != route.project_id {
        bail!(
            "message project '{}' does not match route project '{}'",
            message.project_id,
            route.project_id
        );
    }
    if message.format != crate::MESSAGE_FORMAT {
        bail!("only v1 messages can be migrated");
    }
    message.validate()?;

    let old_digest = digest(message)?;
    let path = message_path(route, &message.id);

    let mut v2 = MessageV2::new(
        message.project_id.clone(),
        message.sender.clone(),
        message.recipient.clone(),
        message.payload_reference.clone(),
        message.payload.clone(),
        message.reply_required,
    );
    // `MessageV2::new` mints a fresh id and idempotency key. Migration must keep
    // the original ones so claims, acknowledgements, and idempotency still line
    // up with the v1 record.
    v2.id = message.id.clone();
    v2.idempotency_key = message.idempotency_key.clone();
    v2.sign(signing)?;

    let new_digest = digest(&v2)?;
    if !dry_run {
        crate::atomic_json(&path, &v2)?;
    }

    Ok(ConvertOutcome {
        message_id: message.id.clone(),
        project_id: message.project_id.clone(),
        old_format: message.format.clone(),
        new_format: MESSAGE_FORMAT_V2.to_owned(),
        old_digest,
        new_digest,
        path,
        dry_run,
    })
}

/// [`convert_v1_to_v2`] for callers that only have an [`AgentIdentity`], such as
/// the CLI. Keeps the signing key inside the crate where it is already held.
pub fn convert_v1_to_v2_with_identity(
    route: &ProjectRoute,
    message: &Message,
    identity: &AgentIdentity,
    dry_run: bool,
) -> Result<ConvertOutcome> {
    convert_v1_to_v2(route, message, &identity.signing, dry_run)
}

fn message_path(route: &ProjectRoute, message_id: &str) -> PathBuf {
    route
        .communications
        .join("messages")
        .join(&route.project_id)
        .join(format!("{message_id}.json"))
}

fn delivery_attempt_dir(route: &ProjectRoute, message_id: &str) -> PathBuf {
    route
        .attachment
        .join("runtime")
        .join("delivery-attempts")
        .join(message_id)
}

fn has_delivery_attempt_record(dir: &Path) -> Result<bool> {
    if !dir.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_v1_messages(dir: &Path, project_id: &str) -> Result<Vec<Message>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut messages = Vec::new();
    for path in paths {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let value: Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        if value.get("format").and_then(Value::as_str) != Some(crate::MESSAGE_FORMAT) {
            // v2 files in a mixed directory are not this tool's input.
            continue;
        }
        let message: Message =
            serde_json::from_value(value).with_context(|| format!("parse {}", path.display()))?;
        message
            .validate()
            .with_context(|| format!("validate {}", path.display()))?;
        if message.project_id != project_id {
            bail!(
                "message {} has project '{}', expected '{}'",
                path.display(),
                message.project_id,
                project_id
            );
        }
        messages.push(message);
    }
    Ok(messages)
}

fn read_v2_message_ids(dir: &Path) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    if !dir.is_dir() {
        return Ok(ids);
    }

    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let value: Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        if value.get("format").and_then(Value::as_str) == Some(MESSAGE_FORMAT_V2)
            && let Some(id) = value.get("id").and_then(Value::as_str)
        {
            ids.insert(id.to_owned());
        }
    }
    Ok(ids)
}

fn digest(value: &impl Serialize) -> Result<String> {
    let canonical = serde_jcs::to_string(value)?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable_auth::{SignerGrant, TrustedSigners};
    use rand::RngCore;
    use serde_json::json;

    fn test_route(temp: &Path) -> ProjectRoute {
        let workspace = temp.join("workspace");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        ProjectRoute {
            project_id: "test-project".into(),
            workspace,
            attachment,
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: "private".into(),
            agents: Vec::new(),
        }
    }

    fn write_message(route: &ProjectRoute, message: &Message) {
        let path = message_path(route, &message.id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(message).unwrap()).unwrap();
    }

    fn write_outbox(route: &ProjectRoute, message: &Message) {
        let path = route
            .attachment
            .join("runtime")
            .join("outbox")
            .join(format!("{}.json", message.id));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(message).unwrap()).unwrap();
    }

    fn write_delivery_attempt(route: &ProjectRoute, message_id: &str) {
        let dir = delivery_attempt_dir(route, message_id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("attempt.json"), b"{}").unwrap();
    }

    fn message(route: &ProjectRoute) -> Message {
        Message::new(
            route.project_id.clone(),
            "sender",
            "recipient",
            "inline",
            json!({"text": "hello"}),
            true,
            None,
        )
    }

    fn key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn trusted_for(signing: &SigningKey) -> TrustedSigners {
        TrustedSigners {
            signers: vec![SignerGrant {
                public_key: hex::encode(signing.verifying_key().as_bytes()),
                projects: Vec::new(),
                roles: Vec::new(),
                capabilities: Vec::new(),
                revoked: false,
            }],
        }
    }

    #[test]
    fn inventory_classifies_local_delivery_attempt_as_convertible() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_message(&route, &message);
        write_delivery_attempt(&route, &message.id);

        let entries = inventory_v1(&route).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            MigrationEntry::Convertible { message: found } => assert_eq!(found.id, message.id),
            other => panic!("expected Convertible, got {other:?}"),
        }
    }

    #[test]
    fn inventory_without_delivery_attempt_is_operator_review() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_message(&route, &message);

        let entries = inventory_v1(&route).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            MigrationEntry::OperatorReview { reason, .. } => {
                assert!(reason.contains("delivery-attempt"))
            }
            other => panic!("expected OperatorReview, got {other:?}"),
        }
    }

    #[test]
    fn inventory_deduplicates_messages_and_outbox() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_message(&route, &message);
        write_outbox(&route, &message);

        let entries = inventory_v1(&route).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(&entries[0], MigrationEntry::OperatorReview { .. }));
    }

    #[test]
    fn dry_run_conversion_writes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_message(&route, &message);
        let path = message_path(&route, &message.id);
        let before = fs::read_to_string(&path).unwrap();

        let outcome = convert_v1_to_v2(&route, &message, &key(), true).unwrap();

        assert!(outcome.dry_run);
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        assert!(before.contains("ferryman-message/v1"));
    }

    #[test]
    fn inventory_finds_outbox_only_v1_message() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_outbox(&route, &message);
        write_delivery_attempt(&route, &message.id);

        let entries = inventory_v1(&route).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(&entries[0], MigrationEntry::Convertible { .. }));
    }

    #[test]
    fn inventory_skips_outbox_v1_when_v2_message_exists() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_outbox(&route, &message);
        write_delivery_attempt(&route, &message.id);

        // Simulate a previous migration: the canonical message file is already v2.
        let path = message_path(&route, &message.id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut v2 = MessageV2::new(
            message.project_id.clone(),
            message.sender.clone(),
            message.recipient.clone(),
            message.payload_reference.clone(),
            message.payload.clone(),
            message.reply_required,
        );
        v2.id = message.id.clone();
        v2.idempotency_key = message.idempotency_key.clone();
        fs::write(&path, serde_json::to_vec_pretty(&v2).unwrap()).unwrap();

        let entries = inventory_v1(&route).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn conversion_writes_signed_v2_and_preserves_identity_fields() {
        let temp = tempfile::tempdir().unwrap();
        let route = test_route(temp.path());
        let message = message(&route);
        write_message(&route, &message);
        let signing = key();
        let path = message_path(&route, &message.id);

        let outcome = convert_v1_to_v2(&route, &message, &signing, false).unwrap();

        assert!(!outcome.dry_run);
        assert_eq!(outcome.old_format, "ferryman-message/v1");
        assert_eq!(outcome.new_format, MESSAGE_FORMAT_V2);
        assert_ne!(outcome.old_digest, outcome.new_digest);

        let written: MessageV2 =
            serde_json::from_slice(&fs::read(&path).unwrap()).expect("v2 message");
        assert_eq!(written.format, MESSAGE_FORMAT_V2);
        assert_eq!(written.id, message.id);
        assert_eq!(written.idempotency_key, message.idempotency_key);
        assert_eq!(written.project_id, message.project_id);

        let signer = written.verify(&trusted_for(&signing)).unwrap();
        assert_eq!(signer.as_str(), written.authentication.signer_id);
    }
}

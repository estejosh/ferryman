//! The `boundary/v1` contract: the two calls Ferryman exposes to and
//! consumes from Custodly (github.com/estejosh/Custodly, a separate
//! secrets-acquisition project). See that repo's `docs/BOUNDARY.md` for the
//! full contract this module implements one half of.
//!
//! Custodly acquires and scores secrets; Ferryman identifies people, grants
//! access, transports, and seals at rest. Neither reimplements the other.
//! This module is entirely the "seals at rest" half: it opens a secret
//! Custodly sealed blind (Custodly never learns who the eventual recipient
//! is) and hands the plaintext back to the caller to re-seal to the actual
//! grant recipient via [`crate::secrets::set_secret`] - the existing,
//! tested, per-recipient sealing this crate already has. Nothing here
//! invents a second sealing scheme.
//!
//! # Why an "ingestion identity" and not a human roster entry
//!
//! Custodly does not hold or know any individual's encryption key - it
//! seals once, to Ferryman, not to a person. That needs a recipient
//! Custodly *can* address without knowing who a grant is ultimately for: a
//! project-scoped [`crate::secrets::EncryptionIdentity`] that exists only
//! to receive deposits. It is generated and stored the same way any
//! encryption identity is, keyed off this project's attachment directory
//! (never the synced `communications` directory - the private key must
//! never travel over Syncthing), but it is never entered in the human
//! roster and never used to open anything except a deposit addressed to
//! it.
//!
//! # What's implemented vs. still open (as of 2026-09-21)
//!
//! `ferryman-server` exposes this identity's public half over HTTP
//! (`GET /v1/projects/{id}/boundary/ingestion-key`) and accepts deposits
//! (`POST /v1/projects/{id}/boundary/deposit`, backed by [`store_deposit`]
//! below). `policy()` is the other direction (Ferryman calling *into*
//! Custodly) and has no caller here - see `custodly-core::server` on the
//! Custodly side, which now runs it.
//!
//! [`store_deposit`] verifies a deposit opens under this project's
//! ingestion identity, then persists it **still sealed** - metadata
//! alongside the ciphertext - under the unsynced attachment directory.
//! Decrypting for real and re-sealing to an actual grant recipient via
//! [`crate::secrets::set_secret`] happens at grant-issuance time, which
//! nothing in this crate implements yet: there is no grant-issuance flow
//! to call it from. [`ContractRequirement`] and [`PolicyResponse`] below
//! fix the payload shape a `policy()` caller needs.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ProjectRoute;
use crate::secrets::{EncryptionIdentity, RecipientSlot, open_slot};

/// Contract version every `boundary/v1` payload carries. A receiver that
/// doesn't recognize the major version rejects the call rather than
/// guessing at its shape - the two repos move at different speeds on
/// purpose.
pub const CONTRACT_VERSION: &str = "boundary/v1";

/// This project's identity for receiving Custodly deposits. One per
/// project, never a human roster member, never used for anything else.
const INGESTION_IDENTITY_NAME: &str = "custodly-ingestion";

/// Load (creating on first use) this project's ingestion identity.
///
/// Rooted at `route.attachment`, not `route.communications`: the private
/// half of an encryption identity must never be written into the synced
/// channel folder, exactly as for every other identity this crate holds.
pub fn ingestion_identity(route: &ProjectRoute) -> Result<EncryptionIdentity> {
    EncryptionIdentity::load_or_create(INGESTION_IDENTITY_NAME, &route.attachment)
}

/// How the deposited secret was acquired, per Custodly's two acquisition
/// tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquiredVia {
    /// Minted through the provider's own key-management API.
    Track1Api,
    /// Produced by a scripted recipe against the provider's dashboard.
    Track2Recipe,
}

/// Everything about a deposited secret except its value. Never the
/// plaintext secret or anything it could be reconstructed from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositMetadata {
    pub provider: String,
    /// Provider-native scope string, e.g. `"repo:read,pr:write"`.
    pub scope: String,
    /// Custodly's own scoring result (0, 1, or 2). Informational to
    /// Ferryman - never re-derived here.
    pub tier: u8,
    pub acquired_via: AcquiredVia,
    pub acquired_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Short human string for Ferryman's dashboard, e.g. "GitHub App
    /// install token, pilot repo, read+PR".
    pub label: String,
}

/// The wire shape of a value sealed to a recipient's X25519 public key.
///
/// Identical in shape to [`RecipientSlot`] (ephemeral key, nonce,
/// ciphertext), because it is opened with exactly that AEAD construction.
/// Kept as its own type because a deposit is not a `RecipientSlot` sitting
/// inside a signed, roster-verified `SecretEnvelope`: there is no
/// envelope, no signer, and no roster check on this path, only AEAD
/// authentication against the ingestion key and the associated data both
/// sides agree on out of band (see [`deposit_aad`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSecret {
    pub ephemeral_public_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl From<&SealedSecret> for RecipientSlot {
    fn from(sealed: &SealedSecret) -> Self {
        RecipientSlot {
            recipient: INGESTION_IDENTITY_NAME.to_string(),
            ephemeral_public_hex: sealed.ephemeral_public_hex.clone(),
            nonce_hex: sealed.nonce_hex.clone(),
            ciphertext_hex: sealed.ciphertext_hex.clone(),
        }
    }
}

/// Custodly's proof that custody transferred. No secret or key material
/// comes back - this is Custodly's own record of what was deposited and
/// when, for the audit trail it owns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositReceipt {
    pub deposit_id: String,
    pub accepted_at: DateTime<Utc>,
    pub contract_version: &'static str,
}

/// The associated data a deposit's AEAD seal is bound to: the contract
/// version, the ingestion identity's name, and this project's id. A
/// deposit sealed for one project cannot be replayed against another, and
/// cannot be mistaken for a `secrets::RecipientSlot` sealed under
/// `associated_data`'s own scheme (see the failing-AAD case in
/// `secrets::tests::open_slot_round_trips_outside_the_envelope_scheme`).
#[must_use]
pub fn deposit_aad(project_id: &str) -> Vec<u8> {
    format!("{CONTRACT_VERSION}\n{INGESTION_IDENTITY_NAME}\n{project_id}").into_bytes()
}

/// Open a Custodly deposit under this project's ingestion identity and
/// return the plaintext value.
///
/// The caller is responsible for immediately re-sealing it to the actual
/// grant recipient - via [`crate::secrets::set_secret`] - and never
/// persisting the plaintext. This function exists to cross that one
/// boundary, not to be a place secrets rest.
pub fn open_deposit(
    route: &ProjectRoute,
    identity: &EncryptionIdentity,
    sealed: &SealedSecret,
) -> Result<String> {
    let slot = RecipientSlot::from(sealed);
    open_slot(identity, &slot, &deposit_aad(&route.project_id)).context(
        "could not open Custodly deposit (wrong ingestion key, or the payload was tampered with)",
    )
}

/// Record a deposit's receipt. `deposit_id` is caller-supplied (Custodly's
/// own id for its audit record) - Ferryman does not mint it.
#[must_use]
pub fn accept(deposit_id: String) -> DepositReceipt {
    DepositReceipt {
        deposit_id,
        accepted_at: Utc::now(),
        contract_version: CONTRACT_VERSION,
    }
}

/// One thing Custodly still needs before it will treat a request for a
/// provider+scope as fulfillable, e.g. `"onboarding_complete"` or
/// `"gate:human_approval"`. A string rather than an enum on this side: the
/// set of requirements is Custodly's to extend, and a Ferryman build
/// should not need to be re-released to recognize a new one - an unknown
/// requirement is still displayable even if Ferryman has no special
/// handling for it yet.
pub type ContractRequirement = String;

/// Custodly's answer to "how sensitive is this provider+scope" - shape
/// only. No caller in this crate constructs this yet: it exists so the
/// payload is fixed before the transport that would carry it (an HTTP
/// call? a CLI subprocess? something else) is decided. See the module
/// docs' "What is still open".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// 0, 1, or 2, per Custodly's scoring model.
    pub tier: u8,
    pub requires: Vec<ContractRequirement>,
}

/// A deposit as Ferryman holds it after `deposit()`: still sealed under
/// the ingestion identity, metadata alongside it, waiting for a grant to
/// name a recipient. See the module docs' "What's implemented vs. still
/// open" for why this stays sealed rather than being opened here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDeposit {
    pub deposit_id: String,
    pub sealed_secret: SealedSecret,
    pub metadata: DepositMetadata,
    pub received_at: DateTime<Utc>,
}

fn deposits_dir(route: &ProjectRoute) -> PathBuf {
    // Under attachment, not communications: a deposit is still sealed
    // ciphertext, safe to persist, but it has no business being copied to
    // every paired machine via Syncthing before a grant even exists.
    route.attachment.join("deposits")
}

fn deposit_path(route: &ProjectRoute, deposit_id: &str) -> PathBuf {
    deposits_dir(route).join(format!("{deposit_id}.json"))
}

/// Accept one Custodly deposit for `route`'s project.
///
/// Verifies the deposit actually opens under this project's ingestion
/// identity - so a wrong key or a corrupted payload fails loudly right
/// away, as an error Custodly's `deposit()` caller sees immediately,
/// rather than silently at whatever future point a grant tries to open
/// it - then persists it, still sealed, metadata alongside. The plaintext
/// from the verification decrypt is a local temporary that goes out of
/// scope at the end of this function; nothing here writes it anywhere.
///
/// Errors if `deposit_id` was already recorded for this project: deposit
/// IDs are Custodly's own, so a duplicate is either a retried request
/// (harmless to reject; Custodly already has its receipt from the first
/// attempt) or two different deposits colliding on an ID (a bug worth
/// surfacing, not silently overwriting).
pub fn store_deposit(
    route: &ProjectRoute,
    deposit_id: String,
    sealed: &SealedSecret,
    metadata: DepositMetadata,
) -> Result<DepositReceipt> {
    let identity = ingestion_identity(route)?;
    open_deposit(route, &identity, sealed)?;
    let path = deposit_path(route, &deposit_id);
    if path.exists() {
        bail!("deposit {deposit_id} already recorded")
    }
    let stored = StoredDeposit {
        deposit_id: deposit_id.clone(),
        sealed_secret: sealed.clone(),
        metadata,
        received_at: Utc::now(),
    };
    crate::atomic_json(&path, &stored)?;
    Ok(accept(deposit_id))
}

/// List deposits recorded for a project, oldest-id first (deposit IDs are
/// UUIDs from Custodly, so this is not chronological - `received_at` on
/// each [`StoredDeposit`] is). For a future dashboard view and for
/// whatever grant-issuance flow eventually opens one.
pub fn list_deposits(route: &ProjectRoute) -> Result<Vec<StoredDeposit>> {
    let directory = deposits_dir(route);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<_> = fs::read_dir(&directory)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| -> Result<StoredDeposit> { Ok(serde_json::from_slice(&fs::read(&path)?)?) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "acme".into(),
            workspace,
            attachment,
            communications: dir.join("workspace/.ferryman/ferryman"),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    #[test]
    fn ingestion_identity_is_stable_across_loads_and_lives_outside_communications() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());

        let first = ingestion_identity(&route).unwrap();
        let second = ingestion_identity(&route).unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());

        // The private key file must land under the unsynced attachment
        // directory, never under communications (the Syncthing-carried
        // channel folder) - see the module docs.
        let key_path = route
            .attachment
            .join("keys")
            .join("custodly-ingestion.enc.key");
        assert!(key_path.is_file(), "expected key at {}", key_path.display());
        let synced_path: PathBuf = route
            .communications
            .join("keys")
            .join("custodly-ingestion.enc.key");
        assert!(!synced_path.is_file());
    }

    #[test]
    fn a_deposit_sealed_to_the_ingestion_key_opens_and_returns_the_plaintext() {
        use x25519_dalek::StaticSecret;

        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let identity = ingestion_identity(&route).unwrap();

        // Stand-in for Custodly's own sealing: same construction
        // (`secrets::seal_value`'s crypto), addressed at the ingestion
        // identity's public key, with `deposit_aad` as associated data -
        // exactly what `custodly-core::seal::seal_for_ingestion` on the
        // Custodly side must produce for this to interoperate for real.
        let ephemeral = StaticSecret::from([4_u8; 32]);
        let slot = crate::secrets::seal_value_for_tests(
            &ephemeral,
            identity.public_key_hex(),
            &deposit_aad(&route.project_id),
            "ghp_deposited_token",
        )
        .unwrap();
        let sealed = SealedSecret {
            ephemeral_public_hex: slot.ephemeral_public_hex,
            nonce_hex: slot.nonce_hex,
            ciphertext_hex: slot.ciphertext_hex,
        };

        let opened = open_deposit(&route, &identity, &sealed).unwrap();
        assert_eq!(opened, "ghp_deposited_token");
    }

    #[test]
    fn a_deposit_sealed_to_a_different_key_does_not_open() {
        use x25519_dalek::StaticSecret;

        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let identity = ingestion_identity(&route).unwrap();
        let wrong_key_hex =
            EncryptionIdentity::from_seed("someone-else", [5_u8; 32]).public_key_hex();

        let ephemeral = StaticSecret::from([4_u8; 32]);
        let slot = crate::secrets::seal_value_for_tests(
            &ephemeral,
            wrong_key_hex,
            &deposit_aad(&route.project_id),
            "ghp_deposited_token",
        )
        .unwrap();
        let sealed = SealedSecret {
            ephemeral_public_hex: slot.ephemeral_public_hex,
            nonce_hex: slot.nonce_hex,
            ciphertext_hex: slot.ciphertext_hex,
        };

        assert!(open_deposit(&route, &identity, &sealed).is_err());
    }

    #[test]
    fn store_deposit_persists_a_valid_deposit_still_sealed() {
        use x25519_dalek::StaticSecret;

        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        let identity = ingestion_identity(&route).unwrap();
        let ephemeral = StaticSecret::from([4_u8; 32]);
        let slot = crate::secrets::seal_value_for_tests(
            &ephemeral,
            identity.public_key_hex(),
            &deposit_aad(&route.project_id),
            "ghp_deposited_token",
        )
        .unwrap();
        let sealed = SealedSecret {
            ephemeral_public_hex: slot.ephemeral_public_hex,
            nonce_hex: slot.nonce_hex,
            ciphertext_hex: slot.ciphertext_hex,
        };
        let metadata = DepositMetadata {
            provider: "github".into(),
            scope: "repo:read".into(),
            tier: 0,
            acquired_via: AcquiredVia::Track1Api,
            acquired_at: Utc::now(),
            expires_at: None,
            label: "GitHub App install token, pilot repo, read-only".into(),
        };

        let receipt = store_deposit(&route, "d-1".into(), &sealed, metadata.clone()).unwrap();
        assert_eq!(receipt.deposit_id, "d-1");
        assert_eq!(receipt.contract_version, CONTRACT_VERSION);

        // Persisted under the unsynced attachment directory, never communications.
        assert!(deposit_path(&route, "d-1").is_file());
        assert!(!route.communications.join("deposits/d-1.json").exists());

        let listed = list_deposits(&route).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].deposit_id, "d-1");
        assert_eq!(listed[0].metadata.provider, "github");
        // Still sealed, not the plaintext.
        assert_eq!(
            listed[0].sealed_secret.ciphertext_hex,
            sealed.ciphertext_hex
        );

        // A second deposit under the same ID is rejected, not overwritten.
        assert!(store_deposit(&route, "d-1".into(), &sealed, metadata).is_err());
        assert_eq!(list_deposits(&route).unwrap().len(), 1);
    }

    #[test]
    fn store_deposit_rejects_and_persists_nothing_for_a_deposit_that_does_not_open() {
        use x25519_dalek::StaticSecret;

        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        // Force ingestion_identity to exist first, then seal to a different key.
        ingestion_identity(&route).unwrap();
        let wrong_key_hex =
            EncryptionIdentity::from_seed("someone-else", [5_u8; 32]).public_key_hex();
        let ephemeral = StaticSecret::from([4_u8; 32]);
        let slot = crate::secrets::seal_value_for_tests(
            &ephemeral,
            wrong_key_hex,
            &deposit_aad(&route.project_id),
            "ghp_deposited_token",
        )
        .unwrap();
        let sealed = SealedSecret {
            ephemeral_public_hex: slot.ephemeral_public_hex,
            nonce_hex: slot.nonce_hex,
            ciphertext_hex: slot.ciphertext_hex,
        };
        let metadata = DepositMetadata {
            provider: "github".into(),
            scope: "repo:read".into(),
            tier: 0,
            acquired_via: AcquiredVia::Track1Api,
            acquired_at: Utc::now(),
            expires_at: None,
            label: "wrong key".into(),
        };

        assert!(store_deposit(&route, "d-2".into(), &sealed, metadata).is_err());
        assert!(list_deposits(&route).unwrap().is_empty());
    }
}

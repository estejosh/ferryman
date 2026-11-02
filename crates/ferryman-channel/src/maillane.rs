//! The email lane's bundle: channel files for one agent, sealed to it and signed (ADR 0032).
//!
//! Email is the fallback lane: it carries what the iroh lane could not, through the fleet's
//! AgentMail inbox, while the live lanes are down. Nothing about a mail is trusted for where
//! it came from. A bundle counts only when:
//!
//! - its format and project are this lane's and this channel's;
//! - it is addressed to the agent opening it;
//! - its signature verifies against the key this channel's roster pins for the sender, and
//!   the sender has not been revoked;
//! - its sealed payload opens with the recipient's own X25519 key, with the bundle id, the
//!   project and the recipient bound in as associated data (the construction sealed secrets
//!   use, [`crate::secrets`]).
//!
//! What a bundle carries is files; whether each may be written is the lane's decision, under
//! the same rules as a file arriving over iroh. Taking each bundle id once is the lane's too,
//! kept in machine state.

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AgentIdentity, ProjectRoute, SignatureCheck,
    secrets::{EncryptionIdentity, RecipientSlot},
};

/// The bundle format.
pub const FORMAT: &str = "ferryman-mail/v1";
/// Every lane mail's subject starts with this, followed by the bundle id.
pub const SUBJECT_PREFIX: &str = "fm/";

/// One channel file in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailFile {
    /// Relative to the channel folder, `/`-separated.
    pub path: String,
    /// Modification time, milliseconds since the Unix epoch, as the iroh lane carries it.
    pub mtime_ms: i64,
    /// The contents, hex.
    pub data_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    files: Vec<MailFile>,
}

/// A sealed, signed bundle, as it travels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub id: String,
    pub project_id: String,
    pub from: String,
    pub to: String,
    pub created_at: DateTime<Utc>,
    pub slot: RecipientSlot,
    pub signature: String,
}

impl Bundle {
    /// The subject a mail carrying this bundle has.
    #[must_use]
    pub fn subject(&self) -> String {
        format!("{SUBJECT_PREFIX}{}", self.id)
    }
}

fn aad(id: &str) -> String {
    format!("mail:{id}")
}

fn signed_bytes(bundle: &Bundle) -> String {
    let slot = serde_json::to_string(&bundle.slot).unwrap_or_default();
    format!(
        "{FORMAT}\n{}\n{}\n{}\n{}\n{}\n{}",
        bundle.id,
        bundle.project_id,
        bundle.from,
        bundle.to,
        bundle.created_at.to_rfc3339(),
        hex::encode(Sha256::digest(slot.as_bytes()))
    )
}

/// Seal `files` to `to` (an agent on `route`'s roster with a published encryption key) and
/// sign the bundle as `identity`.
///
/// # Errors
/// The recipient is not on the roster or has no encryption key, or the payload could not be
/// sealed.
pub fn seal(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    to: &str,
    files: Vec<MailFile>,
) -> Result<Bundle> {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let to = crate::canonical_agent_name(to);
    let payload = serde_json::to_vec(&Payload { files })?;
    let mut slots =
        crate::secrets::seal_slots(route, &aad(&id), &payload, std::slice::from_ref(&to))?;
    let Some(slot) = slots.pop() else {
        bail!("nothing was sealed to {to}")
    };
    let mut bundle = Bundle {
        format: FORMAT.to_string(),
        id,
        project_id: route.project_id.clone(),
        from: identity.name().to_string(),
        to,
        created_at: Utc::now(),
        slot,
        signature: String::new(),
    };
    bundle.signature = identity.sign_bytes(signed_bytes(&bundle).as_bytes());
    Ok(bundle)
}

/// Check `bundle` against `route`'s channel and open it with `identity`'s key: the files it
/// carries. Refuses, and says why, a bundle of another format or project, one addressed to
/// another agent, one whose signature does not hold against the roster, one from a revoked
/// agent, and one whose payload does not open.
///
/// # Errors
/// Any of the above.
pub fn open(
    route: &ProjectRoute,
    identity: &EncryptionIdentity,
    bundle: &Bundle,
) -> Result<Vec<MailFile>> {
    if bundle.format != FORMAT {
        bail!("not a lane bundle ({})", bundle.format)
    }
    if bundle.project_id != route.project_id {
        bail!(
            "bundle {} is for project {}, not {}",
            bundle.id,
            bundle.project_id,
            route.project_id
        )
    }
    if !crate::canonical_agent_name(&bundle.to).eq_ignore_ascii_case(identity.name()) {
        bail!("bundle {} is addressed to {}", bundle.id, bundle.to)
    }
    if !crate::is_safe_component(&bundle.id) {
        bail!("bundle id is not a plain name")
    }
    let roster = crate::gate::roster(route);
    if crate::check_signature(
        Some(&bundle.from),
        Some(&bundle.signature),
        &signed_bytes(bundle),
        &roster,
    ) != SignatureCheck::Valid
    {
        bail!(
            "bundle {} is not signed by {} as this channel's roster knows them",
            bundle.id,
            bundle.from
        )
    }
    if crate::master::is_revoked_in(&route.communications, &roster, &bundle.from) {
        bail!(
            "bundle {} is from {}, who has been revoked",
            bundle.id,
            bundle.from
        )
    }
    let plain = crate::secrets::open_slot(
        std::slice::from_ref(&bundle.slot),
        &aad(&bundle.id),
        &route.project_id,
        identity,
    )?;
    let payload: Payload = serde_json::from_slice(&plain)?;
    Ok(payload.files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;
    use std::fs;
    use std::path::Path;

    fn route_with(dir: &Path, members: &[(&AgentIdentity, &EncryptionIdentity)]) -> ProjectRoute {
        let communications = dir.join("demo-ferryman");
        fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: "demo".into(),
            workspace: dir.join("demo"),
            attachment: dir.join("attachment"),
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for (signing, encryption) in members {
            let agent = AgentRoute {
                name: signing.name().into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(signing.public_key_hex()),
                encryption_key: Some(encryption.public_key_hex()),
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        route
    }

    fn file(path: &str, text: &str) -> MailFile {
        MailFile {
            path: path.into(),
            mtime_ms: 1_700_000_000_000,
            data_hex: hex::encode(text),
        }
    }

    #[test]
    fn a_bundle_opens_for_its_recipient_and_for_nobody_else() {
        let dir = tempfile::tempdir().unwrap();
        let grouchly = AgentIdentity::from_seed("grouchly", [1; 32]);
        let grouchly_enc = EncryptionIdentity::from_seed("grouchly", [11; 32]);
        let beastly = AgentIdentity::from_seed("beastly", [2; 32]);
        let beastly_enc = EncryptionIdentity::from_seed("beastly", [12; 32]);
        let route = route_with(
            dir.path(),
            &[(&grouchly, &grouchly_enc), (&beastly, &beastly_enc)],
        );
        let bundle = seal(
            &route,
            &grouchly,
            "beastly",
            vec![file("orders/o1.json", "{}")],
        )
        .unwrap();
        assert!(bundle.subject().starts_with(SUBJECT_PREFIX));
        // AgentMail sees ciphertext only.
        assert!(
            !serde_json::to_string(&bundle)
                .unwrap()
                .contains("orders/o1.json")
        );
        let files = open(&route, &beastly_enc, &bundle).unwrap();
        assert_eq!(files, vec![file("orders/o1.json", "{}")]);
        // Addressed to beastly: grouchly cannot open it, and is told why.
        let error = open(&route, &grouchly_enc, &bundle)
            .unwrap_err()
            .to_string();
        assert!(error.contains("addressed to beastly"), "{error}");
    }

    #[test]
    fn a_forged_tampered_or_lifted_bundle_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let grouchly = AgentIdentity::from_seed("grouchly", [1; 32]);
        let grouchly_enc = EncryptionIdentity::from_seed("grouchly", [11; 32]);
        let beastly = AgentIdentity::from_seed("beastly", [2; 32]);
        let beastly_enc = EncryptionIdentity::from_seed("beastly", [12; 32]);
        let route = route_with(
            dir.path(),
            &[(&grouchly, &grouchly_enc), (&beastly, &beastly_enc)],
        );
        let good = seal(&route, &grouchly, "beastly", vec![file("a.json", "1")]).unwrap();

        // Someone holding only grouchly's PUBLIC key signs as grouchly: their own key.
        let impostor = AgentIdentity::from_seed("grouchly", [9; 32]);
        let forged = seal(&route, &impostor, "beastly", vec![file("a.json", "2")]).unwrap();
        assert!(open(&route, &beastly_enc, &forged).is_err());

        // Re-addressed after signing.
        let mut readdressed = good.clone();
        readdressed.from = "beastly".into();
        assert!(open(&route, &beastly_enc, &readdressed).is_err());

        // Its ciphertext swapped for another bundle's.
        let other = seal(&route, &grouchly, "beastly", vec![file("b.json", "3")]).unwrap();
        let mut swapped = good.clone();
        swapped.slot = other.slot.clone();
        assert!(open(&route, &beastly_enc, &swapped).is_err());

        // Lifted into another project.
        let mut lifted = good.clone();
        lifted.project_id = "elsewhere".into();
        assert!(open(&route, &beastly_enc, &lifted).is_err());

        // The good one still opens.
        assert!(open(&route, &beastly_enc, &good).is_ok());
    }
}

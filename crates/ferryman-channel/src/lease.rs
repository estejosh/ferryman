//! Short-lived, master-minted lease tokens for workers.
//!
//! A worker should never hold a project's long-lived operator or project token,
//! and it should not be trusted forever. Instead the master mints a short-lived
//! lease: a signed statement of what one worker may do, and for how long. The
//! worker — and every peer that must trust it — verifies the lease against the
//! master's published key. Same authority model as a grant, but expiring and
//! scoped, so a credential that leaks stops working on its own.

use std::fs;
use std::path::PathBuf;

use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature, is_safe_component};

/// A master-signed, short-lived, scoped grant of authority to one worker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseToken {
    pub project_id: String,
    /// The agent the lease is issued to.
    pub issued_to: String,
    /// Capabilities the lease confers. Empty means the worker's membership
    /// roles decide; a non-empty list narrows what this lease allows.
    #[serde(default)]
    pub scope: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn lease_path(route: &ProjectRoute, issued_to: &str) -> PathBuf {
    route
        .communications
        .join("leases")
        .join(format!("{issued_to}.json"))
}

/// Exactly what a lease signature covers.
fn lease_payload(token: &LeaseToken) -> String {
    format!(
        "ferryman-master-lease-v1\n{}\n{}\n{}\n{}\n{}",
        token.project_id,
        token.issued_to,
        token.scope.join(","),
        token.issued_at.to_rfc3339(),
        token.expires_at.to_rfc3339(),
    )
}

/// Mint a short-lived, scoped lease for a worker. Only the declared master may
/// mint one. The signed token is written into the channel so the worker and its
/// peers can read it; the signature makes it tamper-evident and the expiry
/// makes it self-limiting.
pub fn mint_lease(
    route: &ProjectRoute,
    master: &AgentIdentity,
    issued_to: &str,
    scope: Vec<String>,
    ttl: Duration,
) -> Result<LeaseToken> {
    let Some(declaration) = crate::master::read_master(route)? else {
        bail!("this project has no master; run 'ferry channel master init' first");
    };
    if declaration.master != master.name() {
        bail!("only the master ({}) may mint a lease", declaration.master);
    }
    if !is_safe_component(issued_to) {
        bail!("lease recipient must be a path-safe identifier");
    }
    if ttl <= Duration::zero() {
        bail!("lease TTL must be positive");
    }
    let now = Utc::now();
    let mut token = LeaseToken {
        project_id: route.project_id.clone(),
        issued_to: issued_to.to_owned(),
        scope,
        issued_at: now,
        expires_at: now + ttl,
        signed_by: None,
        signature: None,
    };
    let signature = master.signing.sign(lease_payload(&token).as_bytes());
    token.signed_by = Some(master.name().to_owned());
    token.signature = Some(hex::encode(signature.to_bytes()));
    let path = lease_path(route, issued_to);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::atomic_json(&path, &token)?;
    Ok(token)
}

/// Verify a lease: signed by the declared master, for this project, and not
/// expired. Returns `Ok(false)` for any failure rather than an error, so a
/// caller can treat "not authorized" uniformly.
pub fn verify_lease(route: &ProjectRoute, token: &LeaseToken) -> Result<bool> {
    if token.project_id != route.project_id {
        return Ok(false);
    }
    if Utc::now() >= token.expires_at {
        return Ok(false);
    }
    if check_signature(
        token.signed_by.as_ref(),
        token.signature.as_ref(),
        &lease_payload(token),
        &route.agents,
    ) != SignatureCheck::Valid
    {
        return Ok(false);
    }
    let Some(declaration) = crate::master::read_master(route)? else {
        return Ok(false);
    };
    Ok(token.signed_by.as_deref() == Some(declaration.master.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRoute, ProjectRoute};
    use std::fs;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    #[test]
    fn a_minted_lease_verifies_until_it_expires_or_is_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let master = AgentIdentity::load_or_create_in("master", &route.attachment, None).unwrap();
        let worker = AgentIdentity::load_or_create_in("worker", &route.attachment, None).unwrap();
        route.agents = vec![
            AgentRoute {
                name: "master".into(),
                role: "master".into(),
                capabilities: vec![],
                public_key: Some(master.public_key_hex()),
            },
            AgentRoute {
                name: "worker".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(worker.public_key_hex()),
            },
        ];
        crate::master::initialize_master(&route, &master, "master").unwrap();

        let lease = mint_lease(
            &route,
            &master,
            "worker",
            vec!["hone".into()],
            Duration::minutes(30),
        )
        .unwrap();
        assert!(verify_lease(&route, &lease).unwrap());

        // An expired lease fails, even though the signature is intact.
        let mut expired = lease.clone();
        expired.expires_at = Utc::now() - Duration::seconds(1);
        assert!(!verify_lease(&route, &expired).unwrap());

        // A widened scope breaks the signature.
        let mut tampered = lease.clone();
        tampered.scope = vec!["everything".into()];
        assert!(!verify_lease(&route, &tampered).unwrap());
    }

    #[test]
    fn only_the_master_mints() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let master = AgentIdentity::load_or_create_in("master", &route.attachment, None).unwrap();
        let mallory = AgentIdentity::load_or_create_in("mallory", &route.attachment, None).unwrap();
        route.agents = vec![
            AgentRoute {
                name: "master".into(),
                role: "master".into(),
                capabilities: vec![],
                public_key: Some(master.public_key_hex()),
            },
            AgentRoute {
                name: "mallory".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(mallory.public_key_hex()),
            },
        ];
        crate::master::initialize_master(&route, &master, "master").unwrap();

        assert!(
            mint_lease(&route, &mallory, "mallory", vec![], Duration::minutes(30)).is_err(),
            "a non-master must not mint a lease"
        );

        // With no master at all, minting also fails.
        let no_master = test_route(dir.path());
        assert!(mint_lease(&no_master, &master, "worker", vec![], Duration::minutes(30)).is_err());
    }
}

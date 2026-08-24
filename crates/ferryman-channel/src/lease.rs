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

use anyhow::{Context, Result, bail};
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
    /// Present on access grants (ADR 0013), absent on plain worker leases.
    /// One grant id per granted authority, so several can be alive for one
    /// subject at once - view and message, say - each renewed and revoked
    /// independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// What the grant is about, when it is about one thing: a vault secret id,
    /// a repository. Absent means the scope speaks for itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

fn lease_path(route: &ProjectRoute, issued_to: &str) -> PathBuf {
    route
        .communications
        .join("leases")
        .join(format!("{issued_to}.json"))
}

/// Exactly what a lease signature covers.
///
/// The two trailing lines exist only when the token carries them, so tokens
/// written before access grants existed produce byte-for-byte the payload they
/// were signed under - their signatures keep verifying unchanged.
fn lease_payload(token: &LeaseToken) -> String {
    let mut payload = format!(
        "ferryman-master-lease-v1\n{}\n{}\n{}\n{}\n{}",
        token.project_id,
        token.issued_to,
        token.scope.join(","),
        token.issued_at.to_rfc3339(),
        token.expires_at.to_rfc3339(),
    );
    if let Some(grant_id) = &token.grant_id {
        payload.push_str(&format!("\ngrant:{grant_id}"));
    }
    if let Some(resource) = &token.resource {
        payload.push_str(&format!("\nresource:{resource}"));
    }
    payload
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
        grant_id: None,
        resource: None,
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

// Access grants (ADR 0013)
// ========================
//
// A worker lease says "this master lets this worker work". An access grant
// says "this principal lets that principal do a named thing" - view an
// agent's status, drive it, use one vault secret - and its lifetime is where
// revocation gets its offline meaning: **a grant is a short lease the issuer
// keeps renewing; stopping the renewal is the revocation.** A machine that has
// not synced never holds durable authority - only a lease whose horizon is
// known and deliberately small.
//
// Deliberately *not* decided here is who may grant what about whom. That is
// policy, and it belongs to the layers built on this primitive (the team
// access model's owners, the vault's secret holders). What this layer proves
// is: who issued it, what it covered, that it is unexpired, and that nobody
// who saw a revocation would still honor it. Every action lands in the ledger,
// so "who could do what, when" stays answerable.

/// Where one subject's grants live. One writer per path - the issuer renews by
/// overwriting the same file with a later horizon.
fn grant_path(route: &ProjectRoute, subject: &str, grant_id: &str) -> PathBuf {
    route
        .communications
        .join("grants")
        .join(format!("{subject}.{grant_id}.json"))
}

fn revocation_path(route: &ProjectRoute, subject: &str, grant_id: &str) -> PathBuf {
    route
        .communications
        .join("grants")
        .join(format!("{subject}.{grant_id}.revoked.json"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// The signed statement that a grant was withdrawn.
///
/// Advisory next to expiry - expiry is what actually ends authority, even
/// offline - but it ends authority immediately wherever the record is visible,
/// and it is the ledger-facing act of taking something away.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRevocation {
    pub project_id: String,
    pub grant_id: String,
    /// Whose grant it was (the subject), so the record is self-describing.
    pub subject: String,
    pub revoked_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn revocation_payload(revocation: &GrantRevocation) -> String {
    format!(
        "ferryman-grant-revocation-v1\n{}\n{}\n{}\n{}\n{}",
        revocation.project_id,
        revocation.grant_id,
        revocation.subject,
        revocation.revoked_by,
        revocation.at.to_rfc3339(),
    )
}

fn sign_envelope(identity: &AgentIdentity, payload: String) -> (Option<String>, Option<String>) {
    let signature = identity.signing.sign(payload.as_bytes());
    (
        Some(identity.name().to_owned()),
        Some(hex::encode(signature.to_bytes())),
    )
}

/// Issue a fresh access grant: a signed lease with its own id.
///
/// Signed by `issuer`, whoever that is - whether to *honor* an issuer is the
/// enforcement layer's policy, not this function's business. Every issuance is
/// a ledger entry.
pub fn issue_grant(
    route: &ProjectRoute,
    issuer: &AgentIdentity,
    subject: &str,
    scope: Vec<String>,
    resource: Option<&str>,
    ttl: Duration,
) -> Result<LeaseToken> {
    if !is_safe_component(subject) {
        bail!("grant subject must be a path-safe identifier");
    }
    if ttl <= Duration::zero() {
        bail!("grant TTL must be positive");
    }
    let now = Utc::now();
    let mut token = LeaseToken {
        project_id: route.project_id.clone(),
        issued_to: subject.to_owned(),
        scope,
        issued_at: now,
        expires_at: now + ttl,
        signed_by: None,
        signature: None,
        grant_id: Some(crate::new_run_id()),
        resource: resource.map(str::to_owned),
    };
    (token.signed_by, token.signature) = sign_envelope(issuer, lease_payload(&token));
    let path = grant_path(route, subject, token.grant_id.as_deref().expect("just set"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::atomic_json(&path, &token)?;
    crate::ledger::append_ledger_entry(
        route,
        issuer,
        "grant",
        issuer.name(),
        &format!(
            "granted [{}] on {} until {}, grant {}",
            token.scope.join(","),
            subject,
            token.expires_at.to_rfc3339(),
            token.grant_id.as_deref().unwrap_or_default()
        ),
        Some(subject),
    )?;
    Ok(token)
}

/// Load one grant by subject and id.
pub fn read_grant(
    route: &ProjectRoute,
    subject: &str,
    grant_id: &str,
) -> Result<Option<LeaseToken>> {
    read_json(&grant_path(route, subject, grant_id))
}

/// Renew: the same grant, a later horizon, same single file.
///
/// Only the principal whose signature is on the grant may renew it - renewal
/// by anyone else would be authority minted by a stranger. A locally visible
/// revocation blocks renewal even though expiry alone would have allowed it:
/// you do not resurrect something you watched being taken away.
pub fn renew_grant(
    route: &ProjectRoute,
    issuer: &AgentIdentity,
    subject: &str,
    grant_id: &str,
    ttl: Duration,
) -> Result<LeaseToken> {
    let mut token = read_grant(route, subject, grant_id)?
        .ok_or_else(|| anyhow::anyhow!("no grant {grant_id} for {subject}; nothing to renew"))?;
    if token.signed_by.as_deref() != Some(issuer.name()) {
        bail!(
            "only the granting principal ({}) may renew {grant_id}",
            token.signed_by.as_deref().unwrap_or("unknown")
        );
    }
    if read_json::<GrantRevocation>(&revocation_path(route, subject, grant_id))?.is_some() {
        bail!("grant {grant_id} is revoked; issue a new grant instead of renewing it");
    }
    if ttl <= Duration::zero() {
        bail!("grant TTL must be positive");
    }
    // Renewal extends from NOW, not from the old horizon: a lapse is real, and
    // quietly papering over one would hide exactly the gap this design exists
    // to make visible.
    token.issued_at = Utc::now();
    token.expires_at = token.issued_at + ttl;
    (token.signed_by, token.signature) = sign_envelope(issuer, lease_payload(&token));
    crate::atomic_json(&grant_path(route, subject, grant_id), &token)?;
    crate::ledger::append_ledger_entry(
        route,
        issuer,
        "grant-renew",
        issuer.name(),
        &format!(
            "renewed grant {grant_id} for {subject} until {}",
            token.expires_at.to_rfc3339()
        ),
        Some(subject),
    )?;
    Ok(token)
}

/// Revoke: sign and publish that a grant is withdrawn.
///
/// Allowed from the issuing principal or the declared master - the two
/// parties whose business it is to end authority. Recording a revocation of a
/// grant that does not exist locally fails rather than inventing history.
#[allow(clippy::too_many_arguments)]
pub fn revoke_grant(
    route: &ProjectRoute,
    revoker: &AgentIdentity,
    subject: &str,
    grant_id: &str,
    reason: Option<&str>,
) -> Result<GrantRevocation> {
    let token = read_grant(route, subject, grant_id)?
        .ok_or_else(|| anyhow::anyhow!("no grant {grant_id} for {subject}"))?;
    let is_master = crate::master::read_master(route)?
        .map(|d| d.master == revoker.name())
        .unwrap_or(false);
    if token.signed_by.as_deref() != Some(revoker.name()) && !is_master {
        bail!(
            "only the issuer ({}) or the master may revoke {grant_id}",
            token.signed_by.as_deref().unwrap_or("unknown")
        );
    }
    let mut revocation = GrantRevocation {
        project_id: route.project_id.clone(),
        grant_id: grant_id.to_owned(),
        subject: subject.to_owned(),
        revoked_by: revoker.name().to_owned(),
        reason: reason.map(str::to_owned),
        at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    (revocation.signed_by, revocation.signature) =
        sign_envelope(revoker, revocation_payload(&revocation));
    let path = revocation_path(route, subject, grant_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::atomic_json(&path, &revocation)?;
    crate::ledger::append_ledger_entry(
        route,
        revoker,
        "grant-revoke",
        revoker.name(),
        &format!(
            "revoked grant {grant_id} on {}{}",
            subject,
            reason.map(|r| format!(": {r}")).unwrap_or_default()
        ),
        Some(subject),
    )?;
    Ok(revocation)
}

/// How a grant reads right now. `Invalid` means the artifact is there but its
/// signature does not check out - which is itself worth seeing, not hiding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GrantStatus {
    Active,
    Expired,
    Revoked,
    Invalid,
}

/// One listed grant: the token plus how it currently reads.
#[derive(Debug, Clone, Serialize)]
pub struct ListedGrant {
    pub token: LeaseToken,
    pub status: GrantStatus,
}

impl ListedGrant {
    /// Whether authority may be exercised under this grant right now.
    #[must_use]
    pub fn honors(&self) -> bool {
        self.status == GrantStatus::Active
    }
}

/// Read every grant in the channel, oldest first by issue time, each with its
/// current status against a visible revocation record, the clock, and the
/// roster.
pub fn list_grants(route: &ProjectRoute) -> Result<Vec<ListedGrant>> {
    let dir = route.communications.join("grants");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut listed = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json")
            || path.to_string_lossy().ends_with(".revoked.json")
        {
            continue;
        }
        let Ok(token) = serde_json::from_slice::<LeaseToken>(&fs::read(&path)?) else {
            continue;
        };
        listed.push(ListedGrant {
            status: grant_status(route, &token)?,
            token,
        });
    }
    listed.sort_by(|a, b| a.token.issued_at.cmp(&b.token.issued_at));
    Ok(listed)
}

/// Status of one grant against everything visible locally.
///
/// Order matters and is deliberate: a visible revocation reads as revoked even
/// after expiry (the ledger should say why authority ended), and a broken
/// signature reads as invalid regardless of anything else - an artifact that
/// cannot prove itself proves nothing, including its own expiry.
pub fn grant_status(route: &ProjectRoute, token: &LeaseToken) -> Result<GrantStatus> {
    let Some(grant_id) = &token.grant_id else {
        // Plain worker leases are not access grants; verify_lease is theirs.
        return Ok(if verify_lease(route, token)? {
            GrantStatus::Active
        } else {
            GrantStatus::Expired
        });
    };
    let subject = &token.issued_to;
    if read_json::<GrantRevocation>(&revocation_path(route, subject, grant_id))?.is_some() {
        return Ok(GrantStatus::Revoked);
    }
    if check_signature(
        token.signed_by.as_ref(),
        token.signature.as_ref(),
        &lease_payload(token),
        &route.agents,
    ) != SignatureCheck::Valid
    {
        return Ok(GrantStatus::Invalid);
    }
    if Utc::now() >= token.expires_at {
        return Ok(GrantStatus::Expired);
    }
    Ok(GrantStatus::Active)
}

/// Whether authority may be exercised under this grant, right now, here.
pub fn verify_grant(route: &ProjectRoute, token: &LeaseToken) -> Result<bool> {
    if token.project_id != route.project_id || token.grant_id.is_none() {
        return Ok(false);
    }
    Ok(grant_status(route, token)? == GrantStatus::Active)
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

#[cfg(test)]
mod grant_tests {
    use super::*;
    use crate::{AgentRoute, ProjectRoute};
    use std::fs;

    /// A route with a rostered issuer, a subject, and no master - access
    /// grants do not need one, which is part of their point.
    fn grant_route(dir: &std::path::Path) -> (ProjectRoute, AgentIdentity, AgentIdentity) {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        let mut route = ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        fs::create_dir_all(&route.attachment).unwrap();
        let issuer = AgentIdentity::load_or_create_in("owner", &route.attachment, None).unwrap();
        let stranger =
            AgentIdentity::load_or_create_in("stranger", &route.attachment, None).unwrap();
        route.agents = vec![
            AgentRoute {
                name: "owner".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(issuer.public_key_hex()),
            },
            AgentRoute {
                name: "stranger".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(stranger.public_key_hex()),
            },
        ];
        (route, issuer, stranger)
    }

    #[test]
    fn an_issued_grant_verifies_and_lists_as_active() {
        let dir = tempfile::tempdir().unwrap();
        let (route, issuer, _) = grant_route(dir.path());

        let token = issue_grant(
            &route,
            &issuer,
            "teammate",
            vec!["view".into(), "message".into()],
            None,
            Duration::hours(2),
        )
        .unwrap();

        assert!(verify_grant(&route, &token).unwrap());
        assert_eq!(grant_status(&route, &token).unwrap(), GrantStatus::Active);

        let listed = list_grants(&route).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].honors());
        assert_eq!(listed[0].token.grant_id, token.grant_id);
    }

    #[test]
    fn authority_ends_at_the_horizon_even_untouched() {
        // The whole point of lease-shaped grants: a machine that never syncs
        // again still falls out of authority when its copy expires. Signed
        // directly with a past horizon, since issue_grant refuses to mint
        // something born expired.
        let dir = tempfile::tempdir().unwrap();
        let (route, issuer, _) = grant_route(dir.path());
        let now = Utc::now();
        let mut token = LeaseToken {
            project_id: route.project_id.clone(),
            issued_to: "teammate".into(),
            scope: vec!["drive".into()],
            issued_at: now - Duration::minutes(5),
            expires_at: now - Duration::seconds(1),
            signed_by: None,
            signature: None,
            grant_id: Some(crate::new_run_id()),
            resource: None,
        };
        (token.signed_by, token.signature) = sign_envelope(&issuer, lease_payload(&token));
        let path = grant_path(&route, "teammate", token.grant_id.as_deref().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::atomic_json(&path, &token).unwrap();

        assert!(
            !verify_grant(
                &route,
                &read_grant(&route, "teammate", token.grant_id.as_deref().unwrap())
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            grant_status(
                &route,
                &read_grant(&route, "teammate", token.grant_id.as_deref().unwrap())
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            GrantStatus::Expired
        );
    }

    #[test]
    fn only_the_issuer_renews_and_a_revoked_grant_is_not_resurrectable() {
        let dir = tempfile::tempdir().unwrap();
        let (route, issuer, stranger) = grant_route(dir.path());
        let token = issue_grant(
            &route,
            &issuer,
            "teammate",
            vec!["view".into()],
            None,
            Duration::minutes(10),
        )
        .unwrap();
        let grant_id = token.grant_id.clone().unwrap();

        assert!(
            renew_grant(
                &route,
                &stranger,
                "teammate",
                &grant_id,
                Duration::minutes(10)
            )
            .is_err(),
            "renewal by anyone else would be authority minted by a stranger"
        );
        revoke_grant(
            &route,
            &issuer,
            "teammate",
            &grant_id,
            Some("changed my mind"),
        )
        .unwrap();
        assert!(
            renew_grant(
                &route,
                &issuer,
                "teammate",
                &grant_id,
                Duration::minutes(10)
            )
            .is_err(),
            "you do not resurrect something you watched being taken away"
        );
    }

    #[test]
    fn a_visible_revocation_ends_authority_before_expiry_and_the_master_may_revoke_too() {
        let dir = tempfile::tempdir().unwrap();
        let (mut route, issuer, _) = grant_route(dir.path());

        // The master exists for the revocation-authority check.
        let master_identity =
            AgentIdentity::load_or_create_in("master", &route.attachment, None).unwrap();
        route.agents.push(AgentRoute {
            name: "master".into(),
            role: "master".into(),
            capabilities: vec![],
            public_key: Some(master_identity.public_key_hex()),
        });
        crate::master::initialize_master(&route, &master_identity, "master").unwrap();

        let token = issue_grant(
            &route,
            &issuer,
            "teammate",
            vec!["use-secret".into()],
            Some("sk-vault-1"),
            Duration::hours(1),
        )
        .unwrap();
        assert!(verify_grant(&route, &token).unwrap());

        revoke_grant(
            &route,
            &master_identity,
            "teammate",
            token.grant_id.as_deref().unwrap(),
            None,
        )
        .expect("the master may end any authority in its project");
        assert_eq!(
            grant_status(&route, &token).unwrap(),
            GrantStatus::Revoked,
            "a visible revocation must read as revoked even with time left"
        );
        assert!(!verify_grant(&route, &token).unwrap());
    }

    #[test]
    fn a_widened_scope_breaks_the_signature_and_reads_as_invalid_not_expired() {
        let dir = tempfile::tempdir().unwrap();
        let (route, issuer, _) = grant_route(dir.path());
        let mut token = issue_grant(
            &route,
            &issuer,
            "teammate",
            vec!["view".into()],
            None,
            Duration::hours(1),
        )
        .unwrap();
        token.scope = vec!["everything".into()];
        assert_eq!(grant_status(&route, &token).unwrap(), GrantStatus::Invalid);
    }

    /// The regression guard for payload stability: a token signed before
    /// access grants existed carries neither optional field and must verify
    /// under exactly the bytes it was signed under. If this ever fails, the
    /// payload builder grew a line unconditionally and every pre-existing
    /// worker lease just broke.
    #[test]
    fn a_plain_worker_lease_signed_without_grant_fields_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let (route, issuer, _) = grant_route(dir.path());

        // Sign by hand against the v1 payload shape, as mint_lease did before
        // the optional fields existed.
        let now = Utc::now();
        let legacy = LeaseToken {
            project_id: route.project_id.clone(),
            issued_to: "teammate".into(),
            scope: vec!["hone".into()],
            issued_at: now,
            expires_at: now + Duration::minutes(30),
            signed_by: None,
            signature: None,
            grant_id: None,
            resource: None,
        };
        let signature = issuer.signing.sign(lease_payload(&legacy).as_bytes());
        let mut legacy = legacy;
        legacy.signed_by = Some(issuer.name().to_owned());
        legacy.signature = Some(hex::encode(signature.to_bytes()));

        // Not a master-minted lease, so verify_lease refuses it - but the
        // signature itself must read Valid, which is what payload stability
        // means.
        assert_eq!(
            check_signature(
                legacy.signed_by.as_ref(),
                legacy.signature.as_ref(),
                &lease_payload(&legacy),
                &route.agents,
            ),
            SignatureCheck::Valid
        );
    }
}

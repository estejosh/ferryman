//! Releases, approved from wherever the operator happens to be.
//!
//! ADR 0018. The fleet prepares a release and can go no further: it writes a signed
//! **request** naming the version, the exact commit, and what the tests said. A person
//! looks at that and writes a signed **approval**. Only then does anything get tagged.
//!
//! # What holds it together
//!
//! The commit. An approval names the commit it approved, and the signing step refuses
//! unless that is still the commit being tagged. Approving *this* release must never
//! authorise a different one, and that is not a detail - it is the property everything
//! else here exists to protect. A gate that can be pointed at a later commit is not a
//! gate, it is a delay.
//!
//! Both records are signed and verified against the roster, like every other record in
//! this channel, and each is named after its only writer so two of them can never
//! conflict.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck};

/// How long a request stays approvable.
///
/// An approval sitting unread overnight is not consent to ship whatever main became
/// while nobody was looking. Long enough to walk away from, short enough that the thing
/// approved is the thing that was prepared.
pub const REQUEST_GOES_STALE_AFTER_HOURS: i64 = 12;

/// A release the fleet has prepared and cannot itself ship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRequest {
    /// The version to be tagged, as the tag will spell it.
    pub version: String,
    /// The exact commit. The whole design hangs off this.
    pub commit: String,
    /// Which machine prepared it, and its only writer.
    pub prepared_by: String,
    pub prepared_at: DateTime<Utc>,
    /// Whether the tests passed, and what they said.
    pub ci_green: bool,
    #[serde(default)]
    pub ci_summary: String,
    /// What ships, in the words that will go in the tag.
    #[serde(default)]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ReleaseRequest {
    /// How old this request is, in whole minutes.
    #[must_use]
    pub fn age_minutes(&self, now: DateTime<Utc>) -> i64 {
        (now - self.prepared_at).num_minutes().max(0)
    }

    /// Whether this request has been sitting too long to still mean what it said.
    #[must_use]
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        self.age_minutes(now) >= REQUEST_GOES_STALE_AFTER_HOURS * 60
    }
}

/// One person saying yes to one commit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseApproval {
    pub version: String,
    /// Repeated deliberately rather than referenced. An approval that only named the
    /// version would still be valid after the request was rewritten around a different
    /// commit, which is exactly the substitution this refuses.
    pub commit: String,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    /// Where they were standing, for the tag message. Not load-bearing.
    #[serde(default)]
    pub via: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One person saying no to one commit, and why.
///
/// # Why this is a separate record rather than a field on the approval
///
/// An approval is a yes. Adding a yes/no field to it would change the bytes every
/// existing approval was signed over, so every approval already in a channel would stop
/// verifying the moment this shipped - a design that retroactively turns real consent
/// into an unreadable signature. A denial is its own record, on its own path, with its
/// own writer.
///
/// # Why it has to exist at all
///
/// Without it the store can only hold approvals, so a person who reads a request and
/// decides against it has nowhere to put that: silence and refusal are recorded
/// identically. "Has anybody looked at this" is the one question a judgement surface
/// exists to answer, and it could not be answered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseDenial {
    pub version: String,
    /// Pinned for the same reason the approval pins it: a denial of one commit is not a
    /// denial of whatever replaces it.
    pub commit: String,
    pub denied_by: String,
    pub denied_at: DateTime<Utc>,
    /// Why. Optional, because a refusal without a reason is still a refusal and
    /// demanding one is how people learn to type a full stop.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub via: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn release_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("release")
}

/// Where one machine's release request lives.
#[must_use]
pub fn request_path(route: &ProjectRoute, preparer: &str) -> PathBuf {
    release_dir(route).join(format!(
        "request.{}.json",
        crate::canonical_agent_name(preparer)
    ))
}

/// Where one person's approval lives.
#[must_use]
pub fn approval_path(route: &ProjectRoute, approver: &str) -> PathBuf {
    release_dir(route).join(format!(
        "approval.{}.json",
        crate::canonical_agent_name(approver)
    ))
}

fn request_payload(request: &ReleaseRequest) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        request.version,
        request.commit,
        request.prepared_by,
        request.prepared_at.to_rfc3339(),
        request.ci_green,
        request.ci_summary,
        request.notes,
    )
}

/// Where one person's denial lives. One writer per path, like everything else.
#[must_use]
pub fn denial_path(route: &ProjectRoute, denier: &str) -> PathBuf {
    release_dir(route).join(format!(
        "denial.{}.json",
        crate::canonical_agent_name(denier)
    ))
}

fn denial_payload(denial: &ReleaseDenial) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        denial.version,
        denial.commit,
        denial.denied_by,
        denial.denied_at.to_rfc3339(),
        denial.reason,
        denial.via,
    )
}

fn approval_payload(approval: &ReleaseApproval) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        approval.version,
        approval.commit,
        approval.approved_by,
        approval.approved_at.to_rfc3339(),
        approval.via,
    )
}

/// Publish a release request. Signed, because a request nobody can attribute is a
/// request nobody should act on.
pub fn write_request(
    route: &ProjectRoute,
    request: &ReleaseRequest,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let mut request = request.clone();
    request.prepared_by = crate::canonical_agent_name(&request.prepared_by);
    request.signed_by = Some(identity.name().to_string());
    request.signature = Some(identity.sign_bytes(request_payload(&request).as_bytes()));

    let path = request_path(route, &request.prepared_by);
    crate::atomic_json(&path, &request).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Record an approval, signed by the person giving it.
pub fn write_approval(
    route: &ProjectRoute,
    approval: &ReleaseApproval,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let mut approval = approval.clone();
    approval.approved_by = crate::canonical_agent_name(&approval.approved_by);
    approval.signed_by = Some(identity.name().to_string());
    approval.signature = Some(identity.sign_bytes(approval_payload(&approval).as_bytes()));

    let path = approval_path(route, &approval.approved_by);
    crate::atomic_json(&path, &approval).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Record a person's no. Signed by the same key an approval is signed by: a refusal
/// nobody can attribute is not evidence that anybody refused.
pub fn write_denial(
    route: &ProjectRoute,
    denial: &ReleaseDenial,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let mut denial = denial.clone();
    denial.denied_by = crate::canonical_agent_name(&denial.denied_by);
    denial.signed_by = Some(identity.name().to_string());
    denial.signature = Some(identity.sign_bytes(denial_payload(&denial).as_bytes()));

    let path = denial_path(route, &denial.denied_by);
    crate::atomic_json(&path, &denial).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

#[must_use]
pub fn verify_denial(denial: &ReleaseDenial, roster: &[AgentRoute]) -> SignatureCheck {
    crate::check_signature(
        denial.signed_by.as_ref(),
        denial.signature.as_ref(),
        &denial_payload(denial),
        roster,
    )
}

#[must_use]
pub fn verify_request(request: &ReleaseRequest, roster: &[AgentRoute]) -> SignatureCheck {
    crate::check_signature(
        request.signed_by.as_ref(),
        request.signature.as_ref(),
        &request_payload(request),
        roster,
    )
}

#[must_use]
pub fn verify_approval(approval: &ReleaseApproval, roster: &[AgentRoute]) -> SignatureCheck {
    crate::check_signature(
        approval.signed_by.as_ref(),
        approval.signature.as_ref(),
        &approval_payload(approval),
        roster,
    )
}

fn read_dir_of<T: for<'a> Deserialize<'a>>(route: &ProjectRoute, prefix: &str) -> Vec<T> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(release_dir(route)) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let is_ours = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(prefix));
        if !is_ours {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(value) = serde_json::from_str::<T>(&text)
        {
            out.push(value);
        }
    }
    out
}

/// Every release request in the channel, newest first.
pub fn list_requests(route: &ProjectRoute) -> Vec<ReleaseRequest> {
    let mut out: Vec<ReleaseRequest> = read_dir_of(route, "request.");
    out.sort_by_key(|request| std::cmp::Reverse(request.prepared_at));
    out
}

/// Every approval in the channel, newest first.
pub fn list_approvals(route: &ProjectRoute) -> Vec<ReleaseApproval> {
    let mut out: Vec<ReleaseApproval> = read_dir_of(route, "approval.");
    out.sort_by_key(|approval| std::cmp::Reverse(approval.approved_at));
    out
}

/// Every denial in the channel, newest first.
#[must_use]
pub fn list_denials(route: &ProjectRoute) -> Vec<ReleaseDenial> {
    let mut out: Vec<ReleaseDenial> = read_dir_of(route, "denial.");
    out.sort_by_key(|denial| std::cmp::Reverse(denial.denied_at));
    out
}

/// The request a person is being asked to look at, if there is one.
#[must_use]
pub fn pending(route: &ProjectRoute) -> Option<ReleaseRequest> {
    list_requests(route).into_iter().next()
}

/// Why a release may not be signed, in words meant for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Nobody has approved it.
    NotApproved,
    /// Approved, but for a different commit than the one on the table.
    CommitMoved { approved: String, actual: String },
    /// Approved by a name whose signature does not check out.
    ApprovalDoesNotVerify(SignatureCheck),
    /// The request has been sitting too long to still mean what it said.
    Stale { hours: i64 },
    /// The tests did not pass, and which check said so.
    CiNotGreen(String),
    /// Somebody read it and said no. A denial outranks an approval of the same commit
    /// unless the denier themselves changed their mind afterwards.
    Denied { by: String, reason: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApproved => write!(
                f,
                "nobody has approved this release yet - it is waiting for a person"
            ),
            Self::CommitMoved { approved, actual } => write!(
                f,
                "the approval was for {approved} and the release is now at {actual}. \
                 Approving one commit does not approve another; prepare it again and \
                 have it approved as it now stands."
            ),
            Self::ApprovalDoesNotVerify(check) => write!(
                f,
                "the approval does not verify against the roster ({check:?}), so it is \
                 not evidence that anybody approved anything"
            ),
            Self::Stale { hours } => write!(
                f,
                "the request is over {hours} hours old. An approval left unread is not \
                 consent to ship whatever has landed since; prepare it again."
            ),
            Self::CiNotGreen(which) => {
                if which.is_empty() {
                    write!(
                        f,
                        "the tests did not pass. This gate is for judgement, not for \
                         overriding the machine."
                    )
                } else {
                    write!(
                        f,
                        "the tests did not pass: {which}. This gate is for judgement, \
                         not for overriding the machine."
                    )
                }
            }
            Self::Denied { by, reason } => {
                if reason.is_empty() {
                    write!(f, "{by} read this and said no.")
                } else {
                    write!(f, "{by} read this and said no: {reason}")
                }
            }
        }
    }
}

/// Whether this release may be signed, and if not, why not in a sentence.
///
/// Every check is a refusal rather than a warning. There is no `--force`: a release that
/// needs one is a release somebody should look at again.
pub fn may_sign(
    route: &ProjectRoute,
    request: &ReleaseRequest,
    at_commit: &str,
) -> std::result::Result<ReleaseApproval, Refusal> {
    if !request.ci_green {
        return Err(Refusal::CiNotGreen(request.ci_summary.clone()));
    }
    if request.is_stale(Utc::now()) {
        return Err(Refusal::Stale {
            hours: REQUEST_GOES_STALE_AFTER_HOURS,
        });
    }
    let approval = list_approvals(route)
        .into_iter()
        .find(|approval| approval.version == request.version)
        .ok_or(Refusal::NotApproved)?;

    // A no outranks a yes, unless the person who said no said yes afterwards.
    //
    // Timestamps decide it rather than file order, because both records are signed over
    // their own instant and every machine must reach the same verdict from the same
    // files. An unverifiable denial is ignored here rather than honoured: a forged
    // refusal that blocks a release is a denial of service any peer could write into the
    // synced folder, and refusing to ship is not the safe direction when the block
    // itself is unattributable.
    if let Some(denial) = list_denials(route).into_iter().find(|denial| {
        denial.version == request.version
            && denial.commit == at_commit
            && denial.denied_at > approval.approved_at
            && verify_denial(denial, &route.agents) == SignatureCheck::Valid
    }) {
        return Err(Refusal::Denied {
            by: denial.denied_by,
            reason: denial.reason,
        });
    }

    if approval.commit != at_commit {
        return Err(Refusal::CommitMoved {
            approved: approval.commit.clone(),
            actual: at_commit.to_string(),
        });
    }
    match verify_approval(&approval, &route.agents) {
        SignatureCheck::Valid => Ok(approval),
        other => Err(Refusal::ApprovalDoesNotVerify(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn signer(name: &str) -> (AgentIdentity, AgentRoute) {
        let mut seed = [0u8; 32];
        for (slot, byte) in seed.iter_mut().zip(name.bytes().cycle()) {
            *slot = byte;
        }
        let identity = AgentIdentity::from_seed(name, seed);
        let route = AgentRoute {
            name: name.to_string(),
            role: "operator".to_string(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        };
        (identity, route)
    }

    fn request(version: &str, commit: &str) -> ReleaseRequest {
        ReleaseRequest {
            version: version.into(),
            commit: commit.into(),
            prepared_by: "beastly".into(),
            prepared_at: Utc::now(),
            ci_green: true,
            ci_summary: "23 suites, 0 failed".into(),
            notes: "what ships".into(),
            signed_by: None,
            signature: None,
        }
    }

    fn approval(version: &str, commit: &str) -> ReleaseApproval {
        ReleaseApproval {
            version: version.into(),
            commit: commit.into(),
            approved_by: "josh".into(),
            approved_at: Utc::now(),
            via: "dashboard".into(),
            signed_by: None,
            signature: None,
        }
    }

    #[test]
    fn a_prepared_release_cannot_be_signed_until_a_person_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (fleet, _) = signer("beastly");
        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();

        // The fleet prepared it and can go no further. This is the whole point.
        assert_eq!(
            may_sign(&route, &request, "9ed1185").unwrap_err(),
            Refusal::NotApproved
        );
    }

    #[test]
    fn an_approval_verifies_and_lets_it_through() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        let approved = may_sign(&route, &request, "9ed1185").unwrap();
        assert_eq!(approved.approved_by, "josh");
    }

    /// The attack the whole design turns on: approve one commit, ship another. If this
    /// test ever goes green with the pin relaxed, the gate is decorative.
    #[test]
    fn approving_one_commit_does_not_authorise_another() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        // Something landed on main between the approval and the signing.
        let refusal = may_sign(&route, &request, "deadbee").unwrap_err();
        assert_eq!(
            refusal,
            Refusal::CommitMoved {
                approved: "9ed1185".into(),
                actual: "deadbee".into()
            }
        );
        // And it says so in words a person can act on.
        assert!(refusal.to_string().contains("does not approve another"));
    }

    #[test]
    fn an_approval_that_does_not_verify_is_not_evidence_of_anything() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route.clone()];

        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        // Someone edits the approval on disk after it was signed.
        let path = approval_path(&route, "josh");
        let mut tampered: ReleaseApproval =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered.approved_by = "somebody-else".into();
        crate::atomic_json(&path, &tampered).unwrap();

        assert!(matches!(
            may_sign(&route, &request, "9ed1185"),
            Err(Refusal::ApprovalDoesNotVerify(_))
        ));
    }

    #[test]
    fn an_approval_left_overnight_is_not_consent_to_ship_what_landed_since() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let mut request = request("v0.5.6", "9ed1185");
        request.prepared_at =
            Utc::now() - chrono::Duration::hours(REQUEST_GOES_STALE_AFTER_HOURS + 1);
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        assert!(matches!(
            may_sign(&route, &request, "9ed1185"),
            Err(Refusal::Stale { .. })
        ));
    }

    fn denial(version: &str, commit: &str, reason: &str) -> ReleaseDenial {
        ReleaseDenial {
            version: version.into(),
            commit: commit.into(),
            denied_by: "josh".into(),
            denied_at: Utc::now(),
            reason: reason.into(),
            via: "dashboard".into(),
            signed_by: None,
            signature: None,
        }
    }

    /// Before this existed the channel could only hold approvals, so a person who read a
    /// request and decided against it had nowhere to put that. Silence and refusal were
    /// stored identically, and "did anybody look at this" could not be answered.
    #[test]
    fn a_person_can_say_no_and_it_is_recorded_as_a_no() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();
        assert!(may_sign(&route, &request, "9ed1185").is_ok());

        std::thread::sleep(std::time::Duration::from_millis(5));
        write_denial(
            &route,
            &denial("v0.5.6", "9ed1185", "the changelog is wrong"),
            &operator,
        )
        .unwrap();

        match may_sign(&route, &request, "9ed1185").unwrap_err() {
            Refusal::Denied { by, reason } => {
                assert_eq!(by, "josh");
                assert_eq!(reason, "the changelog is wrong");
            }
            other => panic!("a signed no must refuse the release, got {other:?}"),
        }
    }

    /// A refusal nobody can attribute is not evidence that anybody refused - and
    /// honouring one would let any peer with write access to the synced folder block
    /// every release by dropping a file in.
    #[test]
    fn an_unsigned_denial_does_not_block_a_release() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        // Written straight to the path, bypassing write_denial, exactly as a hostile
        // peer would.
        let forged = denial("v0.5.6", "9ed1185", "no reason at all");
        crate::atomic_json(&denial_path(&route, "josh"), &forged).unwrap();

        assert!(
            may_sign(&route, &request, "9ed1185").is_ok(),
            "an unsigned denial must not be able to block a release"
        );
    }

    /// A no about one commit is not a no about whatever replaced it, for exactly the
    /// reason a yes about one commit is not a yes about another.
    #[test]
    fn denying_one_commit_does_not_deny_another() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let request = request("v0.5.6", "40245c7");
        write_request(&route, &request, &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "40245c7"), &operator).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        write_denial(&route, &denial("v0.5.6", "9ed1185", "old one"), &operator).unwrap();

        assert!(
            may_sign(&route, &request, "40245c7").is_ok(),
            "a denial pinned to a different commit must not refuse this one"
        );
    }

    /// Changing your mind is allowed, and the later record is the one that counts.
    #[test]
    fn approving_after_declining_lets_it_through() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, fleet_route) = signer("beastly");
        let (operator, operator_route) = signer("josh");
        let mut route = route(dir.path());
        route.agents = vec![fleet_route, operator_route];

        let request = request("v0.5.6", "9ed1185");
        write_request(&route, &request, &fleet).unwrap();
        write_denial(&route, &denial("v0.5.6", "9ed1185", "hold on"), &operator).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        assert!(
            may_sign(&route, &request, "9ed1185").is_ok(),
            "an approval written after a denial is the newer decision and wins"
        );
    }

    /// Adding a decision must not invalidate consent already given. An approval signed
    /// before any of this existed still has to verify, or shipping this would quietly
    /// turn every real approval in every channel into an unreadable signature.
    #[test]
    fn adding_denials_did_not_change_what_an_approval_signs_over() {
        let (operator, operator_route) = signer("josh");
        let mut approval = approval("v0.5.6", "9ed1185");
        approval.signed_by = Some("josh".into());
        approval.signature = Some(
            operator.sign_bytes(
                format!(
                    "{}\n{}\n{}\n{}\n{}",
                    approval.version,
                    approval.commit,
                    approval.approved_by,
                    approval.approved_at.to_rfc3339(),
                    approval.via,
                )
                .as_bytes(),
            ),
        );
        assert_eq!(
            verify_approval(&approval, &[operator_route]),
            SignatureCheck::Valid,
            "the approval payload is frozen; a denial is its own record for this reason"
        );
    }

    #[test]
    fn red_tests_are_not_a_judgement_call() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let mut request = request("v0.5.6", "9ed1185");
        request.ci_green = false;
        assert!(matches!(
            may_sign(&route, &request, "9ed1185").unwrap_err(),
            Refusal::CiNotGreen(_)
        ));
    }

    #[test]
    fn requests_and_approvals_are_never_mistaken_for_one_another() {
        let dir = tempfile::tempdir().unwrap();
        let (fleet, _) = signer("beastly");
        let (operator, _) = signer("josh");
        let route = route(dir.path());

        write_request(&route, &request("v0.5.6", "9ed1185"), &fleet).unwrap();
        write_approval(&route, &approval("v0.5.6", "9ed1185"), &operator).unwrap();

        assert_eq!(list_requests(&route).len(), 1);
        assert_eq!(list_approvals(&route).len(), 1);
    }
}

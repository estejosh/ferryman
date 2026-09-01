//! Release approval: a signed request in the channel, a signed decision that
//! either authorises or refuses it, and the single gate that turns a decision
//! into a "go".
//!
//! ADR 0018. A release is the one act this product must never do on the word of a
//! machine. The fleet can *propose* a release — version, exact commit, CI conclusion,
//! changelog — and a human approves or denies it from their phone over Telegram. The
//! decision travels as a Telegram message; the secret never does. The bridge checks
//! `from.id == approver_id` (the one authorization model, unchanged), then writes a
//! signed decision on the machine it runs on, and the machine tags and signs with a
//! **release key** that is separate from the operator's personal GPG identity.
//!
//! The request and the decision are two different records with two different writers,
//! each named by its writer, exactly like every other channel artifact:
//!
//! - `release/request.<id>.json` — written once by the machine that proposes.
//! - `release/decision.<id>.<bridge>.json` — written once by the bridge machine that
//!   witnessed the approver's Telegram message.
//!
//! A decision is a claim by the bridge machine that the approver — recorded by name
//! and by the Telegram `from.id` it carried — saw a specific release and approved (or
//! denied) it. The fields that decide what it authorises — `version` and `commit` —
//! are part of the signed payload, so moving the commit after the fact breaks the
//! signature. [`authorize_release`] is the single place that turns a decision into a
//! "go", and it refuses anything that does not verify, names nobody on the roster,
//! points at a different commit, is stale, or whose CI is not green. That is the
//! attack the design turns on: an approval must never authorise a different release.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, check_signature};

/// The request format tag, written into every payload signature.
const REQUEST_FORMAT: &str = "ferryman-release-request/v1";
/// The decision format tag, written into every payload signature.
const DECISION_FORMAT: &str = "ferryman-release-decision/v1";

/// How long a request stays actionable. A request older than this is refused, not
/// because it is wrong but because the world it was written about has moved on.
pub const REQUEST_HORIZON_HOURS: i64 = 24;

/// The only CI conclusion that may pass the gate.
pub const CI_GREEN: &str = "green";

/// A signed release request. One writer per path: the proposing machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRequest {
    /// A stable id for the request, e.g. `v0.5.4`. Becomes part of the file name.
    pub id: String,
    /// The version this release would be tagged, e.g. `0.5.4`.
    pub version: String,
    /// The exact commit the release is built from (full hash). The gate pins on this.
    pub commit: String,
    /// The CI conclusion: `green`, `failed`, or `pending`. Only `green` passes.
    pub ci: String,
    /// A human-readable summary of what changed. Untrusted text written by a machine;
    /// whatever renders it must escape it.
    pub changelog: String,
    /// Which machine proposed it. Its only writer, folded like every other name.
    pub requester: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ReleaseRequest {
    /// A new request, with `id` defaulted from the version and the clock set at write
    /// time rather than here.
    #[must_use]
    pub fn new(version: &str, commit: &str, ci: &str, changelog: &str, requester: &str) -> Self {
        Self {
            id: id_for_version(version),
            version: version.to_string(),
            commit: commit.to_string(),
            ci: ci.to_string(),
            changelog: changelog.to_string(),
            requester: crate::canonical_agent_name(requester),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        }
    }
}

/// A signed decision on a request, written by the bridge machine that witnessed the
/// approver's Telegram message. One writer per path: the bridge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseDecision {
    /// Which request this is about.
    pub request_id: String,
    /// The version as the approver saw it. Must match the request exactly.
    pub version: String,
    /// The commit as the approver saw it. Pinned: a decision over a different commit
    /// authorises nothing, even when its signature is perfectly valid.
    pub commit: String,
    /// `approve` or `deny`. Only `approve` authorises a release.
    pub decision: String,
    /// The approver's own words, when they want to leave any. Optional.
    #[serde(default)]
    pub reason: String,
    /// The approver's name, for the record and the tag message. Not a path component:
    /// it may be a Telegram display name rather than a machine identity.
    pub operator: String,
    /// How the approval was authorised. `telegram` today; kept as a field so a future
    /// surface (the dashboard) cannot be confused with this one.
    #[serde(default)]
    pub via: String,
    /// The Telegram `from.id` that carried the decision. Zero means not via Telegram.
    /// This is evidence recorded by the bridge, not a second authorization: the
    /// `from.id == approver_id` check happened before the bridge wrote this.
    #[serde(default)]
    pub approved_by: i64,
    pub decided_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ReleaseDecision {
    /// An approval (or denial) over a specific version and commit.
    #[must_use]
    pub fn new(
        request: &ReleaseRequest,
        decision: &str,
        reason: &str,
        operator: &str,
        via: &str,
        approved_by: i64,
    ) -> Self {
        Self {
            request_id: request.id.clone(),
            version: request.version.clone(),
            commit: request.commit.clone(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            operator: operator.to_string(),
            via: via.to_string(),
            approved_by,
            decided_at: Utc::now(),
            signed_by: None,
            signature: None,
        }
    }

    #[must_use]
    pub fn approves(&self) -> bool {
        self.decision.eq_ignore_ascii_case("approve")
    }
}

/// A stable, path-safe id derived from a version string. A version like `0.5.4` is
/// already a safe component; anything else is refused at write time rather than used
/// to build a path.
fn id_for_version(version: &str) -> String {
    format!("v{version}")
}

/// Where a request lives. Named by its id, so one proposal is one file.
#[must_use]
pub fn request_path(route: &ProjectRoute, id: &str) -> PathBuf {
    release_dir(route).join(format!("request.{id}.json"))
}

/// Where one bridge's decision on one request lives. Named by the bridge (its only
/// writer), so two bridges never contend for the same file.
#[must_use]
pub fn decision_path(route: &ProjectRoute, id: &str, writer: &str) -> PathBuf {
    release_dir(route).join(format!(
        "decision.{id}.{}.json",
        crate::canonical_agent_name(writer)
    ))
}

fn release_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("release")
}

/// Exactly what a request signature covers. Explicit rather than "serialise the whole
/// struct", so a field added later cannot quietly change what an old signature means.
fn request_payload(request: &ReleaseRequest) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        REQUEST_FORMAT,
        request.id,
        request.version,
        request.commit,
        request.ci,
        request.changelog,
        request.requester,
        request.created_at.to_rfc3339(),
    )
}

/// Exactly what a decision signature covers. `version` and `commit` are here on
/// purpose: that is what makes an approval a pin. `via` and `approved_by` are here so
/// the claim "the approver said yes from their phone" cannot be rewritten later.
fn decision_payload(decision: &ReleaseDecision) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        DECISION_FORMAT,
        decision.request_id,
        decision.version,
        decision.commit,
        decision.decision,
        decision.reason,
        decision.operator,
        decision.via,
        decision.approved_by,
        decision.decided_at.to_rfc3339(),
    )
}

/// Validate the parts that would otherwise become file names.
fn validate_components(request: &ReleaseRequest) -> Result<()> {
    if !crate::is_safe_component(&request.id) {
        bail!("release id {:?} is not a safe path component", request.id);
    }
    if !crate::is_safe_component(&request.requester) {
        bail!(
            "release requester {:?} is not a safe path component",
            request.requester
        );
    }
    Ok(())
}

/// Sign and write a release request. The timestamp is set here, so the record's age is
/// the age of the write, not of the intention.
pub fn propose_release(
    route: &ProjectRoute,
    request: &ReleaseRequest,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let mut request = request.clone();
    request.requester = crate::canonical_agent_name(&request.requester);
    validate_components(&request)?;
    request.created_at = Utc::now();
    request.signed_by = Some(identity.name().to_string());
    request.signature = Some(identity.sign_bytes(request_payload(&request).as_bytes()));

    let path = request_path(route, &request.id);
    crate::atomic_json(&path, &request)
        .with_context(|| format!("write release request {}", path.display()))?;
    Ok(path)
}

/// Read one request by id, if it exists.
pub fn read_request(route: &ProjectRoute, id: &str) -> Result<Option<ReleaseRequest>> {
    let path = request_path(route, id);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read release request {}", path.display()))?;
    Ok(Some(serde_json::from_str(&text).with_context(|| {
        format!("{} is not a readable release request", path.display())
    })?))
}

/// Every request in the channel, newest first.
pub fn list_requests(route: &ProjectRoute) -> Result<Vec<ReleaseRequest>> {
    let dir = release_dir(route);
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(request) = serde_json::from_str::<ReleaseRequest>(&text)
        {
            out.push(request);
        }
    }
    out.sort_by_key(|request| std::cmp::Reverse(request.created_at));
    Ok(out)
}

/// Sign and write a bridge's decision. One file per bridge per request.
pub fn decide_release(
    route: &ProjectRoute,
    decision: &ReleaseDecision,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let mut decision = decision.clone();
    if !crate::is_safe_component(&decision.request_id) {
        bail!(
            "release request id {:?} is not a safe path component",
            decision.request_id
        );
    }
    decision.decided_at = Utc::now();
    decision.signed_by = Some(identity.name().to_string());
    decision.signature = Some(identity.sign_bytes(decision_payload(&decision).as_bytes()));

    let path = decision_path(route, &decision.request_id, identity.name());
    crate::atomic_json(&path, &decision)
        .with_context(|| format!("write release decision {}", path.display()))?;
    Ok(path)
}

/// Read one bridge's decision on one request, if it exists.
pub fn read_decision(
    route: &ProjectRoute,
    id: &str,
    writer: &str,
) -> Result<Option<ReleaseDecision>> {
    let path = decision_path(route, id, writer);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read release decision {}", path.display()))?;
    Ok(Some(serde_json::from_str(&text).with_context(|| {
        format!("{} is not a readable release decision", path.display())
    })?))
}

/// Every decision in the channel, newest first.
pub fn list_decisions(route: &ProjectRoute) -> Result<Vec<ReleaseDecision>> {
    let dir = release_dir(route);
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(decision) = serde_json::from_str::<ReleaseDecision>(&text)
        {
            out.push(decision);
        }
    }
    out.sort_by_key(|decision| std::cmp::Reverse(decision.decided_at));
    Ok(out)
}

/// Whether a request is what its author signed.
#[must_use]
pub fn verify_request(request: &ReleaseRequest, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        request.signed_by.as_ref(),
        request.signature.as_ref(),
        &request_payload(request),
        roster,
    )
}

/// Whether a decision is what its bridge signed.
#[must_use]
pub fn verify_decision(decision: &ReleaseDecision, roster: &[AgentRoute]) -> SignatureCheck {
    check_signature(
        decision.signed_by.as_ref(),
        decision.signature.as_ref(),
        &decision_payload(decision),
        roster,
    )
}

/// The newest decision for a request, if any bridge has decided. Used by the caller
/// (`ferry release land` and the bridge) to find the decision to check.
pub fn latest_decision(route: &ProjectRoute, id: &str) -> Result<Option<ReleaseDecision>> {
    list_decisions(route).map(|decisions| {
        decisions
            .into_iter()
            .find(|decision| decision.request_id == id)
    })
}

/// Why a decision does not authorise a release. A refusal is a message with a reason,
/// never a bare "no" and never a silent drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// The decision exists but is a denial, or there is no decision at all.
    NotApproved,
    /// The decision carries no signature.
    Unsigned,
    /// The signature does not verify against the key on file.
    InvalidSignature,
    /// The decision names a signer the roster does not know.
    UnknownSigner(String),
    /// The decision was signed by a different key than the roster holds for that name.
    KeyChanged,
    /// The approver approved a different version than the request proposes.
    VersionMismatch { requested: String, approved: String },
    /// The approver approved a different commit than the request proposes. This is the
    /// pin: an approval must never authorise a different release.
    CommitMismatch { requested: String, approved: String },
    /// The request is older than the short horizon.
    Stale {
        age_minutes: i64,
        horizon_hours: i64,
    },
    /// CI is not green.
    CiNotGreen(String),
}

impl std::fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApproved => write!(f, "the release has not been approved"),
            Self::Unsigned => write!(f, "the approval carries no signature"),
            Self::InvalidSignature => {
                write!(
                    f,
                    "the approval signature does not verify against the roster"
                )
            }
            Self::UnknownSigner(name) => {
                write!(
                    f,
                    "the approval is from {name:?}, which the roster does not know"
                )
            }
            Self::KeyChanged => write!(
                f,
                "the approval was signed by a key that does not match the roster"
            ),
            Self::VersionMismatch {
                requested,
                approved,
            } => write!(
                f,
                "the approval is for version {approved:?}, not the requested {requested:?}"
            ),
            Self::CommitMismatch {
                requested,
                approved,
            } => write!(
                f,
                "the approval is for commit {approved}, not the requested {requested}; \
                 an approval must never authorise a different release"
            ),
            Self::Stale {
                age_minutes,
                horizon_hours,
            } => write!(
                f,
                "the request is {age_minutes} minutes old, past the {horizon_hours}-hour horizon"
            ),
            Self::CiNotGreen(ci) => write!(f, "CI is not green (it is {ci:?})"),
        }
    }
}

impl std::error::Error for ReleaseRefusal {}

/// The single place a decision becomes a "go".
///
/// Every condition is checked, in order from cheapest and least specific to the two
/// that matter most. Returns `Ok(())` only when the decision is a verifiable approval,
/// signed by a name the roster knows, over exactly this request's version and commit,
/// within the horizon, with green CI. Anything else is a [`ReleaseRefusal`].
pub fn authorize_release(
    request: &ReleaseRequest,
    decision: &ReleaseDecision,
    roster: &[AgentRoute],
    now: DateTime<Utc>,
) -> Result<(), ReleaseRefusal> {
    // The signature is checked first: every field below — version, commit, the word
    // "approve" itself — is only worth trusting once the record is known to be what the
    // bridge signed. Checking an unauthenticated field is how a forged decision gets
    // to pick its own refusal.
    match verify_decision(decision, roster) {
        SignatureCheck::Valid => {}
        SignatureCheck::Unsigned => return Err(ReleaseRefusal::Unsigned),
        SignatureCheck::Invalid => return Err(ReleaseRefusal::InvalidSignature),
        SignatureCheck::UnknownSigner => {
            return Err(ReleaseRefusal::UnknownSigner(
                decision.signed_by.clone().unwrap_or_default(),
            ));
        }
        SignatureCheck::KeyChanged { .. } => return Err(ReleaseRefusal::KeyChanged),
    }

    if !decision.approves() {
        return Err(ReleaseRefusal::NotApproved);
    }

    // The pins. The whole point of the record is that it binds a human to ONE release;
    // a signature over a different release is worse than no signature at all because it
    // looks checked. These must never be relaxed.
    if decision.version != request.version {
        return Err(ReleaseRefusal::VersionMismatch {
            requested: request.version.clone(),
            approved: decision.version.clone(),
        });
    }
    if decision.commit != request.commit {
        return Err(ReleaseRefusal::CommitMismatch {
            requested: request.commit.clone(),
            approved: decision.commit.clone(),
        });
    }
    if !request.ci.eq_ignore_ascii_case(CI_GREEN) {
        return Err(ReleaseRefusal::CiNotGreen(request.ci.clone()));
    }

    // Staleness, because an approval collected last week must not land against a commit
    // that has since moved on. The horizon is short and deliberately generous to a human
    // who checks once a day, and refused loudly rather than silently extended.
    let age_minutes = (now - request.created_at).num_minutes().max(0);
    if age_minutes > REQUEST_HORIZON_HOURS * 60 {
        return Err(ReleaseRefusal::Stale {
            age_minutes,
            horizon_hours: REQUEST_HORIZON_HOURS,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chrono::Duration;

    use super::*;

    /// The Telegram user id the tests treat as the configured approver.
    const APPROVER_ID: i64 = 123_456_789;

    fn route(dir: &Path) -> ProjectRoute {
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
        let entry = AgentRoute {
            name: name.to_string(),
            role: "worker".to_string(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        };
        (identity, entry)
    }

    fn green_request(requester: &str) -> ReleaseRequest {
        ReleaseRequest::new(
            "0.5.4",
            "0123456789abcdef0123456789abcdef01234567",
            "green",
            "A release worth shipping.",
            requester,
        )
    }

    /// The bridge signs an approval as the approver "estejosh" over Telegram, and the
    /// helper returns the decision read back from the channel.
    fn approve_request(
        route: &ProjectRoute,
        request: &ReleaseRequest,
        bridge: &AgentIdentity,
    ) -> ReleaseDecision {
        let decision = ReleaseDecision::new(
            request,
            "approve",
            "ship it",
            "estejosh",
            "telegram",
            APPROVER_ID,
        );
        decide_release(route, &decision, bridge).unwrap();
        read_decision(route, &request.id, bridge.name())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn a_request_and_an_approval_survive_the_round_trip_and_authorise() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, machine_entry) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let read_back = read_request(&route, &request.id).unwrap().unwrap();
        assert_eq!(
            verify_request(&read_back, std::slice::from_ref(&machine_entry)),
            SignatureCheck::Valid
        );

        let decision = approve_request(&route, &request, &bridge);
        assert_eq!(
            verify_decision(&decision, std::slice::from_ref(&bridge_entry)),
            SignatureCheck::Valid
        );

        assert_eq!(
            authorize_release(
                &read_request(&route, &request.id).unwrap().unwrap(),
                &decision,
                std::slice::from_ref(&bridge_entry),
                decision.decided_at,
            ),
            Ok(())
        );
    }

    #[test]
    fn a_denial_does_not_authorise() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let decision = ReleaseDecision::new(
            &request,
            "deny",
            "not ready",
            "estejosh",
            "telegram",
            APPROVER_ID,
        );
        decide_release(&route, &decision, &bridge).unwrap();
        let decision = read_decision(&route, &request.id, bridge.name())
            .unwrap()
            .unwrap();

        assert_eq!(
            authorize_release(
                &request,
                &decision,
                std::slice::from_ref(&bridge_entry),
                request.created_at,
            ),
            Err(ReleaseRefusal::NotApproved)
        );
    }

    #[test]
    fn an_approval_from_a_name_the_roster_does_not_know_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, _) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let decision = approve_request(&route, &request, &bridge);

        assert_eq!(
            authorize_release(&request, &decision, &[], request.created_at),
            Err(ReleaseRefusal::UnknownSigner("telegram".to_string()))
        );
    }

    #[test]
    fn an_approval_with_a_bad_signature_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let mut decision = approve_request(&route, &request, &bridge);
        decision.signature = Some(hex::encode([0u8; 64]));

        assert_eq!(
            authorize_release(&request, &decision, &[bridge_entry], request.created_at),
            Err(ReleaseRefusal::InvalidSignature)
        );
    }

    /// The pin. This test exists so that if anyone ever "simplifies" the version or
    /// commit comparison away, the build fails loudly here rather than a moved commit
    /// being authorised in production.
    #[test]
    fn an_approval_for_a_different_commit_does_not_authorise_the_request() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();

        // A perfectly valid, roster-verifiable approval — over a different commit.
        let mut moved =
            ReleaseDecision::new(&request, "approve", "", "estejosh", "telegram", APPROVER_ID);
        moved.commit = "ffffffffffffffffffffffffffffffffffffffff".to_string();
        decide_release(&route, &moved, &bridge).unwrap();
        let moved = read_decision(&route, &request.id, bridge.name())
            .unwrap()
            .unwrap();

        assert_eq!(
            authorize_release(
                &request,
                &moved,
                std::slice::from_ref(&bridge_entry),
                request.created_at,
            ),
            Err(ReleaseRefusal::CommitMismatch {
                requested: request.commit.clone(),
                approved: moved.commit.clone(),
            })
        );
    }

    #[test]
    fn an_approval_for_a_different_version_does_not_authorise() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let mut moved =
            ReleaseDecision::new(&request, "approve", "", "estejosh", "telegram", APPROVER_ID);
        moved.version = "0.5.5".to_string();
        decide_release(&route, &moved, &bridge).unwrap();
        let moved = read_decision(&route, &request.id, bridge.name())
            .unwrap()
            .unwrap();

        assert_eq!(
            authorize_release(
                &request,
                &moved,
                std::slice::from_ref(&bridge_entry),
                request.created_at,
            ),
            Err(ReleaseRefusal::VersionMismatch {
                requested: request.version.clone(),
                approved: moved.version.clone(),
            })
        );
    }

    #[test]
    fn a_stale_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let decision = approve_request(&route, &request, &bridge);

        let now =
            request.created_at + Duration::hours(REQUEST_HORIZON_HOURS) + Duration::minutes(1);
        assert!(matches!(
            authorize_release(
                &request,
                &decision,
                std::slice::from_ref(&bridge_entry),
                now,
            ),
            Err(ReleaseRefusal::Stale { .. })
        ));
    }

    #[test]
    fn a_request_whose_ci_is_not_green_is_refused_even_when_approved() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let mut request = green_request("grouchly");
        request.ci = "failed".to_string();
        propose_release(&route, &request, &machine).unwrap();
        let decision = approve_request(&route, &request, &bridge);

        assert_eq!(
            authorize_release(
                &request,
                &decision,
                std::slice::from_ref(&bridge_entry),
                request.created_at,
            ),
            Err(ReleaseRefusal::CiNotGreen("failed".to_string()))
        );
    }

    #[test]
    fn editing_a_decision_after_signing_no_longer_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let decision = approve_request(&route, &request, &bridge);

        let mut tampered = decision.clone();
        tampered.reason = "something the operator never said".to_string();
        assert_eq!(
            verify_decision(&tampered, std::slice::from_ref(&bridge_entry)),
            SignatureCheck::Invalid
        );
    }

    /// The Telegram provenance is part of the signed payload: rewriting "who said this"
    /// after the fact must not verify. It is what stops a record being silently
    /// re-attributed to a different approver.
    #[test]
    fn rewriting_the_approved_by_field_after_signing_no_longer_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (bridge, bridge_entry) = signer("telegram");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let decision = approve_request(&route, &request, &bridge);

        let mut tampered = decision.clone();
        tampered.approved_by = 0;
        assert_eq!(
            verify_decision(&tampered, std::slice::from_ref(&bridge_entry)),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn one_writer_per_path_so_two_bridges_cannot_collide() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");
        let (first, _) = signer("telegram");
        let (second, _) = signer("bridge2");

        let request = green_request("grouchly");
        propose_release(&route, &request, &machine).unwrap();
        let a = decide_release(
            &route,
            &ReleaseDecision::new(&request, "approve", "", "estejosh", "telegram", APPROVER_ID),
            &first,
        )
        .unwrap();
        let b = decide_release(
            &route,
            &ReleaseDecision::new(&request, "approve", "", "estejosh", "telegram", APPROVER_ID),
            &second,
        )
        .unwrap();

        assert_ne!(a, b);
        assert_eq!(list_decisions(&route).unwrap().len(), 2);
    }

    #[test]
    fn the_version_becomes_a_path_safe_id() {
        assert_eq!(id_for_version("0.5.4"), "v0.5.4");
        assert!(crate::is_safe_component(&id_for_version("0.5.4")));
    }

    #[test]
    fn an_unsafe_request_id_is_refused_at_write_time() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (machine, _) = signer("grouchly");

        let mut request = green_request("grouchly");
        request.id = "../0.5.4".to_string();
        assert!(propose_release(&route, &request, &machine).is_err());
    }
}

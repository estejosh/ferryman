//! Delegation: the master lets one agent act for them, for named scopes only.
//!
//! A bridge that relays what a person says from their phone has to sign what it relays.
//! Unlocking the person's own key for it meant keeping their password on an always-on
//! machine. A delegation replaces that: the bridge keeps its own key, and the master signs
//! once, from the dashboard or `ferry team delegate`, a statement that this key may act for
//! them in these scopes, in this project, until revoked or expired.
//!
//! ```text
//! <channel>/delegations/
//!   telegram-grouchly.json          the master's signed delegation
//!   <delegation id>.revoked.json    the master's signed revocation of it
//! ```
//!
//! # What a verifier accepts
//!
//! An action carries the name it is taken under (`josh`) and the name that signed it
//! (`telegram-grouchly`). When they differ, the action counts only when all of this holds:
//!
//! - the delegation file names this project, this delegate and this principal;
//! - the principal is the project's verified master, and the master signed it, by the
//!   key the roster knows them by;
//! - the delegate's key on the roster is the key the delegation names, so a new key
//!   minted under the same name inherits nothing;
//! - the scope of the action is listed;
//! - it has not expired, and neither the delegation nor the delegate has a valid
//!   master-signed revocation.
//!
//! Anything else is refused, and a refusal says why. A delegate cannot delegate: only the
//! master's signature makes a delegation, so there is no chain to follow.
//!
//! # What a peer who can write the channel can do
//!
//! Delete a revocation, like any other file in a synced folder. That is the same limit
//! every master-signed record here has; an expiry bounds it, and revoking the delegate
//! itself with `ferry team revoke` writes a second, independent record.

use std::{fs, path::Path, path::PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, SignatureCheck, check_signature};

/// Issue orders under the master's name.
pub const ORDERS: &str = "orders";
/// Approve or send back results, including results only the master may approve.
pub const REVIEW: &str = "review";
/// Switch self-improve on or off, and answer the improve loop's questions.
pub const IMPROVE: &str = "improve";
/// Confirm, retract and write confirmed facts in the fleet's library, and edit its mail tag
/// map (see [`crate::library`]). Advice only: it never confers authority over code or
/// settings.
pub const LIBRARY: &str = "library";
/// Every scope there is. Nothing outside this list can be delegated.
pub const SCOPES: &[&str] = &[ORDERS, REVIEW, IMPROVE, LIBRARY];

const DIR: &str = "delegations";

/// The master's signed statement that `delegate` may act for them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delegation {
    pub id: String,
    pub project_id: String,
    /// Who is acted for: the master, when it was signed.
    pub principal: String,
    /// The agent that may act.
    pub delegate: String,
    /// The delegate's public key, hex. The delegation is for this key, not the name.
    pub delegate_key: String,
    pub scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub signed_by: String,
    pub signature: String,
}

/// The master's signed statement that one delegation has ended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    pub delegation_id: String,
    pub project_id: String,
    pub delegate: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn payload(delegation: &Delegation) -> String {
    let mut scopes = delegation.scopes.clone();
    scopes.sort();
    format!(
        "ferryman-delegation-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        delegation.id,
        delegation.project_id,
        delegation.principal,
        delegation.delegate,
        delegation.delegate_key,
        scopes.join(","),
        delegation.issued_at.to_rfc3339(),
        delegation
            .expires_at
            .map(|at| at.to_rfc3339())
            .unwrap_or_default()
    )
}

fn revocation_payload(revocation: &Revocation) -> String {
    format!(
        "ferryman-delegation-revoke-v1\n{}\n{}\n{}\n{}\n{}",
        revocation.delegation_id,
        revocation.project_id,
        revocation.delegate,
        revocation.reason,
        revocation.revoked_at.to_rfc3339()
    )
}

fn path(communications: &Path, delegate: &str) -> PathBuf {
    communications
        .join(DIR)
        .join(format!("{}.json", crate::canonical_agent_name(delegate)))
}

fn revocation_path(communications: &Path, delegation_id: &str) -> PathBuf {
    communications
        .join(DIR)
        .join(format!("{delegation_id}.revoked.json"))
}

/// What a delegation amounts to right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    Active,
    Expired,
    Revoked,
    /// It does not verify, and why.
    Invalid(String),
}

impl Standing {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Active => "active".to_string(),
            Self::Expired => "expired".to_string(),
            Self::Revoked => "revoked".to_string(),
            Self::Invalid(why) => format!("invalid: {why}"),
        }
    }
}

/// Whoever signed an action, and whether that is enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// Signed by the name it was taken under.
    Own,
    /// Signed by a delegate the principal's valid delegation covers.
    Delegated { principal: String, delegate: String },
    /// Signed by someone else, with nothing that lets them.
    Refused(String),
}

impl Authority {
    #[must_use]
    pub fn allowed(&self) -> bool {
        !matches!(self, Self::Refused(_))
    }
}

/// How the record reads: `josh`, or `josh via telegram-grouchly`.
#[must_use]
pub fn label(actor: &str, signer: &str) -> String {
    if signer.is_empty() || actor.eq_ignore_ascii_case(signer) {
        actor.to_string()
    } else {
        format!("{actor} via {signer}")
    }
}

/// Sign a delegation from the master of the project in `communications` to `delegate`.
///
/// The delegate must already be on the roster with a key: the delegation names that key.
pub fn grant(
    communications: &Path,
    project_id: &str,
    master: &AgentIdentity,
    delegate: &str,
    scopes: &[String],
    expires_at: Option<DateTime<Utc>>,
) -> Result<Delegation> {
    if !crate::is_safe_component(delegate) {
        bail!("the delegate's name must be a path-safe identifier");
    }
    if delegate.eq_ignore_ascii_case(master.name()) {
        bail!("a master does not delegate to themselves");
    }
    let mut wanted: Vec<String> = Vec::new();
    for scope in scopes {
        let scope = scope.trim().to_ascii_lowercase();
        if !SCOPES.contains(&scope.as_str()) {
            bail!(
                "'{scope}' is not a scope; the scopes are {}",
                SCOPES.join(", ")
            );
        }
        if !wanted.contains(&scope) {
            wanted.push(scope);
        }
    }
    if wanted.is_empty() {
        bail!(
            "a delegation needs at least one scope: {}",
            SCOPES.join(", ")
        );
    }
    crate::ferry::require_master(communications, project_id, master, "delegate")?;
    let roster = crate::read_agent_roster(communications)?;
    let Some(delegate_key) = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(delegate))
        .and_then(|agent| agent.public_key.clone())
        .filter(|key| !key.is_empty())
    else {
        bail!(
            "{delegate} has no key on {project_id}'s roster yet; start it once so it \
             publishes one, then delegate"
        );
    };
    let mut delegation = Delegation {
        id: uuid::Uuid::new_v4().simple().to_string()[..16].to_string(),
        project_id: project_id.to_string(),
        principal: master.name().to_string(),
        delegate: crate::canonical_agent_name(delegate),
        delegate_key,
        scopes: wanted,
        issued_at: Utc::now(),
        expires_at,
        signed_by: master.name().to_string(),
        signature: String::new(),
    };
    delegation.signature = hex::encode(
        master
            .signing
            .sign(payload(&delegation).as_bytes())
            .to_bytes(),
    );
    crate::atomic_json(&path(communications, delegate), &delegation)?;
    Ok(delegation)
}

/// End the delegation `delegate` holds in this project. Master only. Returns whether
/// there was one to end.
pub fn revoke(
    communications: &Path,
    project_id: &str,
    master: &AgentIdentity,
    delegate: &str,
    reason: &str,
) -> Result<bool> {
    crate::ferry::require_master(communications, project_id, master, "revoke a delegation")?;
    let Some(delegation) = read(communications, delegate) else {
        return Ok(false);
    };
    let mut revocation = Revocation {
        delegation_id: delegation.id.clone(),
        project_id: project_id.to_string(),
        delegate: delegation.delegate.clone(),
        reason: reason.to_string(),
        revoked_at: Utc::now(),
        signed_by: master.name().to_string(),
        signature: String::new(),
    };
    revocation.signature = hex::encode(
        master
            .signing
            .sign(revocation_payload(&revocation).as_bytes())
            .to_bytes(),
    );
    crate::atomic_json(
        &revocation_path(communications, &delegation.id),
        &revocation,
    )?;
    Ok(true)
}

/// The delegation file for `delegate`, as written, verified or not.
#[must_use]
pub fn read(communications: &Path, delegate: &str) -> Option<Delegation> {
    serde_json::from_slice(&fs::read(path(communications, delegate)).ok()?).ok()
}

/// Every delegation in the channel with where it stands, for the dashboard and the CLI.
#[must_use]
pub fn list(
    communications: &Path,
    project_id: &str,
    now: DateTime<Utc>,
) -> Vec<(Delegation, Standing)> {
    let Ok(entries) = fs::read_dir(communications.join(DIR)) else {
        return Vec::new();
    };
    let mut out: Vec<(Delegation, Standing)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json") && !name.ends_with(".revoked.json"))
        })
        .filter_map(|path| serde_json::from_slice::<Delegation>(&fs::read(path).ok()?).ok())
        .map(|delegation| {
            let standing = standing(communications, project_id, &delegation, now);
            (delegation, standing)
        })
        .collect();
    out.sort_by(|a, b| a.0.delegate.cmp(&b.0.delegate));
    out
}

/// Check a delegation against everything a verifier requires.
#[must_use]
pub fn standing(
    communications: &Path,
    project_id: &str,
    delegation: &Delegation,
    now: DateTime<Utc>,
) -> Standing {
    let invalid = |why: &str| Standing::Invalid(why.to_string());
    if delegation.project_id != project_id {
        return invalid("it is for another project");
    }
    if delegation
        .delegate
        .eq_ignore_ascii_case(&delegation.principal)
    {
        return invalid("it delegates to its own principal");
    }
    let Ok(roster) = crate::read_agent_roster(communications) else {
        return invalid("the roster cannot be read");
    };
    let master = match crate::master::read_master_at(communications, &roster) {
        Ok(Some(master)) if master.project_id == project_id => master,
        _ => return invalid("the project has no verified master"),
    };
    if !delegation.principal.eq_ignore_ascii_case(&master.master)
        || !delegation.signed_by.eq_ignore_ascii_case(&master.master)
    {
        return invalid("the project's master did not sign it");
    }
    if check_signature(
        Some(&delegation.signed_by),
        Some(&delegation.signature),
        &payload(delegation),
        &roster,
    ) != SignatureCheck::Valid
    {
        return invalid("the signature does not verify");
    }
    let key = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(&delegation.delegate))
        .and_then(|agent| agent.public_key.clone());
    if key.as_deref() != Some(delegation.delegate_key.as_str()) {
        return invalid("the delegate's key is not the key it was given to");
    }
    if revoked(
        communications,
        project_id,
        delegation,
        &master.master,
        &roster,
    ) || crate::master::is_revoked_in(communications, &roster, &delegation.delegate)
    {
        return Standing::Revoked;
    }
    if delegation.expires_at.is_some_and(|at| at <= now) {
        return Standing::Expired;
    }
    Standing::Active
}
fn revoked(
    communications: &Path,
    project_id: &str,
    delegation: &Delegation,
    master: &str,
    roster: &[crate::AgentRoute],
) -> bool {
    let Some(revocation) = fs::read(revocation_path(communications, &delegation.id))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Revocation>(&bytes).ok())
    else {
        return false;
    };
    revocation.delegation_id == delegation.id
        && revocation.project_id == project_id
        && revocation.signed_by.eq_ignore_ascii_case(master)
        && check_signature(
            Some(&revocation.signed_by),
            Some(&revocation.signature),
            &revocation_payload(&revocation),
            roster,
        ) == SignatureCheck::Valid
}

/// The delegation `delegate` holds here, when it is active.
#[must_use]
pub fn active(
    communications: &Path,
    project_id: &str,
    delegate: &str,
    now: DateTime<Utc>,
) -> Option<Delegation> {
    let delegation = read(communications, delegate)?;
    (delegation.delegate.eq_ignore_ascii_case(delegate)
        && standing(communications, project_id, &delegation, now) == Standing::Active)
        .then_some(delegation)
}

/// May `signer` take an action in `scope` under `actor`'s name?
#[must_use]
pub fn authority(
    communications: &Path,
    project_id: &str,
    actor: &str,
    signer: &str,
    scope: &str,
    now: DateTime<Utc>,
) -> Authority {
    if actor.eq_ignore_ascii_case(signer) {
        return Authority::Own;
    }
    let Some(delegation) = read(communications, signer) else {
        return Authority::Refused(format!("{signer} holds no delegation from {actor}"));
    };
    if !delegation.delegate.eq_ignore_ascii_case(signer) {
        return Authority::Refused(format!("{signer}'s delegation file names someone else"));
    }
    match standing(communications, project_id, &delegation, now) {
        Standing::Active => {}
        other => {
            return Authority::Refused(format!("{signer}'s delegation is {}", other.describe()));
        }
    }
    if !delegation.principal.eq_ignore_ascii_case(actor) {
        return Authority::Refused(format!(
            "{signer} acts for {}, not {actor}",
            delegation.principal
        ));
    }
    if !delegation.scopes.iter().any(|held| held == scope) {
        return Authority::Refused(format!(
            "{signer} is not delegated '{scope}' (it holds {})",
            delegation.scopes.join(", ")
        ));
    }
    Authority::Delegated {
        principal: delegation.principal,
        delegate: delegation.delegate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRoute, ProjectRoute};

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    fn josh() -> AgentIdentity {
        person("josh", 1)
    }

    fn route_at(dir: &Path, communications: &Path) -> ProjectRoute {
        ProjectRoute {
            project_id: "demo".into(),
            workspace: dir.join("demo"),
            attachment: dir.join("attachment"),
            communications: communications.to_path_buf(),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: crate::read_agent_roster(communications).unwrap_or_default(),
        }
    }

    fn publish(route: &ProjectRoute, member: &AgentIdentity) {
        crate::register_agent(
            route,
            &AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
    }

    /// A channel whose master is josh, with `members` on the roster.
    fn channel(dir: &Path, members: &[&AgentIdentity]) -> PathBuf {
        let communications = dir.join("demo-ferryman");
        fs::create_dir_all(&communications).unwrap();
        let route = route_at(dir, &communications);
        for member in std::iter::once(&josh()).chain(members.iter().copied()) {
            publish(&route, member);
        }
        let route = route_at(dir, &communications);
        crate::master::initialize_master(&route, &josh(), "josh").unwrap();
        communications
    }

    fn scopes(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    const BRIDGE: &str = "telegram-grouchly";

    fn allowed(comms: &Path, project: &str, actor: &str, scope: &str) -> bool {
        authority(comms, project, actor, BRIDGE, scope, Utc::now()).allowed()
    }

    #[test]
    fn a_delegated_action_counts_only_in_scope_and_for_its_principal() {
        let dir = tempfile::tempdir().unwrap();
        let comms = channel(dir.path(), &[&person(BRIDGE, 2)]);
        assert_eq!(
            authority(&comms, "demo", "josh", BRIDGE, ORDERS, Utc::now()),
            Authority::Refused(format!("{BRIDGE} holds no delegation from josh"))
        );
        grant(
            &comms,
            "demo",
            &josh(),
            BRIDGE,
            &scopes(&["orders", "review"]),
            None,
        )
        .unwrap();
        assert_eq!(
            authority(&comms, "demo", "josh", BRIDGE, ORDERS, Utc::now()),
            Authority::Delegated {
                principal: "josh".into(),
                delegate: BRIDGE.into()
            }
        );
        assert!(allowed(&comms, "demo", "josh", REVIEW));
        assert!(!allowed(&comms, "demo", "josh", IMPROVE), "out of scope");
        assert!(
            !allowed(&comms, "demo", "ada", ORDERS),
            "not ada's delegate"
        );
        assert!(!allowed(&comms, "other", "josh", ORDERS), "another project");
        assert_eq!(label("josh", BRIDGE), "josh via telegram-grouchly");
        assert_eq!(label("josh", "josh"), "josh");
    }

    #[test]
    fn only_the_master_delegates_and_a_forged_delegation_counts_for_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bridge = person(BRIDGE, 2);
        let ada = person("ada", 3);
        let comms = channel(dir.path(), &[&bridge, &ada]);
        let error = grant(&comms, "demo", &ada, BRIDGE, &scopes(&["orders"]), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("only josh"), "{error}");
        // Written by hand, validly signed by a member who is not the master.
        let mut forged = Delegation {
            id: "f1".into(),
            project_id: "demo".into(),
            principal: "ada".into(),
            delegate: BRIDGE.into(),
            delegate_key: bridge.public_key_hex(),
            scopes: scopes(&["orders"]),
            issued_at: Utc::now(),
            expires_at: None,
            signed_by: "ada".into(),
            signature: String::new(),
        };
        forged.signature = ada.sign_bytes(payload(&forged).as_bytes());
        crate::atomic_json(&path(&comms, BRIDGE), &forged).unwrap();
        assert!(!allowed(&comms, "demo", "ada", ORDERS));
        assert!(!allowed(&comms, "demo", "josh", ORDERS));
        // Claiming josh as principal and signer, but signed with ada's key.
        forged.principal = "josh".into();
        forged.signed_by = "josh".into();
        forged.signature = ada.sign_bytes(payload(&forged).as_bytes());
        crate::atomic_json(&path(&comms, BRIDGE), &forged).unwrap();
        assert_eq!(
            standing(&comms, "demo", &forged, Utc::now()),
            Standing::Invalid("the signature does not verify".into())
        );
        assert!(!allowed(&comms, "demo", "josh", ORDERS));
    }

    #[test]
    fn a_delegation_widened_after_signing_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let comms = channel(dir.path(), &[&person(BRIDGE, 2)]);
        let mut delegation =
            grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["orders"]), None).unwrap();
        delegation.scopes.push(IMPROVE.into());
        crate::atomic_json(&path(&comms, BRIDGE), &delegation).unwrap();
        assert!(!allowed(&comms, "demo", "josh", IMPROVE));
        assert!(!allowed(&comms, "demo", "josh", ORDERS));
    }

    /// The delegation is for a key. Another key using the delegate's name - re-published
    /// over it, or simply signing with it - gets nothing.
    #[test]
    fn a_new_key_under_the_delegates_name_inherits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let comms = channel(dir.path(), &[&person(BRIDGE, 2)]);
        grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["orders"]), None).unwrap();
        let impostor = person(BRIDGE, 9);
        let route = route_at(dir.path(), &comms);
        assert_eq!(
            crate::verify_order_in(&route, &order_for_josh("tg-5", &impostor)),
            crate::SignatureCheck::Invalid
        );
        let mut rekeyed = read(&comms, BRIDGE).unwrap();
        rekeyed.delegate_key = impostor.public_key_hex();
        assert!(matches!(
            standing(&comms, "demo", &rekeyed, Utc::now()),
            Standing::Invalid(_)
        ));
    }

    #[test]
    fn a_revoked_or_expired_delegation_counts_for_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ada = person("ada", 3);
        let comms = channel(dir.path(), &[&person(BRIDGE, 2), &ada]);
        grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["orders"]), None).unwrap();
        assert!(allowed(&comms, "demo", "josh", ORDERS));
        assert!(
            revoke(&comms, "demo", &ada, BRIDGE, "no").is_err(),
            "members cannot"
        );
        assert!(revoke(&comms, "demo", &josh(), BRIDGE, "phone lost").unwrap());
        assert_eq!(
            authority(&comms, "demo", "josh", BRIDGE, ORDERS, Utc::now()),
            Authority::Refused(format!("{BRIDGE}'s delegation is revoked"))
        );
        // Delegating again is a new decision, and counts.
        grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["orders"]), None).unwrap();
        assert!(allowed(&comms, "demo", "josh", ORDERS));
        let past = Utc::now() - chrono::Duration::minutes(1);
        grant(
            &comms,
            "demo",
            &josh(),
            BRIDGE,
            &scopes(&["orders"]),
            Some(past),
        )
        .unwrap();
        assert_eq!(
            authority(&comms, "demo", "josh", BRIDGE, ORDERS, Utc::now()),
            Authority::Refused(format!("{BRIDGE}'s delegation is expired"))
        );
    }

    #[test]
    fn revoking_the_delegate_itself_also_ends_the_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let comms = channel(dir.path(), &[&person(BRIDGE, 2)]);
        grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["orders"]), None).unwrap();
        crate::master::revoke_member(&route_at(dir.path(), &comms), &josh(), BRIDGE, "gone")
            .unwrap();
        assert!(!allowed(&comms, "demo", "josh", ORDERS));
    }

    #[test]
    fn unknown_scopes_self_delegation_and_keyless_delegates_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let comms = channel(dir.path(), &[&person(BRIDGE, 2)]);
        assert!(grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["secrets"]), None).is_err());
        assert!(grant(&comms, "demo", &josh(), BRIDGE, &[], None).is_err());
        assert!(grant(&comms, "demo", &josh(), "josh", &scopes(&["orders"]), None).is_err());
        let error = grant(
            &comms,
            "demo",
            &josh(),
            "nobody",
            &scopes(&["orders"]),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no key"), "{error}");
    }

    fn order_for_josh(id: &str, signer: &AgentIdentity) -> crate::Order {
        let mut order = crate::Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "josh".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: serde_json::json!({ "task": "tidy the README" }),
            requires_review: true,
            requires_approval: true,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        signer.sign_order(&mut order);
        order
    }

    fn verdict_for_josh(signer: &AgentIdentity) -> crate::Review {
        let mut review = crate::Review {
            order_id: "tg-1".into(),
            revision: 1,
            reviewer: "josh".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        signer.sign_review(&mut review);
        review
    }

    /// The whole path a phone takes: an order and a verdict signed by the bridge for
    /// josh count under his delegation, read as "josh via telegram-grouchly", and the same
    /// records signed by anyone else - or after revocation - count for nothing.
    #[test]
    fn delegated_orders_and_verdicts_count_and_nothing_else_signed_for_the_master_does() {
        use crate::{SignatureCheck, TaskState};
        let dir = tempfile::tempdir().unwrap();
        let bridge = person(BRIDGE, 2);
        let wisp = person("wisp", 4);
        let comms = channel(dir.path(), &[&bridge, &wisp]);
        let route = route_at(dir.path(), &comms);

        let order = order_for_josh("tg-1", &bridge);
        assert_eq!(
            crate::verify_order(&order, &route.agents),
            SignatureCheck::Valid,
            "the signature alone is fine - which is why it is not the whole check"
        );
        assert_eq!(
            crate::verify_order_in(&route, &order),
            SignatureCheck::Invalid
        );
        grant(
            &comms,
            "demo",
            &josh(),
            BRIDGE,
            &scopes(&["orders", "review"]),
            None,
        )
        .unwrap();
        assert_eq!(
            crate::verify_order_in(&route, &order),
            SignatureCheck::Valid
        );
        crate::issue_order(&route, &order).unwrap();
        assert!(
            crate::work_for(&route, "wisp")
                .unwrap()
                .iter()
                .any(|task| task.order.id == "tg-1")
        );
        // A worker signing an order in josh's name holds no delegation of its own.
        assert_eq!(
            crate::verify_order_in(&route, &order_for_josh("tg-2", &wisp)),
            SignatureCheck::Invalid
        );

        let mut result = crate::TaskResult {
            order_id: "tg-1".into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: serde_json::json!({ "output": "done" }),
            signed_by: None,
            signature: None,
        };
        wisp.sign_result(&mut result);
        crate::claim_order(&route, "tg-1", "wisp").unwrap();
        crate::submit_result(&route, &result).unwrap();

        // The worker approving its own work in josh's name: refused.
        assert!(crate::submit_review(&route, &verdict_for_josh(&wisp)).is_err());
        // The bridge, for josh, on an order only the master may approve: accepted.
        crate::submit_review(&route, &verdict_for_josh(&bridge)).unwrap();
        let task = crate::read_task(&route, "tg-1").unwrap();
        assert_eq!(task.state(), TaskState::Accepted);
        let review = &task.reviews[0];
        assert_eq!(
            label(
                &review.reviewer,
                review.signed_by.as_deref().unwrap_or_default()
            ),
            "josh via telegram-grouchly"
        );

        // Revoked: what it signed stops carrying josh's authority.
        revoke(&comms, "demo", &josh(), BRIDGE, "lost the phone").unwrap();
        assert!(crate::read_task(&route, "tg-1").unwrap().reviews.is_empty());
        assert_eq!(
            crate::verify_order_in(&route, &order),
            SignatureCheck::Invalid
        );
        assert!(crate::submit_review(&route, &verdict_for_josh(&bridge)).is_err());
    }

    #[test]
    fn a_review_only_delegation_cannot_issue_orders() {
        let dir = tempfile::tempdir().unwrap();
        let bridge = person(BRIDGE, 2);
        let comms = channel(dir.path(), &[&bridge]);
        let route = route_at(dir.path(), &comms);
        grant(&comms, "demo", &josh(), BRIDGE, &scopes(&["review"]), None).unwrap();
        assert_eq!(
            crate::verify_order_in(&route, &order_for_josh("tg-9", &bridge)),
            crate::SignatureCheck::Invalid
        );
    }
}

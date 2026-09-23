//! Who a machine identity belongs to.
//!
//! A person works from more than one machine. Each machine holds its own signing
//! key - that is the whole point, a key that never leaves the box it was made on -
//! so each machine necessarily signs under its own name: `josh-grouchly`,
//! `josh-beastly`. Without something tying those names together, every machine is
//! a stranger to the channel and the master has to grant each one separately,
//! reviewing a person they already reviewed.
//!
//! An owner attestation is that tie. It is a statement, signed by an identity the
//! channel already knows, that a named agent key belongs to them. It grants
//! nothing by itself: it only lets `master::is_granted` resolve a machine to the
//! person whose access was actually reviewed. Revoke the person and every machine
//! of theirs goes dark in the same moment, because the answer was never stored on
//! the machine.
//!
//! It lives beside the grants, in its own file per agent, for the same reason
//! grants do: the roster entry is written by whoever registers a key, and the
//! roster has 73 construction sites across this workspace. A separate signed file
//! cannot be widened by accident.

use std::{fs, path::PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature};

/// A signed statement that one agent key belongs to one person.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerAttestation {
    /// The machine identity being claimed, e.g. `josh-grouchly`.
    pub agent: String,
    /// That identity's Ed25519 public key, hex encoded. Bound here so the
    /// attestation dies if the name is ever re-keyed.
    pub agent_public_key: String,
    /// The established identity claiming it, e.g. `josh`.
    pub owner: String,
    pub attested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn owners_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("owners")
}

fn attestation_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    owners_dir(route).join(format!("{agent}.json"))
}

/// Exactly what an owner attestation signature covers.
fn owner_payload(attestation: &OwnerAttestation) -> String {
    format!(
        "ferryman-owner-v1\n{}\n{}\n{}\n{}",
        attestation.agent,
        attestation.agent_public_key,
        attestation.owner,
        attestation.attested_at.to_rfc3339(),
    )
}

/// Whether the roster publishes `name` with exactly `public_key`.
fn published_with_key(route: &ProjectRoute, name: &str, public_key: &str) -> bool {
    route.agents.iter().any(|agent| {
        agent.name.eq_ignore_ascii_case(name) && agent.public_key.as_deref() == Some(public_key)
    })
}

/// Claim a machine identity as your own.
///
/// Signed by the owner, not by the master: this is a claim about your own keys,
/// and a person adding their laptop should not have to wake the master. The claim
/// is worth exactly what the owner's own access is worth, and no more.
///
/// Refuses to re-point an existing attestation at a different owner. A machine
/// changing hands is a new key, not an edited file.
pub fn attest_owner(
    route: &ProjectRoute,
    owner: &AgentIdentity,
    agent: &str,
    agent_public_key: &str,
) -> Result<OwnerAttestation> {
    if !crate::is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier");
    }
    if agent.eq_ignore_ascii_case(owner.name()) {
        bail!("an identity cannot be its own machine");
    }
    if !published_with_key(route, owner.name(), &owner.public_key_hex()) {
        bail!(
            "{} is not published in this channel with the key that is signing; register the key first",
            owner.name()
        );
    }

    let path = attestation_path(route, agent);
    if path.is_file()
        && let Ok(existing) = serde_json::from_slice::<OwnerAttestation>(&fs::read(&path)?)
        && !existing.owner.eq_ignore_ascii_case(owner.name())
    {
        bail!("{agent} is already claimed by {}", existing.owner);
    }

    let mut attestation = OwnerAttestation {
        agent: agent.to_owned(),
        agent_public_key: agent_public_key.to_owned(),
        owner: owner.name().to_owned(),
        attested_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = owner.signing.sign(owner_payload(&attestation).as_bytes());
    attestation.signed_by = Some(owner.name().to_owned());
    attestation.signature = Some(hex::encode(signature.to_bytes()));

    fs::create_dir_all(owners_dir(route))?;
    crate::atomic_json(&path, &attestation)?;
    // Claiming a machine again is how an owner brings one back - the undo for a
    // sibling that pulled the switch, or for their own change of mind. It is not
    // the undo for the MASTER: if the master ended this agent, the owner asking
    // again does not settle it, and the file stays.
    let revocation = revocation_path(route, agent);
    if revocation.is_file()
        && let Ok(standing) = serde_json::from_slice::<OwnerRevocation>(&fs::read(&revocation)?)
        && !crate::master::read_master(route)?.is_some_and(|declaration| {
            standing
                .signed_by
                .as_deref()
                .is_some_and(|signer| declaration.master.eq_ignore_ascii_case(signer))
        })
    {
        let _ = fs::remove_file(&revocation);
    }
    Ok(attestation)
}

/// Who `agent` belongs to, if anyone provable.
///
/// Every failure here returns `None` rather than an error: an unverifiable
/// attestation is not a broken channel, it is a claim that does not count.
pub fn owner_of(route: &ProjectRoute, agent: &str) -> Result<Option<String>> {
    if !crate::is_safe_component(agent) {
        return Ok(None);
    }
    let path = attestation_path(route, agent);
    if !path.is_file() {
        return Ok(None);
    }
    let Ok(attestation) = serde_json::from_slice::<OwnerAttestation>(&fs::read(&path)?) else {
        return Ok(None);
    };
    // The file name is not evidence. A claim that names a different agent is a
    // claim about that agent, filed in the wrong place.
    if !attestation.agent.eq_ignore_ascii_case(agent) {
        return Ok(None);
    }
    // Only the owner may claim you. Anything else is someone writing a file that
    // says they own you, which is what this check exists to be worthless against.
    if attestation
        .signed_by
        .as_ref()
        .is_none_or(|signer| !signer.eq_ignore_ascii_case(&attestation.owner))
    {
        return Ok(None);
    }
    if check_signature(
        attestation.signed_by.as_ref(),
        attestation.signature.as_ref(),
        &owner_payload(&attestation),
        &route.agents,
    ) != SignatureCheck::Valid
    {
        return Ok(None);
    }
    // The attestation is about a key, not a name. If the name now publishes a
    // different key, whatever was claimed is not what is signing today.
    if !published_with_key(route, &attestation.agent, &attestation.agent_public_key) {
        return Ok(None);
    }
    Ok(Some(attestation.owner))
}

/// Every machine that provably belongs to `owner`.
pub fn owned_agents(route: &ProjectRoute, owner: &str) -> Result<Vec<String>> {
    let directory = owners_dir(route);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut agents = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !file.ends_with(".json") || file.ends_with(".revoked.json") {
            continue;
        }
        let Some(agent) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if owner_of(route, agent)?.is_some_and(|found| found.eq_ignore_ascii_case(owner)) {
            agents.push(agent.to_owned());
        }
    }
    agents.sort();
    Ok(agents)
}

/// A signed statement that a machine or agent is finished.
///
/// A tombstone and not a deletion. Deleting the claim would work on one machine
/// and then lose an argument with the next replica that still had it: on a synced
/// folder the only durable way to say "this is over" is to write something that
/// says so, signed, that reconciliation carries rather than resolves away.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRevocation {
    pub agent: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn revocation_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    owners_dir(route).join(format!("{agent}.revoked.json"))
}

fn revocation_payload(revocation: &OwnerRevocation) -> String {
    format!(
        "ferryman-owner-revoke-v1\n{}\n{}\n{}",
        revocation.agent,
        revocation.reason,
        revocation.revoked_at.to_rfc3339(),
    )
}

/// Whether `signer` is entitled to end `agent`.
///
/// Three answers, and the third is the one that matters in practice. The master,
/// obviously. The owner, obviously. And any OTHER machine of the same owner -
/// because a kill switch you can only reach from the machine you are trying to
/// kill is not a kill switch. A sibling can end a sibling and nothing else: it
/// cannot grant, cannot claim, cannot speak for the owner anywhere else. The
/// worst a stolen laptop can do with this is turn your other laptops off, which
/// you undo by claiming them again - and that is a better trade than a stolen
/// laptop that keeps working because you are not sitting at the right desk.
fn may_revoke(route: &ProjectRoute, signer: &str, agent: &str) -> Result<bool> {
    if crate::master::read_master(route)?
        .is_some_and(|declaration| declaration.master.eq_ignore_ascii_case(signer))
    {
        return Ok(true);
    }
    let Some(owner) = owner_of(route, agent)? else {
        return Ok(false);
    };
    if owner.eq_ignore_ascii_case(signer) {
        return Ok(true);
    }
    Ok(owner_of(route, signer)?.is_some_and(|theirs| theirs.eq_ignore_ascii_case(&owner)))
}

/// End a machine or agent, from any machine entitled to do it.
pub fn revoke_machine(
    route: &ProjectRoute,
    actor: &AgentIdentity,
    agent: &str,
    reason: &str,
) -> Result<OwnerRevocation> {
    if !crate::is_safe_component(agent) {
        bail!("agent name must be a path-safe identifier");
    }
    if agent.eq_ignore_ascii_case(actor.name()) {
        bail!("{agent} cannot revoke itself; do it from another machine");
    }
    if !may_revoke(route, actor.name(), agent)? {
        bail!(
            "{} is not {agent}'s owner, one of their machines, or this project's master",
            actor.name()
        );
    }
    let mut revocation = OwnerRevocation {
        agent: agent.to_owned(),
        reason: reason.to_owned(),
        revoked_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = actor
        .signing
        .sign(revocation_payload(&revocation).as_bytes());
    revocation.signed_by = Some(actor.name().to_owned());
    revocation.signature = Some(hex::encode(signature.to_bytes()));
    fs::create_dir_all(owners_dir(route))?;
    crate::atomic_json(&revocation_path(route, agent), &revocation)?;
    Ok(revocation)
}

/// Whether a valid revocation stands against `agent`.
///
/// Checked at read time rather than trusted from the file, because the file is on
/// a folder anyone in the project can write to. A revocation nobody entitled to
/// write it signed is somebody's opinion.
pub fn is_revoked(route: &ProjectRoute, agent: &str) -> Result<bool> {
    if !crate::is_safe_component(agent) {
        return Ok(false);
    }
    let path = revocation_path(route, agent);
    if !path.is_file() {
        return Ok(false);
    }
    let Ok(revocation) = serde_json::from_slice::<OwnerRevocation>(&fs::read(&path)?) else {
        return Ok(false);
    };
    if !revocation.agent.eq_ignore_ascii_case(agent) {
        return Ok(false);
    }
    if check_signature(
        revocation.signed_by.as_ref(),
        revocation.signature.as_ref(),
        &revocation_payload(&revocation),
        &route.agents,
    ) != SignatureCheck::Valid
    {
        return Ok(false);
    }
    let Some(signer) = revocation.signed_by.as_deref() else {
        return Ok(false);
    };
    may_revoke(route, signer, agent)
}

/// Every revocation standing on this project, newest first.
pub fn revocations(route: &ProjectRoute) -> Result<Vec<OwnerRevocation>> {
    let directory = owners_dir(route);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(agent) = name.strip_suffix(".revoked.json") else {
            continue;
        };
        if is_revoked(route, agent)? {
            out.push(serde_json::from_slice(&fs::read(&path)?)?);
        }
    }
    out.sort_by_key(|revocation: &OwnerRevocation| std::cmp::Reverse(revocation.revoked_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        std::fs::create_dir_all(&communications).unwrap();
        ProjectRoute {
            project_id: "hone".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "hone-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn roster(identity: &AgentIdentity) -> AgentRoute {
        AgentRoute {
            name: identity.name().to_owned(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }
    }

    #[test]
    fn an_owner_claims_their_own_machine() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        route.agents = vec![roster(&josh), roster(&grouchly)];

        attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex()).unwrap();

        assert_eq!(
            owner_of(&route, "josh-grouchly").unwrap().as_deref(),
            Some("josh")
        );
        assert_eq!(owned_agents(&route, "josh").unwrap(), vec!["josh-grouchly"]);
    }

    /// The failure that matters: anyone with the synced folder can write a file.
    ///
    /// A file is not a claim. Only a signature by the identity being claimed *as*
    /// counts, so a machine that writes its own paperwork owns nothing - including
    /// paperwork that names someone else as the signer and hopes nobody checks.
    #[test]
    fn writing_the_file_yourself_does_not_make_you_owned() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);
        route.agents = vec![roster(&josh), roster(&mallory)];
        fs::create_dir_all(owners_dir(&route)).unwrap();

        // Mallory signs honestly, under her own name, that josh owns her.
        let mut honest = OwnerAttestation {
            agent: "mallory".into(),
            agent_public_key: mallory.public_key_hex(),
            owner: "josh".into(),
            attested_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        let signature = mallory.signing.sign(owner_payload(&honest).as_bytes());
        honest.signed_by = Some("mallory".into());
        honest.signature = Some(hex::encode(signature.to_bytes()));
        crate::atomic_json(&attestation_path(&route, "mallory"), &honest).unwrap();
        assert_eq!(
            owner_of(&route, "mallory").unwrap(),
            None,
            "the owner must be the signer; a claim about josh signed by mallory is mallory's opinion"
        );

        // So she puts josh's name in the signer field instead.
        let mut forged = honest.clone();
        forged.signed_by = Some("josh".into());
        crate::atomic_json(&attestation_path(&route, "mallory"), &forged).unwrap();
        assert_eq!(
            owner_of(&route, "mallory").unwrap(),
            None,
            "the signature is checked against josh's published key, not against the name"
        );
    }

    /// The claim is about a key. Re-key the name and the claim is about nothing.
    #[test]
    fn a_machine_that_changes_its_key_loses_the_claim() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        route.agents = vec![roster(&josh), roster(&grouchly)];
        attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex()).unwrap();

        let replacement = AgentIdentity::from_seed("josh-grouchly", [3u8; 32]);
        route.agents = vec![roster(&josh), roster(&replacement)];
        assert_eq!(owner_of(&route, "josh-grouchly").unwrap(), None);
    }

    #[test]
    fn a_claimed_machine_cannot_be_re_pointed_at_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        route.agents = vec![roster(&josh), roster(&mallory), roster(&grouchly)];
        attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex()).unwrap();

        let error = attest_owner(
            &route,
            &mallory,
            "josh-grouchly",
            &grouchly.public_key_hex(),
        )
        .expect_err("mallory must not be able to adopt josh's machine")
        .to_string();
        assert!(error.contains("already claimed by josh"), "{error}");
    }

    /// Two machines of one person, and a master who is somebody else entirely.
    fn two_machines(
        dir: &std::path::Path,
    ) -> (ProjectRoute, AgentIdentity, AgentIdentity, AgentIdentity) {
        let mut route = test_route(dir);
        let ada = AgentIdentity::from_seed("ada", [7u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        let beastly = AgentIdentity::from_seed("josh-beastly", [3u8; 32]);
        route.agents = vec![
            roster(&ada),
            roster(&josh),
            roster(&grouchly),
            roster(&beastly),
        ];
        crate::master::initialize_master(&route, &ada, "ada").unwrap();
        attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex()).unwrap();
        attest_owner(&route, &josh, "josh-beastly", &beastly.public_key_hex()).unwrap();
        (route, josh, grouchly, beastly)
    }

    /// The point of the whole thing: the laptop still on the desk kills the one
    /// that walked off, without the owner's key and without the master.
    #[test]
    fn a_machine_can_end_its_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let (route, _josh, grouchly, _beastly) = two_machines(dir.path());

        revoke_machine(&route, &grouchly, "josh-beastly", "left in a taxi").unwrap();

        assert!(is_revoked(&route, "josh-beastly").unwrap());
        assert!(
            !is_revoked(&route, "josh-grouchly").unwrap(),
            "ending one machine must not end the one that did it"
        );
    }

    #[test]
    fn an_owner_ends_their_own_machine_from_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, _grouchly, _beastly) = two_machines(dir.path());

        revoke_machine(&route, &josh, "josh-beastly", "sold it").unwrap();
        assert!(is_revoked(&route, "josh-beastly").unwrap());
    }

    /// A stranger's machine is not yours to end, whatever file you write.
    #[test]
    fn somebody_elses_machine_is_not_yours_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let ada = AgentIdentity::from_seed("ada", [7u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);
        route.agents = vec![
            roster(&ada),
            roster(&josh),
            roster(&grouchly),
            roster(&mallory),
        ];
        crate::master::initialize_master(&route, &ada, "ada").unwrap();
        attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex()).unwrap();

        let error = revoke_machine(&route, &mallory, "josh-grouchly", "because")
            .expect_err("mallory owns nothing of josh's")
            .to_string();
        assert!(error.contains("is not"), "{error}");

        // And writing the file by hand gets her no further: entitlement is checked
        // when the revocation is READ, not when it is written.
        let mut forged = OwnerRevocation {
            agent: "josh-grouchly".into(),
            reason: "because".into(),
            revoked_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        let signature = mallory.signing.sign(revocation_payload(&forged).as_bytes());
        forged.signed_by = Some("mallory".into());
        forged.signature = Some(hex::encode(signature.to_bytes()));
        fs::create_dir_all(owners_dir(&route)).unwrap();
        crate::atomic_json(&revocation_path(&route, "josh-grouchly"), &forged).unwrap();
        assert!(!is_revoked(&route, "josh-grouchly").unwrap());
    }

    #[test]
    fn claiming_a_machine_again_brings_it_back_unless_the_master_ended_it() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, grouchly, beastly) = two_machines(dir.path());
        let ada = AgentIdentity::from_seed("ada", [7u8; 32]);

        // A sibling pulled the switch; the owner disagrees and claims it again.
        revoke_machine(&route, &grouchly, "josh-beastly", "thought it was lost").unwrap();
        attest_owner(&route, &josh, "josh-beastly", &beastly.public_key_hex()).unwrap();
        assert!(!is_revoked(&route, "josh-beastly").unwrap());

        // The master's word is not the owner's to overturn.
        revoke_machine(&route, &ada, "josh-beastly", "off the project").unwrap();
        attest_owner(&route, &josh, "josh-beastly", &beastly.public_key_hex()).unwrap();
        assert!(
            is_revoked(&route, "josh-beastly").unwrap(),
            "re-claiming must not undo the master"
        );
    }

    #[test]
    fn a_machine_cannot_revoke_itself() {
        let dir = tempfile::tempdir().unwrap();
        let (route, _josh, grouchly, _beastly) = two_machines(dir.path());
        let error = revoke_machine(&route, &grouchly, "josh-grouchly", "oops")
            .expect_err("a compromised machine must not be able to cover its tracks")
            .to_string();
        assert!(error.contains("cannot revoke itself"), "{error}");
    }

    #[test]
    fn an_unpublished_owner_cannot_attest() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        // Josh's key is not in the roster, so nobody could verify what he signs.
        route.agents = vec![roster(&grouchly)];

        let error = attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex())
            .expect_err("an unverifiable attestation must not be written")
            .to_string();
        assert!(error.contains("register the key first"), "{error}");
    }
}

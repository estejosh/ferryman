//! The project master: the root of trust for a team's shared channel.
//!
//! A team agent touches three folders: the work repository, the shared channel
//! (`<project>-ferryman`), and the master folder (`<project>-master-ferryman`).
//! The master folder holds a signed declaration of who the master is and is
//! synced only to the master's own devices, so its records survive even if the
//! shared channel is wiped.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, check_signature};

/// The canonical Syncthing folder ID for a project's master folder.
///
/// The `-ferryman` suffix is the marker that identifies a folder as ours, so
/// the master folder keeps it: `<project>-master-ferryman`.
pub fn master_folder_name(project_id: &str) -> String {
    format!("{project_id}-master-ferryman")
}

/// A signed declaration of who is this project's master.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterDeclaration {
    pub project_id: String,
    /// The master's name (an agent or operator name).
    pub master: String,
    /// The Syncthing folder ID this declaration is meant to live in.
    pub folder: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn declaration_path(route: &ProjectRoute) -> PathBuf {
    // The declaration is public: it lives in the shared channel so every member
    // can see and verify who the master is. The master's *private* records
    // (grants, checkpoints) belong in the master-only folder (`master_dir`).
    route.communications.join("master.json")
}

/// Exactly what a master declaration signature covers.
fn master_payload(declaration: &MasterDeclaration) -> String {
    format!(
        "ferryman-master-v1\n{}\n{}\n{}\n{}",
        declaration.project_id,
        declaration.master,
        declaration.folder,
        declaration.created_at.to_rfc3339(),
    )
}

/// Choose to be this project's master: write a signed declaration into the
/// master folder. Refuses to overwrite a different master's declaration.
pub fn initialize_master(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    master: &str,
) -> Result<MasterDeclaration> {
    if !crate::is_safe_component(master) {
        bail!("master name must be a path-safe identifier");
    }
    let path = declaration_path(route);
    if path.is_file() {
        let existing: MasterDeclaration = serde_json::from_slice(&fs::read(&path)?)
            .context("read existing master declaration")?;
        if existing.master != master {
            bail!(
                "project {} already has a master ({})",
                route.project_id,
                existing.master
            );
        }
        return Ok(existing);
    }

    let mut declaration = MasterDeclaration {
        project_id: route.project_id.clone(),
        master: master.to_owned(),
        folder: master_folder_name(&route.project_id),
        created_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = identity
        .signing
        .sign(master_payload(&declaration).as_bytes());
    declaration.signed_by = Some(identity.name().to_owned());
    declaration.signature = Some(hex::encode(signature.to_bytes()));

    let directory = route.master_dir();
    fs::create_dir_all(&directory)?;
    crate::atomic_json(&path, &declaration)?;
    Ok(declaration)
}

/// Read and verify the master declaration, if one exists.
pub fn read_master(route: &ProjectRoute) -> Result<Option<MasterDeclaration>> {
    let path = declaration_path(route);
    if !path.is_file() {
        return Ok(None);
    }
    let declaration: MasterDeclaration =
        serde_json::from_slice(&fs::read(&path)?).context("parse master declaration")?;
    if check_signature(
        declaration.signed_by.as_ref(),
        declaration.signature.as_ref(),
        &master_payload(&declaration),
        &route.agents,
    ) != SignatureCheck::Valid
    {
        bail!("master declaration signature does not verify");
    }
    if declaration.project_id != route.project_id {
        bail!("master declaration is for a different project");
    }
    Ok(Some(declaration))
}

/// Transfer the master role to another user. Signed by the current master.
///
/// The chain of authority stays verifiable: the new declaration names the new
/// master but is signed by the key of the master it replaces, so anyone can see
/// the role was disclaimed, not seized.
pub fn transfer_master(
    route: &ProjectRoute,
    current: &AgentIdentity,
    new_master: &str,
) -> Result<MasterDeclaration> {
    if !crate::is_safe_component(new_master) {
        bail!("new master name must be a path-safe identifier");
    }
    let Some(existing) = read_master(route)? else {
        bail!("this project has no master yet; run 'ferry enable' first");
    };
    if existing.master != current.name() {
        bail!(
            "only the current master ({}) may transfer the role",
            existing.master
        );
    }
    // The KEY must be the master's key, not merely a key wearing the master's name.
    //
    // Defence in depth for a hole that was reproduced: the CLI used to resolve the current
    // master's identity with `load_or_create`, so a peer holding only the synced folder minted
    // a key under the master's name and transferred the role to itself. The name check above
    // passed, because the forged key was called the right thing. That call site now refuses,
    // but a name comparison is the wrong check to leave standing behind it - it authorises on
    // a string that the caller chose.
    //
    // Comparing against the key the declaration was actually signed with means a forged key
    // fails here even if some future caller hands one over.
    // `read_master` has already established that the declaration verifies against the roster,
    // so re-checking it against ONLY this caller's key answers a different question: is this
    // the same key? A roster of one.
    let offered = AgentRoute {
        name: current.name().to_owned(),
        role: "master".to_owned(),
        capabilities: Vec::new(),
        public_key: Some(current.public_key_hex()),
    };
    if check_signature(
        existing.signed_by.as_ref(),
        existing.signature.as_ref(),
        &master_payload(&existing),
        std::slice::from_ref(&offered),
    ) != SignatureCheck::Valid
    {
        bail!(
            "the key offered for '{}' is not the key that signed the current master \
             declaration, so this machine does not hold the role it is trying to transfer",
            existing.master
        );
    }

    let mut declaration = MasterDeclaration {
        project_id: route.project_id.clone(),
        master: new_master.to_owned(),
        folder: master_folder_name(&route.project_id),
        created_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = current
        .signing
        .sign(master_payload(&declaration).as_bytes());
    declaration.signed_by = Some(current.name().to_owned());
    declaration.signature = Some(hex::encode(signature.to_bytes()));
    crate::atomic_json(&declaration_path(route), &declaration)?;
    Ok(declaration)
}

/// A master-signed grant of roles/capabilities to one member.
///
/// This is the authority model: the master signs what a member may do, and every
/// member can verify that signature against the master's published key. It is
/// separate from the declaration (who *is* master) and from the trust store
/// (which keys are recognised): a grant says what *this* member may do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterGrant {
    /// The member's name (an agent or operator name).
    pub grantee: String,
    /// The member's Ed25519 public key, hex encoded.
    pub public_key: String,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn grants_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("grants")
}

fn grant_path(route: &ProjectRoute, grantee: &str) -> PathBuf {
    grants_dir(route).join(format!("{grantee}.json"))
}

/// Exactly what a grant signature covers.
fn grant_payload(grant: &MasterGrant) -> String {
    format!(
        "ferryman-master-grant-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        grant.grantee,
        grant.public_key,
        grant.projects.join(","),
        grant.roles.join(","),
        grant.capabilities.join(","),
        grant.granted_at.to_rfc3339(),
    )
}

/// The master's roster entry, if the master is declared and in the roster.
fn master_agent(route: &ProjectRoute) -> Result<Option<AgentRoute>> {
    let Some(declaration) = read_master(route)? else {
        return Ok(None);
    };
    Ok(route
        .agents
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(&declaration.master))
        .cloned())
}

/// Grant roles/capabilities to a member, signed by the master.
pub fn grant_member(
    route: &ProjectRoute,
    master: &AgentIdentity,
    grantee: &str,
    public_key: &str,
    projects: Vec<String>,
    roles: Vec<String>,
    capabilities: Vec<String>,
) -> Result<MasterGrant> {
    if !crate::is_safe_component(grantee) {
        bail!("grantee name must be a path-safe identifier");
    }
    let Some(declaration) = read_master(route)? else {
        bail!("this project has no master yet");
    };
    if declaration.master != master.name() {
        bail!("only the master ({}) may grant roles", declaration.master);
    }

    let mut grant = MasterGrant {
        grantee: grantee.to_owned(),
        public_key: public_key.to_owned(),
        projects,
        roles,
        capabilities,
        granted_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = master.signing.sign(grant_payload(&grant).as_bytes());
    grant.signed_by = Some(master.name().to_owned());
    grant.signature = Some(hex::encode(signature.to_bytes()));

    let directory = grants_dir(route);
    fs::create_dir_all(&directory)?;
    crate::atomic_json(&grant_path(route, grantee), &grant)?;
    Ok(grant)
}

/// Every grant in the channel, each with its verification status against the
/// master's published key.
pub fn member_grants(route: &ProjectRoute) -> Result<Vec<(MasterGrant, SignatureCheck)>> {
    let directory = grants_dir(route);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let master = master_agent(route)?;
    let mut grants = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(grant) = serde_json::from_str::<MasterGrant>(&fs::read_to_string(&path)?) else {
            continue;
        };
        let check = match &master {
            Some(master) => check_signature(
                grant.signed_by.as_ref(),
                grant.signature.as_ref(),
                &grant_payload(&grant),
                std::slice::from_ref(master),
            ),
            None => SignatureCheck::UnknownSigner,
        };
        grants.push((grant, check));
    }
    grants.sort_by(|a, b| a.0.grantee.cmp(&b.0.grantee));
    Ok(grants)
}

/// Whether `grantee` holds a valid master-signed grant for `role` on this
/// project. In team mode this is the gate that decides who may act.
pub fn is_granted(route: &ProjectRoute, grantee: &str, role: &str) -> Result<bool> {
    for (grant, check) in member_grants(route)? {
        if grant.grantee == grantee
            && check == SignatureCheck::Valid
            && (grant.roles.is_empty() || grant.roles.iter().any(|r| r == role))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::AgentRoute;

    fn test_route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
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

    /// A key that merely has the master's NAME cannot transfer the role.
    ///
    /// This was reproduced end to end during review: a peer holding only the synced folder
    /// minted a key under the master's name (the CLI used `load_or_create`), transferred the
    /// role to itself, and left every machine unable to verify anything master-signed with no
    /// way back. The CLI now refuses to mint the key; this is the check behind that one, so a
    /// forged key fails even if some future caller hands one over.
    #[test]
    fn a_forged_key_wearing_the_masters_name_cannot_transfer_the_role() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());

        let alice = AgentIdentity::from_seed("alice", [1u8; 32]);
        // Same NAME, different key - exactly what minting on demand produces.
        let forged_alice = AgentIdentity::from_seed("alice", [2u8; 32]);
        assert_ne!(alice.public_key_hex(), forged_alice.public_key_hex());

        // The roster carries alice's real key, so the declaration verifies for everyone.
        route.agents = vec![AgentRoute {
            name: "alice".into(),
            role: "master".into(),
            capabilities: Vec::new(),
            public_key: Some(alice.public_key_hex()),
        }];
        initialize_master(&route, &alice, "alice").unwrap();

        let error = transfer_master(&route, &forged_alice, "bob")
            .expect_err("a key that is not alice's must not transfer alice's role")
            .to_string();
        assert!(
            error.contains("not the key that signed"),
            "the refusal must say it is the wrong key, not the wrong name: {error}"
        );

        // The real master can still do it, so this is a check and not a wall.
        let moved = transfer_master(&route, &alice, "bob").unwrap();
        assert_eq!(moved.master, "bob");
    }

    #[test]
    fn master_folder_name_keeps_the_ferryman_suffix() {
        assert_eq!(master_folder_name("hone"), "hone-master-ferryman");
        assert_eq!(master_folder_name("ferryman"), "ferryman-master-ferryman");
    }

    #[test]
    fn initialize_then_read_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let identity = AgentIdentity::load_or_create_in("johnny", &route.attachment, None).unwrap();
        route.agents = vec![AgentRoute {
            name: "johnny".into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(identity.public_key_hex()),
        }];

        let declaration = initialize_master(&route, &identity, "johnny").unwrap();
        assert_eq!(declaration.master, "johnny");
        assert_eq!(declaration.folder, "hone-master-ferryman");

        let read = read_master(&route).unwrap().expect("declaration");
        assert_eq!(read.master, "johnny");

        // A second, different master is refused.
        let mallory = AgentIdentity::load_or_create_in("mallory", &route.attachment, None).unwrap();
        assert!(initialize_master(&route, &mallory, "mallory").is_err());
    }

    #[test]
    fn a_tampered_declaration_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let identity = AgentIdentity::load_or_create_in("johnny", &route.attachment, None).unwrap();
        route.agents = vec![AgentRoute {
            name: "johnny".into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(identity.public_key_hex()),
        }];

        initialize_master(&route, &identity, "johnny").unwrap();

        // Rewrite the declaration with a different master; the signature no
        // longer matches.
        let path = route.communications.join("master.json");
        let mut declaration: MasterDeclaration =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        declaration.master = "mallory".into();
        fs::write(&path, serde_json::to_vec_pretty(&declaration).unwrap()).unwrap();

        assert!(read_master(&route).is_err());
    }

    #[test]
    fn master_may_disclaim_to_another() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let johnny = AgentIdentity::load_or_create_in("johnny", &route.attachment, None).unwrap();
        route.agents = vec![AgentRoute {
            name: "johnny".into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(johnny.public_key_hex()),
        }];

        initialize_master(&route, &johnny, "johnny").unwrap();

        let transferred = transfer_master(&route, &johnny, "bob").unwrap();
        assert_eq!(transferred.master, "bob");
        assert_eq!(transferred.signed_by.as_deref(), Some("johnny"));

        let read = read_master(&route).unwrap().expect("declaration");
        assert_eq!(read.master, "bob");

        // A non-master cannot transfer.
        let mallory = AgentIdentity::load_or_create_in("mallory", &route.attachment, None).unwrap();
        assert!(transfer_master(&route, &mallory, "carol").is_err());
    }

    #[test]
    fn master_grants_roles_to_a_member() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let johnny = AgentIdentity::load_or_create_in("johnny", &route.attachment, None).unwrap();
        let bob = AgentIdentity::load_or_create_in("bob", &route.attachment, None).unwrap();
        route.agents = vec![
            AgentRoute {
                name: "johnny".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(johnny.public_key_hex()),
            },
            AgentRoute {
                name: "bob".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(bob.public_key_hex()),
            },
        ];

        initialize_master(&route, &johnny, "johnny").unwrap();
        grant_member(
            &route,
            &johnny,
            "bob",
            &bob.public_key_hex(),
            vec!["hone".into()],
            vec!["worker".into()],
            vec!["code".into()],
        )
        .unwrap();

        assert!(is_granted(&route, "bob", "worker").unwrap());
        assert!(!is_granted(&route, "bob", "orchestrator").unwrap());
        assert!(!is_granted(&route, "carol", "worker").unwrap());

        // A non-master cannot grant.
        let mallory = AgentIdentity::load_or_create_in("mallory", &route.attachment, None).unwrap();
        assert!(
            grant_member(
                &route,
                &mallory,
                "carol",
                &mallory.public_key_hex(),
                vec![],
                vec![],
                vec![],
            )
            .is_err()
        );
    }
}

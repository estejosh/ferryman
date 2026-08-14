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

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature};

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
}

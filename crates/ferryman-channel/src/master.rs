//! The project master: the root of trust for a team's shared channel.
//!
//! A team agent touches three folders: the work repository, the shared channel
//! (`<project>-ferryman`), and the master folder (`<project>-master-ferryman`).
//! The master folder holds a signed declaration of who the master is and is
//! synced only to the master's own devices, so its records survive even if the
//! shared channel is wiped.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use crate::{
    AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, canonical_agent_name, check_signature,
    questions,
};

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
    declare_master(route, identity, master, true)
}

/// `initialize_master`, optionally without making the local master folder.
///
/// A claim made across a whole ferry root reaches channels that have no repository on
/// this machine, where the "attachment" is only the directory the channel sits in; making
/// a `master` folder there left an empty directory among the channels.
fn declare_master(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    master: &str,
    make_master_folder: bool,
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

    if make_master_folder {
        fs::create_dir_all(route.master_dir())?;
    }
    crate::atomic_json(&path, &declaration)?;
    Ok(declaration)
}

/// Read and verify the master declaration, if one exists.
pub fn read_master(route: &ProjectRoute) -> Result<Option<MasterDeclaration>> {
    let Some(declaration) = read_master_at(&route.communications, &route.agents)? else {
        return Ok(None);
    };
    if declaration.project_id != route.project_id {
        bail!("master declaration is for a different project");
    }
    Ok(Some(declaration))
}

/// Read and verify the declaration in a channel directory, against a roster.
///
/// For a caller holding a channel but no route: a machine that syncs a project it does
/// not work in still needs to know who that project's master is.
pub fn read_master_at(
    communications: &Path,
    roster: &[AgentRoute],
) -> Result<Option<MasterDeclaration>> {
    let path = communications.join("master.json");
    if !path.is_file() {
        return Ok(None);
    }
    let declaration: MasterDeclaration =
        serde_json::from_slice(&fs::read(&path)?).context("parse master declaration")?;
    if check_signature(
        declaration.signed_by.as_ref(),
        declaration.signature.as_ref(),
        &master_payload(&declaration),
        roster,
    ) != SignatureCheck::Valid
    {
        bail!("master declaration signature does not verify");
    }
    Ok(Some(declaration))
}

/// What claiming a channel's master role did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The person is now the master.
    Declared,
    /// They already were. Nothing written.
    AlreadyTheirs,
    /// Someone else is master. Nothing written: a master is handed over, never taken.
    Other(String),
    /// The channel knows this name by a different key. Nothing written - a declaration
    /// signed by a key the fleet does not know this name by is one no peer would accept.
    KeyConflict,
}

/// Declare `person` master of the project in `channel`, if it has none.
///
/// For a channel enabled while a person was present: `enable` will not make the machine
/// master and cannot sign as the person, so it left the role empty, and nothing came
/// back for it. This fills it, signed by the person, and first puts their public key on
/// the channel's roster so every peer can verify the declaration. Both files are in the
/// channel, so Syncthing carries them to every machine.
pub fn claim_if_masterless(
    channel: &Path,
    project_id: &str,
    attachment: &Path,
    person: &AgentIdentity,
) -> Result<Claim> {
    let roster = crate::read_agent_roster(channel)?;
    // Decided before anything is written: a project someone else masters gets nothing
    // from this, not even a roster entry.
    if let Some(declaration) = read_master_at(channel, &roster)? {
        return Ok(if declaration.master.eq_ignore_ascii_case(person.name()) {
            Claim::AlreadyTheirs
        } else {
            Claim::Other(declaration.master)
        });
    }
    let key = person.public_key_hex();
    let mut route = ProjectRoute {
        project_id: project_id.to_owned(),
        workspace: attachment.parent().unwrap_or(attachment).to_path_buf(),
        attachment: attachment.to_path_buf(),
        communications: channel.to_path_buf(),
        shared_remote: format!("{project_id}-ferryman"),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: Vec::new(),
    };
    let listing = channel.join("agents").join(format!(
        "{}.json",
        crate::canonical_agent_name(person.name())
    ));
    let listed: Option<AgentRoute> = if listing.is_file() {
        Some(serde_json::from_slice(&fs::read(&listing)?).context("parse roster entry")?)
    } else {
        None
    };
    match listed
        .as_ref()
        .and_then(|agent| agent.public_key.as_deref())
    {
        Some(existing) if existing != key => return Ok(Claim::KeyConflict),
        Some(_) => {}
        // Absent, or reserved without a key: publish it, keeping any role it was given.
        None => {
            let agent = AgentRoute {
                public_key: Some(key.clone()),
                ..listed.unwrap_or_else(|| AgentRoute {
                    name: person.name().to_owned(),
                    role: "operator".into(),
                    capabilities: Vec::new(),
                    public_key: None,
                    encryption_key: None,
                })
            };
            crate::register_agent(&route, &agent)?;
        }
    }
    // Read back through the pins: if this machine has pinned another key for the name,
    // that is the key every check here uses, and a declaration would not verify.
    route.agents = crate::read_agent_roster(channel)?;
    let known = route
        .agents
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(person.name()))
        .and_then(|agent| agent.public_key.clone());
    if known.as_deref() != Some(key.as_str()) {
        return Ok(Claim::KeyConflict);
    }
    declare_master(&route, person, person.name(), false)?;
    Ok(Claim::Declared)
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
        encryption_key: None,
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
    /// When the access this grant gives ends, if it was given for a time. `None` is the
    /// grant every project has always had: it lasts until someone revokes it. Signed (see
    /// [`grant_payload`]), so an edited date no longer verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
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
    let base = format!(
        "ferryman-master-grant-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        grant.grantee,
        grant.public_key,
        grant.projects.join(","),
        grant.roles.join(","),
        grant.capabilities.join(","),
        grant.granted_at.to_rfc3339(),
    );
    // Appended only when the grant ends, so every grant written before the field existed
    // signs over exactly the bytes it was signed over (the same trick as an invite's
    // `owner`). Without it an edited date would verify; with it unconditionally, every
    // existing grant on every channel would stop verifying.
    match grant.expires_at {
        Some(at) => format!("{base}\nexpires:{}", at.to_rfc3339()),
        None => base,
    }
}

/// The master's roster entry, if the master is declared and in the roster.
pub(crate) fn master_agent(route: &ProjectRoute) -> Result<Option<AgentRoute>> {
    let Some(declaration) = read_master(route)? else {
        return Ok(None);
    };
    Ok(route
        .agents
        .iter()
        // Case-insensitive against the DECLARATION, which is stored data: a
        // master declared before names were folded names itself however it was
        // typed, and losing the master over capitalisation would take the
        // channel's root of trust with it.
        .find(|agent| agent.name.eq_ignore_ascii_case(&declaration.master))
        .cloned())
}

/// Grant roles/capabilities to a member, signed by the master. The grant lasts until it is
/// revoked; [`grant_member_until`] is the one that ends.
pub fn grant_member(
    route: &ProjectRoute,
    master: &AgentIdentity,
    grantee: &str,
    public_key: &str,
    projects: Vec<String>,
    roles: Vec<String>,
    capabilities: Vec<String>,
) -> Result<MasterGrant> {
    grant_member_until(
        route,
        master,
        grantee,
        public_key,
        projects,
        roles,
        capabilities,
        None,
    )
}

/// [`grant_member`], for access that ends on `expires_at` unless the master renews it.
///
/// A re-grant replaces the file, as it always has, so granting again starts a fresh term:
/// it carries a new `granted_at`, which is also what stops an old renewal answer from
/// extending it (see [`access_ends`]).
#[allow(clippy::too_many_arguments)]
pub fn grant_member_until(
    route: &ProjectRoute,
    master: &AgentIdentity,
    grantee: &str,
    public_key: &str,
    projects: Vec<String>,
    roles: Vec<String>,
    capabilities: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<MasterGrant> {
    write_grant(
        route,
        master,
        grantee,
        public_key,
        projects,
        roles,
        capabilities,
        Utc::now(),
        expires_at,
    )
}

/// The one place a grant is signed and written. `granted_at` is a parameter only so the
/// tests can build a grant whose term is already over.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_grant(
    route: &ProjectRoute,
    master: &AgentIdentity,
    grantee: &str,
    public_key: &str,
    projects: Vec<String>,
    roles: Vec<String>,
    capabilities: Vec<String>,
    granted_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
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
    // A master whose git anchor has stopped verifying may not hand out anything new
    // (ADR 0022). They keep the role and may still transfer it; what they lose is
    // the power to widen access on a project that may no longer be theirs.
    crate::anchor::refuse_if_paused(route, &declaration.master, "grant new access")?;

    if expires_at.is_some_and(|at| at <= granted_at) {
        bail!("access has to end after it starts");
    }
    let mut grant = MasterGrant {
        grantee: grantee.to_owned(),
        public_key: public_key.to_owned(),
        projects,
        roles,
        capabilities,
        granted_at,
        expires_at,
        signed_by: None,
        signature: None,
    };
    let signature = master.signing.sign(grant_payload(&grant).as_bytes());
    grant.signed_by = Some(master.name().to_owned());
    grant.signature = Some(hex::encode(signature.to_bytes()));

    let directory = grants_dir(route);
    fs::create_dir_all(&directory)?;
    crate::atomic_json(&grant_path(route, grantee), &grant)?;
    // A fresh grant after a revocation means the master changed their mind; the
    // revocation file must not outlive the decision it recorded.
    let _ = fs::remove_file(revocation_path(route, grantee));
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

/// The canonical names of the agents the master has admitted to the channel: those with a
/// `grants/<name>.json` that verifies as the master's and has no valid revocation beside
/// it. The roster itself is unsigned and trusted on first use, so being on it admits nobody.
#[must_use]
pub fn admitted_at(
    communications: &Path,
    roster: &[AgentRoute],
) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let Ok(Some(declaration)) = read_master_at(communications, roster) else {
        return out;
    };
    let Some(master) = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(&declaration.master))
    else {
        return out;
    };
    let Ok(entries) = fs::read_dir(communications.join("grants")) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Some(grant) = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<MasterGrant>(&text).ok())
        else {
            continue;
        };
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !stem.eq_ignore_ascii_case(&grant.grantee) {
            continue;
        }
        let valid = check_signature(
            grant.signed_by.as_ref(),
            grant.signature.as_ref(),
            &grant_payload(&grant),
            std::slice::from_ref(master),
        ) == SignatureCheck::Valid;
        if valid && !is_revoked_in(communications, roster, &grant.grantee) {
            out.insert(grant.grantee.to_ascii_lowercase());
        }
    }
    out
}

/// A master-signed statement that a member's access has ended.
///
/// Kept beside the grant rather than deleting it: the history should say who had
/// access, who ended it, and why. A grant with a valid revocation beside it confers
/// nothing, whatever it says.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterRevocation {
    pub grantee: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn revocation_path(route: &ProjectRoute, grantee: &str) -> PathBuf {
    grants_dir(route).join(format!("{grantee}.revoked.json"))
}

fn revocation_payload(revocation: &MasterRevocation) -> String {
    format!(
        "ferryman-master-revoke-v1\n{}\n{}\n{}",
        revocation.grantee,
        revocation.reason,
        revocation.revoked_at.to_rfc3339(),
    )
}

/// End a member's access. Signed by the master; refuses anyone else.
pub fn revoke_member(
    route: &ProjectRoute,
    master: &AgentIdentity,
    grantee: &str,
    reason: &str,
) -> Result<MasterRevocation> {
    if !crate::is_safe_component(grantee) {
        bail!("grantee name must be a path-safe identifier");
    }
    let Some(declaration) = read_master(route)? else {
        bail!("this project has no master yet");
    };
    if !declaration.master.eq_ignore_ascii_case(master.name()) {
        bail!("only the master ({}) may revoke access", declaration.master);
    }
    let mut revocation = MasterRevocation {
        grantee: grantee.to_owned(),
        reason: reason.to_owned(),
        revoked_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = master
        .signing
        .sign(revocation_payload(&revocation).as_bytes());
    revocation.signed_by = Some(master.name().to_owned());
    revocation.signature = Some(hex::encode(signature.to_bytes()));
    fs::create_dir_all(grants_dir(route))?;
    crate::atomic_json(&revocation_path(route, grantee), &revocation)?;
    Ok(revocation)
}

/// Whether `grantee` has no access here any more: the master revoked it, or access that
/// was given for a time has run out unrenewed.
///
/// Lapsing is treated as revoking on purpose. Everything that already asks this question
/// (the gate, a worker taking work, the iroh lane's admission, a delegate's standing, the
/// doctor) then stops a lapsed person without each learning about expiry. A grant with no
/// `expires_at` is exactly as before.
pub fn is_revoked(route: &ProjectRoute, grantee: &str) -> Result<bool> {
    if is_explicitly_revoked(route, grantee)? {
        return Ok(true);
    }
    Ok(has_lapsed(
        &route.communications,
        &route.agents,
        &route.project_id,
        grantee,
        Utc::now(),
    ))
}

/// Whether a valid master-signed revocation exists for `grantee`. Unlike [`is_revoked`],
/// a lapsed term is not one: this is for a screen that tells "the master ended it" from
/// "it ran out".
pub fn is_explicitly_revoked(route: &ProjectRoute, grantee: &str) -> Result<bool> {
    let path = revocation_path(route, grantee);
    if !path.is_file() {
        return Ok(false);
    }
    let revocation: MasterRevocation = serde_json::from_str(&fs::read_to_string(&path)?)?;
    let Some(master) = master_agent(route)? else {
        return Ok(false);
    };
    Ok(check_signature(
        revocation.signed_by.as_ref(),
        revocation.signature.as_ref(),
        &revocation_payload(&revocation),
        std::slice::from_ref(&master),
    ) == SignatureCheck::Valid)
}

/// [`is_revoked`], for a caller holding a channel directory and its roster rather than
/// a route.
#[must_use]
pub fn is_revoked_in(communications: &Path, roster: &[AgentRoute], grantee: &str) -> bool {
    explicitly_revoked_in(communications, roster, grantee)
        || lapsed_in(communications, roster, grantee)
}

fn explicitly_revoked_in(communications: &Path, roster: &[AgentRoute], grantee: &str) -> bool {
    let path = communications
        .join("grants")
        .join(format!("{grantee}.revoked.json"));
    let Some(revocation) = fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<MasterRevocation>(&text).ok())
    else {
        return false;
    };
    let Ok(Some(declaration)) = read_master_at(communications, roster) else {
        return false;
    };
    let Some(master) = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(&declaration.master))
    else {
        return false;
    };
    check_signature(
        revocation.signed_by.as_ref(),
        revocation.signature.as_ref(),
        &revocation_payload(&revocation),
        std::slice::from_ref(master),
    ) == SignatureCheck::Valid
}

// --- access that ends (ADR 0029) ---

/// What the master's answer to a renewal question says to extend the access.
pub const RENEW: &str = "Renew";
/// ...and what it says to leave it alone. Nothing is signed or changed by choosing it: the
/// access ends on the date it always had. It is a button so the question gets an answer.
pub const LET_IT_END: &str = "Let it end";

/// The grant in `grants/<grantee>.json` when it is timed and the master signed it, with
/// the project id of the verified declaration.
///
/// The cheap exit comes first: a grant with no `expires_at` (all of them, until someone
/// asks for a timed one) costs one file read here and nothing else, because
/// `is_revoked_in` runs on every poll of every gate.
fn timed_grant(
    communications: &Path,
    roster: &[AgentRoute],
    grantee: &str,
) -> Option<(MasterGrant, String)> {
    let dir = communications.join("grants");
    let read = |name: &str| {
        fs::read_to_string(dir.join(format!("{name}.json")))
            .ok()
            .and_then(|text| serde_json::from_str::<MasterGrant>(&text).ok())
    };
    let grant = read(grantee).or_else(|| read(&canonical_agent_name(grantee)))?;
    grant.expires_at?;
    if !grant.grantee.eq_ignore_ascii_case(grantee) {
        return None;
    }
    let declaration = read_master_at(communications, roster).ok().flatten()?;
    let master = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(&declaration.master))?;
    (check_signature(
        grant.signed_by.as_ref(),
        grant.signature.as_ref(),
        &grant_payload(&grant),
        std::slice::from_ref(master),
    ) == SignatureCheck::Valid)
        .then_some((grant, declaration.project_id))
}

thread_local! {
    /// Grants whose renewals are being worked out on this thread. See [`access_ends`].
    static RENEWING: std::cell::RefCell<Vec<(PathBuf, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Marks a grant as being worked out for as long as it lives.
struct Renewing;

impl Renewing {
    fn enter(communications: &Path, grantee: &str) -> Option<Self> {
        let key = (communications.to_path_buf(), canonical_agent_name(grantee));
        RENEWING.with(|active| {
            let mut active = active.borrow_mut();
            if active.contains(&key) {
                return None;
            }
            active.push(key);
            Some(Self)
        })
    }
}

impl Drop for Renewing {
    fn drop(&mut self) {
        RENEWING.with(|active| {
            active.borrow_mut().pop();
        });
    }
}

/// When `grant`'s access ends, counting the renewals the master has answered. `None` when
/// the grant has no end at all.
///
/// A renewal is the master's signed answer to an `access` question (so no key has to be on
/// the machine that asks, and the history is the question and answer files). Four things
/// must all hold for one to count, and each is what stops a different forgery:
///
/// - the question verifies as signed by a roster member, and the answer as the master's
///   (or their `improve` delegate's), by `questions::answer_to`;
/// - the question's id names THIS grantee and THIS grant's `granted_at`, so a renewal of
///   an earlier grant never extends a fresh one;
/// - the answer is exactly [`RENEW`];
/// - the date it runs to is at most one term past the end reached so far. The id (and so
///   the date) is chosen by whoever asked; without this bound any member could ask for
///   "renew until 2099" in the master's name and rely on the master tapping the button.
///   The questions this module asks always sit exactly on the bound.
///
/// Working this out can re-enter itself: verifying an answer given by a delegate asks
/// whether the delegate is revoked, and a delegate may itself be on a timed grant. A grant
/// met again while it is already being worked out counts only up to its own date, which
/// means a person whose time has run out cannot renew their own access by answering as
/// the master's delegate.
#[must_use]
pub fn access_ends(
    communications: &Path,
    roster: &[AgentRoute],
    project_id: &str,
    grant: &MasterGrant,
) -> Option<DateTime<Utc>> {
    let base = grant.expires_at?;
    let term = base - grant.granted_at;
    if term <= Duration::zero() {
        return Some(base);
    }
    let Some(_working) = Renewing::enter(communications, &grant.grantee) else {
        return Some(base);
    };
    let route = channel_route(communications, roster, project_id);
    let prefix = format!(
        "access-{}-{}-",
        canonical_agent_name(&grant.grantee),
        grant.granted_at.timestamp()
    );
    let mut dates: Vec<DateTime<Utc>> = questions::list_with_prefix(&route, &prefix)
        .into_iter()
        .filter(|(question, answer)| {
            question.kind == questions::ACCESS
                && answer.as_ref().is_some_and(|answer| answer.answer == RENEW)
        })
        .filter_map(|(question, _)| {
            let seconds = question.id.strip_prefix(&prefix)?.parse::<i64>().ok()?;
            DateTime::from_timestamp(seconds, 0)
        })
        .collect();
    dates.sort();
    let mut end = base;
    for until in dates {
        if until > end + term {
            break;
        }
        end = end.max(until);
    }
    Some(end)
}

/// A route that knows a channel and its roster and nothing else, which is all the
/// questions need to verify themselves.
fn channel_route(communications: &Path, roster: &[AgentRoute], project_id: &str) -> ProjectRoute {
    ProjectRoute {
        project_id: project_id.to_owned(),
        workspace: communications.to_path_buf(),
        attachment: communications
            .parent()
            .unwrap_or(communications)
            .to_path_buf(),
        communications: communications.to_path_buf(),
        shared_remote: String::new(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: roster.to_vec(),
    }
}

/// Whether `grantee`'s timed access has run out by `now`. False for access with no end,
/// for a grantee with no grant, and for a grant the master did not sign.
#[must_use]
pub fn has_lapsed(
    communications: &Path,
    roster: &[AgentRoute],
    project_id: &str,
    grantee: &str,
    now: DateTime<Utc>,
) -> bool {
    timed_grant(communications, roster, grantee).is_some_and(|(grant, _)| {
        access_ends(communications, roster, project_id, &grant).is_some_and(|end| end <= now)
    })
}

/// [`has_lapsed`] as of now, for a caller that has no project id to hand: it comes from
/// the verified master declaration.
fn lapsed_in(communications: &Path, roster: &[AgentRoute], grantee: &str) -> bool {
    timed_grant(communications, roster, grantee).is_some_and(|(grant, project_id)| {
        access_ends(communications, roster, &project_id, &grant)
            .is_some_and(|end| end <= Utc::now())
    })
}

/// When `grantee`'s timed access ends (or ended), if it is timed and the grant verifies.
#[must_use]
pub fn access_end_of(route: &ProjectRoute, grantee: &str) -> Option<DateTime<Utc>> {
    let (grant, _) = timed_grant(&route.communications, &route.agents, grantee)?;
    access_ends(
        &route.communications,
        &route.agents,
        &route.project_id,
        &grant,
    )
}

/// How long before the end a renewal is asked about: three days, or a third of the term
/// when the term is shorter than nine days (a one-day trial is not asked about three days
/// before it is over).
fn notice_before(term: Duration) -> Duration {
    if term < Duration::days(9) {
        term / 3
    } else {
        Duration::days(3)
    }
}

/// Ask the master whether to renew each timed access that is about to end.
///
/// For every valid, unrevoked, timed grant whose end is ahead of `now` but inside the
/// notice window, asks once (the question id is the idempotency key) with the two buttons
/// [`RENEW`] and [`LET_IT_END`]. The id is `access-{grantee}-{granted_at}-{until}`: bound
/// to the grant it is about, and to the date a renewal would run to (one more term past
/// the current end). Anyone on the roster may ask; only the master's answer counts, so
/// the machine that notices does not need the master's key. Nothing is asked after the
/// end, or for access with none. Returns the ids asked now.
///
/// An invited person's agent is granted for the same time as the person and is asked
/// about separately, because the master may reasonably keep one and not the other.
#[must_use]
pub fn ask_renewals(
    route: &ProjectRoute,
    asker: &AgentIdentity,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut asked = Vec::new();
    // A question signed by a key the roster does not carry would never verify, so it
    // would be a question nobody ever sees.
    let key = asker.public_key_hex();
    if !route.agents.iter().any(|agent| {
        agent.name.eq_ignore_ascii_case(asker.name()) && agent.public_key.as_deref() == Some(&key)
    }) {
        return asked;
    }
    let Ok(grants) = member_grants(route) else {
        return asked;
    };
    for (grant, check) in grants {
        let (Some(expires_at), SignatureCheck::Valid) = (grant.expires_at, check) else {
            continue;
        };
        let term = expires_at - grant.granted_at;
        if term <= Duration::zero() || is_explicitly_revoked(route, &grant.grantee).unwrap_or(true)
        {
            continue;
        }
        let Some(end) = access_ends(
            &route.communications,
            &route.agents,
            &route.project_id,
            &grant,
        ) else {
            continue;
        };
        if end <= now || end - notice_before(term) > now {
            continue;
        }
        let until = end + term;
        let id = format!(
            "access-{}-{}-{}",
            canonical_agent_name(&grant.grantee),
            grant.granted_at.timestamp(),
            until.timestamp()
        );
        let days = term.num_days();
        let length = if days >= 1 {
            format!("{days} day{}", if days == 1 { "" } else { "s" })
        } else {
            format!("{} hours", term.num_hours().max(1))
        };
        let text = format!(
            "{}'s access to {} ends {} UTC. Renew for another {length}, until {}? \
             If nobody answers, it ends on {}.",
            grant.grantee,
            route.project_id,
            end.format("%Y-%m-%d"),
            until.format("%Y-%m-%d"),
            end.format("%Y-%m-%d"),
        );
        if questions::ask(
            route,
            asker,
            &id,
            questions::ACCESS,
            &text,
            &[RENEW.to_string(), LET_IT_END.to_string()],
            None,
        )
        .unwrap_or(false)
        {
            asked.push(id);
        }
    }
    asked
}

/// Every valid revocation on this project, by grantee.
pub fn revoked_members(route: &ProjectRoute) -> Result<Vec<MasterRevocation>> {
    let dir = grants_dir(route);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(grantee) = name.strip_suffix(".revoked.json") else {
            continue;
        };
        if is_explicitly_revoked(route, grantee)? {
            out.push(serde_json::from_str(&fs::read_to_string(&path)?)?);
        }
    }
    Ok(out)
}

/// Whether `agent` may take work in this project in the given role.
///
/// A worker is the floor (ADR 0014): it takes the work it is given and returns
/// results, and needs no grant for that. Requiring one made every new worker
/// machine sit idle until someone found a channel path, a public key and a role
/// flag, which is how the first worker on a second machine stayed idle for a
/// day. What a worker can still lose is the right to be here at all, so a
/// signed revocation - of it, or of the person who owns it - stops it exactly as
/// it stops anyone else. Every other role is authority over other agents, and
/// waits for the master's grant.
pub fn may_work(route: &ProjectRoute, agent: &str, role: &str) -> Result<bool> {
    if !role.eq_ignore_ascii_case("worker") {
        return is_granted(route, agent, role);
    }
    if is_revoked(route, agent)? || crate::owner::is_revoked(route, agent)? {
        return Ok(false);
    }
    match crate::owner::owner_of(route, agent)? {
        Some(owner) if !owner.eq_ignore_ascii_case(agent) => Ok(!is_revoked(route, &owner)?),
        _ => Ok(true),
    }
}

/// Whether `grantee` holds a valid master-signed grant for `role` on this
/// project. In team mode this is the gate that decides who may act.
pub fn is_granted(route: &ProjectRoute, grantee: &str, role: &str) -> Result<bool> {
    // A revocation aimed at this exact name wins over everything below it,
    // including an owner who is still in good standing: taking one machine away
    // from a person has to be possible without taking the person away.
    if is_revoked(route, grantee)? {
        return Ok(false);
    }
    // The same, signed by an owner rather than the master. A person does not need
    // the master's attention to turn off their own machine, and must be able to do
    // it from whichever machine they are actually sitting at.
    if crate::owner::is_revoked(route, grantee)? {
        return Ok(false);
    }
    if holds_grant(route, grantee, role)? {
        return Ok(true);
    }

    // Otherwise: a machine identity acts on behalf of the person who claimed it.
    // The grant that was reviewed is the person's; the machine adds nothing of
    // its own and is exactly as revoked as they are. One hop only - an owner
    // cannot itself be owned, so a chain of claims cannot manufacture authority.
    let Some(owner) = crate::owner::owner_of(route, grantee)? else {
        return Ok(false);
    };
    if owner.eq_ignore_ascii_case(grantee) || is_revoked(route, &owner)? {
        return Ok(false);
    }
    holds_grant(route, &owner, role)
}

/// Whether `grantee` has any live access here at all, whatever it covers.
///
/// A reserved name on the roster is not a member. This is the difference between
/// someone who was let in and someone whose name was merely written down.
pub fn has_any_access(route: &ProjectRoute, grantee: &str) -> Result<bool> {
    if is_revoked(route, grantee)? {
        return Ok(false);
    }
    Ok(member_grants(route)?
        .iter()
        .any(|(grant, check)| grant.grantee == grantee && *check == SignatureCheck::Valid))
}

/// Whether a valid grant naming `grantee` covers `role`. Ignores ownership and
/// revocation; `is_granted` is the gate, this is the lookup behind it.
fn holds_grant(route: &ProjectRoute, grantee: &str, role: &str) -> Result<bool> {
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

    /// A channel enabled while a person was present has no master. The person claims
    /// it once, every peer can verify it, and nobody else's project is touched.
    #[test]
    fn a_person_claims_a_masterless_channel_and_only_that() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let comms = dir.path().join("comms");
        let channel = comms.join("natv-ferryman");
        fs::create_dir_all(&channel).unwrap();
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);

        assert_eq!(
            claim_if_masterless(&channel, "natv", &comms, &josh).unwrap(),
            Claim::Declared
        );
        assert!(
            channel.join("agents").join("josh.json").is_file(),
            "the key every peer verifies against"
        );
        let roster = crate::read_agent_roster(&channel).unwrap();
        let declared = read_master_at(&channel, &roster)
            .unwrap()
            .expect("declared");
        assert_eq!(declared.master, "josh");
        assert_eq!(declared.project_id, "natv");
        assert!(
            !comms.join("master").exists(),
            "no empty folder left among the channels"
        );

        // Again is a no-op, not a second declaration.
        assert_eq!(
            claim_if_masterless(&channel, "natv", &comms, &josh).unwrap(),
            Claim::AlreadyTheirs
        );

        // Someone else claiming finds it taken, and leaves no trace on the roster.
        let ada = AgentIdentity::from_seed("ada", [3u8; 32]);
        assert_eq!(
            claim_if_masterless(&channel, "natv", &comms, &ada).unwrap(),
            Claim::Other("josh".into())
        );
        assert!(!channel.join("agents").join("ada.json").exists());
    }

    /// A key that is not the one the channel knows the name by declares nothing.
    #[test]
    fn a_different_key_under_the_same_name_claims_nothing() {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let comms = dir.path().join("comms");
        let channel = comms.join("natv-ferryman");
        fs::create_dir_all(channel.join("agents")).unwrap();
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
        let listed = AgentRoute {
            name: "josh".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(josh.public_key_hex()),
            encryption_key: None,
        };
        fs::write(
            channel.join("agents").join("josh.json"),
            serde_json::to_vec(&listed).unwrap(),
        )
        .unwrap();

        let impostor = AgentIdentity::from_seed("josh", [9u8; 32]);
        assert_eq!(
            claim_if_masterless(&channel, "natv", &comms, &impostor).unwrap(),
            Claim::KeyConflict
        );
        assert!(!channel.join("master.json").exists());
    }

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
            encryption_key: None,
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
            encryption_key: None,
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
            encryption_key: None,
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
            encryption_key: None,
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

    /// A worker works without a grant; authority still needs one; a revocation stops both.
    #[test]
    fn a_worker_needs_no_grant_but_a_revocation_still_stops_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let johnny = AgentIdentity::load_or_create_in("johnny", &route.attachment, None).unwrap();
        let bob = AgentIdentity::load_or_create_in("bob", &route.attachment, None).unwrap();
        route.agents = vec![
            AgentRoute {
                name: "johnny".into(),
                role: "orchestrator".into(),
                capabilities: vec![],
                public_key: Some(johnny.public_key_hex()),
                encryption_key: None,
            },
            AgentRoute {
                name: "bob".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(bob.public_key_hex()),
                encryption_key: None,
            },
        ];
        initialize_master(&route, &johnny, "johnny").unwrap();

        assert!(
            may_work(&route, "bob", "worker").unwrap(),
            "no grant, and still works"
        );
        assert!(
            !may_work(&route, "bob", "orchestrator").unwrap(),
            "authority waits for the master"
        );

        revoke_member(&route, &johnny, "bob", "left").unwrap();
        assert!(
            !may_work(&route, "bob", "worker").unwrap(),
            "revoked means stopped"
        );
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
                encryption_key: None,
            },
            AgentRoute {
                name: "bob".into(),
                role: "worker".into(),
                capabilities: vec![],
                public_key: Some(bob.public_key_hex()),
                encryption_key: None,
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

    /// A person, their two machines, and the master who only ever reviewed the
    /// person. This is the whole point of the owner attestation.
    fn fleet(dir: &std::path::Path) -> (ProjectRoute, AgentIdentity, AgentIdentity) {
        let mut route = test_route(dir);
        std::fs::create_dir_all(&route.communications).unwrap();
        let ada = AgentIdentity::from_seed("ada", [7u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        let entry = |identity: &AgentIdentity| AgentRoute {
            name: identity.name().to_owned(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        };
        route.agents = vec![entry(&ada), entry(&josh), entry(&grouchly)];

        initialize_master(&route, &ada, "ada").unwrap();
        grant_member(
            &route,
            &ada,
            "josh",
            &josh.public_key_hex(),
            vec!["hone".into()],
            vec!["worker".into()],
            vec!["code".into()],
        )
        .unwrap();
        crate::owner::attest_owner(&route, &josh, "josh-grouchly", &grouchly.public_key_hex())
            .unwrap();
        (route, ada, josh)
    }

    #[test]
    fn a_machine_inherits_the_grant_of_the_person_who_owns_it() {
        let dir = tempfile::tempdir().unwrap();
        let (route, _ada, _josh) = fleet(dir.path());

        assert!(
            is_granted(&route, "josh-grouchly", "worker").unwrap(),
            "the master reviewed josh; his machine is him"
        );
        assert!(
            !is_granted(&route, "josh-grouchly", "orchestrator").unwrap(),
            "inheriting means inheriting exactly, not more"
        );
        assert!(
            !is_granted(&route, "josh-beastly", "worker").unwrap(),
            "a machine nobody has claimed is a stranger"
        );
    }

    #[test]
    fn revoking_the_person_takes_their_machines_with_them() {
        let dir = tempfile::tempdir().unwrap();
        let (route, ada, _josh) = fleet(dir.path());
        assert!(is_granted(&route, "josh-grouchly", "worker").unwrap());

        revoke_member(&route, &ada, "josh", "left the project").unwrap();

        assert!(!is_granted(&route, "josh", "worker").unwrap());
        assert!(
            !is_granted(&route, "josh-grouchly", "worker").unwrap(),
            "revocation that leaves the laptop working is not revocation"
        );
    }

    /// The master is not in this story at all, and does not need to be.
    #[test]
    fn one_machine_ends_another_without_the_master() {
        let dir = tempfile::tempdir().unwrap();
        let (mut route, _ada, _josh) = fleet(dir.path());
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        let beastly = AgentIdentity::from_seed("josh-beastly", [3u8; 32]);
        route.agents.push(AgentRoute {
            name: "josh-beastly".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(beastly.public_key_hex()),
            encryption_key: None,
        });
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        crate::owner::attest_owner(&route, &josh, "josh-beastly", &beastly.public_key_hex())
            .unwrap();
        assert!(is_granted(&route, "josh-beastly", "worker").unwrap());

        crate::owner::revoke_machine(&route, &grouchly, "josh-beastly", "left in a taxi").unwrap();

        assert!(
            !is_granted(&route, "josh-beastly", "worker").unwrap(),
            "the laptop on the desk has to be able to kill the one that walked off"
        );
        assert!(is_granted(&route, "josh-grouchly", "worker").unwrap());
        assert!(is_granted(&route, "josh", "worker").unwrap());
    }

    #[test]
    fn revoking_one_machine_leaves_the_person_standing() {
        let dir = tempfile::tempdir().unwrap();
        let (route, ada, _josh) = fleet(dir.path());

        revoke_member(&route, &ada, "josh-grouchly", "laptop stolen").unwrap();

        assert!(
            !is_granted(&route, "josh-grouchly", "worker").unwrap(),
            "the machine-specific revocation has to outrank the owner's standing"
        );
        assert!(
            is_granted(&route, "josh", "worker").unwrap(),
            "losing a laptop is not losing your access"
        );
    }

    // --- access that ends (ADR 0029) ---

    /// The master is `josh`; `bob` is a person who joined; `mallory` is on the roster too
    /// and is nobody's master.
    fn timed_fixture(dir: &std::path::Path) -> (ProjectRoute, AgentIdentity, AgentIdentity) {
        let mut route = test_route(dir);
        std::fs::create_dir_all(&route.communications).unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let bob = AgentIdentity::from_seed("bob", [2u8; 32]);
        let mallory = AgentIdentity::from_seed("mallory", [3u8; 32]);
        route.agents = [&josh, &bob, &mallory]
            .into_iter()
            .map(|identity| AgentRoute {
                name: identity.name().to_owned(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            })
            .collect();
        // The delegation tests read the roster from the channel, not from the route.
        for agent in &route.agents {
            crate::register_agent(&route, agent).unwrap();
        }
        initialize_master(&route, &josh, "josh").unwrap();
        (route, josh, bob)
    }

    /// Grant `bob` access for the given window, in the past if the test wants it over.
    fn grant_window(
        route: &ProjectRoute,
        josh: &AgentIdentity,
        bob: &AgentIdentity,
        granted_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> MasterGrant {
        write_grant(
            route,
            josh,
            "bob",
            &bob.public_key_hex(),
            vec!["hone".into()],
            vec!["worker".into()],
            Vec::new(),
            granted_at,
            expires_at,
        )
        .unwrap()
    }

    /// An answer written by someone who is not the master, in the master's name, signed
    /// properly by themselves: what a member with write access to the channel can do.
    fn forge_answer(route: &ProjectRoute, id: &str, forger: &AgentIdentity, master: &str) {
        let at = Utc::now();
        let payload = format!(
            "ferryman-answer-v1\n{id}\n{}\n{master}\n{}\n{RENEW}",
            route.project_id,
            at.to_rfc3339()
        );
        let forged = questions::Answer {
            question_id: id.to_owned(),
            project_id: route.project_id.clone(),
            answer: RENEW.to_owned(),
            by: master.to_owned(),
            answered_at: at,
            signed_by: forger.name().to_owned(),
            signature: forger.sign_bytes(payload.as_bytes()),
        };
        crate::atomic_json(
            &route
                .communications
                .join("questions")
                .join(format!("{id}.answer.json")),
            &forged,
        )
        .unwrap();
    }

    #[test]
    fn a_grant_with_no_end_signs_the_bytes_it_always_did() {
        let at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let mut grant = MasterGrant {
            grantee: "bob".into(),
            public_key: "KEY".into(),
            projects: vec!["hone".into()],
            roles: vec!["worker".into()],
            capabilities: vec!["code".into()],
            granted_at: at,
            expires_at: None,
            signed_by: None,
            signature: None,
        };
        let payload = grant_payload(&grant);
        assert_eq!(
            payload,
            "ferryman-master-grant-v1\nbob\nKEY\nhone\nworker\ncode\n2026-01-02T03:04:05+00:00"
        );
        assert!(!payload.contains("expires:"));
        grant.expires_at = Some(at + Duration::days(30));
        assert_eq!(
            grant_payload(&grant),
            format!("{payload}\nexpires:2026-02-01T03:04:05+00:00"),
            "the end is appended, never interleaved"
        );
    }

    #[test]
    fn a_timed_grant_verifies_and_an_edited_end_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let until = Utc::now() + Duration::days(30);
        let grant = grant_member_until(
            &route,
            &josh,
            "bob",
            &bob.public_key_hex(),
            vec!["hone".into()],
            vec!["worker".into()],
            Vec::new(),
            Some(until),
        )
        .unwrap();
        assert_eq!(grant.expires_at, Some(until));
        let (read, check) = member_grants(&route).unwrap().remove(0);
        assert_eq!(read.expires_at, Some(until));
        assert_eq!(check, SignatureCheck::Valid);
        assert!(is_granted(&route, "bob", "worker").unwrap());

        // Moving the end later is exactly what someone who wanted more time would do.
        let path = grant_path(&route, "bob");
        let mut forged: MasterGrant = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        forged.expires_at = Some(until + Duration::days(3000));
        fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert_eq!(member_grants(&route).unwrap()[0].1, SignatureCheck::Invalid);
        assert!(!is_granted(&route, "bob", "worker").unwrap());

        // And stripping the end altogether fails the same way.
        forged.expires_at = None;
        fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert_eq!(member_grants(&route).unwrap()[0].1, SignatureCheck::Invalid);
    }

    #[test]
    fn an_end_before_the_start_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let error = grant_member_until(
            &route,
            &josh,
            "bob",
            &bob.public_key_hex(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(Utc::now() - Duration::days(1)),
        )
        .expect_err("access that has already ended is not a grant");
        assert!(error.to_string().contains("end after it starts"), "{error}");
    }

    #[test]
    fn access_that_ran_out_counts_as_revoked_everywhere_and_before_that_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();

        grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(1),
            Some(now + Duration::days(9)),
        );
        assert!(!is_revoked(&route, "bob").unwrap());
        assert!(!is_revoked_in(&route.communications, &route.agents, "bob"));
        assert!(is_granted(&route, "bob", "worker").unwrap());
        assert!(may_work(&route, "bob", "worker").unwrap());
        assert!(has_any_access(&route, "bob").unwrap());
        assert!(admitted_at(&route.communications, &route.agents).contains("bob"));

        grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(10),
            Some(now - Duration::days(1)),
        );
        assert!(is_revoked(&route, "bob").unwrap());
        assert!(is_revoked_in(&route.communications, &route.agents, "bob"));
        assert!(!is_granted(&route, "bob", "worker").unwrap());
        assert!(
            !may_work(&route, "bob", "worker").unwrap(),
            "a worker lapses too"
        );
        assert!(!has_any_access(&route, "bob").unwrap());
        assert!(!admitted_at(&route.communications, &route.agents).contains("bob"));
        assert!(
            !is_explicitly_revoked(&route, "bob").unwrap(),
            "running out is not the master revoking"
        );
        assert!(revoked_members(&route).unwrap().is_empty());
    }

    #[test]
    fn a_grant_the_master_did_not_sign_cannot_lapse_anyone() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(1),
            Some(now + Duration::days(9)),
        );
        // Somebody rewrites bob's file with an old end, to switch him off.
        let path = grant_path(&route, "bob");
        let mut edited: MasterGrant = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edited.expires_at = Some(now - Duration::days(1));
        fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
        assert!(!has_lapsed(
            &route.communications,
            &route.agents,
            "hone",
            "bob",
            now
        ));
    }

    #[test]
    fn a_grant_with_no_end_never_lapses_and_reads_no_questions() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        grant_window(&route, &josh, &bob, Utc::now() - Duration::days(4000), None);
        assert!(!is_revoked(&route, "bob").unwrap());
        assert!(!has_lapsed(
            &route.communications,
            &route.agents,
            "hone",
            "bob",
            Utc::now() + Duration::days(40000)
        ));
        let (grant, _) = member_grants(&route).unwrap().remove(0);
        assert_eq!(
            access_ends(&route.communications, &route.agents, "hone", &grant),
            None
        );
    }

    /// Ask at a moment inside the notice window and return the one question's id.
    fn ask_one(route: &ProjectRoute, asker: &AgentIdentity, grant: &MasterGrant) -> String {
        let at = grant.expires_at.unwrap() - Duration::days(1);
        let mut ids = ask_renewals(route, asker, at);
        assert_eq!(ids.len(), 1, "{ids:?}");
        ids.remove(0)
    }

    #[test]
    fn the_masters_renew_extends_access_and_let_it_end_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        // A ten-day term that ended five days ago.
        let grant = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(15),
            Some(now - Duration::days(5)),
        );
        assert!(is_revoked(&route, "bob").unwrap());
        let id = ask_one(&route, &josh, &grant);

        // Let it end changes nothing.
        questions::answer(&route, &id, LET_IT_END, "josh", &josh).unwrap();
        assert!(is_revoked(&route, "bob").unwrap());
        assert_eq!(
            access_ends(&route.communications, &route.agents, "hone", &grant),
            grant.expires_at
        );

        // A different grant of the same person answered Renew does.
        let grant = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(16),
            Some(now - Duration::days(6)),
        );
        let id = ask_one(&route, &josh, &grant);
        questions::answer(&route, &id, RENEW, "josh", &josh).unwrap();
        let end = access_ends(&route.communications, &route.agents, "hone", &grant).unwrap();
        assert_eq!(
            end.timestamp(),
            (grant.expires_at.unwrap() + Duration::days(10)).timestamp()
        );
        assert!(end > now, "five days of the ten-day renewal are left");
        assert!(!is_revoked(&route, "bob").unwrap());
        assert!(is_granted(&route, "bob", "worker").unwrap());
    }

    #[test]
    fn a_renewal_from_anyone_but_the_master_extends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let mallory = AgentIdentity::from_seed("mallory", [3u8; 32]);
        let now = Utc::now();
        let grant = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(15),
            Some(now - Duration::days(5)),
        );
        let id = ask_one(&route, &josh, &grant);

        // The honest route refuses her, and so does a file she writes herself.
        assert!(questions::answer(&route, &id, RENEW, "josh", &mallory).is_err());
        forge_answer(&route, &id, &mallory, "josh");
        assert!(
            is_revoked(&route, "bob").unwrap(),
            "a forged renewal renews nothing"
        );

        // Nor does the person whose time it is renew themselves.
        forge_answer(&route, &id, &bob, "josh");
        assert!(is_revoked(&route, "bob").unwrap());
    }

    #[test]
    fn a_question_that_asks_for_more_than_one_term_extends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        let grant = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(15),
            Some(now - Duration::days(5)),
        );
        // A member asks "renew until 2099" in the master's name and the master taps Renew.
        let id = format!(
            "access-bob-{}-{}",
            grant.granted_at.timestamp(),
            4_070_908_800_i64
        );
        questions::ask(
            &route,
            &bob,
            &id,
            questions::ACCESS,
            "bob's access ends soon. Renew?",
            &[RENEW.to_string(), LET_IT_END.to_string()],
            None,
        )
        .unwrap();
        questions::answer(&route, &id, RENEW, "josh", &josh).unwrap();
        assert!(is_revoked(&route, "bob").unwrap());
        assert_eq!(
            access_ends(&route.communications, &route.agents, "hone", &grant),
            grant.expires_at
        );
    }

    #[test]
    fn a_renewal_of_an_older_grant_does_not_extend_a_fresh_one() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        let old = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(30),
            Some(now - Duration::days(20)),
        );
        let id = ask_one(&route, &josh, &old);
        questions::answer(&route, &id, RENEW, "josh", &josh).unwrap();

        // The master grants again: a new term, a new granted_at.
        let fresh = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(1),
            Some(now + Duration::days(9)),
        );
        assert_eq!(
            access_ends(&route.communications, &route.agents, "hone", &fresh),
            fresh.expires_at,
            "the old renewal belongs to the old grant"
        );
    }

    #[test]
    fn renewals_are_asked_once_inside_the_notice_window_and_not_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        let granted = now - Duration::days(27);
        let ends = granted + Duration::days(30);
        let grant = grant_window(&route, &josh, &bob, granted, Some(ends));

        assert!(
            ask_renewals(&route, &josh, ends - Duration::days(4)).is_empty(),
            "four days out is before the three-day notice"
        );
        let asked = ask_renewals(&route, &josh, ends - Duration::days(2));
        let id = format!(
            "access-bob-{}-{}",
            grant.granted_at.timestamp(),
            (ends + Duration::days(30)).timestamp()
        );
        assert_eq!(asked, vec![id.clone()]);
        assert!(
            ask_renewals(&route, &josh, ends - Duration::days(1)).is_empty(),
            "asked once, not on every pass"
        );

        let question = questions::read(&route, &id).unwrap();
        assert_eq!(question.kind, questions::ACCESS);
        assert_eq!(
            question.options,
            vec![RENEW.to_string(), LET_IT_END.to_string()]
        );
        assert!(question.text.contains("bob"), "{}", question.text);
        assert!(question.text.contains("30 days"), "{}", question.text);
        assert_eq!(questions::pending(&route).len(), 1);

        // After the end, nobody is asked.
        assert!(ask_renewals(&route, &josh, ends + Duration::seconds(1)).is_empty());
    }

    #[test]
    fn a_short_term_is_asked_about_a_third_of_the_way_from_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let granted = Utc::now() - Duration::days(1);
        let ends = granted + Duration::days(6);
        grant_window(&route, &josh, &bob, granted, Some(ends));
        assert!(ask_renewals(&route, &josh, ends - Duration::days(3)).is_empty());
        assert_eq!(
            ask_renewals(&route, &josh, ends - Duration::days(1)).len(),
            1
        );
    }

    #[test]
    fn access_with_no_end_or_already_revoked_is_never_asked_about() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        grant_window(&route, &josh, &bob, now - Duration::days(1), None);
        assert!(ask_renewals(&route, &josh, now).is_empty());

        let ends = now + Duration::days(2);
        grant_window(&route, &josh, &bob, now - Duration::days(28), Some(ends));
        revoke_member(&route, &josh, "bob", "left").unwrap();
        assert!(ask_renewals(&route, &josh, now).is_empty());
    }

    #[test]
    fn someone_the_roster_does_not_carry_cannot_ask() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        let now = Utc::now();
        grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(28),
            Some(now + Duration::days(2)),
        );
        let stranger = AgentIdentity::from_seed("stranger", [9u8; 32]);
        assert!(ask_renewals(&route, &stranger, now).is_empty());
        let impostor = AgentIdentity::from_seed("josh", [9u8; 32]);
        assert!(
            ask_renewals(&route, &impostor, now).is_empty(),
            "the name, not the key"
        );
    }

    #[test]
    fn a_machine_loses_the_access_it_inherited_when_its_owner_runs_out() {
        let dir = tempfile::tempdir().unwrap();
        let (mut route, josh, bob) = timed_fixture(dir.path());
        let laptop = AgentIdentity::from_seed("bob-laptop", [4u8; 32]);
        route.agents.push(AgentRoute {
            name: "bob-laptop".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(laptop.public_key_hex()),
            encryption_key: None,
        });
        let now = Utc::now();
        grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(1),
            Some(now + Duration::days(9)),
        );
        crate::owner::attest_owner(&route, &bob, "bob-laptop", &laptop.public_key_hex()).unwrap();
        assert!(is_granted(&route, "bob-laptop", "worker").unwrap());

        grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(10),
            Some(now - Duration::days(1)),
        );
        assert!(!is_granted(&route, "bob", "worker").unwrap());
        assert!(
            !is_granted(&route, "bob-laptop", "worker").unwrap(),
            "a machine is exactly as lapsed as its owner"
        );
        assert!(!may_work(&route, "bob-laptop", "worker").unwrap());
    }

    /// A delegate on a timed grant is the one place working out a grant's end meets itself:
    /// the delegate's standing asks whether they are revoked, which asks whether they ran
    /// out, which reads the answers they may have signed. It must finish, and a delegate
    /// whose time is up must not be able to renew their own access.
    #[test]
    fn a_delegate_whose_time_ran_out_cannot_renew_themselves() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh, bob) = timed_fixture(dir.path());
        crate::delegation::grant(
            &route.communications,
            "hone",
            &josh,
            "bob",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        let now = Utc::now();
        let grant = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(15),
            Some(now - Duration::days(5)),
        );
        let id = ask_one(&route, &josh, &grant);
        assert!(questions::answer(&route, &id, RENEW, "josh", &bob).is_err());
        // Written by hand, as a delegate's properly signed answer would be.
        forge_answer(&route, &id, &bob, "josh");
        assert!(
            is_revoked(&route, "bob").unwrap(),
            "bob's own answer, as a lapsed delegate, does not count"
        );
        // While bob is in time, the same delegate may answer for the master.
        let grant = grant_window(
            &route,
            &josh,
            &bob,
            now - Duration::days(9),
            Some(now + Duration::days(1)),
        );
        let id = ask_one(&route, &josh, &grant);
        questions::answer(&route, &id, RENEW, "josh", &bob).unwrap();
        assert_eq!(
            access_ends(&route.communications, &route.agents, "hone", &grant)
                .unwrap()
                .timestamp(),
            (grant.expires_at.unwrap() + Duration::days(10)).timestamp()
        );
    }
}

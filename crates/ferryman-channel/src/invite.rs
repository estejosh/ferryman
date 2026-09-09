//! Team invitations: one code from the master, one line for the newcomer.
//!
//! Bringing a person onto a channel used to be a runbook: pair Syncthing by hand,
//! exchange device ids, reserve a name, wait, grant. Every step was a place to stop.
//! An invitation folds it into a protocol:
//!
//! 1. The master runs `ferry team invite create` (or clicks Invite on the dashboard).
//!    That reserves the operator and agent names on the roster, writes a signed
//!    `invites/<id>.json` into the channel, and prints a CODE - a short string that
//!    carries the project id, the Syncthing folder id, the inviter's device id, the
//!    reserved names and a nonce. It carries no secret and no key.
//! 2. The newcomer runs `ferry team invite accept <code>`. Their machine starts its
//!    managed Syncthing, names itself `ferry:<invite id>`, adds the inviter as a trusted
//!    device, enables the project so the channel folder exists under the right folder
//!    id, and shares it with the inviter. Their operator and agent keys land in their
//!    copy of the channel, with an acceptance record carrying the nonce.
//! 3. The inviter's `ferry` - the agent loop, or the dashboard while it is open - sees a
//!    device knocking whose announced name matches a live invite, trusts it, and shares
//!    the folder. The folder syncs; the newcomer's keys and acceptance arrive; the
//!    master (through the dashboard, which holds the unlocked key) signs the grant the
//!    invite promised.
//!
//! The device NAME is the handshake because it is the one field Syncthing announces
//! before any folder is shared. Nothing else the newcomer writes can reach the inviter
//! until the folder does.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature, is_safe_component};

/// The record the master writes into the channel. Signed, so a forged invitation cannot
/// make the inviter's machine trust a device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    pub id: String,
    pub project_id: String,
    /// The Syncthing folder id the newcomer must configure.
    pub folder: String,
    /// The inviter's Syncthing device id.
    pub device_id: String,
    /// Reserved operator (human) name.
    pub operator: String,
    /// Reserved agent name, when the invite includes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The access the master promised, granted when the keys arrive.
    #[serde(default)]
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// SHA-256 of the nonce the code carries. The acceptance must present the nonce.
    pub nonce_hash: String,
    /// The device this invite was accepted from, once one has been.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_device: Option<String>,
    /// When the grant was signed, if it has been.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// What the code carries. Nothing here is secret; the nonce is a proof of having been
/// given the code, not a key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteCode {
    pub v: u8,
    pub id: String,
    pub project: String,
    pub folder: String,
    pub device: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub expires: i64,
    pub nonce: String,
}

/// The newcomer's signed acceptance, written into their copy of the channel so it
/// syncs to the inviter once the folder is shared.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Acceptance {
    pub invite_id: String,
    pub nonce: String,
    pub device_id: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub accepted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

pub fn invites_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("invites")
}

fn invite_path(route: &ProjectRoute, id: &str) -> PathBuf {
    invites_dir(route).join(format!("{id}.json"))
}

fn acceptance_path(route: &ProjectRoute, id: &str) -> PathBuf {
    invites_dir(route).join(format!("{id}.accept.json"))
}

/// The announced Syncthing device name a newcomer uses while accepting.
#[must_use]
pub fn handshake_name(id: &str) -> String {
    format!("ferry:{id}")
}

fn invite_payload(invite: &Invite) -> String {
    format!(
        "ferryman-invite-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        invite.id,
        invite.project_id,
        invite.folder,
        invite.device_id,
        invite.operator,
        invite.agent.as_deref().unwrap_or(""),
        invite.roles.join(","),
        invite.expires_at.to_rfc3339(),
        invite.nonce_hash,
    )
}

fn acceptance_payload(accept: &Acceptance) -> String {
    format!(
        "ferryman-invite-accept-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        accept.invite_id,
        accept.nonce,
        accept.device_id,
        accept.operator,
        accept.agent.as_deref().unwrap_or(""),
        accept.accepted_at.to_rfc3339(),
    )
}

fn hash_nonce(nonce: &str) -> String {
    hex::encode(Sha256::digest(nonce.as_bytes()))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0_u8; bytes];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
    hex::encode(buf)
}

/// Create an invitation. Only the declared master may.
///
/// Reserves the names on the roster (first-key-wins protects them from then on), writes
/// the signed record, and returns it with the code to hand over.
pub fn create(
    route: &ProjectRoute,
    master: &AgentIdentity,
    operator: &str,
    agent: Option<&str>,
    roles: Vec<String>,
    ttl: Duration,
    inviter_device_id: &str,
) -> Result<(Invite, String)> {
    let Some(declaration) = crate::master::read_master(route)? else {
        bail!("this project has no master yet; become the master first");
    };
    if !declaration.master.eq_ignore_ascii_case(master.name()) {
        bail!(
            "only the master ({}) may invite; you are {}",
            declaration.master,
            master.name()
        );
    }
    if !is_safe_component(operator) {
        bail!("the operator name must be a plain identifier");
    }
    if let Some(agent) = agent
        && !is_safe_component(agent)
    {
        bail!("the agent name must be a plain identifier");
    }
    let roster = crate::read_agent_roster(&route.communications)?;
    for name in std::iter::once(operator).chain(agent) {
        if let Some(existing) = roster.iter().find(|a| a.name.eq_ignore_ascii_case(name))
            && existing.public_key.is_some()
        {
            bail!("{name} is already in this channel and has published a key");
        }
    }
    crate::register_expected_agent(route, operator, "operator", &["messages.receive".into()])?;
    if let Some(agent) = agent {
        crate::register_expected_agent(route, agent, "worker", &["messages.receive".into()])?;
    }

    let id = random_hex(4);
    let nonce = random_hex(16);
    let now = Utc::now();
    let mut invite = Invite {
        id: id.clone(),
        project_id: route.project_id.clone(),
        folder: crate::channel_folder_id(route),
        device_id: inviter_device_id.to_string(),
        operator: operator.to_string(),
        agent: agent.map(str::to_string),
        roles,
        created_at: now,
        expires_at: now + ttl,
        nonce_hash: hash_nonce(&nonce),
        accepted_device: None,
        granted_at: None,
        signed_by: None,
        signature: None,
    };
    let signature = master.signing.sign(invite_payload(&invite).as_bytes());
    invite.signed_by = Some(master.name().to_string());
    invite.signature = Some(hex::encode(signature.to_bytes()));
    fs::create_dir_all(invites_dir(route))?;
    crate::atomic_json(&invite_path(route, &id), &invite)?;

    let code = encode_code(&InviteCode {
        v: 1,
        id,
        project: route.project_id.clone(),
        folder: invite.folder.clone(),
        device: inviter_device_id.to_string(),
        operator: operator.to_string(),
        agent: agent.map(str::to_string),
        expires: invite.expires_at.timestamp(),
        nonce,
    });
    Ok((invite, code))
}

/// Every invitation on this channel, with whether its signature verifies.
pub fn list(route: &ProjectRoute) -> Result<Vec<(Invite, SignatureCheck)>> {
    let dir = invites_dir(route);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".json") || name.ends_with(".accept.json") {
            continue;
        }
        let Ok(invite) = serde_json::from_str::<Invite>(&fs::read_to_string(&path)?) else {
            continue;
        };
        let check = check_signature(
            invite.signed_by.as_ref(),
            invite.signature.as_ref(),
            &invite_payload(&invite),
            &route.agents,
        );
        out.push((invite, check));
    }
    out.sort_by(|a, b| b.0.created_at.cmp(&a.0.created_at));
    Ok(out)
}

pub fn read(route: &ProjectRoute, id: &str) -> Result<Option<Invite>> {
    let path = invite_path(route, id);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

fn write(route: &ProjectRoute, invite: &Invite) -> Result<()> {
    crate::atomic_json(&invite_path(route, &invite.id), invite)
}

/// Whether an invite is still usable: unexpired and not yet granted.
#[must_use]
pub fn is_open(invite: &Invite, now: DateTime<Utc>) -> bool {
    invite.granted_at.is_none() && invite.expires_at > now
}

/// The newcomer's side: record acceptance in their copy of the channel, signed by their
/// new operator key. Syncs to the inviter once the folder does.
pub fn write_acceptance(
    route: &ProjectRoute,
    operator: &AgentIdentity,
    code: &InviteCode,
    device_id: &str,
) -> Result<PathBuf> {
    let mut accept = Acceptance {
        invite_id: code.id.clone(),
        nonce: code.nonce.clone(),
        device_id: device_id.to_string(),
        operator: code.operator.clone(),
        agent: code.agent.clone(),
        accepted_at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    let signature = operator.signing.sign(acceptance_payload(&accept).as_bytes());
    accept.signed_by = Some(operator.name().to_string());
    accept.signature = Some(hex::encode(signature.to_bytes()));
    fs::create_dir_all(invites_dir(route))?;
    let path = acceptance_path(route, &code.id);
    crate::atomic_json(&path, &accept)?;
    Ok(path)
}

pub fn read_acceptance(route: &ProjectRoute, id: &str) -> Result<Option<Acceptance>> {
    let path = acceptance_path(route, id);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

/// What the inviter's machine did on one pass over pending devices and acceptances.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Settled {
    /// Devices trusted and given the folder, as (invite id, device id).
    pub paired: Vec<(String, String)>,
    /// Invites whose acceptance and keys have arrived and now need the master's grant.
    pub ready_to_grant: Vec<Invite>,
}

/// The inviter's side, without the master key: trust any knocking device whose announced
/// name matches a live invite, share the folder with it, and report which invites have
/// come all the way back and are waiting for a grant.
///
/// Safe to run on every poll: it touches Syncthing only for a name that matches an open
/// invite, and never grants - that needs the master's signature, which lives in the
/// dashboard session.
pub fn settle_pending(route: &ProjectRoute) -> Result<Settled> {
    let now = Utc::now();
    let mut settled = Settled::default();
    let invites: Vec<Invite> = list(route)?
        .into_iter()
        .filter(|(invite, check)| *check == SignatureCheck::Valid && is_open(invite, now))
        .map(|(invite, _)| invite)
        .collect();
    if invites.is_empty() {
        return Ok(settled);
    }

    // Knocking devices first: this is the step nothing else can do.
    if let Ok(pending) = crate::syncthing_pending_devices() {
        for device in pending {
            let Some(invite) = invites
                .iter()
                .find(|i| device.name == handshake_name(&i.id) && i.accepted_device.is_none())
            else {
                continue;
            };
            crate::syncthing_add_device(&device.device_id, &invite.operator)
                .with_context(|| format!("trust {}'s device", invite.operator))?;
            crate::syncthing_share_folder(route, &[device.device_id.clone()])
                .with_context(|| format!("share the folder with {}", invite.operator))?;
            let mut updated = invite.clone();
            updated.accepted_device = Some(device.device_id.clone());
            write(route, &updated)?;
            settled.paired.push((invite.id.clone(), device.device_id.clone()));
        }
    }

    // Then acceptances that have synced back with the keys they promise.
    let roster = crate::read_agent_roster(&route.communications)?;
    for invite in list(route)?.into_iter().map(|(i, _)| i) {
        if !is_open(&invite, now) {
            continue;
        }
        let Some(accept) = read_acceptance(route, &invite.id)? else {
            continue;
        };
        if hash_nonce(&accept.nonce) != invite.nonce_hash {
            continue;
        }
        let has_key = |name: &str| {
            roster
                .iter()
                .any(|a| a.name.eq_ignore_ascii_case(name) && a.public_key.is_some())
        };
        if !has_key(&invite.operator) {
            continue;
        }
        if let Some(agent) = &invite.agent
            && !has_key(agent)
        {
            continue;
        }
        if check_signature(
            accept.signed_by.as_ref(),
            accept.signature.as_ref(),
            &acceptance_payload(&accept),
            &roster,
        ) != SignatureCheck::Valid
        {
            continue;
        }
        settled.ready_to_grant.push(invite);
    }
    Ok(settled)
}

/// The joiner's side, after the folder has synced: if this device still carries a
/// handshake name and the invite record now says the inviter accepted this device,
/// take a normal name. Returns the new name when it renamed.
pub fn finish_handshake(route: &ProjectRoute) -> Result<Option<String>> {
    let Ok(health) = crate::syncthing_health() else {
        return Ok(None);
    };
    let Some(me) = health.my_id else {
        return Ok(None);
    };
    for (invite, _) in list(route)? {
        if invite.accepted_device.as_deref() != Some(me.as_str()) {
            continue;
        }
        // Our own announced name is in the config under our own id; the peers list
        // excludes us, so read it straight from the config.
        let Some(key) = crate::syncthing_api_key() else {
            return Ok(None);
        };
        let mine = crate::syncthing_get(&crate::syncthing_api_base(), &format!("/rest/config/devices/{me}"), &key)?
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .unwrap_or_default();
        if mine != handshake_name(&invite.id) {
            return Ok(None);
        }
        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "machine".into())
            .to_lowercase();
        let name = format!("{}-{host}", invite.operator);
        crate::syncthing_set_my_name(&name)?;
        return Ok(Some(name));
    }
    Ok(None)
}

/// Expire every open invitation naming `operator`, now. Returns how many.
pub fn burn_for(route: &ProjectRoute, operator: &str) -> Result<usize> {
    let mut burned = 0;
    for (mut invite, _) in list(route)? {
        if invite.operator.eq_ignore_ascii_case(operator) && invite.granted_at.is_none() {
            invite.expires_at = Utc::now();
            write(route, &invite)?;
            burned += 1;
        }
    }
    Ok(burned)
}

/// Mark an invite granted, after the master has signed the grants it promised.
pub fn mark_granted(route: &ProjectRoute, id: &str) -> Result<()> {
    let Some(mut invite) = read(route, id)? else {
        bail!("no invite {id}");
    };
    invite.granted_at = Some(Utc::now());
    write(route, &invite)
}

// --- the code itself: base64url of compact JSON, no padding, nothing clever ---

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in text.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        let v = B64.iter().position(|&x| x == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Codes are prefixed so a person can tell what they are holding.
const CODE_PREFIX: &str = "ferry1.";

pub fn encode_code(code: &InviteCode) -> String {
    let json = serde_json::to_vec(code).expect("invite code serialises");
    format!("{CODE_PREFIX}{}", b64url_encode(&json))
}

pub fn decode_code(text: &str) -> Result<InviteCode> {
    let text = text.trim();
    let Some(body) = text.strip_prefix(CODE_PREFIX) else {
        bail!("that is not a Ferryman invite code (it should start with {CODE_PREFIX})");
    };
    let bytes = b64url_decode(body).context("the invite code is damaged")?;
    let code: InviteCode = serde_json::from_slice(&bytes).context("the invite code is damaged")?;
    if code.v != 1 {
        bail!("this invite code is from a newer Ferryman; update and try again");
    }
    if code.expires < Utc::now().timestamp() {
        bail!("this invite has expired; ask for a new one");
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_round_trips_and_is_one_token() {
        let code = InviteCode {
            v: 1,
            id: "1a2b3c4d".into(),
            project: "redaktly".into(),
            folder: "redaktly-ferryman".into(),
            device: "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH".into(),
            operator: "david".into(),
            agent: Some("david-agent".into()),
            expires: Utc::now().timestamp() + 3600,
            nonce: "00112233445566778899aabbccddeeff".into(),
        };
        let text = encode_code(&code);
        assert!(text.starts_with("ferry1."));
        assert!(!text.contains(' '));
        assert_eq!(decode_code(&text).unwrap(), code);
    }

    #[test]
    fn an_expired_code_is_refused_with_the_reason() {
        let code = InviteCode {
            v: 1,
            id: "x".into(),
            project: "p".into(),
            folder: "p-ferryman".into(),
            device: "D".into(),
            operator: "o".into(),
            agent: None,
            expires: Utc::now().timestamp() - 1,
            nonce: "n".into(),
        };
        let err = decode_code(&encode_code(&code)).unwrap_err().to_string();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn base64url_handles_every_remainder() {
        for len in 0..10 {
            let bytes: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64url_decode(&b64url_encode(&bytes)).unwrap(), bytes);
        }
    }
}

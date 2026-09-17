//! Binding a Ferryman key to a git account, so the role is anchored outside the
//! folder it governs. ADR 0022.
//!
//! `master.json` lives in the shared channel, and `initialize_master` only refuses
//! when that file is present. Delete it and the next machine takes the role. The
//! answer is evidence kept somewhere the channel cannot reach: an account whose
//! published keys only its holder can change.
//!
//! The binding is proven once and verified by arithmetic ever after. Nothing in
//! the grant model reaches the network - `is_granted` did not before this and does
//! not now. What the network buys is the moment of claiming, and later, a check
//! that can pause a role it can never move.
//!
//! ## Signed in both directions
//!
//! The account's published SSH key signs a payload naming the Ferryman key, and
//! the Ferryman key signs the record naming the account. Each signature names the
//! other side, so neither can be lifted off and replayed against a different key.
//! A one-way assertion - a file saying "I am estejosh" - proves nothing, because
//! anybody can write a file.
//!
//! ## Why SSH and not GPG
//!
//! An `ssh-ed25519` key is an ed25519 key: the primitive this crate already signs
//! everything with. GitHub publishes them unauthenticated at `<login>.keys`, which
//! is what lets every member check a master rather than only the master's own
//! machine. Verifying GPG instead would mean an OpenPGP stack in the dependency
//! tree for no cryptographic gain.

use std::{fmt, fs, path::PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, check_signature};

/// How long a contradiction has to stand before it pauses anything.
///
/// The ADR says "several checks across days agree", and this is that in hours. A
/// provider can be wrong for an afternoon - a bad deploy, a cache, a half-applied
/// account change - and a role that pauses on the first disagreement would be a
/// role that pauses on weather.
pub const PAUSE_AFTER_HOURS: i64 = 72;

/// The SSHSIG namespace. Namespaces exist so a signature made for one purpose
/// cannot be presented as a signature for another; `ssh-keygen -Y sign -n` sets it
/// and `-Y verify -n` requires it to match.
pub const NAMESPACE: &str = "ferryman-anchor";

/// Whether the account is a person or an organisation. GitHub reports both in one
/// numeric id space, so this only says which kind of proof the claim carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountType {
    /// A person. Proves itself: `<login>.keys` is published by the holder alone.
    User,
    /// An organisation. Has no published key of its own, so the claim is really
    /// about a person who administers it (ADR 0022) and carries a weaker proof.
    Organization,
}

impl fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "User",
            Self::Organization => "Organization",
        })
    }
}

/// A master's binding to one git account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitAnchor {
    /// `github` today. Nothing here is GitHub-shaped except the URLs it was read from.
    pub provider: String,
    /// The immutable numeric account id. This is what is checked.
    pub account_id: u64,
    /// The handle, for people to read. Never checked: handles are reassignable, and
    /// a claim pinned to the string would follow the name to its next owner.
    pub login: String,
    pub account_type: AccountType,
    /// The Ferryman public key being bound, hex encoded.
    pub ferryman_key: String,
    /// The account's published key, exactly as `<login>.keys` served it.
    pub ssh_key: String,
    /// `ssh-keygen -Y sign` output over [`ssh_payload`], armoured.
    pub ssh_signature: String,
    pub claimed_at: DateTime<Utc>,
    /// Where the key list was read, and when. Evidence for anyone who wants to
    /// re-check; never needed to verify.
    pub evidence_url: String,
    pub evidence_read_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// What the ACCOUNT's ssh key signs: the immutable half of the binding.
///
/// Deliberately excludes the login and every timestamp. A handle can move and a
/// record can be rewritten; neither should require going back to `ssh-keygen`, and
/// neither is what the account is being asked to attest to.
#[must_use]
pub fn ssh_payload(provider: &str, account_id: u64, ferryman_key: &str) -> String {
    format!("ferryman-anchor-v1\n{provider}\n{account_id}\n{ferryman_key}")
}

/// What the FERRYMAN key signs: the whole record, including the account's key.
fn anchor_payload(anchor: &GitAnchor) -> String {
    format!(
        "ferryman-anchor-record-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        anchor.provider,
        anchor.account_id,
        anchor.account_type,
        anchor.login,
        anchor.ferryman_key,
        anchor.ssh_key.trim(),
        anchor.claimed_at.to_rfc3339(),
    )
}

/// Why an anchor did not verify. Every failure is specific: "it does not verify"
/// with no reason is the kind of message that gets worked around rather than read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorCheck {
    Valid,
    /// The Ferryman-side signature is absent, or the signer is not on the roster,
    /// or it does not verify.
    FerrymanSignature(SignatureCheck),
    /// The record names a Ferryman key that is not the key that signed it.
    KeyIsNotTheSigners,
    /// The published key could not be read as an `ssh-ed25519` key.
    UnreadableSshKey,
    /// The armoured signature could not be parsed.
    UnreadableSshSignature,
    /// The signature was made by a different key from the one the record publishes.
    SshSignatureIsFromAnotherKey,
    /// The signature is for a different purpose.
    WrongNamespace,
    /// The ssh signature does not verify over the payload naming this Ferryman key.
    SshSignatureInvalid,
}

impl AnchorCheck {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Verify an anchor with no network and no trust in anything but arithmetic.
///
/// The roster supplies the Ferryman key that must have signed the record; the
/// record supplies the account key that must have signed the binding. Both have to
/// hold, and each must name the other.
pub fn verify(anchor: &GitAnchor, roster: &[AgentRoute]) -> AnchorCheck {
    let check = check_signature(
        anchor.signed_by.as_ref(),
        anchor.signature.as_ref(),
        &anchor_payload(anchor),
        roster,
    );
    if check != SignatureCheck::Valid {
        return AnchorCheck::FerrymanSignature(check);
    }
    // The record must bind the key that signed it. Without this a member could take
    // a valid anchor, leave the signature alone, and point `ferryman_key` at a key
    // of their own - the record would still verify as "signed by the master".
    let signer_key = anchor
        .signed_by
        .as_ref()
        .and_then(|name| {
            roster
                .iter()
                .find(|agent| agent.name.eq_ignore_ascii_case(name))
        })
        .and_then(|agent| agent.public_key.clone());
    if signer_key.as_deref() != Some(anchor.ferryman_key.as_str()) {
        return AnchorCheck::KeyIsNotTheSigners;
    }

    let Some(account_key) = parse_public_key(&anchor.ssh_key) else {
        return AnchorCheck::UnreadableSshKey;
    };
    let Some(parsed) = parse_signature(&anchor.ssh_signature) else {
        return AnchorCheck::UnreadableSshSignature;
    };
    if parsed.public_key != account_key {
        return AnchorCheck::SshSignatureIsFromAnotherKey;
    }
    if parsed.namespace != NAMESPACE {
        return AnchorCheck::WrongNamespace;
    }
    let payload = ssh_payload(&anchor.provider, anchor.account_id, &anchor.ferryman_key);
    if verify_sshsig(&parsed, payload.as_bytes()) {
        AnchorCheck::Valid
    } else {
        AnchorCheck::SshSignatureInvalid
    }
}

/// Seal a record with the Ferryman key. The ssh half must already be in place -
/// this side cannot make it, which is the point.
pub fn sign_anchor(anchor: &mut GitAnchor, identity: &crate::AgentIdentity) -> Result<()> {
    use ed25519_dalek::Signer;
    if anchor.ferryman_key != identity.public_key_hex() {
        bail!("this anchor is for another key, so this identity cannot sign it");
    }
    anchor.signed_by = None;
    anchor.signature = None;
    let signature = identity.signing.sign(anchor_payload(anchor).as_bytes());
    anchor.signed_by = Some(identity.name().to_owned());
    anchor.signature = Some(hex::encode(signature.to_bytes()));
    Ok(())
}

// --- ssh wire formats ---------------------------------------------------------
//
// Two small binary formats, both built from the same "uint32 length, then bytes"
// string. Parsing them by hand is a few dozen lines and costs no dependency; the
// alternative was an ssh crate, or GPG, for arithmetic this crate already does.

/// A reader over an ssh wire buffer. Every read is fallible and bounds-checked;
/// this parses bytes that arrive from a network and must not panic on any of them.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.bytes.len() < n {
            return None;
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    /// An ssh `string`: a big-endian length, then that many bytes.
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// An `ssh-ed25519` public key from one line of an `authorized_keys` file, which is
/// exactly what `github.com/<login>.keys` serves. The comment field is ignored.
#[must_use]
pub fn parse_public_key(line: &str) -> Option<[u8; 32]> {
    let mut fields = line.split_whitespace();
    let kind = fields.next()?;
    if kind != "ssh-ed25519" {
        return None;
    }
    let blob = b64_decode(fields.next()?)?;
    let mut reader = Reader::new(&blob);
    if reader.string()? != b"ssh-ed25519" {
        return None;
    }
    reader.string()?.try_into().ok()
}

struct Sshsig {
    public_key: [u8; 32],
    namespace: String,
    reserved: Vec<u8>,
    hash_algorithm: String,
    signature: [u8; 64],
}

/// Parse the armoured output of `ssh-keygen -Y sign`, per OpenSSH's PROTOCOL.sshsig.
fn parse_signature(armoured: &str) -> Option<Sshsig> {
    let body: String = armoured
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
        .collect();
    let blob = b64_decode(&body)?;

    let mut reader = Reader::new(&blob);
    if reader.take(6)? != b"SSHSIG" {
        return None;
    }
    if reader.u32()? != 1 {
        return None;
    }
    let key_blob = reader.string()?;
    let namespace = String::from_utf8(reader.string()?.to_vec()).ok()?;
    let reserved = reader.string()?.to_vec();
    let hash_algorithm = String::from_utf8(reader.string()?.to_vec()).ok()?;
    let signature_blob = reader.string()?;

    let mut key_reader = Reader::new(key_blob);
    if key_reader.string()? != b"ssh-ed25519" {
        return None;
    }
    let public_key: [u8; 32] = key_reader.string()?.try_into().ok()?;

    let mut signature_reader = Reader::new(signature_blob);
    if signature_reader.string()? != b"ssh-ed25519" {
        return None;
    }
    let signature: [u8; 64] = signature_reader.string()?.try_into().ok()?;

    Some(Sshsig {
        public_key,
        namespace,
        reserved,
        hash_algorithm,
        signature,
    })
}

/// What an SSHSIG signature actually covers.
///
/// Not the message: the message is hashed first, and the hash is wrapped in a
/// framing that repeats the namespace. That framing is the whole reason a signature
/// cannot be lifted from one protocol into another.
fn signed_blob(parsed: &Sshsig, message: &[u8]) -> Option<Vec<u8>> {
    let digest: Vec<u8> = match parsed.hash_algorithm.as_str() {
        "sha512" => Sha512::digest(message).to_vec(),
        "sha256" => sha2::Sha256::digest(message).to_vec(),
        _ => return None,
    };
    let mut out = Vec::from(*b"SSHSIG");
    put_string(&mut out, parsed.namespace.as_bytes());
    put_string(&mut out, &parsed.reserved);
    put_string(&mut out, parsed.hash_algorithm.as_bytes());
    put_string(&mut out, &digest);
    Some(out)
}

fn verify_sshsig(parsed: &Sshsig, message: &[u8]) -> bool {
    let Some(blob) = signed_blob(parsed, message) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&parsed.public_key) else {
        return false;
    };
    verifying
        .verify_strict(&blob, &Signature::from_bytes(&parsed.signature))
        .is_ok()
}

/// Standard-alphabet base64, which is what both ssh formats use. The invite code
/// uses the url-safe alphabet and has its own; sharing one would mean a decoder
/// that silently accepts either, and accepting more than the format allows is how
/// a parser becomes a liability.
fn b64_decode(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = ALPHABET.iter().position(|&x| x == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// --- the claim in a channel, and what watching it does -------------------------

fn anchors_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("anchors")
}

fn claim_path(route: &ProjectRoute, master: &str) -> PathBuf {
    anchors_dir(route).join(format!("claim.{}.json", crate::canonical_agent_name(master)))
}

/// One observer's file, so two machines watching at once never write the same one.
/// The same reason marvin keeps a page per holder rather than a shared document.
fn observation_path(route: &ProjectRoute, observer: &str) -> PathBuf {
    anchors_dir(route).join(format!("seen.{}.json", crate::canonical_agent_name(observer)))
}

/// Put a verified claim into a channel. Refuses to publish one that does not
/// verify, because an anchor nobody can check is worse than none: it reads as
/// evidence at a glance and is not.
pub fn publish(route: &ProjectRoute, anchor: &GitAnchor) -> Result<PathBuf> {
    let check = verify(anchor, &route.agents);
    if !check.is_valid() {
        bail!("this anchor does not verify ({check:?}), so it will not be published");
    }
    let Some(master) = anchor.signed_by.as_deref() else {
        bail!("an unsigned anchor has nobody to file it under");
    };
    fs::create_dir_all(anchors_dir(route))?;
    let path = claim_path(route, master);
    crate::atomic_json(&path, anchor)?;
    Ok(path)
}

/// The anchor `master` published here, if it is present and still verifies.
pub fn read_claim(route: &ProjectRoute, master: &str) -> Result<Option<GitAnchor>> {
    let path = claim_path(route, master);
    if !path.is_file() {
        return Ok(None);
    }
    let Ok(anchor) = serde_json::from_slice::<GitAnchor>(&fs::read(&path)?) else {
        return Ok(None);
    };
    if verify(&anchor, &route.agents).is_valid() {
        Ok(Some(anchor))
    } else {
        Ok(None)
    }
}

/// What a check found. There is no third outcome that means anything: either the
/// provider answered and agreed, or it answered and disagreed. Failing to reach it
/// is not an observation and is never recorded as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Verified,
    Contradicted,
}

/// One member's report of what the provider said about a master's anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorObservation {
    /// Whose anchor was checked.
    pub master: String,
    pub account_id: u64,
    pub outcome: Outcome,
    /// What disagreed, in words, for whoever reads the finding.
    pub detail: String,
    pub observed_at: DateTime<Utc>,
    /// When this observer FIRST saw the disagreement that is still standing.
    /// Carried forward across checks and cleared by a verify, so "it has been wrong
    /// for three days" is answerable from one record instead of a history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contradicted_since: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn observation_payload(observation: &AnchorObservation) -> String {
    format!(
        "ferryman-anchor-seen-v1\n{}\n{}\n{:?}\n{}\n{}\n{}",
        observation.master,
        observation.account_id,
        observation.outcome,
        observation.detail,
        observation.observed_at.to_rfc3339(),
        observation
            .contradicted_since
            .map(|at| at.to_rfc3339())
            .unwrap_or_default(),
    )
}

/// Record what this machine saw. Signed, because a report that can pause a role is
/// worth forging.
pub fn record(
    route: &ProjectRoute,
    observer: &AgentIdentity,
    master: &str,
    account_id: u64,
    outcome: Outcome,
    detail: &str,
) -> Result<AnchorObservation> {
    let now = Utc::now();
    // A contradiction that was already standing keeps its original date. Restarting
    // the clock on every check would mean the grace period never elapses and the
    // pause never arrives.
    let contradicted_since = match outcome {
        Outcome::Verified => None,
        Outcome::Contradicted => read_observation(route, observer.name())
            .ok()
            .flatten()
            .filter(|previous| previous.outcome == Outcome::Contradicted)
            .and_then(|previous| previous.contradicted_since)
            .or(Some(now)),
    };
    let mut observation = AnchorObservation {
        master: master.to_owned(),
        account_id,
        outcome,
        detail: detail.to_owned(),
        observed_at: now,
        contradicted_since,
        signed_by: None,
        signature: None,
    };
    use ed25519_dalek::Signer;
    let signature = observer
        .signing
        .sign(observation_payload(&observation).as_bytes());
    observation.signed_by = Some(observer.name().to_owned());
    observation.signature = Some(hex::encode(signature.to_bytes()));
    fs::create_dir_all(anchors_dir(route))?;
    crate::atomic_json(&observation_path(route, observer.name()), &observation)?;
    Ok(observation)
}

fn read_observation(route: &ProjectRoute, observer: &str) -> Result<Option<AnchorObservation>> {
    let path = observation_path(route, observer);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&fs::read(&path)?).ok())
}

/// Every observation that verifies, whoever wrote it.
pub fn observations(route: &ProjectRoute, master: &str) -> Result<Vec<AnchorObservation>> {
    let directory = anchors_dir(route);
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("seen.") || !name.ends_with(".json") {
            continue;
        }
        let Ok(observation) = serde_json::from_slice::<AnchorObservation>(&fs::read(&path)?) else {
            continue;
        };
        if !observation.master.eq_ignore_ascii_case(master) {
            continue;
        }
        if check_signature(
            observation.signed_by.as_ref(),
            observation.signature.as_ref(),
            &observation_payload(&observation),
            &route.agents,
        ) == SignatureCheck::Valid
        {
            out.push(observation);
        }
    }
    out.sort_by_key(|observation| observation.observed_at);
    Ok(out)
}

/// Where a master's anchor stands on this project right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Nobody has checked, or nobody's check could be verified. The ordinary state
    /// for a fleet that has been offline, and it means nothing.
    NotChecked,
    Verified,
    /// The provider disagreed, and has not yet disagreed for long enough to bite.
    Contradicted { since: DateTime<Utc> },
    /// The provider disagreed and has kept disagreeing. The role is frozen.
    Paused { since: DateTime<Utc> },
}

/// The newest verifiable observation wins.
///
/// Newest rather than a quorum, and that cuts both ways on purpose. A member who
/// lies can pause a master - but only until any honest member's check lands, and
/// every member checks on a jitter, so the lie is overwritten rather than argued
/// with. A quorum would instead let one silent member hold a project open.
pub fn standing(route: &ProjectRoute, master: &str) -> Result<Standing> {
    let Some(latest) = observations(route, master)?.pop() else {
        return Ok(Standing::NotChecked);
    };
    if latest.outcome == Outcome::Verified {
        return Ok(Standing::Verified);
    }
    let Some(since) = latest.contradicted_since else {
        return Ok(Standing::NotChecked);
    };
    if Utc::now() - since >= chrono::Duration::hours(PAUSE_AFTER_HOURS) {
        Ok(Standing::Paused { since })
    } else {
        Ok(Standing::Contradicted { since })
    }
}

/// Whether `master`'s authority to hand out anything new is frozen.
///
/// Frozen, never vacated: `read_master` still names them and `initialize_master`
/// still refuses, so a paused project cannot be walked into. What a paused master
/// keeps is the ability to transfer the role, because that is the recovery path
/// and blocking it would strand a project whose account is genuinely gone.
pub fn is_paused(route: &ProjectRoute, master: &str) -> Result<bool> {
    Ok(matches!(standing(route, master)?, Standing::Paused { .. }))
}

/// The one line to put in front of an operation a paused master may not do.
pub fn refuse_if_paused(route: &ProjectRoute, master: &str, doing: &str) -> Result<()> {
    if let Standing::Paused { since } = standing(route, master)? {
        bail!(
            "{master}'s git anchor has not verified since {}, so this project will not {doing}. \
             Re-publish the key to the account, or transfer the role to a master who has claimed.",
            since.format("%Y-%m-%d")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A signature produced by real `ssh-keygen -Y sign`, over exactly these bytes,
    /// with namespace `ferryman-anchor`, and verified by real `ssh-keygen -Y verify`
    /// before it was pasted here.
    ///
    /// The end-to-end tests below build their own signatures, which would happily
    /// agree with a parser that had the format wrong in the same way twice. This one
    /// is the check on that: OpenSSH made it, and nothing here had a say.
    const REAL_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFM+bIb/EF6GCFALmua7hjXIybgrxGtBRERwVm77qNLy ferryman-anchor-fixture";
    const REAL_PAYLOAD: &str = "ferryman-anchor-v1\ngithub\n196700792\n00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const REAL_SIGNATURE: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgUz5shv8QXoYIUAua5ruGNcjJuC
vEa0FERHBWbvuo0vIAAAAPZmVycnltYW4tYW5jaG9yAAAAAAAAAAZzaGE1MTIAAABTAAAA
C3NzaC1lZDI1NTE5AAAAQHT0YLG8OpcBlhvVfj0zkc/yGKMP2sEx7dXBaXs9xow7uv1oyO
jKfZX/1IvIKtx+F2N1MKYGElhGZMb8TPh7oAU=
-----END SSH SIGNATURE-----
";

    #[test]
    fn a_real_ssh_keygen_signature_parses_and_verifies() {
        let key = parse_public_key(REAL_KEY).expect("a github .keys line is an authorized key");
        let parsed = parse_signature(REAL_SIGNATURE).expect("real ssh-keygen output parses");
        assert_eq!(parsed.public_key, key, "the signature carries its own key");
        assert_eq!(parsed.namespace, NAMESPACE);
        assert_eq!(parsed.hash_algorithm, "sha512");
        assert!(verify_sshsig(&parsed, REAL_PAYLOAD.as_bytes()));
    }

    /// The payload is built from the account id and the Ferryman key, so this is the
    /// property that stops a signature being reused for a different binding.
    #[test]
    fn one_changed_byte_breaks_the_real_signature() {
        let parsed = parse_signature(REAL_SIGNATURE).unwrap();
        let tampered = REAL_PAYLOAD.replace("196700792", "196700793");
        assert!(!verify_sshsig(&parsed, tampered.as_bytes()));
        assert!(!verify_sshsig(&parsed, format!("{REAL_PAYLOAD}\n").as_bytes()));
    }

    #[test]
    fn the_payload_is_what_the_fixture_signed() {
        assert_eq!(
            ssh_payload(
                "github",
                196_700_792,
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            ),
            REAL_PAYLOAD,
            "if this drifts, every anchor ever signed stops verifying"
        );
    }

    #[test]
    fn an_rsa_key_is_not_something_this_can_use() {
        assert!(parse_public_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB me@host").is_none());
        assert!(parse_public_key("").is_none());
        assert!(parse_public_key("ssh-ed25519 not-base64!!").is_none());
    }

    // --- building signatures, for the end-to-end tests ---

    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn b64_encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn key_blob(signing: &SigningKey) -> Vec<u8> {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &signing.verifying_key().to_bytes());
        blob
    }

    fn published_key(signing: &SigningKey) -> String {
        format!("ssh-ed25519 {} test@fixture", b64_encode(&key_blob(signing)))
    }

    fn make_sshsig(signing: &SigningKey, namespace: &str, message: &[u8]) -> String {
        let mut to_sign = Vec::from(*b"SSHSIG");
        put_string(&mut to_sign, namespace.as_bytes());
        put_string(&mut to_sign, b"");
        put_string(&mut to_sign, b"sha512");
        put_string(&mut to_sign, &Sha512::digest(message));

        let mut signature_blob = Vec::new();
        put_string(&mut signature_blob, b"ssh-ed25519");
        put_string(&mut signature_blob, &signing.sign(&to_sign).to_bytes());

        let mut out = Vec::from(*b"SSHSIG");
        out.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut out, &key_blob(signing));
        put_string(&mut out, namespace.as_bytes());
        put_string(&mut out, b"");
        put_string(&mut out, b"sha512");
        put_string(&mut out, &signature_blob);

        format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            b64_encode(&out)
        )
    }

    /// The fixture proves this helper agrees with OpenSSH: both go through the same
    /// parser, and the fixture's signature was made by neither of them.
    #[test]
    fn the_test_signer_agrees_with_openssh() {
        let signing = SigningKey::from_bytes(&[4u8; 32]);
        let armoured = make_sshsig(&signing, NAMESPACE, b"hello");
        let parsed = parse_signature(&armoured).expect("our own output parses");
        assert_eq!(
            parsed.public_key,
            parse_public_key(&published_key(&signing)).unwrap()
        );
        assert!(verify_sshsig(&parsed, b"hello"));
        assert!(!verify_sshsig(&parsed, b"hello "));
    }

    /// The key standing in for a github account across these tests.
    pub(super) fn test_account() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    pub(super) fn roster_entry(identity: &AgentIdentity) -> AgentRoute {
        AgentRoute {
            name: identity.name().to_owned(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }
    }

    /// An anchor as a master would actually hold one, with both halves real.
    pub(super) fn anchored(account: &SigningKey, identity: &AgentIdentity) -> GitAnchor {
        let mut anchor = GitAnchor {
            provider: "github".into(),
            account_id: 196_700_792,
            login: "estejosh".into(),
            account_type: AccountType::User,
            ferryman_key: identity.public_key_hex(),
            ssh_key: published_key(account),
            ssh_signature: String::new(),
            claimed_at: Utc::now(),
            evidence_url: "https://github.com/estejosh.keys".into(),
            evidence_read_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        anchor.ssh_signature = make_sshsig(
            account,
            NAMESPACE,
            ssh_payload("github", anchor.account_id, &anchor.ferryman_key).as_bytes(),
        );
        sign_anchor(&mut anchor, identity).unwrap();
        anchor
    }

    #[test]
    fn an_anchor_signed_on_both_sides_verifies() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let anchor = anchored(&account, &josh);
        assert_eq!(verify(&anchor, &[roster_entry(&josh)]), AnchorCheck::Valid);
    }

    /// The attack the two-way binding exists to stop: take a master's valid anchor,
    /// leave their signature untouched, and point it at a key of your own.
    #[test]
    fn an_anchor_cannot_be_repointed_at_a_key_that_did_not_sign_it() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);
        let mut anchor = anchored(&account, &josh);

        anchor.ferryman_key = mallory.public_key_hex();
        assert_eq!(
            verify(&anchor, &[roster_entry(&josh), roster_entry(&mallory)]),
            AnchorCheck::FerrymanSignature(SignatureCheck::Invalid),
            "the record signature covers the key, so editing it breaks that first"
        );

        // So she re-signs the record as herself, which is the interesting case: the
        // record is now perfectly signed, by her, and still claims josh's account.
        let mut hers = anchor.clone();
        hers.signed_by = None;
        hers.signature = None;
        let payload = anchor_payload(&hers);
        let signature = mallory.signing.sign(payload.as_bytes());
        hers.signed_by = Some("mallory".into());
        hers.signature = Some(hex::encode(signature.to_bytes()));
        assert_eq!(
            verify(&hers, &[roster_entry(&josh), roster_entry(&mallory)]),
            AnchorCheck::SshSignatureInvalid,
            "the account never signed anything naming mallory's key"
        );
    }

    /// A master must not be able to publish an anchor for somebody else's key.
    #[test]
    fn signing_an_anchor_for_a_key_that_is_not_yours_is_refused() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);
        let mut anchor = anchored(&account, &josh);
        let error = sign_anchor(&mut anchor, &mallory)
            .expect_err("mallory's key does not match this anchor")
            .to_string();
        assert!(error.contains("another key"), "{error}");
    }

    #[test]
    fn a_signature_made_for_another_purpose_does_not_count() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mut anchor = anchored(&account, &josh);
        anchor.ssh_signature = make_sshsig(
            &account,
            "git",
            ssh_payload("github", anchor.account_id, &anchor.ferryman_key).as_bytes(),
        );
        sign_anchor(&mut anchor, &josh).unwrap();
        assert_eq!(
            verify(&anchor, &[roster_entry(&josh)]),
            AnchorCheck::WrongNamespace,
            "a signature this person made to sign commits is not a claim on an account"
        );
    }

    #[test]
    fn a_signature_from_a_different_key_than_the_one_published_is_refused() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let other = SigningKey::from_bytes(&[6u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mut anchor = anchored(&account, &josh);
        anchor.ssh_signature = make_sshsig(
            &other,
            NAMESPACE,
            ssh_payload("github", anchor.account_id, &anchor.ferryman_key).as_bytes(),
        );
        sign_anchor(&mut anchor, &josh).unwrap();
        assert_eq!(
            verify(&anchor, &[roster_entry(&josh)]),
            AnchorCheck::SshSignatureIsFromAnotherKey
        );
    }

    /// The id is the identity. Moving a proven anchor onto another account is the
    /// same move as re-pointing the key, from the other end.
    #[test]
    fn an_anchor_cannot_be_moved_to_another_account() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let mut anchor = anchored(&account, &josh);
        anchor.account_id = 1;
        anchor.login = "somebody-else".into();
        sign_anchor(&mut anchor, &josh).unwrap();
        assert_eq!(
            verify(&anchor, &[roster_entry(&josh)]),
            AnchorCheck::SshSignatureInvalid
        );
    }

    #[test]
    fn an_anchor_from_a_stranger_is_not_verifiable_at_all() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let anchor = anchored(&account, &josh);
        assert_eq!(
            verify(&anchor, &[]),
            AnchorCheck::FerrymanSignature(SignatureCheck::UnknownSigner),
            "an anchor signed by a key nobody published proves nothing"
        );
    }

    #[test]
    fn an_anchor_round_trips_through_json() {
        let account = SigningKey::from_bytes(&[5u8; 32]);
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let anchor = anchored(&account, &josh);
        let text = serde_json::to_string(&anchor).unwrap();
        let back: GitAnchor = serde_json::from_str(&text).unwrap();
        assert_eq!(back, anchor);
        assert_eq!(verify(&back, &[roster_entry(&josh)]), AnchorCheck::Valid);
    }
}

#[cfg(test)]
mod watching {
    use super::tests::{anchored, roster_entry, test_account};
    use super::*;
    use ed25519_dalek::Signer;

    fn channel(dir: &std::path::Path, josh: &AgentIdentity) -> ProjectRoute {
        let workspace = dir.join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&communications).unwrap();
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "ferryman-ferryman".into(),
            git_remote: "git@github.com:estejosh/ferryman.git".into(),
            git_visibility: "private".into(),
            agents: vec![roster_entry(josh)],
        }
    }

    /// Back-date a standing contradiction, because a test cannot wait three days.
    fn age_the_contradiction(route: &ProjectRoute, observer: &AgentIdentity, hours: i64) {
        let path = observation_path(route, observer.name());
        let mut observation: AnchorObservation =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        observation.contradicted_since = Some(Utc::now() - chrono::Duration::hours(hours));
        // Re-sign, because the payload covers the date. Editing one WITHOUT signing
        // again is the forgery a test below relies on being caught.
        let signature = observer
            .signing
            .sign(observation_payload(&observation).as_bytes());
        observation.signature = Some(hex::encode(signature.to_bytes()));
        crate::atomic_json(&path, &observation).unwrap();
    }

    #[test]
    fn an_anchor_is_published_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);
        let anchor = anchored(&test_account(), &josh);

        publish(&route, &anchor).unwrap();
        assert_eq!(read_claim(&route, "josh").unwrap().as_ref(), Some(&anchor));
    }

    #[test]
    fn an_anchor_that_does_not_verify_is_not_published() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);
        let mut anchor = anchored(&test_account(), &josh);
        anchor.account_id = 7;
        sign_anchor(&mut anchor, &josh).unwrap();

        let error = publish(&route, &anchor)
            .expect_err("an unverifiable anchor reads as evidence and is not")
            .to_string();
        assert!(error.contains("does not verify"), "{error}");
    }

    #[test]
    fn nobody_checking_is_not_a_finding() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);
        assert_eq!(standing(&route, "josh").unwrap(), Standing::NotChecked);
        assert!(!is_paused(&route, "josh").unwrap());
    }

    /// The grace period is the whole difference between a pause and a tantrum.
    #[test]
    fn one_days_disagreement_does_not_pause_anything() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);

        record(
            &route,
            &josh,
            "josh",
            196_700_792,
            Outcome::Contradicted,
            "the key is not on the account",
        )
        .unwrap();
        assert!(matches!(
            standing(&route, "josh").unwrap(),
            Standing::Contradicted { .. }
        ));
        assert!(!is_paused(&route, "josh").unwrap());

        age_the_contradiction(&route, &josh, PAUSE_AFTER_HOURS - 1);
        assert!(!is_paused(&route, "josh").unwrap());

        age_the_contradiction(&route, &josh, PAUSE_AFTER_HOURS + 1);
        assert!(is_paused(&route, "josh").unwrap());
    }

    /// Checking again must not restart the clock, or the grace period never elapses
    /// and the pause never arrives - a bug that would look exactly like "it works".
    #[test]
    fn checking_again_keeps_the_date_the_disagreement_started() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);

        record(&route, &josh, "josh", 1, Outcome::Contradicted, "gone").unwrap();
        age_the_contradiction(&route, &josh, PAUSE_AFTER_HOURS + 1);
        let again = record(&route, &josh, "josh", 1, Outcome::Contradicted, "still gone").unwrap();

        assert!(
            Utc::now() - again.contradicted_since.unwrap()
                >= chrono::Duration::hours(PAUSE_AFTER_HOURS),
            "the second check must inherit the first check's date"
        );
        assert!(is_paused(&route, "josh").unwrap());
    }

    #[test]
    fn republishing_the_key_clears_the_pause() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);

        record(&route, &josh, "josh", 1, Outcome::Contradicted, "gone").unwrap();
        age_the_contradiction(&route, &josh, PAUSE_AFTER_HOURS + 1);
        assert!(is_paused(&route, "josh").unwrap());

        record(&route, &josh, "josh", 1, Outcome::Verified, "back").unwrap();
        assert_eq!(standing(&route, "josh").unwrap(), Standing::Verified);
        assert!(!is_paused(&route, "josh").unwrap());
    }

    /// A report that can freeze a project is worth forging, so it is signed and the
    /// signature is checked when it is read.
    #[test]
    fn an_unsigned_or_edited_report_freezes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);

        record(&route, &josh, "josh", 1, Outcome::Verified, "fine").unwrap();
        // Flip the verdict without re-signing, which is what an attacker with the
        // folder can actually do.
        let path = observation_path(&route, "josh");
        let mut observation: AnchorObservation =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        observation.outcome = Outcome::Contradicted;
        observation.contradicted_since = Some(Utc::now() - chrono::Duration::days(30));
        crate::atomic_json(&path, &observation).unwrap();

        assert_eq!(
            standing(&route, "josh").unwrap(),
            Standing::NotChecked,
            "an edited report is not a report"
        );
        assert!(!is_paused(&route, "josh").unwrap());
    }

    /// A stranger's report counts for nothing, because they are not on the roster
    /// and their signature resolves to no published key.
    #[test]
    fn somebody_not_on_the_project_cannot_freeze_it() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let route = channel(dir.path(), &josh);
        let mallory = AgentIdentity::from_seed("mallory", [9u8; 32]);

        record(&route, &mallory, "josh", 1, Outcome::Contradicted, "lies").unwrap();
        assert_eq!(standing(&route, "josh").unwrap(), Standing::NotChecked);
    }

    /// The newest verifiable check wins, so an honest machine overwrites a lying
    /// one rather than arguing with it.
    #[test]
    fn an_honest_check_lands_on_top_of_a_dishonest_one() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let grouchly = AgentIdentity::from_seed("josh-grouchly", [2u8; 32]);
        let mut route = channel(dir.path(), &josh);
        route.agents.push(roster_entry(&grouchly));

        record(&route, &grouchly, "josh", 1, Outcome::Contradicted, "lie").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        record(&route, &josh, "josh", 1, Outcome::Verified, "checked").unwrap();

        assert_eq!(standing(&route, "josh").unwrap(), Standing::Verified);
    }

    #[test]
    fn a_paused_master_cannot_grant_but_can_still_hand_over() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let bob = AgentIdentity::from_seed("bob", [3u8; 32]);
        let mut route = channel(dir.path(), &josh);
        route.agents.push(roster_entry(&bob));
        crate::master::initialize_master(&route, &josh, "josh").unwrap();

        record(&route, &josh, "josh", 1, Outcome::Contradicted, "gone").unwrap();
        age_the_contradiction(&route, &josh, PAUSE_AFTER_HOURS + 1);

        let error = crate::master::grant_member(
            &route,
            &josh,
            "bob",
            &bob.public_key_hex(),
            vec!["ferryman".into()],
            vec!["worker".into()],
            Vec::new(),
        )
        .expect_err("a paused master hands out nothing new")
        .to_string();
        assert!(error.contains("will not grant new access"), "{error}");

        // The recovery path has to stay open, or an account genuinely lost leaves a
        // project frozen for good.
        let moved = crate::master::transfer_master(&route, &josh, "bob")
            .expect("a paused master may still give the role away");
        assert_eq!(moved.master, "bob");
    }

    #[test]
    fn a_verified_master_grants_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let bob = AgentIdentity::from_seed("bob", [3u8; 32]);
        let mut route = channel(dir.path(), &josh);
        route.agents.push(roster_entry(&bob));
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        record(&route, &josh, "josh", 1, Outcome::Verified, "fine").unwrap();

        crate::master::grant_member(
            &route,
            &josh,
            "bob",
            &bob.public_key_hex(),
            vec!["ferryman".into()],
            vec!["worker".into()],
            Vec::new(),
        )
        .expect("nothing about a healthy anchor changes what a master can do");
    }
}

/// What a pause does to work in flight, which is the part most likely to be got
/// wrong by someone tightening this later.
#[cfg(test)]
mod paused_work {
    use super::tests::roster_entry;
    use super::*;
    use crate::AgentIdentity;
    use ed25519_dalek::Signer;

    fn project(dir: &std::path::Path, who: &[&AgentIdentity]) -> ProjectRoute {
        let workspace = dir.join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&communications).unwrap();
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "ferryman-ferryman".into(),
            git_remote: "git@github.com:estejosh/ferryman.git".into(),
            git_visibility: "private".into(),
            agents: who.iter().map(|i| roster_entry(i)).collect(),
        }
    }

    fn pause(route: &ProjectRoute, master: &AgentIdentity) {
        record(route, master, master.name(), 1, Outcome::Contradicted, "gone").unwrap();
        let path = observation_path(route, master.name());
        let mut observation: AnchorObservation =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        observation.contradicted_since =
            Some(Utc::now() - chrono::Duration::hours(PAUSE_AFTER_HOURS + 1));
        let signature = master
            .signing
            .sign(observation_payload(&observation).as_bytes());
        observation.signature = Some(hex::encode(signature.to_bytes()));
        crate::atomic_json(&path, &observation).unwrap();
        assert!(is_paused(route, master.name()).unwrap());
    }

    /// Signed, because `work_for` refuses to offer an order nobody signed - so an
    /// unsigned one would make this test pass or fail for the wrong reason.
    fn an_order(id: &str, from: &AgentIdentity, to: &str) -> crate::Order {
        let mut order = unsigned_order(id, from.name(), to);
        from.sign_order(&mut order);
        order
    }

    fn unsigned_order(id: &str, from: &str, to: &str) -> crate::Order {
        crate::Order {
            id: id.into(),
            project_id: "ferryman".into(),
            issued_by: from.into(),
            assigned_to: Some(to.into()),
            created_at: Utc::now(),
            payload: serde_json::json!({ "task": "do the thing" }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
        }
    }

    /// The whole point of pausing rather than stopping: work already under way
    /// finishes. Killing a fleet mid-task leaves repositories half-done.
    #[test]
    fn work_already_in_flight_runs_to_completion() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let fang = AgentIdentity::from_seed("fang", [2u8; 32]);
        let route = project(dir.path(), &[&josh, &fang]);
        crate::master::initialize_master(&route, &josh, "josh").unwrap();

        crate::issue_order(&route, &an_order("t-1", &josh, "fang")).unwrap();
        pause(&route, &josh);

        crate::claim_order(&route, "t-1", "fang").expect("a claim is not new work");
        assert!(
            !crate::work_for(&route, "fang").unwrap().is_empty(),
            "a paused master must not hide work its fleet already holds"
        );
    }

    #[test]
    fn a_paused_master_issues_no_new_orders() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let fang = AgentIdentity::from_seed("fang", [2u8; 32]);
        let route = project(dir.path(), &[&josh, &fang]);
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        pause(&route, &josh);

        let error = crate::issue_order(&route, &an_order("t-2", &josh, "fang"))
            .expect_err("the outgoing master points the fleet at nothing new")
            .to_string();
        assert!(error.contains("take new orders from you"), "{error}");
    }

    /// A paused master is not a paused project. Everybody else works as before,
    /// including issuing orders of their own under their own grant.
    #[test]
    fn everybody_else_carries_on() {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1u8; 32]);
        let fang = AgentIdentity::from_seed("fang", [2u8; 32]);
        let route = project(dir.path(), &[&josh, &fang]);
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        pause(&route, &josh);

        crate::issue_order(&route, &an_order("t-3", &fang, "fang"))
            .expect("an orchestrator's own orders are not the master's to pause");
    }

    /// A project with no master at all must not acquire one of these checks by
    /// accident: `issue_order` is on the hot path for every fleet that exists.
    #[test]
    fn a_project_with_no_master_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let fang = AgentIdentity::from_seed("fang", [2u8; 32]);
        let route = project(dir.path(), &[&fang]);
        crate::issue_order(&route, &an_order("t-4", &fang, "fang")).unwrap();
    }
}

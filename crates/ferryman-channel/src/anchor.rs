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

use std::fmt;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{AgentRoute, SignatureCheck, check_signature};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentIdentity;
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

    fn roster_entry(identity: &AgentIdentity) -> AgentRoute {
        AgentRoute {
            name: identity.name().to_owned(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }
    }

    /// An anchor as a master would actually hold one, with both halves real.
    fn anchored(account: &SigningKey, identity: &AgentIdentity) -> GitAnchor {
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

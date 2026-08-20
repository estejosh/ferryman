//! What the operator said, kept where the fleet can read it.
//!
//! # The gap this fills
//!
//! Ferryman had durable memory for everything except the one conversation that decides what
//! the work is. Orders, results, trajectories, the ledger and each agent's profile all live
//! in the synced channel. The operator's own words - the goal, the constraint, the "actually,
//! do it this way" - arrived over Telegram, went into one prompt, and were gone.
//!
//! Two things went wrong because of it, on the same afternoon. An agent asked the operator a
//! question, the operator answered it in the next message, and the answer arrived stripped of
//! the question: each run genuinely saw its message for the first time, so it asked again.
//! And nothing an agent on another machine did could be informed by any of it - the standing
//! goal for a project existed only in a chat window on a phone.
//!
//! A conversation is the unit a person thinks in. One message is only the unit the transport
//! happens to deliver in.
//!
//! # Why it is signed
//!
//! Not as a defence against the operator: the bridge accepts messages from one Telegram
//! account and nobody else, and that same identity can already issue signed orders, so
//! anything able to speak here could simply command the fleet instead. The signature is here
//! for what it does everywhere else in this channel - it makes the file an attributable
//! source rather than an anonymous one, so `ferry ask` can cite it, and a file that merely
//! *appears* in this directory by some other route is not read as something the operator
//! said.

use std::path::{Path, PathBuf};

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::memory::{ProfileAttestation, slugify};
use crate::{AgentIdentity, AgentRoute, SignatureCheck};

/// The format tag written into every conversation sidecar.
pub const CONVERSATION_FORMAT: &str = "ferryman.conversation.v1";

/// Where a project's conversations live inside its memory bank.
#[must_use]
pub fn conversations_dir(bank: &Path) -> PathBuf {
    bank.join("conversations")
}

/// One topic's file. Named by the topic, because that is the unit the operator sees.
#[must_use]
pub fn conversation_path(bank: &Path, topic: &str) -> PathBuf {
    conversations_dir(bank).join(format!("{}.md", slugify(topic)))
}

/// The detached signature beside it. Appended rather than substituted, so `<slug>.md` and
/// `<slug>.md.sig.json` can never collide with another topic's name.
#[must_use]
pub fn conversation_attestation_path(bank: &Path, topic: &str) -> PathBuf {
    let file = conversation_path(bank, topic);
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(".sig.json");
    file.with_file_name(name)
}

fn digest_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Collapse a turn onto one line.
///
/// The file is read back as a list of turns, so a newline inside one would read as the start
/// of the next. Keeping the whole thing on a line means the tail can be taken without
/// parsing anything.
fn one_line(said: &str) -> String {
    said.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Add a turn and re-sign, in that order.
///
/// The identity is required rather than optional, for the reason `append_agent_profile`
/// gives: an "append now, sign later" API has a window in which the file is unverifiable,
/// and something eventually takes that window as normal.
pub fn append_turn(
    bank: &Path,
    topic: &str,
    who: &str,
    said: &str,
    identity: &AgentIdentity,
) -> std::io::Result<()> {
    let path = conversation_path(bank, topic);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(
            file,
            "- {} **{}**: {}",
            Utc::now().format("%Y-%m-%dT%H:%MZ"),
            who,
            one_line(said)
        )?;
    }
    sign_conversation(bank, topic, identity)
}

/// Sign a conversation as it currently stands on disk.
pub fn sign_conversation(
    bank: &Path,
    topic: &str,
    identity: &AgentIdentity,
) -> std::io::Result<()> {
    let bytes = std::fs::read(conversation_path(bank, topic))?;
    let mut attestation = ProfileAttestation {
        format: CONVERSATION_FORMAT.to_string(),
        agent: slugify(topic),
        sha256: digest_of(&bytes),
        signed_by: None,
        signature: None,
    };
    identity.sign_profile_attestation(&mut attestation);
    let json = serde_json::to_vec_pretty(&attestation)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    std::fs::write(conversation_attestation_path(bank, topic), json)
}

/// Whether this conversation was written by someone the roster knows.
///
/// Unlike an agent profile, the signer is not expected to be named after the file: a topic
/// is not an agent, and the bridge signs on the operator's behalf. So the check is that the
/// bytes are the bytes that were signed, and that a key the roster accepts signed them.
#[must_use]
pub fn verify_conversation(bank: &Path, topic: &str, roster: &[AgentRoute]) -> SignatureCheck {
    let Ok(bytes) = std::fs::read(conversation_path(bank, topic)) else {
        return SignatureCheck::Unsigned;
    };
    let Ok(text) = std::fs::read_to_string(conversation_attestation_path(bank, topic)) else {
        return SignatureCheck::Unsigned;
    };
    let Ok(attestation) = serde_json::from_str::<ProfileAttestation>(&text) else {
        return SignatureCheck::Invalid;
    };
    if attestation.format != CONVERSATION_FORMAT {
        return SignatureCheck::Invalid;
    }
    // The signature covers a hash, so the hash must be the hash of what is actually there.
    // Skipping this would let a valid signature be replayed over edited content.
    if attestation.sha256 != digest_of(&bytes) {
        return SignatureCheck::Invalid;
    }
    if slugify(&attestation.agent) != slugify(topic) {
        return SignatureCheck::Invalid;
    }
    crate::check_signature(
        attestation.signed_by.as_ref(),
        attestation.signature.as_ref(),
        &crate::memory::attestation_payload_for(&attestation.agent, &attestation.sha256),
        roster,
    )
}

/// The whole conversation, if there is one.
#[must_use]
pub fn load_conversation(bank: &Path, topic: &str) -> Option<String> {
    std::fs::read_to_string(conversation_path(bank, topic)).ok()
}

/// The last `turns` turns, rendered for a prompt, but only if the file verifies.
///
/// Returns both, deliberately: a caller that forgets to look at the check is the shape of
/// bug the signature exists to prevent.
#[must_use]
pub fn recent_turns(
    bank: &Path,
    topic: &str,
    turns: usize,
    roster: &[AgentRoute],
) -> (String, SignatureCheck) {
    let check = verify_conversation(bank, topic, roster);
    let Some(text) = load_conversation(bank, topic) else {
        return (String::new(), check);
    };
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("- "))
        .collect();
    let tail = lines
        .iter()
        .skip(lines.len().saturating_sub(turns))
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    (tail, check)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(dir: &Path, name: &str) -> AgentIdentity {
        AgentIdentity::load_or_create(name, dir).expect("identity")
    }

    #[test]
    fn a_turn_is_kept_on_one_line_so_the_tail_can_be_read_back() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        append_turn(
            &bank,
            "Bullship",
            "Josh",
            "get bullship ready\nfor daily players",
            &id,
        )
        .expect("append");
        let text = load_conversation(&bank, "Bullship").expect("written");
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("get bullship ready for daily players"));
    }

    #[test]
    fn the_answer_to_a_question_still_has_the_question_above_it() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        append_turn(
            &bank,
            "Bullship",
            "Josh",
            "get bullship ready for daily players",
            &id,
        )
        .expect("one");
        append_turn(
            &bank,
            "Bullship",
            "you",
            "which machine holds bullship?",
            &id,
        )
        .expect("two");
        append_turn(&bank, "Bullship", "Josh", "bullship is on grouchly", &id).expect("three");
        let (recent, _) = recent_turns(&bank, "Bullship", 8, &[]);
        assert!(recent.contains("ready for daily players"));
        assert!(recent.contains("on grouchly"));
    }

    #[test]
    fn only_the_last_turns_are_recalled() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        for n in 0..12 {
            append_turn(&bank, "Ferryman", "Josh", &format!("message {n}"), &id).expect("append");
        }
        let (recent, _) = recent_turns(&bank, "Ferryman", 4, &[]);
        assert_eq!(recent.lines().count(), 4);
        assert!(recent.contains("message 11"));
        assert!(!recent.contains("message 7"));
    }

    #[test]
    fn editing_the_file_without_re_signing_stops_it_verifying() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        append_turn(&bank, "Bullship", "Josh", "the real instruction", &id).expect("append");
        std::fs::write(
            conversation_path(&bank, "Bullship"),
            "- 2026-01-01T00:00Z **Josh**: something he never said\n",
        )
        .expect("tamper");
        let roster = vec![AgentRoute {
            name: "telegram".to_string(),
            role: "bridge".to_string(),
            capabilities: Vec::new(),
            public_key: Some(id.public_key_hex()),
        }];
        assert!(matches!(
            verify_conversation(&bank, "Bullship", &roster),
            SignatureCheck::Invalid
        ));
    }
}

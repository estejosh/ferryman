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
use fs2::FileExt;
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

/// Serialize appends to one conversation on the local filesystem.
///
/// Two surfaces write this file through the same [`append_turn`] - the Telegram bridge and
/// the dashboard - and they can run as two processes on one machine. `append` itself is
/// one atomic write, but the read-back-and-resign that follows it is not: two writers can
/// each read a different snapshot of the file and write a sidecar that no longer matches
/// what is on disk. The bridge never met this because it is a single-threaded loop; the
/// dashboard is a multi-threaded server, so the lock is load-bearing now.
///
/// The lock lives beside the conversations, not in the non-synced attachment: [`append_turn`]
/// is given a bank, not a route, and a lock file is an empty, never-written marker that is
/// invisible to every reader that lists `*.md`. It serialises writers on one filesystem,
/// which is all a lock can do - it does not (and cannot) coordinate two machines that each
/// hold their own copy of a Syncthing folder. The cross-machine rule is the one the whole
/// channel already relies on: one writer per path, which here means the operator writes a
/// conversation from one machine at a time.
fn conversation_lock(bank: &Path) -> std::io::Result<std::fs::File> {
    let dir = conversations_dir(bank);
    std::fs::create_dir_all(&dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(".append.lock"))?;
    file.lock_exclusive()?;
    Ok(file)
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
    let _lock = conversation_lock(bank)?;
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

/// The topics that have a conversation, as their slugs.
///
/// The channel keeps a topic's name only as the slug it files under, because
/// [`conversation_path`] derives the filename from the topic and nothing stores the
/// original spelling. A dashboard listing conversations therefore shows slugs - the only
/// name the channel preserves - which are still the names a person gave their topics,
/// lowercased and dashed.
#[must_use]
pub fn list_conversations(bank: &Path) -> Vec<String> {
    let dir = conversations_dir(bank);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut topics = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("md"))
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    topics.sort();
    topics
}

/// One turn, parsed back out of the file it is stored in. Kept public so the dashboard
/// renders turns without knowing the line format; [`append_turn`] owns that format and the
/// dashboard should not have a second copy of it to drift out of step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationTurn {
    pub at: String,
    pub who: String,
    pub said: String,
}

/// Parse the turn lines out of a conversation file's text. Lines that do not look like a
/// turn are skipped, so an empty or foreign file yields no turns rather than a failure.
#[must_use]
pub fn parse_turns(text: &str) -> Vec<ConversationTurn> {
    text.lines().filter_map(parse_turn).collect()
}

fn parse_turn(line: &str) -> Option<ConversationTurn> {
    let rest = line.trim_start().strip_prefix("- ")?;
    let (at, rest) = rest.split_once(" **")?;
    let (who, said) = rest.split_once("**: ")?;
    Some(ConversationTurn {
        at: at.to_string(),
        who: who.to_string(),
        said: said.to_string(),
    })
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
            "Shop",
            "the operator",
            "get the shop ready\nfor daily players",
            &id,
        )
        .expect("append");
        let text = load_conversation(&bank, "Shop").expect("written");
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("get the shop ready for daily players"));
    }

    #[test]
    fn the_answer_to_a_question_still_has_the_question_above_it() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        append_turn(
            &bank,
            "Shop",
            "the operator",
            "get the shop ready for daily players",
            &id,
        )
        .expect("one");
        append_turn(&bank, "Shop", "you", "which machine holds the shop?", &id).expect("two");
        append_turn(
            &bank,
            "Shop",
            "the operator",
            "the shop is on the other machine",
            &id,
        )
        .expect("three");
        let (recent, _) = recent_turns(&bank, "Shop", 8, &[]);
        assert!(recent.contains("ready for daily players"));
        assert!(recent.contains("on the other machine"));
    }

    #[test]
    fn only_the_last_turns_are_recalled() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        for n in 0..12 {
            append_turn(
                &bank,
                "Ferryman",
                "the operator",
                &format!("message {n}"),
                &id,
            )
            .expect("append");
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
        append_turn(&bank, "Shop", "the operator", "the real instruction", &id).expect("append");
        std::fs::write(
            conversation_path(&bank, "Shop"),
            "- 2026-01-01T00:00Z **the operator**: something he never said\n",
        )
        .expect("tamper");
        let roster = vec![AgentRoute {
            name: "telegram".to_string(),
            role: "bridge".to_string(),
            capabilities: Vec::new(),
            public_key: Some(id.public_key_hex()),
            encryption_key: None,
        }];
        assert!(matches!(
            verify_conversation(&bank, "Shop", &roster),
            SignatureCheck::Invalid
        ));
    }

    #[test]
    fn turns_parse_back_out_of_a_written_file() {
        let text = "- 2026-08-20T21:30Z **the operator**: get the shop ready\n\
                    - 2026-08-20T21:35Z **you**: which machine holds the shop?\n\
                    - 2026-08-20T21:40Z **the operator**: the shop is on the other machine\n";
        let turns = parse_turns(text);
        assert_eq!(turns.len(), 3);
        assert_eq!(turns[0].who, "the operator");
        assert_eq!(turns[0].said, "get the shop ready");
        assert_eq!(turns[1].who, "you");
        assert_eq!(turns[1].at, "2026-08-20T21:35Z");
        assert_eq!(turns[2].said, "the shop is on the other machine");
    }

    #[test]
    fn a_turn_can_contain_a_colon_without_breaking_the_parse() {
        let text = "- 2026-08-20T21:40Z **the operator**: run: the tests, all of them\n";
        let turns = parse_turns(text);
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].said, "run: the tests, all of them");
    }

    #[test]
    fn listing_conversations_returns_slugs_and_ignores_sidecars() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bank = tmp.path().join("memory-bank");
        let id = identity(tmp.path(), "telegram");
        append_turn(&bank, "Shop", "the operator", "hello", &id).expect("append");
        append_turn(&bank, "My Project", "the operator", "hi", &id).expect("append");
        let topics = list_conversations(&bank);
        assert_eq!(topics, vec!["my-project", "shop"]);
    }
}

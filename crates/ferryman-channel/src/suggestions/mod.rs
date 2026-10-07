//! Outside suggestions: let anyone suggest an improvement to a product, through Ferryman,
//! under the owner's terms.
//!
//! A project's owner opens it to suggestions, and a stranger who has agreed to the owner's
//! terms can send one. The stranger never joins the private channel and never touches
//! Syncthing: suggestions travel through a *public inbox* the owner names (v1: a public
//! GitHub repository, one issue per suggestion), which is untrusted by construction. What
//! makes a suggestion believable is not where it was found but what is signed on it.
//!
//! ```text
//! owner (master)                public inbox (untrusted)            contributor
//! --------------                ------------------------            -----------
//! SUGGESTIONS record  --invite-->  TERMS.md, ferryman-suggest.json  <--join: verify, read, agree
//!   (signed, seq,                  issue + signed block        <--new: signed suggestion
//!    high-water)                   comments, labels                   + signed acceptance
//! intake: verify, limit, dedupe
//! triage: a model with no tools   -> verdict
//! owner decides (needs me)        -> signed answer, signed order, signed ledger
//! ```
//!
//! # Trust
//!
//! * The offer (project, inbox, terms hash, allowed types, caps) is signed by the project's
//!   master and carried both in the private channel (the [`record`]) and, as the signed
//!   [`record::Offer`], in the invite and in the inbox repository. A contributor's client
//!   checks that signature against the owner key the invite names, and pins that key.
//! * The terms the contributor reads are fetched from the inbox and must hash to the value
//!   the owner signed: a changed `TERMS.md` is refused, not shown.
//! * An [`contributor::Acceptance`] is signed by the contributor's own key over the project,
//!   the owner's key, the terms version and hash, their GitHub login and the time. A
//!   suggestion is only reviewed if its acceptance verifies, names the CURRENT terms hash,
//!   and the suggestion is signed by the same key. Nothing in the inbox is trusted beyond
//!   that: the human-readable issue text is a rendering and is never read by a model.
//! * Authority to act on a suggestion is the owner's, read at the time: the decision is a
//!   signed answer to a question in the private channel, the build is an ordinary signed
//!   order, and every step is a line in the signed, hash-chained ledger.
//!
//! Nothing here widens an existing authority check: the record is verified exactly like
//! `FOCUS` and `ENGINE_POLICY`, and the contributor's key is never added to a roster.

pub mod client;
pub mod contributor;
pub mod flow;
pub mod inbox;
pub mod intake;
pub mod invite;
pub mod publish;
pub mod record;
pub mod triage;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{AgentRoute, SignatureCheck, check_signature};

/// The question kind the owner's decisions are asked under.
pub use crate::questions::SUGGESTION as QUESTION_KIND;

/// A fresh unguessable token: the boundary around a contributor's words in a model's prompt.
#[must_use]
pub fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Lowercase hex SHA-256.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The canonical JSON of `value` without its top-level `signature`: what a signature covers,
/// after a one-line tag naming what is being signed.
pub(crate) fn sealed_payload<T: Serialize>(tag: &str, value: &T) -> String {
    let mut json = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    if let Some(object) = json.as_object_mut() {
        object.remove("signature");
    }
    format!("{tag}\n{}", serde_jcs::to_string(&json).unwrap_or_default())
}

/// Whether `signature` is `key`'s signature over `payload`. A roster of one: this is for
/// parties who are on no roster (the owner as the invite names them, a contributor).
pub(crate) fn verify_hex(name: &str, key: &str, payload: &str, signature: &str) -> bool {
    let only = AgentRoute {
        name: name.to_owned(),
        role: "signer".into(),
        capabilities: Vec::new(),
        public_key: Some(key.to_owned()),
        encryption_key: None,
    };
    check_signature(
        Some(&name.to_owned()),
        Some(&signature.to_owned()),
        payload,
        &[only],
    ) == SignatureCheck::Valid
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    for chunk in bytes.chunks(3) {
        let third = |index: usize| u32::from(chunk.get(index).copied().unwrap_or(0));
        let n = (third(0) << 16) | (third(1) << 8) | third(2);
        out.push(BASE64URL[(n >> 18) as usize & 63] as char);
        out.push(BASE64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL[n as usize & 63] as char);
        }
    }
    out
}

/// Unpadded (or padded) base64url.
pub(crate) fn b64_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' {
            continue;
        }
        let value = BASE64URL
            .iter()
            .position(|candidate| *candidate == byte)
            .context("that is not base64url text")?;
        acc = (acc << 6) | u32::try_from(value).unwrap_or(0);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            acc &= (1u32 << bits) - 1;
        }
    }
    Ok(out)
}

/// Whether `text` is a plausible GitHub login: what a contributor's login is checked against
/// before it is put into any order or credit line.
#[must_use]
pub fn is_login(text: &str) -> bool {
    (1..=39).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !text.starts_with('-')
}

/// Whether `c` changes what a reader sees, or what a model reads, without showing: text
/// direction overrides and isolates, zero-width and invisible separators, blank-looking
/// fillers, the byte-order mark and the invisible "tag" characters. Zero-width joiners and
/// variation selectors are left alone (emoji and several scripts need them).
#[must_use]
pub fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180E}'
            | '\u{200B}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// A text with control characters and hidden ones ([`is_hidden`]) removed (newline and tab
/// kept; the Unicode line and paragraph separators become newlines) and cut to `max`
/// characters.
#[must_use]
pub(crate) fn clean(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| !is_hidden(*c))
        .map(|c| {
            if matches!(c, '\u{2028}' | '\u{2029}') {
                '\n'
            } else {
                c
            }
        })
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .take(max)
        .collect()
}

/// A text for a person's terminal or a one-line label: [`clean`], on one line.
#[must_use]
pub fn plain(text: &str, max: usize) -> String {
    clean(text, max.saturating_mul(2))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

/// Whether `text` has a character that must not be in text a person is asked to agree to:
/// a control character (an escape sequence can rewrite what a terminal shows) other than
/// newline, carriage return and tab, or a hidden one ([`is_hidden`]).
#[must_use]
pub fn has_hidden_text(text: &str) -> bool {
    text.chars()
        .any(|c| is_hidden(c) || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
}

/// `text` with links made unclickable (`://` and `www.` broken), for showing a stranger's
/// words to the owner where an app would turn them into links.
#[must_use]
pub fn defang(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut rest = text;
    while !rest.is_empty() {
        if rest.starts_with("://") {
            out.push_str("[:]//");
            rest = &rest[3..];
        } else if rest.len() >= 4 && rest.as_bytes()[..4].eq_ignore_ascii_case(b"www.") {
            out.push_str(&rest[..3]);
            out.push_str("[.]");
            rest = &rest[4..];
        } else if let Some(first) = rest.chars().next() {
            out.push(first);
            rest = &rest[first.len_utf8()..];
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_every_length() {
        for length in 0..40usize {
            let bytes: Vec<u8> = (0..length)
                .map(|index| u8::try_from((index * 37 + 11) % 256).unwrap())
                .collect();
            let text = b64_encode(&bytes);
            assert!(!text.contains('=') && !text.contains('+') && !text.contains('/'));
            assert_eq!(b64_decode(&text).unwrap(), bytes, "length {length}");
        }
        assert!(b64_decode("not base64 !").is_err());
    }

    #[test]
    fn hidden_and_direction_changing_characters_are_removed_or_refused() {
        let sneaky =
            "pay\u{202E}live\u{200B}\u{2066}x\u{2069}\u{FEFF}\u{E0041}\u{E0069}ok\u{1b}[2J\u{7}";
        assert_eq!(clean(sneaky, 100), "payliveXok[2J".replace('X', "x"));
        assert!(has_hidden_text(sneaky));
        assert!(has_hidden_text("a\u{1b}[8mb"), "an escape sequence");
        assert!(has_hidden_text("a\u{85}b"), "a C1 control");
        assert!(!has_hidden_text(
            "plain\r\n\ttext, and an emoji \u{1F468}\u{200D}\u{1F469}\u{FE0F}"
        ));
        assert_eq!(clean("a\u{2028}b\u{2029}c", 10), "a\nb\nc");
        assert_eq!(plain("one\n two\t\u{202E}three", 100), "one two three");
        assert_eq!(plain(&"x".repeat(500), 10).chars().count(), 10);
    }

    #[test]
    fn links_are_defanged_for_the_owner() {
        let text = defang("see https://evil.example/x and HTTP://A.B and www.x.y, WWW.Z.Q");
        assert!(
            !text.contains("://") && !text.to_ascii_lowercase().contains("www."),
            "{text}"
        );
        assert!(text.contains("evil.example"));
        assert_eq!(defang("naïve ünïcode ✓"), "naïve ünïcode ✓");
    }

    #[test]
    fn logins_are_checked() {
        assert!(is_login("octo-cat"));
        assert!(!is_login(""));
        assert!(!is_login("-bad"));
        assert!(!is_login("a b"));
        assert!(!is_login("`rm`"));
        assert!(!is_login(&"a".repeat(40)));
    }
}

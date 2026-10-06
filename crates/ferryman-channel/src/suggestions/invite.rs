//! The invite: one line a person (or their agent) pastes to `ferry suggest join`.
//!
//! ```text
//! ferry-suggest:<base64url of {"v":1,"offer":{...the owner's signed offer...}}>
//! ```
//!
//! The offer inside carries the product's name, the inbox, which terms file is meant (and
//! its sha256), the owner's public key and the owner's signature over all of it. A client
//! that decodes an invite checks that signature against the key the invite itself names,
//! so a changed name, inbox or terms hash is refused. The key is then *pinned*: it is what
//! every later offer for that project must be signed by. An invite is how a contributor
//! first learns who the owner is, so it is worth passing on a channel the owner controls
//! (their repository's README does) and the client shows the key's fingerprint to compare.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::record::Offer;
use super::{b64_decode, b64_encode};

/// What an invite starts with, so a person or an agent can tell what it is.
pub const PREFIX: &str = "ferry-suggest:";
const MAX_INVITE: usize = 24 * 1024;

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u32,
    offer: Offer,
}

/// A decoded invite whose signature has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub offer: Offer,
}

impl Invite {
    /// The invite for `offer`.
    #[must_use]
    pub fn new(offer: &Offer) -> Self {
        Self {
            offer: offer.clone(),
        }
    }

    /// The one line.
    #[must_use]
    pub fn encode(&self) -> String {
        let wire = Wire {
            v: 1,
            offer: self.offer.clone(),
        };
        let json = serde_json::to_vec(&wire).unwrap_or_default();
        format!("{PREFIX}{}", b64_encode(&json))
    }

    /// Decode an invite and check the owner's signature on what it carries.
    ///
    /// # Errors
    /// Text that is not an invite, an offer that does not verify against the key it names,
    /// or one this version does not understand.
    pub fn decode(text: &str) -> Result<Self> {
        let text = text.trim();
        let body = text.strip_prefix(PREFIX).unwrap_or(text);
        if body.is_empty() || body.len() > MAX_INVITE || body.contains(char::is_whitespace) {
            bail!("that is not a Ferryman suggestion invite (it is one line starting `{PREFIX}`)");
        }
        let bytes = b64_decode(body).context("that is not a Ferryman suggestion invite")?;
        let wire: Wire = serde_json::from_slice(&bytes)
            .context("that is not a Ferryman suggestion invite: it does not parse")?;
        if wire.v != 1 {
            bail!("this invite is version {}; update ferry to read it", wire.v);
        }
        if !wire.offer.verify() {
            bail!(
                "the invite does not verify against the owner's key it names: it was edited, \
                 or it is not from that owner. Do not use it"
            );
        }
        super::inbox::InboxRef::parse(&wire.offer.inbox)?;
        Ok(Self { offer: wire.offer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggestions::record::tests as rt;

    #[test]
    fn an_invite_round_trips_and_names_the_owner_it_is_signed_by() {
        let dir = tempfile::tempdir().unwrap();
        let josh = rt::person("josh", 1);
        let route = rt::route(dir.path(), &[&josh]);
        let record = rt::open_it(&route, &josh);
        let line = Invite::new(&record.offer).encode();
        assert!(line.starts_with(PREFIX) && !line.contains(char::is_whitespace));
        let back = Invite::decode(&line).unwrap();
        assert_eq!(back.offer, record.offer);
        assert_eq!(back.offer.owner_key, josh.public_key_hex());
        // With stray whitespace, or without the prefix, it is the same invite.
        assert!(Invite::decode(&format!("  {line}\n")).is_ok());
        assert!(Invite::decode(line.strip_prefix(PREFIX).unwrap()).is_ok());
    }

    #[test]
    fn an_edited_or_foreign_invite_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let josh = rt::person("josh", 1);
        let route = rt::route(dir.path(), &[&josh]);
        let record = rt::open_it(&route, &josh);
        // The name, the inbox and the terms hash are all under the signature.
        let mut renamed = record.offer.clone();
        renamed.display_name = "Something Else".into();
        assert!(Invite::decode(&Invite::new(&renamed).encode()).is_err());
        let mut moved = record.offer.clone();
        moved.inbox = "github:mallory/ideas".into();
        assert!(Invite::decode(&Invite::new(&moved).encode()).is_err());
        let mut swapped = record.offer.clone();
        swapped.terms.sha256 = "0".repeat(64);
        assert!(Invite::decode(&Invite::new(&swapped).encode()).is_err());
        // Someone else's key swapped in is a good signature by the wrong party: it verifies,
        // and it is the pin (and the fingerprint the person compares) that catches it.
        for junk in [
            "",
            "ferry-suggest:",
            "not an invite",
            "ferry-suggest:!!!",
            "a b c",
        ] {
            assert!(Invite::decode(junk).is_err(), "{junk:?}");
        }
        assert!(Invite::decode(&"A".repeat(MAX_INVITE + 1)).is_err());
    }
}

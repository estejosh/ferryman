//! The contributor's side: a key of their own, a signed agreement to the owner's terms, and
//! signed suggestions, replies and withdrawals.
//!
//! A contributor is on no roster and never will be. Their key signs three things the owner's
//! side checks: an [`Acceptance`] (this person, with this key and this GitHub login, agreed
//! to *this* version of *these* terms, offered by *this* owner, at this time), a
//! [`Suggestion`] (bound to that acceptance), and later a [`Reply`] or [`Withdrawal`]. The
//! key lives in a file in the contributor's own state directory; it is never printed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::record::Offer;
use super::{clean, is_hidden, is_login, sealed_payload, sha256_hex, verify_hex};
use crate::AgentIdentity;

/// What a contributor types to agree. Nothing else counts, and there is no default-yes.
pub const ACCEPT_PHRASE: &str = "I agree";
pub const ACCEPTANCE_FORMAT: &str = "ferryman-acceptance/v1";
pub const SUGGESTION_FORMAT: &str = "ferryman-suggestion/v1";
pub const REPLY_FORMAT: &str = "ferryman-reply/v1";
pub const WITHDRAW_FORMAT: &str = "ferryman-withdraw/v1";
/// The name a contributor's key is checked under: it is on no roster, only on a roster of one.
const SIGNER: &str = "contributor";
/// Longest reply.
pub const REPLY_MAX: usize = 1000;

macro_rules! signed {
    ($ty:ident, $tag:literal, $format:expr) => {
        impl $ty {
            /// Exactly what `signature` covers.
            #[must_use]
            pub fn payload(&self) -> String {
                sealed_payload($tag, self)
            }

            /// Whether the contributor's key signed this, over exactly what it says.
            #[must_use]
            pub fn verify(&self) -> bool {
                self.format == $format
                    && verify_hex(
                        SIGNER,
                        &self.contributor_key,
                        &self.payload(),
                        &self.signature,
                    )
            }
        }
    };
}

/// A contributor's signed agreement to one version of an owner's terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acceptance {
    pub format: String,
    pub project_id: String,
    pub inbox: String,
    /// The owner's key as the offer named it: the agreement is with this owner.
    pub owner_key: String,
    pub terms_version: u32,
    pub terms_sha256: String,
    pub contributor_key: String,
    pub contributor_login: String,
    /// What was typed (`I agree`), or `--agree <sha256>` for the flag.
    pub phrase: String,
    /// How consent was given: `typed` at a terminal, or `flag` (`--agree <sha256>` of the
    /// text shown). The owner's record shows which.
    pub accepted_via: String,
    pub accepted_at: DateTime<Utc>,
    pub signature: String,
}
signed!(Acceptance, "ferryman-acceptance-v1", ACCEPTANCE_FORMAT);

impl Acceptance {
    /// A hash that names this exact acceptance, signature included: what a suggestion binds to.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(format!("{}\n{}", self.payload(), self.signature).as_bytes())
    }
}

/// A signed suggestion, bound to an acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    pub format: String,
    pub id: String,
    pub project_id: String,
    pub kind: String,
    pub fields: BTreeMap<String, String>,
    pub contributor_key: String,
    pub contributor_login: String,
    pub created_at: DateTime<Utc>,
    pub terms_sha256: String,
    pub acceptance_digest: String,
    pub signature: String,
}
signed!(Suggestion, "ferryman-suggestion-v1", SUGGESTION_FORMAT);

fn squash(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

impl Suggestion {
    /// What two suggestions have to share to be the same one said twice.
    #[must_use]
    pub fn content_hash(&self) -> String {
        let get = |id: &str| squash(self.fields.get(id).map_or("", String::as_str));
        sha256_hex(format!("{}|{}|{}", self.kind, get("title"), get("pitch")).as_bytes())
    }

    /// `title`, as one line.
    #[must_use]
    pub fn title(&self) -> String {
        clean(self.fields.get("title").map_or("", String::as_str), 200).replace('\n', " ")
    }
}

/// The contributor's answer to a clarifying question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub format: String,
    pub suggestion_id: String,
    pub project_id: String,
    /// Which round of questions this answers: how many rounds the owner's side had asked.
    pub round: u32,
    pub text: String,
    pub contributor_key: String,
    pub contributor_login: String,
    pub created_at: DateTime<Utc>,
    pub signature: String,
}
signed!(Reply, "ferryman-reply-v1", REPLY_FORMAT);

/// The contributor taking a suggestion back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub format: String,
    pub suggestion_id: String,
    pub project_id: String,
    pub reason: String,
    pub contributor_key: String,
    pub contributor_login: String,
    pub created_at: DateTime<Utc>,
    pub signature: String,
}
signed!(Withdrawal, "ferryman-withdraw-v1", WITHDRAW_FORMAT);

/// What goes in the machine-readable block of an issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub suggestion: Suggestion,
    pub acceptance: Acceptance,
}

/// How a contributor agrees. There is no default-yes: either they type the phrase, or a
/// script names the hash of the exact text that was shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent<'a> {
    /// They typed this at a terminal; it must be the agreement phrase.
    Typed(&'a str),
    /// `--agree <sha256>`: the hash of the terms text that was shown, so a script cannot
    /// agree to a text it never displayed.
    Flag(&'a str),
}

/// Agree to `offer`'s terms. The offer must be genuinely the owner's.
///
/// # Errors
/// An offer that does not verify, a login that is not one, a phrase that is not exactly
/// the agreement phrase, or a hash that is not the terms' hash.
pub fn accept(
    identity: &AgentIdentity,
    offer: &Offer,
    login: &str,
    consent: Consent<'_>,
    now: DateTime<Utc>,
) -> Result<Acceptance> {
    if !offer.verify() {
        bail!("the offer does not verify against the owner's key, so it is not agreed to");
    }
    if !is_login(login) {
        bail!("'{login}' is not a GitHub login");
    }
    let (phrase, via) = match consent {
        Consent::Typed(typed) => {
            if !typed.trim().eq_ignore_ascii_case(ACCEPT_PHRASE) {
                bail!("not agreed: to agree, type exactly `{ACCEPT_PHRASE}`");
            }
            (ACCEPT_PHRASE.to_string(), "typed")
        }
        Consent::Flag(hash) => {
            if !hash.trim().eq_ignore_ascii_case(&offer.terms.sha256) {
                bail!(
                    "not agreed: --agree must be the sha256 of the terms you were shown ({}), \
                     not '{}'",
                    offer.terms.sha256,
                    hash.trim()
                );
            }
            (format!("--agree {}", offer.terms.sha256), "flag")
        }
    };
    let mut acceptance = Acceptance {
        format: ACCEPTANCE_FORMAT.to_string(),
        project_id: offer.project_id.clone(),
        inbox: offer.inbox.clone(),
        owner_key: offer.owner_key.clone(),
        terms_version: offer.terms.version,
        terms_sha256: offer.terms.sha256.clone(),
        contributor_key: identity.public_key_hex(),
        contributor_login: login.to_string(),
        phrase,
        accepted_via: via.to_string(),
        accepted_at: now,
        signature: String::new(),
    };
    acceptance.signature = identity.sign_bytes(acceptance.payload().as_bytes());
    Ok(acceptance)
}

/// Whether `acceptance` is this contributor's, for exactly the terms `offer` now names.
#[must_use]
pub fn acceptance_current(acceptance: &Acceptance, offer: &Offer) -> bool {
    acceptance.verify()
        && acceptance.project_id == offer.project_id
        && acceptance.inbox == offer.inbox
        && acceptance.owner_key == offer.owner_key
        && acceptance.terms_version == offer.terms.version
        && acceptance.terms_sha256 == offer.terms.sha256
}

/// Sign a suggestion. Refuses without a current acceptance, and refuses what the owner's
/// side would refuse: fields over their caps, an unknown kind, an offer that is closed.
///
/// # Errors
/// Every reason, one per line.
pub fn compose(
    identity: &AgentIdentity,
    offer: &Offer,
    acceptance: Option<&Acceptance>,
    kind: &str,
    fields: &BTreeMap<String, String>,
    now: DateTime<Utc>,
) -> Result<Suggestion> {
    let Some(acceptance) = acceptance else {
        bail!("you have not agreed to this project's terms yet: run `ferry suggest join <invite>`");
    };
    if !acceptance_current(acceptance, offer) {
        bail!(
            "your agreement is to an earlier version of the terms (or another owner's): run \
             `ferry suggest join <invite>` and read the current ones"
        );
    }
    if acceptance.contributor_key != identity.public_key_hex() {
        bail!("this agreement was signed with a different key than the one in use");
    }
    if !offer.is_open() {
        bail!("{} is not taking suggestions right now", offer.display_name);
    }
    let fields: BTreeMap<String, String> = fields
        .iter()
        .map(|(id, value)| (id.clone(), value.trim().to_string()))
        .filter(|(_, value)| !value.is_empty())
        .collect();
    let problems = offer.check_fields(kind, &fields);
    if !problems.is_empty() {
        bail!("{}", problems.join("\n"));
    }
    let mut suggestion = Suggestion {
        format: SUGGESTION_FORMAT.to_string(),
        id: uuid::Uuid::new_v4().to_string(),
        project_id: offer.project_id.clone(),
        kind: kind.to_string(),
        fields,
        contributor_key: identity.public_key_hex(),
        contributor_login: acceptance.contributor_login.clone(),
        created_at: now,
        terms_sha256: offer.terms.sha256.clone(),
        acceptance_digest: acceptance.digest(),
        signature: String::new(),
    };
    suggestion.signature = identity.sign_bytes(suggestion.payload().as_bytes());
    Ok(suggestion)
}

/// Sign a reply to the owner's clarifying questions.
///
/// # Errors
/// An empty or over-long reply.
pub fn compose_reply(
    identity: &AgentIdentity,
    login: &str,
    suggestion: &Suggestion,
    round: u32,
    text: &str,
    now: DateTime<Utc>,
) -> Result<Reply> {
    let text = text.trim();
    if text.is_empty() {
        bail!("a reply needs words");
    }
    if text.chars().count() > REPLY_MAX {
        bail!("a reply is at most {REPLY_MAX} characters");
    }
    if text
        .chars()
        .any(|c| is_hidden(c) || (c.is_control() && !matches!(c, '\n' | '\t')))
    {
        bail!("a reply cannot have control, zero-width or text-direction characters in it");
    }
    let mut reply = Reply {
        format: REPLY_FORMAT.to_string(),
        suggestion_id: suggestion.id.clone(),
        project_id: suggestion.project_id.clone(),
        round,
        text: text.to_string(),
        contributor_key: identity.public_key_hex(),
        contributor_login: login.to_string(),
        created_at: now,
        signature: String::new(),
    };
    reply.signature = identity.sign_bytes(reply.payload().as_bytes());
    Ok(reply)
}

/// Sign a withdrawal.
#[must_use]
pub fn compose_withdrawal(
    identity: &AgentIdentity,
    login: &str,
    suggestion: &Suggestion,
    reason: &str,
    now: DateTime<Utc>,
) -> Withdrawal {
    let mut withdrawal = Withdrawal {
        format: WITHDRAW_FORMAT.to_string(),
        suggestion_id: suggestion.id.clone(),
        project_id: suggestion.project_id.clone(),
        reason: clean(reason.trim(), 300),
        contributor_key: identity.public_key_hex(),
        contributor_login: login.to_string(),
        created_at: now,
        signature: String::new(),
    };
    withdrawal.signature = identity.sign_bytes(withdrawal.payload().as_bytes());
    withdrawal
}

// --- the contributor's own state ---------------------------------------------------------

/// A suggestion this contributor sent, as they remember it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent {
    pub project_id: String,
    pub inbox: String,
    pub issue: u64,
    pub url: String,
    pub suggestion: Suggestion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pin {
    owner_key: String,
    inbox: String,
    seq: u64,
}

/// The contributor's key, the owners they have pinned, their agreements and what they sent:
/// a directory of their own, nowhere near any channel.
pub struct ContributorStore {
    dir: PathBuf,
}

impl ContributorStore {
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// `FERRYMAN_SUGGEST_DIR`, or `suggest` in this machine's state directory.
    ///
    /// # Errors
    /// A machine with neither.
    pub fn default_dir() -> Result<PathBuf> {
        if let Ok(dir) = std::env::var("FERRYMAN_SUGGEST_DIR")
            && !dir.trim().is_empty()
        {
            return Ok(PathBuf::from(dir));
        }
        crate::licensing::machine_state_dir()
            .map(|dir| dir.join("suggest"))
            .context("this machine has no state directory; set FERRYMAN_SUGGEST_DIR")
    }

    /// This contributor's key, made the first time. The seed stays in the file.
    ///
    /// # Errors
    /// A directory that cannot be written, or a key file that is not a key.
    pub fn identity(&self) -> Result<AgentIdentity> {
        let path = self.dir.join("contributor.key");
        if path.is_file() {
            let text = std::fs::read_to_string(&path).context("read the contributor key")?;
            let bytes =
                hex::decode(text.trim()).context("the contributor key file is not a key")?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("the contributor key file is not a key"))?;
            return Ok(AgentIdentity::from_seed(SIGNER, seed));
        }
        std::fs::create_dir_all(&self.dir)?;
        let mut seed = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
        // Made private from the first byte (never world-readable for an instant), and never
        // over a key another run made a moment ago: that one is used instead.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&path) {
            Ok(mut file) => {
                std::io::Write::write_all(&mut file, hex::encode(seed).as_bytes())
                    .context("write the contributor key")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return self.identity();
            }
            Err(error) => return Err(error).context("create the contributor key"),
        }
        crate::restrict_to_owner(&path)?;
        Ok(AgentIdentity::from_seed(SIGNER, seed))
    }

    fn file(&self, folder: &str, project: &str) -> Result<PathBuf> {
        if !crate::is_safe_component(project) {
            bail!("'{project}' is not a project id");
        }
        Ok(self.dir.join(folder).join(format!("{project}.json")))
    }

    fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    /// Remember the owner's key for this project the first time it is seen, and refuse a
    /// different key afterwards or an offer older than one already seen.
    ///
    /// # Errors
    /// A key that changed, or an offer that went back.
    pub fn pin_owner(&self, offer: &Offer) -> Result<()> {
        let mut pin = self.check_owner(offer)?;
        let path = self.file("owners", &offer.project_id)?;
        pin.seq = offer.seq;
        crate::atomic_json(&path, &pin)
    }

    /// [`Self::pin_owner`] without remembering anything: whether `offer` is acceptable as
    /// the next word from the owner this project was joined under.
    ///
    /// # Errors
    /// A key that changed, or an offer that went back.
    fn check_owner(&self, offer: &Offer) -> Result<Pin> {
        let path = self.file("owners", &offer.project_id)?;
        let pin = Self::read::<Pin>(&path).unwrap_or(Pin {
            owner_key: offer.owner_key.clone(),
            inbox: offer.inbox.clone(),
            seq: 0,
        });
        if pin.owner_key != offer.owner_key || pin.inbox != offer.inbox {
            bail!(
                "this is not the owner you first joined {} under: the key or the inbox changed. \
                 If the owner really moved, confirm it with them another way, then remove {} and \
                 join again",
                offer.project_id,
                path.display()
            );
        }
        if offer.seq < pin.seq {
            bail!(
                "this offer (sequence {}) is older than one you have already seen (sequence {}): \
                 someone is replaying an old copy",
                offer.seq,
                pin.seq
            );
        }
        Ok(pin)
    }

    /// Whether `offer` could be pinned: its owner is the one joined under and it is not older
    /// than one already seen. Remembers nothing.
    ///
    /// # Errors
    /// A key that changed, or an offer that went back.
    pub fn check(&self, offer: &Offer) -> Result<()> {
        self.check_owner(offer).map(|_| ())
    }

    /// Keep the offer and the terms text that was read, so `new` can say what was agreed to.
    ///
    /// # Errors
    /// A directory that cannot be written.
    pub fn save_offer(&self, offer: &Offer, terms_text: &str) -> Result<()> {
        crate::atomic_json(
            &self.file("offers", &offer.project_id)?,
            &serde_json::json!({ "offer": offer, "terms_text": terms_text }),
        )
    }

    /// The offer last agreed to for the project, if it still verifies.
    #[must_use]
    pub fn offer(&self, project: &str) -> Option<Offer> {
        let value: serde_json::Value = Self::read(&self.file("offers", project).ok()?)?;
        let offer: Offer = serde_json::from_value(value.get("offer")?.clone()).ok()?;
        offer.verify().then_some(offer)
    }

    /// The projects this contributor has joined.
    #[must_use]
    pub fn projects(&self) -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(self.dir.join("owners"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_suffix(".json")
                    .map(str::to_string)
            })
            .collect();
        found.sort();
        found
    }

    /// The agreement this contributor made to the project, if it verifies.
    #[must_use]
    pub fn acceptance(&self, project: &str) -> Option<Acceptance> {
        let acceptance: Acceptance = Self::read(&self.file("acceptances", project).ok()?)?;
        acceptance.verify().then_some(acceptance)
    }

    /// Keep an agreement.
    ///
    /// # Errors
    /// A directory that cannot be written.
    pub fn save_acceptance(&self, acceptance: &Acceptance) -> Result<()> {
        crate::atomic_json(
            &self.file("acceptances", &acceptance.project_id)?,
            acceptance,
        )
    }

    /// Remember a suggestion that was sent.
    ///
    /// # Errors
    /// A directory that cannot be written.
    pub fn remember(&self, sent: Sent) -> Result<()> {
        let path = self.file("sent", &sent.project_id)?;
        let mut all: Vec<Sent> = Self::read(&path).unwrap_or_default();
        all.retain(|old| old.issue != sent.issue);
        all.push(sent);
        crate::atomic_json(&path, &all)
    }

    /// What this contributor sent to the project.
    #[must_use]
    pub fn sent(&self, project: &str) -> Vec<Sent> {
        self.file("sent", project)
            .ok()
            .and_then(|path| Self::read(&path))
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::suggestions::record::{self, Limits, TriageConfig, tests as rt};

    pub(crate) fn offer_and_owner(dir: &Path) -> (record::SuggestionsRecord, AgentIdentity) {
        let josh = rt::person("josh", 1);
        let route = rt::route(dir, &[&josh]);
        (rt::open_it(&route, &josh), josh)
    }

    pub(crate) fn fields(title: &str) -> BTreeMap<String, String> {
        [
            ("title", title),
            (
                "pitch",
                "Let the offline timer show what you would have earned.",
            ),
            ("why", "It fits the idle loop."),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
    }

    #[test]
    fn agreeing_takes_the_phrase_and_a_forged_offer_is_not_agreed_to() {
        let dir = tempfile::tempdir().unwrap();
        let (record, _) = offer_and_owner(dir.path());
        let store = ContributorStore::open(&dir.path().join("me"));
        let me = store.identity().unwrap();
        let now = Utc::now();
        for wrong in ["", "yes", "y", "I agree.", "agree"] {
            assert!(
                accept(&me, &record.offer, "octo", Consent::Typed(wrong), now).is_err(),
                "{wrong:?}"
            );
        }
        let agreed = accept(&me, &record.offer, "octo", Consent::Typed(" i AGREE "), now).unwrap();
        assert!(agreed.verify());
        assert!(acceptance_current(&agreed, &record.offer));
        assert_eq!(agreed.terms_sha256, record.offer.terms.sha256);
        assert!(
            accept(
                &me,
                &record.offer,
                "bad login",
                Consent::Typed(ACCEPT_PHRASE),
                now
            )
            .is_err()
        );
        // An offer edited after the owner signed it is not agreed to.
        let mut edited = record.offer.clone();
        edited.limits = Limits {
            open_per_contributor: 20,
            ..Limits::default()
        };
        assert!(accept(&me, &edited, "octo", Consent::Typed(ACCEPT_PHRASE), now).is_err());
        // The flag path: only the hash of the text that was shown agrees.
        assert!(accept(&me, &record.offer, "octo", Consent::Flag("deadbeef"), now).is_err());
        assert!(
            accept(
                &me,
                &record.offer,
                "octo",
                Consent::Flag(ACCEPT_PHRASE),
                now
            )
            .is_err()
        );
        let flagged = accept(
            &me,
            &record.offer,
            "octo",
            Consent::Flag(&record.offer.terms.sha256),
            now,
        )
        .unwrap();
        assert_eq!(flagged.accepted_via, "flag");
        assert!(flagged.verify() && acceptance_current(&flagged, &record.offer));
        assert_eq!(agreed.accepted_via, "typed");
        let _ = TriageConfig::default();
        // An acceptance edited after signing does not verify.
        let mut tampered = agreed.clone();
        tampered.contributor_login = "someone-else".into();
        assert!(!tampered.verify());
    }

    #[test]
    fn a_suggestion_needs_a_current_acceptance_and_fits_the_caps() {
        let dir = tempfile::tempdir().unwrap();
        let (record, josh) = offer_and_owner(dir.path());
        let store = ContributorStore::open(&dir.path().join("me"));
        let me = store.identity().unwrap();
        let now = Utc::now();
        let offer = &record.offer;
        assert!(
            compose(&me, offer, None, "idea", &fields("Offline timer"), now)
                .unwrap_err()
                .to_string()
                .contains("ferry suggest join")
        );
        let agreed = accept(&me, offer, "octo", Consent::Typed(ACCEPT_PHRASE), now).unwrap();
        let suggestion = compose(
            &me,
            offer,
            Some(&agreed),
            "idea",
            &fields("Offline timer"),
            now,
        )
        .unwrap();
        assert!(suggestion.verify());
        assert_eq!(suggestion.acceptance_digest, agreed.digest());
        assert_eq!(suggestion.contributor_login, "octo");
        // Over the cap: refused, saying how far.
        let long = compose(
            &me,
            offer,
            Some(&agreed),
            "idea",
            &fields(&"x".repeat(81)),
            now,
        );
        assert!(long.unwrap_err().to_string().contains("limit is 80"));
        // New terms: the old agreement no longer counts for a new submission.
        let newer = record::set_terms(
            &dir.path().join("idle-ish-ferryman"),
            rt::PROJECT,
            &josh,
            "Different terms.\n",
            false,
            now,
        )
        .unwrap();
        let stale = compose(
            &me,
            &newer.offer,
            Some(&agreed),
            "idea",
            &fields("Offline timer"),
            now,
        );
        assert!(stale.unwrap_err().to_string().contains("earlier version"));
        // A closed project takes nothing.
        record::close(
            &dir.path().join("idle-ish-ferryman"),
            rt::PROJECT,
            &josh,
            now,
        )
        .unwrap();
        let closed = record::current(&dir.path().join("idle-ish-ferryman"), rt::PROJECT).unwrap();
        let again = accept(
            &me,
            &closed.offer,
            "octo",
            Consent::Typed(ACCEPT_PHRASE),
            now,
        )
        .unwrap();
        assert!(compose(&me, &closed.offer, Some(&again), "idea", &fields("t"), now).is_err());
    }

    #[test]
    fn the_key_is_made_once_kept_private_and_never_shown() {
        let dir = tempfile::tempdir().unwrap();
        let store = ContributorStore::open(dir.path());
        let first = store.identity().unwrap();
        let second = store.identity().unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());
        let seed = hex::encode(first.seed_bytes());
        assert!(!format!("{first:?}").contains(&seed));
    }

    #[test]
    fn the_owner_is_pinned_and_a_changed_key_or_an_older_offer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (record, josh) = offer_and_owner(dir.path());
        let store = ContributorStore::open(&dir.path().join("me"));
        store.pin_owner(&record.offer).unwrap();
        store.pin_owner(&record.offer).unwrap();
        let channel = dir.path().join("idle-ish-ferryman");
        let newer = record::close(&channel, rt::PROJECT, &josh, Utc::now()).unwrap();
        assert!(newer);
        let closed = record::current(&channel, rt::PROJECT).unwrap();
        store.pin_owner(&closed.offer).unwrap();
        let replay = store.pin_owner(&record.offer);
        assert!(replay.unwrap_err().to_string().contains("older"));
        // The same project and inbox, signed by a different key.
        let other = rt::person("mallory", 9);
        let mut forged = closed.offer.clone();
        forged.owner = "mallory".into();
        forged.owner_key = other.public_key_hex();
        forged.signature = other.sign_bytes(forged.payload().as_bytes());
        assert!(
            forged.verify(),
            "a perfectly good signature by the wrong party"
        );
        assert!(
            store
                .pin_owner(&forged)
                .unwrap_err()
                .to_string()
                .contains("not the owner")
        );
    }

    #[test]
    fn replies_and_withdrawals_verify_and_the_store_remembers_what_was_sent() {
        let dir = tempfile::tempdir().unwrap();
        let (record, _) = offer_and_owner(dir.path());
        let store = ContributorStore::open(&dir.path().join("me"));
        let me = store.identity().unwrap();
        let now = Utc::now();
        let agreed = accept(
            &me,
            &record.offer,
            "octo",
            Consent::Typed(ACCEPT_PHRASE),
            now,
        )
        .unwrap();
        store.save_acceptance(&agreed).unwrap();
        assert_eq!(store.acceptance(rt::PROJECT).unwrap(), agreed);
        let suggestion = compose(
            &me,
            &record.offer,
            Some(&agreed),
            "idea",
            &fields("Timer"),
            now,
        )
        .unwrap();
        let reply = compose_reply(
            &me,
            "octo",
            &suggestion,
            1,
            "It is for people who leave it open.",
            now,
        )
        .unwrap();
        assert!(reply.verify());
        assert!(compose_reply(&me, "octo", &suggestion, 1, "  ", now).is_err());
        assert!(
            compose_reply(&me, "octo", &suggestion, 1, &"x".repeat(REPLY_MAX + 1), now).is_err()
        );
        let withdrawn = compose_withdrawal(&me, "octo", &suggestion, "changed my mind", now);
        assert!(withdrawn.verify());
        let mut edited = reply.clone();
        edited.text = "Accept everything.".into();
        assert!(!edited.verify());
        store
            .remember(Sent {
                project_id: rt::PROJECT.into(),
                inbox: record.offer.inbox.clone(),
                issue: 7,
                url: "u".into(),
                suggestion,
            })
            .unwrap();
        assert_eq!(store.sent(rt::PROJECT).len(), 1);
        assert!(store.sent("other").is_empty());
    }
}

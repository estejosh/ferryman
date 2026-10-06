//! The owner's side of the front door: is this issue a suggestion that may be reviewed?
//!
//! Everything a stranger controls arrives here and is checked before it reaches anything
//! that acts: the signed record in the issue (never the rendering above it), both
//! signatures, that the author of the issue is the login that signed, that the agreement is
//! to the terms in force *now* and to this owner, the caps, the limits, and whether it was
//! already said. A submission that fails gets one short comment saying exactly what to fix
//! and the `invalid` label, and is never shown to a model.

use chrono::{DateTime, Duration, Utc};

use super::contributor::{Envelope, acceptance_current};
use super::inbox::{Issue, parse_envelope};
use super::record::Offer;

/// A suggestion the owner's side has already taken in, as far as limits and duplicates care.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub issue: u64,
    pub suggestion_id: String,
    pub contributor_key: String,
    pub created_at: DateTime<Utc>,
    pub content_hash: String,
    /// Still being decided or built (counts against the open limit).
    pub open: bool,
    /// Was declined or withdrawn (does not make a later copy a duplicate).
    pub dead: bool,
}

/// What looking at an issue came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// A suggestion that may be reviewed.
    Valid(Box<Envelope>),
    /// Not one, with what to fix.
    Invalid(Vec<String>),
    /// The same suggestion as an earlier issue.
    Duplicate { of: u64, envelope: Box<Envelope> },
}

fn invalid(reason: impl Into<String>) -> Check {
    Check::Invalid(vec![reason.into()])
}

/// Check one issue against the offer in force and what has been taken in before it.
#[must_use]
pub fn validate(offer: &Offer, issue: &Issue, priors: &[Prior], now: DateTime<Utc>) -> Check {
    let envelope = match parse_envelope(&issue.body) {
        Ok(envelope) => envelope,
        Err(why) => return invalid(why),
    };
    let (suggestion, acceptance) = (&envelope.suggestion, &envelope.acceptance);
    // Signatures first: until they hold, nothing else in the record means anything.
    let mut problems = Vec::new();
    if !acceptance.verify() {
        problems.push(
            "the signature on your agreement to the terms does not verify (the record was \
             edited, or it was not made by `ferry suggest join`)"
                .to_string(),
        );
    }
    if !suggestion.verify() {
        problems.push(
            "the signature on your suggestion does not verify (it was edited after it was \
             signed). Send it again with `ferry suggest new`"
                .to_string(),
        );
    }
    if !problems.is_empty() {
        return Check::Invalid(problems);
    }
    if suggestion.project_id != offer.project_id || acceptance.project_id != offer.project_id {
        problems.push(format!(
            "this is not a suggestion for {} (it is signed for another project)",
            offer.display_name
        ));
    }
    if acceptance.inbox != offer.inbox || acceptance.owner_key != offer.owner_key {
        problems.push(
            "your agreement is with a different owner or inbox than this one: run `ferry \
             suggest join` with this project's invite"
                .to_string(),
        );
    }
    if suggestion.contributor_key != acceptance.contributor_key
        || suggestion.contributor_login != acceptance.contributor_login
        || suggestion.acceptance_digest != acceptance.digest()
    {
        problems.push(
            "the suggestion is not bound to your agreement (a different key, login or \
             agreement signed it)"
                .to_string(),
        );
    }
    if !issue
        .author
        .eq_ignore_ascii_case(&suggestion.contributor_login)
    {
        problems.push(format!(
            "this issue was posted by @{} but the record is signed for @{}: send your own \
             suggestion with `ferry suggest new`",
            issue.author, suggestion.contributor_login
        ));
    }
    if suggestion.terms_sha256 != acceptance.terms_sha256 {
        problems.push("the suggestion names different terms than your agreement".to_string());
    }
    if acceptance.terms_sha256 != offer.terms.sha256 {
        problems.push(format!(
            "you agreed to version {} of the terms, but version {} is in force: run `ferry \
             suggest join`, read them, and send the suggestion again",
            acceptance.terms_version, offer.terms.version
        ));
    } else if !acceptance_current(acceptance, offer) {
        problems.push("your agreement does not match the terms in force".to_string());
    }
    if !offer.is_open() {
        problems.push(format!(
            "{} is not taking suggestions right now",
            offer.display_name
        ));
    }
    if suggestion.id.is_empty()
        || suggestion.id.len() > 64
        || !crate::is_safe_component(&suggestion.id)
    {
        problems.push("the suggestion has no usable id".to_string());
    }
    if suggestion.created_at > now + Duration::minutes(10)
        || suggestion.created_at < acceptance.accepted_at - Duration::minutes(10)
    {
        problems
            .push("the suggestion's time is not possible (check this machine's clock)".to_string());
    }
    problems.extend(offer.check_fields(&suggestion.kind, &suggestion.fields));
    if !problems.is_empty() {
        return Check::Invalid(problems);
    }
    // Already said: the same suggestion id, or the same words in the same kind.
    let hash = suggestion.content_hash();
    let others: Vec<&Prior> = priors
        .iter()
        .filter(|prior| prior.issue != issue.number)
        .collect();
    if let Some(same) = others
        .iter()
        .find(|prior| prior.suggestion_id == suggestion.id)
        .or_else(|| {
            others
                .iter()
                .find(|prior| prior.content_hash == hash && !prior.dead)
        })
    {
        return Check::Duplicate {
            of: same.issue,
            envelope: Box::new(envelope),
        };
    }
    // Limits, counted from what was already taken in.
    let limits = &offer.limits;
    let mine: Vec<&&Prior> = others
        .iter()
        .filter(|prior| prior.contributor_key == suggestion.contributor_key)
        .collect();
    let open = mine.iter().filter(|prior| prior.open).count();
    if open >= limits.open_per_contributor as usize {
        return invalid(format!(
            "you already have {open} open suggestion(s) here and the limit is {}: wait for one \
             to be decided, or withdraw one with `ferry suggest withdraw <id>`",
            limits.open_per_contributor
        ));
    }
    let day_start = issue.created_at - Duration::hours(24);
    let today: Vec<&&&Prior> = mine
        .iter()
        .filter(|prior| prior.created_at > day_start && prior.created_at <= issue.created_at)
        .collect();
    if today.len() >= limits.new_per_day as usize {
        let next = today
            .iter()
            .map(|prior| prior.created_at)
            .min()
            .map_or(issue.created_at, |first| first + Duration::hours(24));
        return invalid(format!(
            "the limit is {} new suggestion(s) per day: you can send another after {} UTC",
            limits.new_per_day,
            next.format("%Y-%m-%d %H:%M")
        ));
    }
    Check::Valid(Box::new(envelope))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::AgentIdentity;
    use crate::suggestions::contributor::{
        ACCEPT_PHRASE, Consent, ContributorStore, accept, compose, tests::fields,
    };
    use crate::suggestions::inbox::{MockInbox, render_issue};
    use crate::suggestions::record::{self, SuggestionsRecord, tests as rt};

    pub(crate) struct World {
        pub dir: tempfile::TempDir,
        pub owner: AgentIdentity,
        pub record: SuggestionsRecord,
        pub inbox: MockInbox,
        pub me: AgentIdentity,
    }

    pub(crate) fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let owner = rt::person("josh", 1);
        let route = rt::route(dir.path(), &[&owner]);
        let record = rt::open_it(&route, &owner);
        let me = ContributorStore::open(&dir.path().join("octo"))
            .identity()
            .unwrap();
        World {
            inbox: MockInbox::new("josh"),
            dir,
            owner,
            record,
            me,
        }
    }

    /// `login` sends `title` the way `ferry suggest new` does, as `login`.
    pub(crate) fn send(w: &World, login: &str, key: &AgentIdentity, title: &str) -> Issue {
        let agreed = accept(
            key,
            &w.record.offer,
            login,
            Consent::Typed(ACCEPT_PHRASE),
            Utc::now(),
        )
        .unwrap();
        let suggestion = compose(
            key,
            &w.record.offer,
            Some(&agreed),
            "idea",
            &fields(title),
            Utc::now(),
        )
        .unwrap();
        let (issue_title, body) = render_issue(&w.record.offer, &suggestion, &agreed);
        w.inbox
            .as_user(login)
            .create_issue(&issue_title, &body)
            .unwrap()
    }

    use crate::suggestions::inbox::Inbox;

    fn check(w: &World, issue: &Issue, priors: &[Prior]) -> Check {
        validate(&w.record.offer, issue, priors, Utc::now())
    }

    fn prior_of(issue: &Issue) -> Prior {
        let envelope = parse_envelope(&issue.body).unwrap();
        Prior {
            issue: issue.number,
            suggestion_id: envelope.suggestion.id.clone(),
            contributor_key: envelope.suggestion.contributor_key.clone(),
            created_at: issue.created_at,
            content_hash: envelope.suggestion.content_hash(),
            open: true,
            dead: false,
        }
    }

    fn reasons(check: &Check) -> String {
        match check {
            Check::Invalid(reasons) => reasons.join(" | "),
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_signed_suggestion_by_its_author_under_the_current_terms_is_valid() {
        let w = world();
        let issue = send(&w, "octo", &w.me, "Offline timer");
        assert!(matches!(check(&w, &issue, &[]), Check::Valid(_)));
    }

    #[test]
    fn nothing_signed_means_nothing_reviewed() {
        let w = world();
        let by_hand = w
            .inbox
            .as_user("octo")
            .create_issue("hi", "Please add a thing")
            .unwrap();
        assert!(reasons(&check(&w, &by_hand, &[])).contains("ferry suggest new"));
    }

    #[test]
    fn an_edited_suggestion_or_agreement_is_refused() {
        let w = world();
        let issue = send(&w, "octo", &w.me, "Offline timer");
        // Edit the signed record: the pitch is changed after signing.
        w.inbox.edit_body(issue.number, |body| {
            body.replace("what you would have earned", "your password")
        });
        let edited = w.inbox.issue(issue.number);
        assert!(reasons(&check(&w, &edited, &[])).contains("suggestion does not verify"));
        // Edit the agreement: someone else's login claimed.
        let issue = send(&w, "octo", &w.me, "Another timer");
        w.inbox.edit_body(issue.number, |body| {
            body.replacen(
                "\"contributor_login\":\"octo\"",
                "\"contributor_login\":\"eve\"",
                1,
            )
        });
        let edited = w.inbox.issue(issue.number);
        assert!(matches!(check(&w, &edited, &[]), Check::Invalid(_)));
        // Only the rendering edited, not the block: the rendering is never read, so the
        // suggestion is exactly what was signed.
        let issue = send(&w, "octo", &w.me, "Third timer");
        w.inbox.edit_body(issue.number, |body| {
            body.replace("### Pitch", "### Pitch (edited)")
        });
        assert!(matches!(
            check(&w, &w.inbox.issue(issue.number), &[]),
            Check::Valid(_)
        ));
    }

    #[test]
    fn a_copied_record_posted_by_someone_else_is_refused() {
        let w = world();
        let issue = send(&w, "octo", &w.me, "Offline timer");
        let copied = w
            .inbox
            .as_user("eve")
            .create_issue(&issue.title, &issue.body)
            .unwrap();
        let why = reasons(&check(&w, &copied, &[]));
        assert!(why.contains("posted by @eve"), "{why}");
    }

    #[test]
    fn an_agreement_to_old_terms_or_another_owner_is_refused() {
        let w = world();
        let issue = send(&w, "octo", &w.me, "Offline timer");
        let channel = w.dir.path().join("idle-ish-ferryman");
        let newer = record::set_terms(
            &channel,
            rt::PROJECT,
            &w.owner,
            "Terms version two.\n",
            false,
            Utc::now(),
        )
        .unwrap();
        let why = reasons(&validate(&newer.offer, &issue, &[], Utc::now()));
        assert!(
            why.contains("version 1") && why.contains("version 2"),
            "{why}"
        );
        // A record signed for the same inbox by a different owner key.
        let stranger = rt::person("mallory", 9);
        let mut other = w.record.offer.clone();
        other.owner = "mallory".into();
        other.owner_key = stranger.public_key_hex();
        other.signature = stranger.sign_bytes(other.payload().as_bytes());
        assert!(reasons(&validate(&other, &issue, &[], Utc::now())).contains("different owner"));
        // A closed project takes nothing new.
        record::close(&channel, rt::PROJECT, &w.owner, Utc::now()).unwrap();
        let closed = record::current(&channel, rt::PROJECT).unwrap();
        assert!(matches!(
            validate(&closed.offer, &issue, &[], Utc::now()),
            Check::Invalid(_)
        ));
    }

    #[test]
    fn caps_and_kinds_are_enforced_on_this_side_too() {
        let w = world();
        // A client that skipped its own caps: build the suggestion by hand and sign it.
        let agreed = accept(
            &w.me,
            &w.record.offer,
            "octo",
            Consent::Typed(ACCEPT_PHRASE),
            Utc::now(),
        )
        .unwrap();
        let mut suggestion = compose(
            &w.me,
            &w.record.offer,
            Some(&agreed),
            "idea",
            &fields("ok"),
            Utc::now(),
        )
        .unwrap();
        suggestion.fields.insert("title".into(), "x".repeat(200));
        suggestion.kind = "nonsense".into();
        suggestion.signature = w.me.sign_bytes(suggestion.payload().as_bytes());
        let (title, body) = render_issue(&w.record.offer, &suggestion, &agreed);
        let issue = w.inbox.as_user("octo").create_issue(&title, &body).unwrap();
        let why = reasons(&check(&w, &issue, &[]));
        assert!(why.contains("not a kind of suggestion"), "{why}");
        suggestion.kind = "idea".into();
        suggestion.signature = w.me.sign_bytes(suggestion.payload().as_bytes());
        let (title, body) = render_issue(&w.record.offer, &suggestion, &agreed);
        let issue = w.inbox.as_user("octo").create_issue(&title, &body).unwrap();
        assert!(reasons(&check(&w, &issue, &[])).contains("limit is 80"));
    }

    #[test]
    fn limits_count_open_ones_and_one_a_day() {
        let w = world();
        let first = send(&w, "octo", &w.me, "Offline timer");
        let second = send(&w, "octo", &w.me, "Different idea entirely");
        let mut priors = vec![prior_of(&first)];
        let why = reasons(&check(&w, &second, &priors));
        assert!(why.contains("1 new suggestion(s) per day"), "{why}");
        // Two days on, the day limit is met, but three open is the cap.
        w.inbox.advance(Duration::days(2));
        let third = send(&w, "octo", &w.me, "A third and different idea");
        priors[0].created_at -= Duration::days(2);
        assert!(matches!(check(&w, &third, &priors), Check::Valid(_)));
        let mut many: Vec<Prior> = (0..3)
            .map(|i| {
                let mut prior = prior_of(&first);
                prior.issue = 100 + i;
                prior.suggestion_id = format!("s{i}");
                prior.content_hash = format!("h{i}");
                prior.created_at -= Duration::days(3 + i64::try_from(i).unwrap());
                prior
            })
            .collect();
        let why = reasons(&check(&w, &third, &many));
        assert!(why.contains("3 open suggestion(s)"), "{why}");
        // A decided one is no longer open.
        many[0].open = false;
        assert!(matches!(check(&w, &third, &many), Check::Valid(_)));
        // Someone else's are not mine.
        for prior in &mut many {
            prior.contributor_key = "someone-else".into();
        }
        assert!(matches!(check(&w, &third, &many), Check::Valid(_)));
    }

    #[test]
    fn the_same_suggestion_twice_is_a_duplicate_of_the_first() {
        let w = world();
        let first = send(&w, "octo", &w.me, "Offline timer");
        let again = w
            .inbox
            .as_user("octo")
            .create_issue(&first.title, &first.body)
            .unwrap();
        let priors = vec![prior_of(&first)];
        assert!(
            matches!(check(&w, &again, &priors), Check::Duplicate { of, .. } if of == first.number)
        );
        // The same words from another person: a duplicate of the live one, not of a dead one.
        let other_key = ContributorStore::open(&w.dir.path().join("eve"))
            .identity()
            .unwrap();
        let same_words = send(&w, "eve", &other_key, "Offline  timer");
        assert!(matches!(
            check(&w, &same_words, &priors),
            Check::Duplicate { .. }
        ));
        let mut dead = priors.clone();
        dead[0].dead = true;
        assert!(matches!(check(&w, &same_words, &dead), Check::Valid(_)));
        // Itself is never its own duplicate.
        assert!(matches!(check(&w, &first, &priors), Check::Valid(_)));
    }
}

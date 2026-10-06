use std::collections::BTreeMap;

use super::*;
use crate::suggestions::contributor::{ACCEPT_PHRASE, tests::fields};
use crate::suggestions::inbox::{self, MockInbox, parse_envelope};
use crate::suggestions::intake::tests::{World, world};
use crate::suggestions::publish;
use crate::suggestions::record;
use crate::suggestions::record::tests as rt;

struct Joiner {
    w: World,
    store: ContributorStore,
    inbox: MockInbox,
    invite: String,
}

/// An owner who has published the join page, and a contributor with nothing yet.
fn joiner() -> Joiner {
    let w = world();
    publish::publish(&w.inbox, &w.record.offer, &w.record.terms_text).unwrap();
    let store = ContributorStore::open(&w.dir.path().join("octo"));
    let invite = Invite::new(&w.record.offer).encode();
    let inbox = w.inbox.as_user("octo");
    Joiner {
        w,
        store,
        inbox,
        invite,
    }
}

fn join_typed(j: &Joiner) -> Agreed {
    let joined = prepare_join(&j.store, &j.inbox, &j.invite).unwrap();
    agree(
        &j.store,
        &j.inbox,
        &joined,
        "octo",
        Consent::Typed(ACCEPT_PHRASE),
        Utc::now(),
    )
    .unwrap()
}

#[test]
fn joining_verifies_the_owner_shows_the_terms_and_records_a_typed_agreement() {
    let j = joiner();
    let joined = prepare_join(&j.store, &j.inbox, &j.invite).unwrap();
    assert!(joined.first_time);
    assert_eq!(joined.terms_text, j.w.record.terms_text);
    assert_eq!(joined.offer.owner_key, j.w.owner.public_key_hex());
    // Looking is not agreeing: nothing is remembered yet.
    assert!(j.store.acceptance(rt::PROJECT).is_none() && j.store.projects().is_empty());
    let agreed = agree(
        &j.store,
        &j.inbox,
        &joined,
        "octo",
        Consent::Typed(ACCEPT_PHRASE),
        Utc::now(),
    )
    .unwrap();
    assert_eq!(agreed.acceptance.accepted_via, "typed");
    assert_eq!(j.store.acceptance(rt::PROJECT).unwrap(), agreed.acceptance);
    assert_eq!(j.store.projects(), [rt::PROJECT]);
    assert!(
        !prepare_join(&j.store, &j.inbox, &j.invite)
            .unwrap()
            .first_time
    );
}

#[test]
fn nothing_is_agreed_to_without_the_phrase_or_the_hash_that_was_shown() {
    let j = joiner();
    let joined = prepare_join(&j.store, &j.inbox, &j.invite).unwrap();
    let now = Utc::now();
    for wrong in ["", "yes", "ok", "I agree."] {
        assert!(
            agree(
                &j.store,
                &j.inbox,
                &joined,
                "octo",
                Consent::Typed(wrong),
                now
            )
            .is_err()
        );
    }
    assert!(
        agree(
            &j.store,
            &j.inbox,
            &joined,
            "octo",
            Consent::Flag("not-the-hash"),
            now
        )
        .is_err()
    );
    assert!(agree(&j.store, &j.inbox, &joined, "octo", Consent::Flag(""), now).is_err());
    assert!(
        j.store.acceptance(rt::PROJECT).is_none(),
        "a refused agreement leaves nothing behind"
    );
    let flagged = agree(
        &j.store,
        &j.inbox,
        &joined,
        "octo",
        Consent::Flag(&joined.offer.terms.sha256),
        now,
    )
    .unwrap();
    assert_eq!(flagged.acceptance.accepted_via, "flag");
    assert!(
        flagged
            .acceptance
            .phrase
            .contains(&joined.offer.terms.sha256)
    );
}

#[test]
fn terms_changed_after_the_owner_signed_are_refused_not_shown() {
    let j = joiner();
    j.w.inbox
        .write_file("TERMS.md", "You also give us your house.\n", "edit")
        .unwrap();
    let error = prepare_join(&j.store, &j.inbox, &j.invite)
        .unwrap_err()
        .to_string();
    assert!(error.contains("changed after the owner signed"), "{error}");
}

#[test]
fn an_offer_in_the_inbox_from_someone_else_is_not_the_owners() {
    let j = joiner();
    let other = rt::person("mallory", 9);
    let mut forged = j.w.record.offer.clone();
    forged.owner = "mallory".into();
    forged.owner_key = other.public_key_hex();
    forged.display_name = "Idle-ish".into();
    forged.signature = other.sign_bytes(forged.payload().as_bytes());
    let page = publish::machine_page(&forged, &Invite::new(&forged).encode());
    j.w.inbox
        .write_file("ferryman-suggest.json", &page.to_string(), "evil")
        .unwrap();
    let error = prepare_join(&j.store, &j.inbox, &j.invite)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not signed by the owner this invite names"),
        "{error}"
    );
    // And an invite that is not an invite is refused before the inbox is even read.
    assert!(prepare_join(&j.store, &j.inbox, "ferry-suggest:AAAA").is_err());
}

#[test]
fn a_joined_owner_cannot_be_swapped_for_another_later() {
    let j = joiner();
    join_typed(&j);
    let other = rt::person("mallory", 9);
    let mut forged = j.w.record.offer.clone();
    forged.owner = "mallory".into();
    forged.owner_key = other.public_key_hex();
    forged.signature = other.sign_bytes(forged.payload().as_bytes());
    // The inbox's page is the real owner's, so the invite does not match it...
    assert!(prepare_join(&j.store, &j.inbox, &Invite::new(&forged).encode()).is_err());
    // ...and where the inbox has no page to disagree, the pin is what refuses.
    let bare = MockInbox::new("estejosh").as_user("octo");
    let error = prepare_join(&j.store, &bare, &Invite::new(&forged).encode()).unwrap_err();
    assert!(
        format!("{error:#}").contains("not the owner you first joined"),
        "{error:#}"
    );
}

fn idea(title: &str) -> (String, BTreeMap<String, String>) {
    ("idea".to_string(), fields(title))
}

#[test]
fn a_suggestion_is_refused_before_joining_and_sent_after() {
    let j = joiner();
    let (kind, fields) = idea("Offline timer");
    let early = send(&j.store, &j.inbox, rt::PROJECT, &kind, &fields, Utc::now());
    assert!(early.is_err());
    join_typed(&j);
    let sent = send(&j.store, &j.inbox, rt::PROJECT, &kind, &fields, Utc::now()).unwrap();
    let issue = j.w.inbox.issue(sent.issue);
    assert_eq!(issue.author, "octo");
    let envelope = parse_envelope(&issue.body).unwrap();
    assert!(envelope.suggestion.verify() && envelope.acceptance.verify());
    assert_eq!(envelope.acceptance.accepted_via, "typed");
    assert_eq!(j.store.sent(rt::PROJECT).len(), 1);
    // The second one today is over the limit, and says when.
    let second = send(
        &j.store,
        &j.inbox,
        rt::PROJECT,
        "idea",
        &fields_of_title("A different thing"),
        Utc::now(),
    );
    assert!(
        second
            .unwrap_err()
            .to_string()
            .contains("1 new suggestion(s) per day")
    );
}

fn fields_of_title(title: &str) -> BTreeMap<String, String> {
    fields(title)
}

#[test]
fn the_wrong_github_account_or_changed_terms_stop_a_send() {
    let j = joiner();
    join_typed(&j);
    let (kind, fields) = idea("Offline timer");
    let eve = j.w.inbox.as_user("eve");
    let error = send(&j.store, &eve, rt::PROJECT, &kind, &fields, Utc::now()).unwrap_err();
    assert!(error.to_string().contains("agreed as @octo"), "{error}");
    // The owner publishes new terms.
    let channel = j.w.dir.path().join("idle-ish-ferryman");
    let newer = record::set_terms(
        &channel,
        rt::PROJECT,
        &j.w.owner,
        "Terms v2.\n",
        false,
        Utc::now(),
    )
    .unwrap();
    publish::publish(&j.w.inbox, &newer.offer, &newer.terms_text).unwrap();
    let error = send(&j.store, &j.inbox, rt::PROJECT, &kind, &fields, Utc::now()).unwrap_err();
    assert!(error.to_string().contains("earlier version"), "{error}");
}

#[test]
fn agreeing_again_posts_the_new_agreement_on_suggestions_already_sent() {
    let j = joiner();
    join_typed(&j);
    let (kind, fields) = idea("Offline timer");
    let sent = send(&j.store, &j.inbox, rt::PROJECT, &kind, &fields, Utc::now()).unwrap();
    let channel = j.w.dir.path().join("idle-ish-ferryman");
    let newer = record::set_terms(
        &channel,
        rt::PROJECT,
        &j.w.owner,
        "Terms v2.\n",
        false,
        Utc::now(),
    )
    .unwrap();
    publish::publish(&j.w.inbox, &newer.offer, &newer.terms_text).unwrap();
    let joined = prepare_join(&j.store, &j.inbox, &j.invite).unwrap();
    assert_eq!(
        joined.offer.terms.version, 2,
        "the inbox's newer offer is what is shown"
    );
    let agreed = agree(
        &j.store,
        &j.inbox,
        &joined,
        "octo",
        Consent::Typed(ACCEPT_PHRASE),
        Utc::now(),
    )
    .unwrap();
    assert_eq!(agreed.reposted, [sent.issue]);
    let comments = j.w.inbox.comments(sent.issue).unwrap();
    let posted = inbox::parse_acceptance(&comments[0].body).unwrap();
    assert!(posted.verify());
    assert_eq!(posted.terms_version, 2);
}

#[test]
fn status_shows_the_question_and_a_reply_is_signed_and_posted_once_it_is_asked() {
    let j = joiner();
    join_typed(&j);
    let (kind, fields) = idea("Offline timer");
    let sent = send(&j.store, &j.inbox, rt::PROJECT, &kind, &fields, Utc::now()).unwrap();
    let before = status(&j.store, &j.inbox, rt::PROJECT).unwrap();
    assert_eq!(before[0].state, "sent");
    assert!(
        reply(&j.store, &j.inbox, rt::PROJECT, "1", "hello", Utc::now()).is_err(),
        "nothing was asked"
    );
    // The owner's side asks a question.
    j.w.inbox
        .set_labels(sent.issue, &["needs-clarification".to_string()])
        .unwrap();
    j.w.inbox
        .comment(
            sent.issue,
            &format!(
                "What do you mean by offline?\n\n{}",
                inbox::marker("clarify-1")
            ),
        )
        .unwrap();
    let asked = status(&j.store, &j.inbox, rt::PROJECT).unwrap();
    assert!(asked[0].needs_reply);
    assert_eq!(asked[0].round, Some(1));
    assert_eq!(
        asked[0].question.as_deref(),
        Some("What do you mean by offline?")
    );
    let number = reply(
        &j.store,
        &j.inbox,
        rt::PROJECT,
        &format!("#{}", sent.issue),
        "The game closed.",
        Utc::now(),
    )
    .unwrap();
    assert_eq!(number, sent.issue);
    let comments = j.w.inbox.comments(sent.issue).unwrap();
    let posted = inbox::parse_reply(&comments.last().unwrap().body).unwrap();
    assert!(posted.verify());
    assert_eq!(
        (posted.round, posted.text.as_str()),
        (1, "The game closed.")
    );
    // A suggestion id (prefix) names it as well as the number.
    let id = &sent.suggestion.id[..8];
    assert!(reply(&j.store, &j.inbox, rt::PROJECT, id, "again", Utc::now()).is_ok());
    assert!(reply(&j.store, &j.inbox, rt::PROJECT, "99", "x", Utc::now()).is_err());
}

#[test]
fn a_withdrawal_is_signed_posted_and_closes_the_issue() {
    let j = joiner();
    join_typed(&j);
    let (kind, fields) = idea("Offline timer");
    let sent = send(&j.store, &j.inbox, rt::PROJECT, &kind, &fields, Utc::now()).unwrap();
    withdraw(
        &j.store,
        &j.inbox,
        rt::PROJECT,
        "1",
        "changed my mind",
        Utc::now(),
    )
    .unwrap();
    let comments = j.w.inbox.comments(sent.issue).unwrap();
    let posted = inbox::parse_withdrawal(&comments[0].body).unwrap();
    assert!(posted.verify() && posted.reason == "changed my mind");
    assert!(!j.w.inbox.issue(sent.issue).open);
}

#[test]
fn a_submission_file_is_a_flat_object_with_a_type() {
    let (kind, fields) = parse_submission(
        r#"{"type":"bug","title":"t","pitch":"p","why":"w","steps":"s"}"#,
        None,
    )
    .unwrap();
    assert_eq!(kind, "bug");
    assert_eq!(fields["steps"], "s");
    assert!(!fields.contains_key("type"));
    assert_eq!(
        parse_submission(r#"{"title":"t"}"#, Some("idea"))
            .unwrap()
            .0,
        "idea"
    );
    for bad in ["not json", "[]", r#"{"title":1}"#, r#"{"title":"t"}"#] {
        assert!(parse_submission(bad, None).is_err(), "{bad}");
    }
}

#[test]
fn the_project_is_the_only_one_or_named() {
    let j = joiner();
    assert!(pick_project(&j.store, None).is_err());
    join_typed(&j);
    assert_eq!(pick_project(&j.store, None).unwrap(), rt::PROJECT);
    assert_eq!(
        pick_project(&j.store, Some(rt::PROJECT)).unwrap(),
        rt::PROJECT
    );
    assert!(pick_project(&j.store, Some("elsewhere")).is_err());
}

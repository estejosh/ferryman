//! The contributor's commands, over any [`Inbox`]: join (read and agree to the terms),
//! send, follow, answer, withdraw. Nothing here prompts or prints: the CLI shows the terms
//! and asks; this checks, signs and posts. The contributor's own GitHub credentials are the
//! inbox's business, and are never seen here.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use super::contributor::{
    self, Acceptance, Consent, ContributorStore, REPLY_MAX, Sent, Suggestion, accept, compose,
    compose_reply, compose_withdrawal,
};
use super::inbox::{self, Inbox, InboxRef};
use super::invite::Invite;
use super::record::{OFFER_FILE, Offer, TERMS_FILE};
use super::{clean, has_hidden_text, sha256_hex};

/// The signed offer inside the inbox's machine-readable page.
#[must_use]
pub fn offer_from_page(text: &str) -> Option<Offer> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    serde_json::from_value(value.get("offer")?.clone()).ok()
}

/// What `join` has verified and is about to ask a person to agree to.
#[derive(Debug, Clone)]
pub struct Joined {
    pub offer: Offer,
    /// The terms text, whose hash is the one the owner signed.
    pub terms_text: String,
    /// Whether this project is being joined for the first time on this machine.
    pub first_time: bool,
}

/// Read an invite, fetch what the owner published, and check it all: the invite's signature,
/// that the inbox's own offer is from the same owner, and that `TERMS.md` is exactly the
/// text the owner signed. Nothing is remembered until the person agrees.
///
/// # Errors
/// Anything that does not check: a bad invite, an offer from someone else, terms that were
/// changed after the owner signed them, an inbox that cannot be read.
pub fn prepare_join(
    store: &ContributorStore,
    inbox: &dyn Inbox,
    invite_text: &str,
) -> Result<Joined> {
    let invite = Invite::decode(invite_text)?;
    let mut offer = invite.offer;
    if let Some(page) = inbox
        .read_file(OFFER_FILE)?
        .as_deref()
        .and_then(offer_from_page)
    {
        if !page.verify()
            || page.owner_key != offer.owner_key
            || page.inbox != offer.inbox
            || page.project_id != offer.project_id
        {
            bail!(
                "the offer published in the inbox is not signed by the owner this invite names: \
                 do not agree to anything from it"
            );
        }
        if page.seq >= offer.seq {
            offer = page;
        }
    }
    let first_time = store
        .projects()
        .iter()
        .all(|project| *project != offer.project_id);
    store.check(&offer)?;
    let terms_text = inbox
        .read_file(TERMS_FILE)?
        .with_context(|| format!("{TERMS_FILE} is not in the inbox"))?;
    let found = sha256_hex(terms_text.as_bytes());
    if found != offer.terms.sha256 {
        bail!(
            "{TERMS_FILE} in the inbox hashes to {found}, but the owner signed {}: the terms \
             were changed after the owner signed the offer. Do not agree; tell the owner",
            offer.terms.sha256
        );
    }
    // A person is asked to agree to what a screen shows them. An escape sequence can rewrite
    // what a terminal shows, and zero-width or direction-changing characters can hide words,
    // so terms that carry any are not shown, whoever signed them.
    if has_hidden_text(&terms_text) {
        bail!(
            "the terms in the inbox have control, zero-width or text-direction characters in \
             them, which can hide what they say. Do not agree to them; tell the owner"
        );
    }
    Ok(Joined {
        offer,
        terms_text,
        first_time,
    })
}

/// What agreeing did.
#[derive(Debug, Clone)]
pub struct Agreed {
    pub acceptance: Acceptance,
    /// Suggestions already sent under older terms, on which the new agreement was posted.
    pub reposted: Vec<u64>,
}

/// Agree. `login` is the GitHub login of the credentials that will post. The agreement is
/// signed with this contributor's key, kept, and posted on suggestions sent earlier under
/// older terms so the owner's side can see it.
///
/// # Errors
/// A phrase or hash that is not the agreement, or a directory that cannot be written.
pub fn agree(
    store: &ContributorStore,
    inbox: &dyn Inbox,
    joined: &Joined,
    login: &str,
    consent: Consent<'_>,
    now: DateTime<Utc>,
) -> Result<Agreed> {
    let identity = store.identity()?;
    let acceptance = accept(&identity, &joined.offer, login, consent, now)?;
    store.pin_owner(&joined.offer)?;
    store.save_offer(&joined.offer, &joined.terms_text)?;
    store.save_acceptance(&acceptance)?;
    let mut reposted = Vec::new();
    for sent in store.sent(&joined.offer.project_id) {
        if sent.inbox == joined.offer.inbox
            && sent.suggestion.terms_sha256 != joined.offer.terms.sha256
            && inbox
                .comment(sent.issue, &inbox::render_acceptance(&acceptance))
                .is_ok()
        {
            reposted.push(sent.issue);
        }
    }
    Ok(Agreed {
        acceptance,
        reposted,
    })
}

/// The owner's current offer for a joined project, read from the inbox and held to the key
/// that was pinned at the join: never an older offer, never another owner's.
///
/// # Errors
/// An inbox that cannot be read or has nothing from the owner, or an offer that does not
/// check against the pin.
pub fn current_offer(store: &ContributorStore, inbox: &dyn Inbox, project: &str) -> Result<Offer> {
    let kept = store.offer(project).with_context(|| {
        format!("you have not joined {project}: run `ferry suggest join <invite>`")
    })?;
    let page = inbox
        .read_file(OFFER_FILE)?
        .as_deref()
        .and_then(offer_from_page)
        .with_context(|| format!("the inbox has no {OFFER_FILE} from the owner"))?;
    if !page.verify() || page.owner_key != kept.owner_key || page.project_id != kept.project_id {
        bail!("the offer in the inbox is not from the owner you joined under; nothing was sent");
    }
    store.check(&page)?;
    Ok(page)
}

/// Which joined project a command is about: the one named, or the only one.
///
/// # Errors
/// None joined, or several with none named.
pub fn pick_project(store: &ContributorStore, named: Option<&str>) -> Result<String> {
    let projects = store.projects();
    match (named, projects.as_slice()) {
        (Some(name), _) if projects.iter().any(|project| project == name) => Ok(name.to_string()),
        (Some(name), _) => bail!(
            "you have not joined '{name}' (joined: {})",
            projects.join(", ")
        ),
        (None, [only]) => Ok(only.clone()),
        (None, []) => bail!("you have not joined any project: run `ferry suggest join <invite>`"),
        (None, many) => bail!(
            "you have joined several projects ({}): say which with --project",
            many.join(", ")
        ),
    }
}

/// Whether a suggestion in the inbox is still open to being decided: no final label.
fn in_flight(issue: &inbox::Issue) -> bool {
    issue.open
        && !issue.labels.iter().any(|label| {
            matches!(
                label.as_str(),
                inbox::DECLINED | inbox::SHIPPED | inbox::DUPLICATE | inbox::INVALID
            )
        })
}

/// Sign a suggestion and post it.
///
/// Refuses what the owner's side would refuse, with the same words, before anything is
/// posted: no current agreement, a kind the project does not take, fields over their caps,
/// too many open, more than the day's allowance.
///
/// # Errors
/// Every reason, one per line, or the inbox's refusal.
pub fn send(
    store: &ContributorStore,
    inbox: &dyn Inbox,
    project: &str,
    kind: &str,
    fields: &std::collections::BTreeMap<String, String>,
    now: DateTime<Utc>,
) -> Result<Sent> {
    let offer = current_offer(store, inbox, project)?;
    let identity = store.identity()?;
    let acceptance = store.acceptance(project);
    let suggestion = compose(&identity, &offer, acceptance.as_ref(), kind, fields, now)?;
    let acceptance = acceptance.context("no agreement")?;
    let login = inbox.whoami()?;
    if !login.eq_ignore_ascii_case(&acceptance.contributor_login) {
        bail!(
            "you agreed as @{} but the credentials in use are @{login}: use the same GitHub \
             account, or run `ferry suggest join` again as this one",
            acceptance.contributor_login
        );
    }
    let limits = &offer.limits;
    let mine: Vec<Sent> = store
        .sent(project)
        .into_iter()
        .filter(|sent| sent.inbox == offer.inbox)
        .collect();
    let today: Vec<&Sent> = mine
        .iter()
        .filter(|sent| now - sent.suggestion.created_at < Duration::hours(24))
        .collect();
    if today.len() >= limits.new_per_day as usize {
        let next = today
            .iter()
            .map(|sent| sent.suggestion.created_at)
            .min()
            .map_or(now, |first| first + Duration::hours(24));
        bail!(
            "the limit is {} new suggestion(s) per day: you can send another after {} UTC",
            limits.new_per_day,
            next.format("%Y-%m-%d %H:%M")
        );
    }
    let issues = inbox.list_issues()?;
    let open = mine
        .iter()
        .filter(|sent| {
            issues
                .iter()
                .any(|issue| issue.number == sent.issue && in_flight(issue))
        })
        .count();
    if open >= limits.open_per_contributor as usize {
        bail!(
            "you already have {open} open suggestion(s) here and the limit is {}: wait for one \
             to be decided, or withdraw one with `ferry suggest withdraw <id>`",
            limits.open_per_contributor
        );
    }
    let (title, body) = inbox::render_issue(&offer, &suggestion, &acceptance);
    let issue = inbox.create_issue(&title, &body)?;
    let sent = Sent {
        project_id: project.to_string(),
        inbox: offer.inbox.clone(),
        issue: issue.number,
        url: issue.url,
        suggestion,
    };
    store.remember(sent.clone())?;
    Ok(sent)
}

/// Where one sent suggestion stands, as the inbox shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub issue: u64,
    pub id: String,
    pub title: String,
    pub kind: String,
    pub url: String,
    /// `received`, `needs-clarification`, `accepted`, `building`, `shipped`, `declined`,
    /// `duplicate`, `invalid`, or `sent` (nothing has happened yet) or `closed`.
    pub state: String,
    pub open: bool,
    /// The owner's side's question, when there is one waiting.
    pub question: Option<String>,
    /// Which round the question is, for `reply`.
    pub round: Option<u32>,
    /// Where it is waiting for the contributor.
    pub needs_reply: bool,
}

fn clarify_round(comment: &inbox::Comment) -> Option<u32> {
    let start = comment.body.find("<!-- ferryman:clarify-")? + "<!-- ferryman:clarify-".len();
    let end = comment.body[start..].find(" -->")? + start;
    comment.body[start..end].parse().ok()
}

/// What the project's inbox says about everything this contributor sent to it.
///
/// # Errors
/// An inbox that cannot be read.
pub fn status(store: &ContributorStore, inbox: &dyn Inbox, project: &str) -> Result<Vec<Status>> {
    let issues = inbox.list_issues()?;
    let mut out = Vec::new();
    for sent in store.sent(project) {
        let Some(issue) = issues.iter().find(|issue| issue.number == sent.issue) else {
            continue;
        };
        let label = issue
            .labels
            .iter()
            .find(|label| inbox::is_status_label(label))
            .cloned();
        let state = label.clone().unwrap_or_else(|| {
            if issue.open {
                "sent".to_string()
            } else {
                "closed".to_string()
            }
        });
        let needs_reply = label.as_deref() == Some(inbox::NEEDS_CLARIFICATION) && issue.open;
        let (question, round) = if needs_reply {
            let comments = inbox.comments(issue.number)?;
            // The owner's side's question: a comment the inbox says comes from someone with a
            // say in the repository, not from the contributor and not from any stranger who
            // has copied the hidden marker. What it says is shown to a person (and an agent),
            // so it is cleaned of anything that could rewrite a screen.
            comments
                .iter()
                .rev()
                .find(|comment| {
                    comment.trusted
                        && !comment.author.eq_ignore_ascii_case(&issue.author)
                        && clarify_round(comment).is_some()
                })
                .map_or((None, None), |comment| {
                    let text = clean(
                        comment
                            .body
                            .split("<!-- ferryman:")
                            .next()
                            .unwrap_or_default()
                            .trim(),
                        2000,
                    );
                    (Some(text), clarify_round(comment))
                })
        } else {
            (None, None)
        };
        out.push(Status {
            issue: issue.number,
            id: sent.suggestion.id.clone(),
            title: sent.suggestion.title(),
            kind: sent.suggestion.kind.clone(),
            url: issue.url.clone(),
            state,
            open: issue.open,
            question,
            round,
            needs_reply,
        });
    }
    Ok(out)
}

fn find_sent(store: &ContributorStore, project: &str, which: &str) -> Result<Sent> {
    let which = which.trim().trim_start_matches('#');
    let all = store.sent(project);
    let hits: Vec<&Sent> = all
        .iter()
        .filter(|sent| {
            sent.issue.to_string() == which
                || (which.len() >= 6 && sent.suggestion.id.starts_with(which))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("you have not sent a suggestion '{which}' to {project} from this machine"),
        _ => bail!("'{which}' matches more than one suggestion; use the issue number"),
    }
}

/// Answer the owner's question on a suggestion, signed.
///
/// # Errors
/// Nothing is waiting for an answer, or the reply is empty or too long.
pub fn reply(
    store: &ContributorStore,
    inbox: &dyn Inbox,
    project: &str,
    which: &str,
    text: &str,
    now: DateTime<Utc>,
) -> Result<u64> {
    let sent = find_sent(store, project, which)?;
    let states = status(store, inbox, project)?;
    let state = states
        .iter()
        .find(|state| state.issue == sent.issue)
        .context("that suggestion is not in the inbox any more")?;
    let Some(round) = state.round.filter(|_| state.needs_reply) else {
        bail!(
            "nothing is waiting for your answer on #{} (its state is {})",
            sent.issue,
            state.state
        );
    };
    let identity = store.identity()?;
    let login = inbox.whoami()?;
    let reply = compose_reply(&identity, &login, &sent.suggestion, round, text, now)?;
    inbox.comment(sent.issue, &inbox::render_reply(&reply))?;
    Ok(sent.issue)
}

/// Take a suggestion back, signed.
///
/// # Errors
/// No such suggestion sent from here, or the inbox refused.
pub fn withdraw(
    store: &ContributorStore,
    inbox: &dyn Inbox,
    project: &str,
    which: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<u64> {
    let sent = find_sent(store, project, which)?;
    let identity = store.identity()?;
    let login = inbox.whoami()?;
    let withdrawal = compose_withdrawal(&identity, &login, &sent.suggestion, reason, now);
    inbox.comment(sent.issue, &inbox::render_withdrawal(&withdrawal))?;
    // The author may close their own issue; the owner's side closes it too when it sees this.
    let _ = inbox.set_open(sent.issue, false);
    Ok(sent.issue)
}

/// The kinds of suggestion and fields a person is asked for, as a short description.
#[must_use]
pub fn describe_fields(offer: &Offer, kind: &str) -> Vec<(String, String, usize, bool)> {
    offer.field_specs(kind)
}

/// A fresh suggestion from a JSON file or stdin text: `{"type":"idea","title":"..",..}`.
///
/// # Errors
/// JSON that is not an object of strings, or has no `type`.
pub fn parse_submission(
    text: &str,
    default_kind: Option<&str>,
) -> Result<(String, std::collections::BTreeMap<String, String>)> {
    let value: serde_json::Value =
        serde_json::from_str(text).context("the suggestion is not valid JSON")?;
    let Some(object) = value.as_object() else {
        bail!(
            "the suggestion is a JSON object: {{\"type\":\"idea\",\"title\":...,\"pitch\":...,\"why\":...}}"
        );
    };
    let mut kind = default_kind.map(str::to_string);
    let mut fields = std::collections::BTreeMap::new();
    for (key, value) in object {
        let Some(text) = value.as_str() else {
            bail!("'{key}' must be text");
        };
        if key == "type" {
            kind = Some(text.to_string());
        } else {
            fields.insert(key.clone(), text.to_string());
        }
    }
    let kind = kind.context("say what kind of suggestion it is: add \"type\" (or pass --type)")?;
    Ok((kind, fields))
}

/// Open the suggestion under `Suggestion` for tests and callers that want the fields back.
#[must_use]
pub fn fields_of(suggestion: &Suggestion) -> &std::collections::BTreeMap<String, String> {
    &suggestion.fields
}

/// Re-exports a CLI needs to name things without reaching into submodules.
pub use contributor::ACCEPT_PHRASE;

/// The inbox a joined project's offer names.
///
/// # Errors
/// An inbox this version does not understand.
pub fn inbox_ref(offer: &Offer) -> Result<InboxRef> {
    InboxRef::parse(&offer.inbox)
}

/// Longest reply, for a prompt to show.
pub const REPLY_LIMIT: usize = REPLY_MAX;

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

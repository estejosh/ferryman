//! The public inbox: where suggestions travel, behind a small trait.
//!
//! v1 is a public GitHub repository for the product, one issue per suggestion, clarifications
//! as comments, and status as labels. The trait is deliberately the least an inbox must do,
//! so another one (email through AgentMail, an endpoint on a hub) is one more implementation
//! and nothing else changes. Nothing in this module talks to a network: the GitHub
//! implementation lives in `ferryman-ops`, and [`MockInbox`] is what the tests use.
//!
//! An inbox is untrusted. What is read from it is checked for signatures and caps before it
//! reaches anything that acts; the labels and comments on an issue are bookkeeping that the
//! owner's side writes and a stranger cannot, and are never what authorises anything.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};

use super::contributor::{Acceptance, Envelope, Reply, Suggestion, Withdrawal};
use super::record::Offer;

pub const RECEIVED: &str = "received";
pub const NEEDS_CLARIFICATION: &str = "needs-clarification";
pub const ACCEPTED: &str = "accepted";
pub const BUILDING: &str = "building";
pub const SHIPPED: &str = "shipped";
pub const DECLINED: &str = "declined";
pub const DUPLICATE: &str = "duplicate";
pub const INVALID: &str = "invalid";

/// The labels the inbox repository carries, with a colour each.
pub const LABELS: [(&str, &str); 8] = [
    (RECEIVED, "0e8a16"),
    (NEEDS_CLARIFICATION, "fbca04"),
    (ACCEPTED, "1d76db"),
    (BUILDING, "5319e7"),
    (SHIPPED, "0e8a16"),
    (DECLINED, "b60205"),
    (DUPLICATE, "cfd3d7"),
    (INVALID, "e4e669"),
];

/// Whether `label` is one the owner's side sets to say where a suggestion stands.
#[must_use]
pub fn is_status_label(label: &str) -> bool {
    LABELS.iter().any(|(name, _)| *name == label)
}

pub const BLOCK_SUGGESTION: &str = "ferryman-suggestion";
pub const BLOCK_REPLY: &str = "ferryman-reply";
pub const BLOCK_WITHDRAW: &str = "ferryman-withdraw";
pub const BLOCK_ACCEPT: &str = "ferryman-accept";

/// Where an inbox is. Only GitHub for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxRef {
    Github { owner: String, repo: String },
}

fn repo_part(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len())
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl InboxRef {
    /// `github:owner/repo`, or the repository's `https://github.com/owner/repo` address.
    ///
    /// # Errors
    /// Anything else: the inbox is part of what the owner signs, so it is checked here.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let rest = text
            .strip_prefix("github:")
            .or_else(|| text.strip_prefix("https://github.com/"))
            .map(|rest| rest.trim_end_matches('/').trim_end_matches(".git"));
        let Some((owner, repo)) = rest.and_then(|rest| rest.split_once('/')) else {
            bail!(
                "an inbox is github:owner/repo (a public repository for this product), not '{text}'"
            );
        };
        if !repo_part(owner, 39) || !repo_part(repo, 100) {
            bail!("'{text}' is not a GitHub repository name");
        }
        Ok(Self::Github {
            owner: owner.to_string(),
            repo: repo.to_string(),
        })
    }

    /// The canonical spelling: what is signed.
    #[must_use]
    pub fn spec(&self) -> String {
        match self {
            Self::Github { owner, repo } => format!("github:{owner}/{repo}"),
        }
    }

    /// A path-safe name for the inbox: `owner-repo`, lowercase.
    #[must_use]
    pub fn slug(&self) -> String {
        match self {
            Self::Github { owner, repo } => format!("{owner}-{repo}")
                .to_ascii_lowercase()
                .replace('.', "-"),
        }
    }

    /// A file in the inbox repository, as a person opens it.
    #[must_use]
    pub fn file_url(&self, file: &str) -> String {
        match self {
            Self::Github { owner, repo } => {
                format!("https://github.com/{owner}/{repo}/blob/HEAD/{file}")
            }
        }
    }

    /// An issue, as a person opens it.
    #[must_use]
    pub fn issue_url(&self, number: u64) -> String {
        match self {
            Self::Github { owner, repo } => {
                format!("https://github.com/{owner}/{repo}/issues/{number}")
            }
        }
    }
}

/// One suggestion as the inbox holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub number: u64,
    pub title: String,
    pub body: String,
    /// The login that posted it, as the inbox says: what a signed login is checked against.
    pub author: String,
    pub labels: Vec<String>,
    pub open: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub url: String,
}

/// One comment on an issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub id: u64,
    pub author: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    /// Whether the inbox itself says the author has a say in the repository (its owner, a
    /// member, a collaborator): the one fact that tells the owner's side's comments from a
    /// stranger's that merely look like them. Only used where there is no signature.
    pub trusted: bool,
}

/// The least an inbox must do. Every call is one request to a service that may be slow,
/// down or hostile; implementations return an error rather than guess.
pub trait Inbox {
    /// The login of whoever holds the credentials in use.
    ///
    /// # Errors
    /// No credentials, or the inbox refused them.
    fn whoami(&self) -> Result<String>;
    /// Every issue, open and closed, oldest first. Pull requests are not issues.
    ///
    /// # Errors
    /// The inbox could not be read.
    fn list_issues(&self) -> Result<Vec<Issue>>;
    /// One issue's comments, oldest first.
    ///
    /// # Errors
    /// The inbox could not be read.
    fn comments(&self, issue: u64) -> Result<Vec<Comment>>;
    /// A new suggestion, as the holder of the credentials.
    ///
    /// # Errors
    /// The inbox refused it.
    fn create_issue(&self, title: &str, body: &str) -> Result<Issue>;
    /// A comment, as the holder of the credentials.
    ///
    /// # Errors
    /// The inbox refused it.
    fn comment(&self, issue: u64, body: &str) -> Result<Comment>;
    /// Replace all of an issue's labels. Owner side.
    ///
    /// # Errors
    /// The inbox refused it.
    fn set_labels(&self, issue: u64, labels: &[String]) -> Result<()>;
    /// Open or close an issue.
    ///
    /// # Errors
    /// The inbox refused it.
    fn set_open(&self, issue: u64, open: bool) -> Result<()>;
    /// A file from the default branch, `None` when it is not there.
    ///
    /// # Errors
    /// The inbox could not be read.
    fn read_file(&self, path: &str) -> Result<Option<String>>;
    /// Create or replace a file on the default branch. Owner side, `--publish` only.
    ///
    /// # Errors
    /// The inbox refused it.
    fn write_file(&self, path: &str, content: &str, message: &str) -> Result<()>;
    /// Make sure the status labels exist. Owner side, `--publish` only.
    ///
    /// # Errors
    /// The inbox refused it.
    fn ensure_labels(&self) -> Result<()>;
}

// --- what an issue says -----------------------------------------------------------------

fn quoted(text: &str) -> String {
    let mut out = String::new();
    for line in text.trim().lines() {
        if line.trim().is_empty() {
            out.push_str(">\n");
        } else {
            out.push_str("> ");
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }
    out
}

/// The title and body of the issue a suggestion becomes: a rendering for people, then the
/// signed record in a fenced block for machines. Only the block is ever read.
#[must_use]
pub fn render_issue(
    offer: &Offer,
    suggestion: &Suggestion,
    acceptance: &Acceptance,
) -> (String, String) {
    let title_text: String = suggestion
        .fields
        .get("title")
        .map_or("", String::as_str)
        .chars()
        .take(80)
        .collect();
    let title = format!("[{}] {}", suggestion.kind, title_text.replace('\n', " "));
    let mut body = format!(
        "**{} suggestion** for {} from @{}\n\n",
        suggestion.kind, offer.display_name, suggestion.contributor_login
    );
    for (id, label, ..) in offer.field_specs(&suggestion.kind) {
        if let Some(value) = suggestion
            .fields
            .get(&id)
            .filter(|value| !value.trim().is_empty())
        {
            body.push_str(&format!("### {label}\n{}\n", quoted(value)));
        }
    }
    let envelope = Envelope {
        suggestion: suggestion.clone(),
        acceptance: acceptance.clone(),
    };
    body.push_str(&format!(
        "---\nSent under the terms of {} (version {}, sha256 `{}`), accepted by @{} on {}.\n\n\
         <details><summary>Signed record</summary>\n\n```{BLOCK_SUGGESTION}\n{}\n```\n\n</details>\n",
        offer.display_name,
        acceptance.terms_version,
        &acceptance.terms_sha256[..12.min(acceptance.terms_sha256.len())],
        acceptance.contributor_login,
        acceptance.accepted_at.format("%Y-%m-%d"),
        serde_json::to_string(&envelope).unwrap_or_default()
    ));
    (title, body)
}

/// A reply to a clarifying question, as a comment: readable text, then the signed record.
#[must_use]
pub fn render_reply(reply: &Reply) -> String {
    format!(
        "Reply (round {}) from @{}:\n\n{}\n<details><summary>Signed reply</summary>\n\n```{BLOCK_REPLY}\n{}\n```\n\n</details>\n",
        reply.round,
        reply.contributor_login,
        quoted(&reply.text),
        serde_json::to_string(reply).unwrap_or_default()
    )
}

/// A withdrawal, as a comment.
#[must_use]
pub fn render_withdrawal(withdrawal: &Withdrawal) -> String {
    format!(
        "Withdrawn by @{}.\n\n<details><summary>Signed withdrawal</summary>\n\n```{BLOCK_WITHDRAW}\n{}\n```\n\n</details>\n",
        withdrawal.contributor_login,
        serde_json::to_string(withdrawal).unwrap_or_default()
    )
}

/// A fresh agreement to newer terms, posted on a suggestion already sent.
#[must_use]
pub fn render_acceptance(acceptance: &Acceptance) -> String {
    format!(
        "@{} agreed to version {} of the terms.\n\n<details><summary>Signed agreement</summary>\n\n```{BLOCK_ACCEPT}\n{}\n```\n\n</details>\n",
        acceptance.contributor_login,
        acceptance.terms_version,
        serde_json::to_string(acceptance).unwrap_or_default()
    )
}

/// A signed agreement in a comment, if it carries one that parses.
#[must_use]
pub fn parse_acceptance(body: &str) -> Option<Acceptance> {
    serde_json::from_str(extract_block(body, BLOCK_ACCEPT)?).ok()
}

/// The one line after the first ```` ```tag ```` fence. The signed JSON is one line (newlines
/// in it are escaped), so the rendering above it - quoted line by line - cannot forge a block.
#[must_use]
pub fn extract_block<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let fence = format!("```{tag}");
    let mut lines = body.lines();
    while let Some(line) = lines.next() {
        if line.trim_end() == fence {
            return lines.next().map(str::trim);
        }
    }
    None
}

/// The signed record in an issue body.
///
/// # Errors
/// What is missing or does not parse, in words the contributor can act on.
pub fn parse_envelope(body: &str) -> Result<Envelope, String> {
    let Some(block) = extract_block(body, BLOCK_SUGGESTION) else {
        return Err(
            "there is no signed Ferryman record in this issue. Send a suggestion with \
             `ferry suggest new` (do not open the issue by hand): it signs your suggestion and \
             your agreement to the terms, and that is what gets reviewed"
                .to_string(),
        );
    };
    serde_json::from_str(block).map_err(|error| {
        format!("the signed record in this issue does not parse ({error}); it may have been edited")
    })
}

/// A signed reply in a comment, if it carries one that parses.
#[must_use]
pub fn parse_reply(body: &str) -> Option<Reply> {
    serde_json::from_str(extract_block(body, BLOCK_REPLY)?).ok()
}

/// A signed withdrawal in a comment, if it carries one that parses.
#[must_use]
pub fn parse_withdrawal(body: &str) -> Option<Withdrawal> {
    serde_json::from_str(extract_block(body, BLOCK_WITHDRAW)?).ok()
}

/// The hidden marker that makes an automatic comment idempotent.
#[must_use]
pub fn marker(kind: &str) -> String {
    format!("<!-- ferryman:{kind} -->")
}

/// Whether `comments` already holds the owner's side's comment with this marker.
#[must_use]
pub fn has_marker(comments: &[Comment], author: &str, kind: &str) -> bool {
    let wanted = marker(kind);
    comments.iter().any(|comment| {
        comment.author.eq_ignore_ascii_case(author) && comment.body.contains(&wanted)
    })
}

// --- the mock ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    owner: String,
    issues: Vec<Issue>,
    comments: BTreeMap<u64, Vec<Comment>>,
    files: BTreeMap<String, String>,
    clock: Option<DateTime<Utc>>,
    next_issue: u64,
    next_comment: u64,
    labels_ensured: bool,
}

impl MockState {
    fn now(&self) -> DateTime<Utc> {
        self.clock.unwrap_or_else(Utc::now)
    }
}

/// An in-memory inbox with GitHub's permissions: anyone reads and posts; only the owner
/// labels, and writes files; the owner or an issue's author opens and closes it. Cloning
/// shares the inbox; [`MockInbox::as_user`] is the same inbox seen as another login.
#[derive(Clone)]
pub struct MockInbox {
    shared: Arc<Mutex<MockState>>,
    login: String,
}

impl MockInbox {
    /// A new inbox, seen as its owner `owner`.
    #[must_use]
    pub fn new(owner: &str) -> Self {
        let state = MockState {
            owner: owner.to_string(),
            next_issue: 1,
            next_comment: 1,
            ..MockState::default()
        };
        Self {
            shared: Arc::new(Mutex::new(state)),
            login: owner.to_string(),
        }
    }

    /// The same inbox, acting as `login`.
    #[must_use]
    pub fn as_user(&self, login: &str) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            login: login.to_string(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fix the inbox's clock.
    pub fn set_clock(&self, at: DateTime<Utc>) {
        self.state().clock = Some(at);
    }

    /// Move the inbox's clock on.
    pub fn advance(&self, by: Duration) {
        let mut state = self.state();
        let now = state.now();
        state.clock = Some(now + by);
    }

    /// One issue, as it stands.
    ///
    /// # Panics
    /// There is no such issue.
    #[must_use]
    pub fn issue(&self, number: u64) -> Issue {
        self.state()
            .issues
            .iter()
            .find(|issue| issue.number == number)
            .cloned()
            .expect("no such issue")
    }

    /// Rewrite an issue's body, as an edit on the site would.
    pub fn edit_body(&self, number: u64, edit: impl FnOnce(&str) -> String) {
        let mut state = self.state();
        let now = state.now();
        if let Some(issue) = state.issues.iter_mut().find(|issue| issue.number == number) {
            issue.body = edit(&issue.body);
            issue.updated_at = now;
        }
    }

    /// Whether the owner's side asked for the labels to exist.
    #[must_use]
    pub fn labels_ensured(&self) -> bool {
        self.state().labels_ensured
    }

    fn touch(state: &mut MockState, number: u64) {
        let now = state.now();
        if let Some(issue) = state.issues.iter_mut().find(|issue| issue.number == number) {
            issue.updated_at = now;
        }
    }
}

impl Inbox for MockInbox {
    fn whoami(&self) -> Result<String> {
        Ok(self.login.clone())
    }

    fn list_issues(&self) -> Result<Vec<Issue>> {
        let mut issues = self.state().issues.clone();
        issues.sort_by_key(|issue| (issue.created_at, issue.number));
        Ok(issues)
    }

    fn comments(&self, issue: u64) -> Result<Vec<Comment>> {
        Ok(self
            .state()
            .comments
            .get(&issue)
            .cloned()
            .unwrap_or_default())
    }

    fn create_issue(&self, title: &str, body: &str) -> Result<Issue> {
        let mut state = self.state();
        let number = state.next_issue;
        state.next_issue += 1;
        let now = state.now();
        let issue = Issue {
            number,
            title: title.to_string(),
            body: body.to_string(),
            author: self.login.clone(),
            labels: Vec::new(),
            open: true,
            created_at: now,
            updated_at: now,
            url: format!("https://github.com/mock/inbox/issues/{number}"),
        };
        state.issues.push(issue.clone());
        Ok(issue)
    }

    fn comment(&self, issue: u64, body: &str) -> Result<Comment> {
        let mut state = self.state();
        if !state
            .issues
            .iter()
            .any(|candidate| candidate.number == issue)
        {
            bail!("no such issue");
        }
        let id = state.next_comment;
        state.next_comment += 1;
        let comment = Comment {
            id,
            author: self.login.clone(),
            body: body.to_string(),
            created_at: state.now(),
            trusted: state.owner == self.login,
        };
        state
            .comments
            .entry(issue)
            .or_default()
            .push(comment.clone());
        Self::touch(&mut state, issue);
        Ok(comment)
    }

    fn set_labels(&self, issue: u64, labels: &[String]) -> Result<()> {
        let mut state = self.state();
        if state.owner != self.login {
            bail!("only the owner of the inbox may label");
        }
        let Some(found) = state
            .issues
            .iter_mut()
            .find(|candidate| candidate.number == issue)
        else {
            bail!("no such issue");
        };
        found.labels = labels.to_vec();
        Self::touch(&mut state, issue);
        Ok(())
    }

    fn set_open(&self, issue: u64, open: bool) -> Result<()> {
        let mut state = self.state();
        let owner = state.owner.clone();
        let Some(found) = state
            .issues
            .iter_mut()
            .find(|candidate| candidate.number == issue)
        else {
            bail!("no such issue");
        };
        if self.login != owner && !found.author.eq_ignore_ascii_case(&self.login) {
            bail!("only the owner or the author may open or close an issue");
        }
        found.open = open;
        Self::touch(&mut state, issue);
        Ok(())
    }

    fn read_file(&self, path: &str) -> Result<Option<String>> {
        Ok(self.state().files.get(path).cloned())
    }

    fn write_file(&self, path: &str, content: &str, _message: &str) -> Result<()> {
        let mut state = self.state();
        if state.owner != self.login {
            bail!("only the owner of the inbox may write files");
        }
        state.files.insert(path.to_string(), content.to_string());
        Ok(())
    }

    fn ensure_labels(&self) -> Result<()> {
        let mut state = self.state();
        if state.owner != self.login {
            bail!("only the owner of the inbox may make labels");
        }
        state.labels_ensured = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inbox_is_a_github_repository_and_nothing_else() {
        let inbox = InboxRef::parse("github:estejosh/idle-ish-ideas").unwrap();
        assert_eq!(inbox.spec(), "github:estejosh/idle-ish-ideas");
        assert_eq!(inbox.slug(), "estejosh-idle-ish-ideas");
        assert_eq!(
            InboxRef::parse("https://github.com/estejosh/idle-ish-ideas.git/").unwrap(),
            inbox
        );
        for bad in [
            "estejosh/idle-ish-ideas",
            "github:nobody",
            "github:a/b/c",
            "github:../etc",
            "github:a/..",
            "gitlab:a/b",
            "github:a b/c",
            "",
        ] {
            assert!(InboxRef::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_block_is_found_after_its_fence_and_a_quoted_rendering_cannot_forge_one() {
        let body = "> ```ferryman-suggestion\n> {\"fake\":1}\n\n```ferryman-suggestion\n{\"real\":1}\n```\n";
        assert_eq!(extract_block(body, BLOCK_SUGGESTION), Some("{\"real\":1}"));
        assert_eq!(extract_block("nothing here", BLOCK_SUGGESTION), None);
        assert!(
            parse_envelope("just words")
                .unwrap_err()
                .contains("ferry suggest new")
        );
        assert!(parse_envelope("```ferryman-suggestion\nnot json\n```").is_err());
    }

    #[test]
    fn the_mock_has_githubs_permissions() {
        let owner = MockInbox::new("josh");
        let stranger = owner.as_user("octo");
        let issue = stranger.create_issue("t", "b").unwrap();
        assert_eq!(issue.author, "octo");
        assert!(
            stranger
                .set_labels(issue.number, &["accepted".to_string()])
                .is_err()
        );
        assert!(stranger.write_file("TERMS.md", "x", "m").is_err());
        assert!(
            owner
                .set_labels(issue.number, &["received".to_string()])
                .is_ok()
        );
        assert!(
            stranger.set_open(issue.number, false).is_ok(),
            "an author closes their own"
        );
        let other = owner.as_user("eve");
        assert!(other.set_open(issue.number, true).is_err());
        let comment = owner
            .comment(issue.number, &format!("hi {}", marker("received")))
            .unwrap();
        assert!(has_marker(
            std::slice::from_ref(&comment),
            "josh",
            "received"
        ));
        assert!(
            !has_marker(&[comment], "octo", "received"),
            "only the owner's own marker counts"
        );
    }
}

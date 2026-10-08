//! The library's signed, append-only entries, and what they add up to.
//!
//! ```text
//! <home channel>/library/events.<author>__<machine>.jsonl     one writer per file
//! ```
//!
//! Each line is an [`Event`], signed by its author over exactly what it says and chained to
//! the author's previous line by hash (the same shape as the attribution ledger, and for the
//! same reason: a file has one writing machine, so two machines recording in one sync window
//! never collide). A *fact* is never edited. A new fact *supersedes* an old one and history
//! stays; the master's `confirm` and `retract` are further lines, not changes.
//!
//! # Authority
//!
//! Anyone on the home channel's roster may write a fact; it is *unconfirmed*. A fact written
//! by the master, or by a delegate holding the master's `library` scope, is *confirmed*; so
//! is any fact the master later confirms. Confirming, retracting and editing the mail tag map
//! are the master's (or that delegate's) alone. Authority is read from the channel every time
//! (nothing on disk is trusted): revoking a delegation also un-confirms what that delegate
//! confirmed, and the master can confirm it again.
//!
//! # Rollback
//!
//! This machine remembers, outside the synced folder, the verified lines of every library
//! file it has read. A file that comes back shorter, loses a line, is deleted or forks from
//! what was seen leaves what this machine saw in force and raises a notice, exactly as
//! `FOCUS` and `ENGINE_POLICY` do for their one record.
//!
//! # What a superseding fact does
//!
//! A fact hides the facts it supersedes only if it is confirmed, or if it is its author
//! correcting their own unconfirmed fact. So an unconfirmed proposal from some agent never
//! pushes a confirmed fact out of sight: both stay live, and the disagreement is put to the
//! master.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::guard;
use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck};

/// The folder inside the home channel.
pub const DIR: &str = "library";
/// Longest a fact's text may be, in characters.
pub const MAX_TEXT: usize = 1000;
/// Longest a fact's subject may be.
pub const MAX_SUBJECT: usize = 120;
/// Longest a fact's `source` may be.
pub const MAX_SOURCE: usize = 160;
/// Most tags on one fact.
pub const MAX_TAGS: usize = 8;
/// Longest tag.
pub const MAX_TAG: usize = 32;
/// Most facts one fact may supersede.
pub const MAX_SUPERSEDES: usize = 8;
/// Longest a reason on a confirm or retract may be.
pub const MAX_REASON: usize = 200;
/// Most entries in the mail tag map.
pub const MAX_TAG_MAP: usize = 64;
/// Longest line looked at in a library file.
const MAX_LINE: usize = 8 * 1024;

/// The prefix of a fact's id.
pub const FACT_PREFIX: &str = "f";
const EVENT_PREFIX: &str = "e";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Fact,
    Confirm,
    Retract,
    TagMap,
}

/// Where a fact stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Confirmed,
    Unconfirmed,
    Retracted,
    /// A row of a generated view: read from live state, never a fact anyone signed.
    Generated,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Unconfirmed => "unconfirmed",
            Self::Retracted => "retracted",
            Self::Generated => "generated",
        }
    }
}

/// One signed line of a library file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub kind: Kind,
    /// The home project: part of what is signed, so a line cannot be lifted from another
    /// channel.
    pub home: String,
    /// The machine whose file this is.
    pub machine: String,
    /// 1 for the first line of the file, then one more each time.
    pub seq: u64,
    /// Hex SHA-256 of the previous line of this file, empty for the first.
    pub prev: String,
    pub created_at: DateTime<Utc>,
    /// Who signed it.
    pub author: String,
    /// The master, when a delegate holding the `library` scope signed for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Who or what or where it came from, in the author's words.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
    /// The fact a confirm or retract is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// The mail tag map: subject tag to project.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tag_map: BTreeMap<String, String>,
    pub signature: String,
}

/// A fact as it stands now: what was signed, plus what the rest of the library says about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fact {
    pub id: String,
    pub subject: String,
    pub text: String,
    pub tags: Vec<String>,
    pub project: Option<String>,
    pub source: String,
    pub author: String,
    pub on_behalf_of: Option<String>,
    pub machine: String,
    pub created_at: DateTime<Utc>,
    pub supersedes: Vec<String>,
    pub status: Status,
    /// Who made it confirmed: the master, or `master via delegate`.
    pub confirmed_by: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub retracted_by: Option<String>,
    pub retract_reason: String,
    /// The facts that took its place.
    pub superseded_by: Vec<String>,
    pub generated: bool,
}

impl Fact {
    /// Still current: not retracted and not replaced.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.status != Status::Retracted && self.superseded_by.is_empty()
    }

    /// `josh`, or `josh via telegram-grouchly`.
    #[must_use]
    pub fn written_by(&self) -> String {
        match &self.on_behalf_of {
            Some(principal) => crate::delegation::label(principal, &self.author),
            None => self.author.clone(),
        }
    }
}

/// The mail tag map in force: subject tag to project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TagMap {
    pub map: BTreeMap<String, String>,
    pub set_by: Option<String>,
    pub set_at: Option<DateTime<Utc>>,
}

/// Two live facts about one subject that say different things.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    /// The id the master is asked under; the same two facts always give the same one.
    pub id: String,
    pub subject: String,
    pub project: Option<String>,
    pub facts: Vec<String>,
}

/// The library as read now.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Library {
    pub home: String,
    pub master: Option<String>,
    /// Every fact, oldest first, with its standing.
    pub facts: Vec<Fact>,
    pub tag_map: TagMap,
    /// What is wrong with the files, when this machine is holding on to what it saw.
    pub notices: Vec<String>,
    /// Lines that were read and not believed, one reason each.
    pub rejected: Vec<String>,
}

// --- names and checks --------------------------------------------------------------------

/// This machine's name as it appears in a library file name.
#[must_use]
pub fn machine_name() -> String {
    let label = crate::receipts::machine_label();
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "machine".to_string()
    } else {
        cleaned
    }
}

fn machine_ok(machine: &str) -> bool {
    (1..=40).contains(&machine.len())
        && machine
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn file_name(author: &str, machine: &str) -> String {
    format!("events.{author}__{machine}.jsonl")
}

fn dir(channel: &Path) -> PathBuf {
    channel.join(DIR)
}

/// An id of the shape `<prefix>-<10 hex>`.
#[must_use]
pub fn id_ok(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|hex| hex.len() == 10 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn fresh_id(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

/// A tag: lower-case letters, digits, `-`, `_` and `.`.
#[must_use]
pub fn tag_ok(tag: &str) -> bool {
    (1..=MAX_TAG).contains(&tag.len())
        && tag.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

fn sha_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn payload(event: &Event) -> String {
    crate::suggestions::sealed_payload("ferryman-library-v1", event)
}

fn signed_validly(event: &Event, roster: &[AgentRoute]) -> bool {
    crate::check_signature(
        Some(&event.author),
        Some(&event.signature),
        &payload(event),
        roster,
    ) == SignatureCheck::Valid
}

/// The reason an event's content is not believed, if it is not. Run on write and on read.
fn content_problem(event: &Event) -> Option<String> {
    let hidden = |text: &str| crate::suggestions::has_hidden_text(text);
    let id_prefix = if event.kind == Kind::Fact {
        FACT_PREFIX
    } else {
        EVENT_PREFIX
    };
    if !id_ok(&event.id, id_prefix) {
        return Some("its id is not of the right shape".into());
    }
    if !crate::is_safe_component(&event.author) || !machine_ok(&event.machine) {
        return Some("its author or machine is not a plain name".into());
    }
    match event.kind {
        Kind::Fact => {
            let subject = event.subject.trim();
            if subject.is_empty() || event.subject.chars().count() > MAX_SUBJECT {
                return Some(format!("a subject is 1 to {MAX_SUBJECT} characters"));
            }
            if event.text.trim().is_empty() || event.text.chars().count() > MAX_TEXT {
                return Some(format!("a fact is 1 to {MAX_TEXT} characters"));
            }
            if event.source.chars().count() > MAX_SOURCE {
                return Some(format!("the source is at most {MAX_SOURCE} characters"));
            }
            if hidden(&event.subject) || hidden(&event.text) || hidden(&event.source) {
                return Some("it has hidden or control characters".into());
            }
            if event.tags.len() > MAX_TAGS || event.tags.iter().any(|tag| !tag_ok(tag)) {
                return Some(format!(
                    "tags are at most {MAX_TAGS}, each lower-case letters, digits, '-', '_' or '.'"
                ));
            }
            if let Some(project) = &event.project
                && !crate::is_safe_component(project)
            {
                return Some("the project is not a plain project id".into());
            }
            if event.supersedes.len() > MAX_SUPERSEDES
                || event.supersedes.iter().any(|id| !id_ok(id, FACT_PREFIX))
            {
                return Some("supersedes names up to 8 fact ids".into());
            }
            for (label, field) in [
                ("subject", &event.subject),
                ("text", &event.text),
                ("source", &event.source),
            ] {
                if let Err(why) = guard::check(label, field) {
                    return Some(why);
                }
            }
            if let Err(why) = guard::check("tags", &event.tags.join(" ")) {
                return Some(why);
            }
            None
        }
        Kind::Confirm | Kind::Retract => {
            if !event
                .target
                .as_deref()
                .is_some_and(|target| id_ok(target, FACT_PREFIX))
            {
                return Some("it must name a fact".into());
            }
            if event.reason.chars().count() > MAX_REASON || hidden(&event.reason) {
                return Some("the reason is too long or has hidden characters".into());
            }
            guard::check("reason", &event.reason).err()
        }
        Kind::TagMap => {
            if event.tag_map.len() > MAX_TAG_MAP
                || event
                    .tag_map
                    .iter()
                    .any(|(tag, project)| !tag_ok(tag) || !crate::is_safe_component(project))
            {
                return Some("the tag map is up to 64 tags, each to a plain project id".into());
            }
            None
        }
    }
}

// --- authority ---------------------------------------------------------------------------

/// Whether `author` signing `on_behalf_of` speaks with the master's authority in the
/// library: it is the master, or a delegate holding the master's `library` scope.
fn master_authority(
    channel: &Path,
    home: &str,
    master: Option<&str>,
    author: &str,
    on_behalf_of: Option<&str>,
    now: DateTime<Utc>,
) -> bool {
    let Some(master) = master else {
        return false;
    };
    let principal = on_behalf_of.unwrap_or(author);
    principal.eq_ignore_ascii_case(master)
        && crate::delegation::authority(
            channel,
            home,
            principal,
            author,
            crate::delegation::LIBRARY,
            now,
        )
        .allowed()
}

// --- reading -----------------------------------------------------------------------------

type Line = (Event, String, Option<String>);

/// The prefix of `lines` that is a valid chain, each with the reason its content is not
/// believed (the chain goes on past such a line), and what stopped it, if anything did.
fn verify_chain(
    lines: &[String],
    name: &str,
    home: &str,
    roster: &[AgentRoute],
) -> (Vec<Line>, Option<String>) {
    let mut out: Vec<Line> = Vec::new();
    let mut prev = String::new();
    for (index, line) in lines.iter().enumerate() {
        let stop = |why: &str| Some(format!("{name} line {}: {why}", index + 1));
        if line.len() > MAX_LINE {
            return (out, stop("longer than a library line may be"));
        }
        let Ok(event) = serde_json::from_str::<Event>(line) else {
            return (out, stop("not a library entry"));
        };
        if event.home != home {
            return (out, stop("signed for another home project"));
        }
        if !crate::is_safe_component(&event.author)
            || !machine_ok(&event.machine)
            || file_name(&event.author, &event.machine) != name
        {
            return (out, stop("not this file's author and machine"));
        }
        if event.seq != index as u64 + 1 || event.prev != prev {
            return (out, stop("the chain does not line up"));
        }
        if !signed_validly(&event, roster) {
            return (
                out,
                stop("the signature does not verify against the roster"),
            );
        }
        prev = sha_hex(line);
        let problem = content_problem(&event);
        out.push((event, line.clone(), problem));
    }
    (out, None)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Seen {
    lines: Vec<String>,
}

#[cfg(test)]
thread_local! {
    static STATE_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// This crate's tests keep the library's memory in a directory of their own, per test, so
/// that a test elsewhere finishing and removing the shared machine-state base cannot pull
/// the floor out from under one still running.
#[cfg(test)]
pub(crate) fn use_state_dir_for_this_thread(dir: PathBuf) {
    STATE_OVERRIDE.with(|state| *state.borrow_mut() = Some(dir));
}

/// The machine's state directory: where what this machine has seen is kept, outside the
/// synced folder.
pub(crate) fn machine_state() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = STATE_OVERRIDE.with(|state| state.borrow().clone()) {
        let _ = fs::create_dir_all(&dir);
        return Some(dir);
    }
    crate::licensing::machine_state_dir()
}

fn state_dir(channel: &Path, home: &str) -> Option<PathBuf> {
    let base = machine_state()?.join("library");
    let channel = fs::canonicalize(channel).unwrap_or_else(|_| channel.to_path_buf());
    let key = sha_hex(&format!("{}\n{home}", channel.display()));
    Some(base.join(&key[..24]))
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn library_files(channel: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = fs::read_dir(dir(channel)) else {
        return Vec::new();
    };
    let mut files: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            (name.starts_with("events.")
                && name.ends_with(".jsonl")
                && !name.contains(".sync-conflict-"))
            .then(|| (name, entry.path()))
        })
        .collect();
    files.sort();
    files
}

/// What this machine believes of one file: the verified chain, and any notice.
fn settle_file(
    name: &str,
    file_lines: &[String],
    seen: Option<&Seen>,
    home: &str,
    roster: &[AgentRoute],
) -> (Vec<Line>, Vec<String>, Option<Seen>) {
    let (good, stopped) = verify_chain(file_lines, name, home, roster);
    let good_lines: Vec<String> = good.iter().map(|(_, line, _)| line.clone()).collect();
    let mut notices = Vec::new();
    if let Some(why) = stopped {
        notices.push(why);
    }
    let remembered: Vec<String> = seen.map(|seen| seen.lines.clone()).unwrap_or_default();
    if remembered.is_empty() || good_lines.starts_with(&remembered) {
        let update = if !good_lines.is_empty() && good_lines != remembered {
            Some(Seen { lines: good_lines })
        } else {
            None
        };
        return (good, notices, update);
    }
    // What this machine saw is verified again; nothing on disk is trusted.
    let (kept, _) = verify_chain(&remembered, name, home, roster);
    let why = if remembered.starts_with(&good_lines) {
        format!(
            "{name} has {} entries but this machine has already seen {}: it went back, or \
             lost lines",
            good_lines.len(),
            remembered.len()
        )
    } else {
        format!("{name} no longer continues what this machine saw: it was replaced or forked")
    };
    notices.push(why);
    (kept, notices, None)
}

impl Library {
    /// Read the library in `channel` (the home project `home`'s channel): verify every file,
    /// hold on to what this machine saw if a file went back, and add it up.
    #[must_use]
    pub fn load(channel: &Path, home: &str) -> Self {
        let roster = crate::read_agent_roster(channel).unwrap_or_default();
        let master = crate::master::read_master_at(channel, &roster)
            .ok()
            .flatten()
            .map(|declaration| declaration.master);
        let state = state_dir(channel, home);
        let mut library = Self {
            home: home.to_string(),
            master: master.clone(),
            ..Self::default()
        };
        let mut lines: Vec<Line> = Vec::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        for (name, path) in library_files(channel) {
            names.insert(name.clone());
            let seen_path = state
                .as_ref()
                .map(|state| state.join(format!("{name}.json")));
            let seen = seen_path
                .as_deref()
                .and_then(|path| fs::read(path).ok())
                .and_then(|bytes| serde_json::from_slice::<Seen>(&bytes).ok());
            let (chain, notices, update) =
                settle_file(&name, &read_lines(&path), seen.as_ref(), home, &roster);
            library.notices.extend(notices);
            if let (Some(update), Some(seen_path)) = (update, seen_path) {
                let _ = crate::atomic_json(&seen_path, &update);
            }
            lines.extend(chain);
        }
        // A file that is gone but was seen: what was seen stays in force.
        if let Some(state) = &state
            && let Ok(entries) = fs::read_dir(state)
        {
            for entry in entries.flatten() {
                let Some(file) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let Some(name) = file.strip_suffix(".json") else {
                    continue;
                };
                if names.contains(name) || !name.starts_with("events.") {
                    continue;
                }
                let Some(seen) = fs::read(entry.path())
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Seen>(&bytes).ok())
                else {
                    continue;
                };
                let (chain, _) = verify_chain(&seen.lines, name, home, &roster);
                if !chain.is_empty() {
                    library.notices.push(format!(
                        "{name} is gone from the channel; this machine keeps what it saw"
                    ));
                    lines.extend(chain);
                }
            }
        }
        library.fold(channel, home, lines);
        library
    }

    fn fold(&mut self, channel: &Path, home: &str, lines: Vec<Line>) {
        let now = Utc::now();
        let master = self.master.clone();
        let authority = |event: &Event| {
            master_authority(
                channel,
                home,
                master.as_deref(),
                &event.author,
                event.on_behalf_of.as_deref(),
                now,
            )
        };
        let mut events: Vec<Event> = Vec::new();
        let mut seen_ids: BTreeSet<String> = BTreeSet::new();
        for (event, _, problem) in lines {
            if let Some(why) = problem {
                self.rejected.push(format!("{}: {why}", event.id));
                continue;
            }
            if !seen_ids.insert(event.id.clone()) {
                self.rejected.push(format!("{}: used twice", event.id));
                continue;
            }
            // Someone claiming to speak for the master without holding the scope is not
            // believed, whatever they wrote.
            let claims_master = event.on_behalf_of.is_some();
            let master_only = matches!(event.kind, Kind::Confirm | Kind::Retract | Kind::TagMap);
            if (claims_master || master_only) && !authority(&event) {
                self.rejected.push(format!(
                    "{}: {} has no authority to do that",
                    event.id, event.author
                ));
                continue;
            }
            events.push(event);
        }
        let mut facts: BTreeMap<String, Fact> = BTreeMap::new();
        for event in events.iter().filter(|event| event.kind == Kind::Fact) {
            let confirmed = authority(event);
            let by = confirmed.then(|| {
                event.on_behalf_of.as_ref().map_or_else(
                    || event.author.clone(),
                    |principal| crate::delegation::label(principal, &event.author),
                )
            });
            facts.insert(
                event.id.clone(),
                Fact {
                    id: event.id.clone(),
                    subject: event.subject.trim().to_string(),
                    text: event.text.trim().to_string(),
                    tags: event.tags.clone(),
                    project: event.project.clone(),
                    source: event.source.clone(),
                    author: event.author.clone(),
                    on_behalf_of: event.on_behalf_of.clone(),
                    machine: event.machine.clone(),
                    created_at: event.created_at,
                    supersedes: event.supersedes.clone(),
                    status: if confirmed {
                        Status::Confirmed
                    } else {
                        Status::Unconfirmed
                    },
                    confirmed_by: by,
                    confirmed_at: confirmed.then_some(event.created_at),
                    retracted_by: None,
                    retract_reason: String::new(),
                    superseded_by: Vec::new(),
                    generated: false,
                },
            );
        }
        // The master's later word, in order: the last confirm or retract of a fact stands.
        let mut decisions: Vec<&Event> = events
            .iter()
            .filter(|event| matches!(event.kind, Kind::Confirm | Kind::Retract))
            .collect();
        decisions.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then(a.author.cmp(&b.author))
                .then(a.seq.cmp(&b.seq))
        });
        for event in decisions {
            let Some(fact) = event
                .target
                .as_ref()
                .and_then(|target| facts.get_mut(target))
            else {
                self.rejected
                    .push(format!("{}: there is no such fact", event.id));
                continue;
            };
            let by = event.on_behalf_of.as_ref().map_or_else(
                || event.author.clone(),
                |principal| crate::delegation::label(principal, &event.author),
            );
            if event.kind == Kind::Confirm {
                fact.status = Status::Confirmed;
                fact.confirmed_by = Some(by);
                fact.confirmed_at = Some(event.created_at);
                fact.retracted_by = None;
                fact.retract_reason.clear();
            } else {
                fact.status = Status::Retracted;
                fact.retracted_by = Some(by);
                fact.retract_reason.clone_from(&event.reason);
            }
        }
        // Supersession: only a confirmed fact, or an author correcting their own
        // unconfirmed one, takes another out of sight. A fact can only replace an older one.
        type Replacement = (String, Status, String, DateTime<Utc>, Vec<String>);
        let snapshot: Vec<Replacement> = facts
            .values()
            .map(|fact| {
                (
                    fact.id.clone(),
                    fact.status,
                    fact.author.clone(),
                    fact.created_at,
                    fact.supersedes.clone(),
                )
            })
            .collect();
        for (newer, newer_status, newer_author, newer_at, replaces) in snapshot {
            if newer_status == Status::Retracted {
                continue;
            }
            for old in replaces {
                if old == newer {
                    continue;
                }
                let Some(target) = facts.get_mut(&old) else {
                    continue;
                };
                let own_correction =
                    target.status != Status::Confirmed && target.author == newer_author;
                if target.created_at < newer_at
                    && (newer_status == Status::Confirmed || own_correction)
                    && !target.superseded_by.contains(&newer)
                {
                    target.superseded_by.push(newer.clone());
                }
            }
        }
        let mut tag_events: Vec<&Event> = events
            .iter()
            .filter(|event| event.kind == Kind::TagMap)
            .collect();
        tag_events.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.seq.cmp(&b.seq)));
        if let Some(last) = tag_events.last() {
            self.tag_map = TagMap {
                map: last.tag_map.clone(),
                set_by: Some(last.on_behalf_of.as_ref().map_or_else(
                    || last.author.clone(),
                    |principal| crate::delegation::label(principal, &last.author),
                )),
                set_at: Some(last.created_at),
            };
        }
        let mut all: Vec<Fact> = facts.into_values().collect();
        all.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        self.facts = all;
    }

    /// One fact by id, whatever its standing.
    #[must_use]
    pub fn fact(&self, id: &str) -> Option<&Fact> {
        self.facts.iter().find(|fact| fact.id == id)
    }

    /// The facts still current.
    pub fn live(&self) -> impl Iterator<Item = &Fact> {
        self.facts.iter().filter(|fact| fact.is_live())
    }

    /// Facts waiting for the master.
    pub fn unconfirmed(&self) -> impl Iterator<Item = &Fact> {
        self.live()
            .filter(|fact| fact.status == Status::Unconfirmed)
    }

    /// Everything ever said about `subject`, oldest first: replaced and retracted too.
    #[must_use]
    pub fn history(&self, subject: &str) -> Vec<&Fact> {
        let key = subject_key(subject);
        self.facts
            .iter()
            .filter(|fact| subject_key(&fact.subject) == key)
            .collect()
    }

    /// Live facts about one subject (in one project) that say different things.
    #[must_use]
    pub fn conflicts(&self) -> Vec<Conflict> {
        let mut groups: BTreeMap<(String, Option<String>), Vec<&Fact>> = BTreeMap::new();
        for fact in self.live().filter(|fact| fact.status != Status::Generated) {
            groups
                .entry((subject_key(&fact.subject), fact.project.clone()))
                .or_default()
                .push(fact);
        }
        let mut out = Vec::new();
        for ((_, project), facts) in groups {
            let texts: BTreeSet<String> =
                facts.iter().map(|fact| subject_key(&fact.text)).collect();
            if facts.len() < 2 || texts.len() < 2 {
                continue;
            }
            let mut ids: Vec<String> = facts.iter().map(|fact| fact.id.clone()).collect();
            ids.sort();
            out.push(Conflict {
                id: format!("library-conflict-{}", &sha_hex(&ids.join(","))[..12]),
                subject: facts[0].subject.clone(),
                project,
                facts: ids,
            });
        }
        out
    }

    /// (confirmed, unconfirmed, retracted, replaced) counts.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut counts = (0, 0, 0, 0);
        for fact in &self.facts {
            if fact.status == Status::Retracted {
                counts.2 += 1;
            } else if !fact.superseded_by.is_empty() {
                counts.3 += 1;
            } else if fact.status == Status::Confirmed {
                counts.0 += 1;
            } else {
                counts.1 += 1;
            }
        }
        counts
    }
}

/// A subject or text compared loosely: case, spacing and trailing punctuation do not make
/// two claims different.
#[must_use]
pub fn subject_key(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|c: char| c.is_ascii_punctuation())
        .to_lowercase()
}

// --- writing -----------------------------------------------------------------------------

/// A fact to be written.
#[derive(Debug, Clone, Default)]
pub struct NewFact {
    pub subject: String,
    pub text: String,
    pub tags: Vec<String>,
    pub project: Option<String>,
    pub source: String,
    pub supersedes: Vec<String>,
}

/// What a write came to.
#[derive(Debug, Clone)]
pub struct Written {
    pub event: Event,
    /// A fact is confirmed on the spot only when it carries the master's authority.
    pub status: Status,
}

fn blank(kind: Kind, home: &str, identity: &AgentIdentity, on_behalf_of: Option<&str>) -> Event {
    Event {
        id: fresh_id(if kind == Kind::Fact {
            FACT_PREFIX
        } else {
            EVENT_PREFIX
        }),
        kind,
        home: home.to_string(),
        machine: machine_name(),
        seq: 0,
        prev: String::new(),
        created_at: Utc::now(),
        author: identity.name().to_string(),
        on_behalf_of: on_behalf_of
            .filter(|principal| !principal.eq_ignore_ascii_case(identity.name()))
            .map(str::to_string),
        subject: String::new(),
        text: String::new(),
        tags: Vec::new(),
        project: None,
        source: String::new(),
        supersedes: Vec::new(),
        target: None,
        reason: String::new(),
        tag_map: BTreeMap::new(),
        signature: String::new(),
    }
}

/// Refuse unless `identity` is on the channel's roster under its own key: otherwise
/// nothing it signs would be believed by anyone.
pub(crate) fn require_on_roster(channel: &Path, identity: &AgentIdentity) -> Result<()> {
    let roster = crate::read_agent_roster(channel)?;
    let known = roster
        .iter()
        .find(|agent| agent.name.eq_ignore_ascii_case(identity.name()))
        .and_then(|agent| agent.public_key.clone());
    if known.as_deref() != Some(identity.public_key_hex().as_str()) {
        bail!(
            "{} is not on the home channel's roster under this key, so nothing it writes \
             would be believed. Ask the master to add it (or start it once so it publishes \
             its key)",
            identity.name()
        );
    }
    Ok(())
}

/// Refuse unless the signer has the master's authority for a master-only action.
fn require_master_authority(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    on_behalf_of: Option<&str>,
    what: &str,
) -> Result<()> {
    match on_behalf_of.filter(|p| !p.eq_ignore_ascii_case(identity.name())) {
        None => crate::ferry::require_master(channel, home, identity, what),
        Some(principal) => {
            let Some(master) = crate::ferry::master_of(channel)? else {
                bail!("{home} has no master, and only its master can {what}");
            };
            if !principal.eq_ignore_ascii_case(&master) {
                bail!("only {master}, {home}'s master, can {what} - not {principal}");
            }
            if let crate::delegation::Authority::Refused(why) = crate::delegation::authority(
                channel,
                home,
                principal,
                identity.name(),
                crate::delegation::LIBRARY,
                Utc::now(),
            ) {
                bail!("{} cannot {what} for {principal}: {why}", identity.name());
            }
            Ok(())
        }
    }
}

fn write_lock() -> Option<fs::File> {
    let path = machine_state()?.join("library").join("write.lock");
    fs::create_dir_all(path.parent()?).ok()?;
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .ok()?;
    file.lock_exclusive().ok()?;
    Some(file)
}

/// Sign `event` as `identity` and append it to the writer's own file.
fn append(channel: &Path, home: &str, identity: &AgentIdentity, mut event: Event) -> Result<Event> {
    if let Some(why) = content_problem(&event) {
        bail!("{why}");
    }
    let roster = crate::read_agent_roster(channel)?;
    let name = file_name(identity.name(), &event.machine);
    let path = dir(channel).join(&name);
    let _lock = write_lock();
    let state = state_dir(channel, home);
    let seen_path = state
        .as_ref()
        .map(|state| state.join(format!("{name}.json")));
    let seen = seen_path
        .as_deref()
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Seen>(&bytes).ok());
    let (chain, notices, _) = settle_file(&name, &read_lines(&path), seen.as_ref(), home, &roster);
    if let Some(notice) = notices.first() {
        bail!(
            "this machine's library file is not in a state to append to ({notice}). The \
             master can settle it; nothing was written"
        );
    }
    let prev = chain
        .last()
        .map(|(_, line, _)| sha_hex(line))
        .unwrap_or_default();
    event.seq = chain.len() as u64 + 1;
    event.prev = prev;
    event.created_at = Utc::now();
    event.signature = identity.sign_bytes(payload(&event).as_bytes());
    let line = serde_json::to_string(&event)?;
    if line.len() > MAX_LINE {
        bail!("that entry is too long");
    }
    fs::create_dir_all(dir(channel))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "{line}")?;
    drop(file);
    if let Some(seen_path) = seen_path {
        let mut lines: Vec<String> = chain.into_iter().map(|(_, line, _)| line).collect();
        lines.push(line);
        let _ = crate::atomic_json(&seen_path, &Seen { lines });
    }
    Ok(event)
}

/// Write a fact. Confirmed on the spot when `identity` is the master (or a delegate with the
/// `library` scope signing for them); otherwise it waits for the master.
///
/// # Errors
/// The fact looks like a secret, is too long, names a fact that is not there, or the signer
/// is not on the home channel's roster.
pub fn remember(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    on_behalf_of: Option<&str>,
    new: NewFact,
) -> Result<Written> {
    if !channel.is_dir() {
        bail!(
            "the library lives in {home}'s channel, which is not on this machine ({})",
            channel.display()
        );
    }
    require_on_roster(channel, identity)?;
    let mut event = blank(Kind::Fact, home, identity, on_behalf_of);
    event.subject = new.subject.split_whitespace().collect::<Vec<_>>().join(" ");
    event.text = new.text.trim().to_string();
    let mut tags: Vec<String> = new
        .tags
        .iter()
        .map(|tag| tag.trim().to_lowercase())
        .collect();
    tags.retain(|tag| !tag.is_empty());
    tags.sort();
    tags.dedup();
    event.tags = tags;
    event.project = new
        .project
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    event.source = new.source.trim().to_string();
    event.supersedes = new.supersedes;
    if let Some(why) = content_problem(&event) {
        bail!("{why}");
    }
    let library = Library::load(channel, home);
    for id in &event.supersedes {
        if library.fact(id).is_none() {
            bail!("there is no fact {id} to supersede (see `ferry library search`)");
        }
    }
    let master_says = event.on_behalf_of.is_some()
        || library
            .master
            .as_deref()
            .is_some_and(|master| master.eq_ignore_ascii_case(identity.name()));
    if master_says {
        require_master_authority(
            channel,
            home,
            identity,
            event.on_behalf_of.as_deref(),
            "write confirmed facts",
        )?;
    }
    let event = append(channel, home, identity, event)?;
    Ok(Written {
        status: if master_says {
            Status::Confirmed
        } else {
            Status::Unconfirmed
        },
        event,
    })
}

fn decide(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    on_behalf_of: Option<&str>,
    kind: Kind,
    id: &str,
    reason: &str,
) -> Result<Event> {
    if !channel.is_dir() {
        bail!("{home}'s channel is not on this machine");
    }
    require_on_roster(channel, identity)?;
    let what = if kind == Kind::Confirm {
        "confirm facts"
    } else {
        "retract facts"
    };
    require_master_authority(channel, home, identity, on_behalf_of, what)?;
    let library = Library::load(channel, home);
    let Some(fact) = library.fact(id) else {
        bail!("there is no fact {id}");
    };
    match kind {
        Kind::Confirm if fact.status == Status::Confirmed => bail!("{id} is already confirmed"),
        Kind::Retract if fact.status == Status::Retracted => bail!("{id} is already retracted"),
        _ => {}
    }
    let mut event = blank(kind, home, identity, on_behalf_of);
    event.target = Some(id.to_string());
    event.reason = reason.trim().to_string();
    append(channel, home, identity, event)
}

/// Confirm a fact: the master's word (or a `library` delegate's) that it is true.
///
/// # Errors
/// The signer is not the master, the fact is not there or is already confirmed.
pub fn confirm(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    on_behalf_of: Option<&str>,
    id: &str,
) -> Result<Event> {
    decide(channel, home, identity, on_behalf_of, Kind::Confirm, id, "")
}

/// Retract a fact: it stays in the history, and is no longer an answer.
///
/// # Errors
/// The signer is not the master, the fact is not there or is already retracted.
pub fn retract(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    on_behalf_of: Option<&str>,
    id: &str,
    reason: &str,
) -> Result<Event> {
    decide(
        channel,
        home,
        identity,
        on_behalf_of,
        Kind::Retract,
        id,
        reason,
    )
}

/// Replace the mail tag map. Master only.
///
/// # Errors
/// The signer is not the master, or the map is not tags to plain project ids.
pub fn set_tag_map(
    channel: &Path,
    home: &str,
    identity: &AgentIdentity,
    on_behalf_of: Option<&str>,
    map: BTreeMap<String, String>,
) -> Result<Event> {
    if !channel.is_dir() {
        bail!("{home}'s channel is not on this machine");
    }
    require_on_roster(channel, identity)?;
    require_master_authority(
        channel,
        home,
        identity,
        on_behalf_of,
        "edit the mail tag map",
    )?;
    let mut event = blank(Kind::TagMap, home, identity, on_behalf_of);
    event.tag_map = map;
    append(channel, home, identity, event)
}

// --- the master's questions --------------------------------------------------------------

/// Ask the master about each contradiction not yet asked about, once each, through the same
/// signed question every other "needs me" uses. Returns the question ids asked now.
///
/// # Errors
/// A question could not be written.
pub fn ask_about_conflicts(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    library: &Library,
) -> Result<Vec<String>> {
    let mut asked = Vec::new();
    for conflict in library.conflicts() {
        let mut lines = vec![format!(
            "The library disagrees with itself about \"{}\"{}. Which is right?",
            crate::suggestions::plain(&conflict.subject, 80),
            conflict
                .project
                .as_ref()
                .map_or(String::new(), |project| format!(" ({project})"))
        )];
        for id in &conflict.facts {
            if let Some(fact) = library.fact(id) {
                lines.push(format!(
                    "{} ({}, {} on {}): {}",
                    fact.id,
                    fact.status.as_str(),
                    fact.written_by(),
                    fact.created_at.format("%Y-%m-%d"),
                    crate::suggestions::defang(&crate::suggestions::plain(&fact.text, 300))
                ));
            }
        }
        lines.push(
            "To settle it: `ferry library confirm <id>` for the true one, `ferry library \
             retract <id>` for the wrong one, or write a new fact that supersedes both."
                .to_string(),
        );
        if crate::questions::ask(
            route,
            identity,
            &conflict.id,
            crate::questions::LIBRARY,
            &lines.join("\n"),
            &["Understood".to_string()],
            None,
        )? {
            asked.push(conflict.id.clone());
        }
    }
    Ok(asked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    const HOME: &str = "ferryman";

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    /// The home project's channel, its master `members[0]`, every member on the roster; and
    /// this thread's own machine-state directory, so rollback memory is never shared.
    fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
        use_state_dir_for_this_thread(dir.join("state"));
        let communications = dir.join("ferryman-ferryman");
        fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: HOME.into(),
            workspace: dir.join("ferryman"),
            attachment: dir.join("attachment"),
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in members {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, members[0], members[0].name()).unwrap();
        route
    }

    fn fact(subject: &str, text: &str) -> NewFact {
        NewFact {
            subject: subject.into(),
            text: text.into(),
            source: "test".into(),
            ..NewFact::default()
        }
    }

    fn say(route: &ProjectRoute, who: &AgentIdentity, subject: &str, text: &str) -> Written {
        remember(&route.communications, HOME, who, None, fact(subject, text)).unwrap()
    }

    fn load(route: &ProjectRoute) -> Library {
        Library::load(&route.communications, HOME)
    }

    fn file_of(route: &ProjectRoute, who: &AgentIdentity) -> PathBuf {
        dir(&route.communications).join(file_name(who.name(), &machine_name()))
    }

    #[test]
    fn the_masters_facts_are_confirmed_and_anyone_elses_wait() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);

        let mine = say(
            &route,
            &josh,
            "grouchly",
            "grouchly is the always-on Ubuntu box",
        );
        let theirs = say(&route, &grouchly, "beastly", "beastly is Windows with WSL");
        assert_eq!(mine.status, Status::Confirmed);
        assert_eq!(theirs.status, Status::Unconfirmed);

        let library = load(&route);
        assert_eq!(library.master.as_deref(), Some("josh"));
        assert!(library.notices.is_empty() && library.rejected.is_empty());
        let a = library.fact(&mine.event.id).unwrap();
        assert_eq!(a.status, Status::Confirmed);
        assert_eq!(a.confirmed_by.as_deref(), Some("josh"));
        let b = library.fact(&theirs.event.id).unwrap();
        assert_eq!(b.status, Status::Unconfirmed);
        assert_eq!(b.written_by(), "grouchly");
        assert_eq!(library.unconfirmed().count(), 1);
        assert_eq!(library.counts(), (1, 1, 0, 0));
    }

    #[test]
    fn only_the_master_or_a_library_delegate_confirms_or_retracts() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &grouchly, &bridge]);
        let channel = &route.communications;
        let proposed = say(&route, &grouchly, "port", "the dashboard listens on 7821");
        let id = proposed.event.id.clone();

        // A member, someone using the master's name with another key, a delegate with no
        // delegation and one with the wrong scope: none of them confirm.
        assert!(confirm(channel, HOME, &grouchly, None, &id).is_err());
        assert!(retract(channel, HOME, &grouchly, None, &id, "no").is_err());
        assert!(confirm(channel, HOME, &person("josh", 9), None, &id).is_err());
        assert!(confirm(channel, HOME, &bridge, Some("josh"), &id).is_err());
        crate::delegation::grant(
            channel,
            HOME,
            &josh,
            bridge.name(),
            &["improve".to_string()],
            None,
        )
        .unwrap();
        assert!(confirm(channel, HOME, &bridge, Some("josh"), &id).is_err());
        assert!(confirm(channel, HOME, &bridge, Some("grouchly"), &id).is_err());
        assert_eq!(load(&route).fact(&id).unwrap().status, Status::Unconfirmed);

        // The master does.
        confirm(channel, HOME, &josh, None, &id).unwrap();
        let confirmed = load(&route);
        let fact = confirmed.fact(&id).unwrap();
        assert_eq!(fact.status, Status::Confirmed);
        assert_eq!(fact.confirmed_by.as_deref(), Some("josh"));
        assert!(
            confirm(channel, HOME, &josh, None, &id).is_err(),
            "already so"
        );

        // And so does a delegate holding the library scope, as "josh via ...".
        let second = say(&route, &grouchly, "second", "a second claim to confirm");
        crate::delegation::grant(
            channel,
            HOME,
            &josh,
            bridge.name(),
            &["library".to_string()],
            None,
        )
        .unwrap();
        confirm(channel, HOME, &bridge, Some("josh"), &second.event.id).unwrap();
        let library = load(&route);
        assert_eq!(
            library
                .fact(&second.event.id)
                .unwrap()
                .confirmed_by
                .as_deref(),
            Some("josh via telegram-grouchly")
        );

        // Retract is the master's too, and keeps the fact in the history.
        assert!(retract(channel, HOME, &grouchly, None, &id, "x").is_err());
        retract(channel, HOME, &josh, None, &id, "the port moved").unwrap();
        let library = load(&route);
        let gone = library.fact(&id).unwrap();
        assert_eq!(gone.status, Status::Retracted);
        assert_eq!(gone.retract_reason, "the port moved");
        assert!(!gone.is_live());
        assert_eq!(library.live().count(), 1);
        assert_eq!(library.history("port").len(), 1, "history keeps it");

        // Revoking the delegation un-confirms what the delegate confirmed, until the
        // master confirms it again.
        crate::delegation::revoke(channel, HOME, &josh, bridge.name(), "lost the phone").unwrap();
        assert_eq!(
            load(&route).fact(&second.event.id).unwrap().status,
            Status::Unconfirmed
        );
        confirm(channel, HOME, &josh, None, &second.event.id).unwrap();
        assert_eq!(
            load(&route).fact(&second.event.id).unwrap().status,
            Status::Confirmed
        );
    }

    #[test]
    fn a_fact_is_never_edited_a_new_one_supersedes_it_and_history_stays() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;

        let first = say(&route, &josh, "release cadence", "releases go out weekly");
        let mut next = fact("release cadence", "releases go out fortnightly");
        next.supersedes = vec![first.event.id.clone()];
        let second = remember(channel, HOME, &josh, None, next).unwrap();
        let mut third_text = fact("Release cadence", "releases go out when approved");
        third_text.supersedes = vec![second.event.id.clone()];
        let third = remember(channel, HOME, &josh, None, third_text).unwrap();

        let library = load(&route);
        let live: Vec<&str> = library.live().map(|f| f.id.as_str()).collect();
        assert_eq!(
            live,
            [third.event.id.as_str()],
            "only the newest is current"
        );
        assert_eq!(
            library.fact(&first.event.id).unwrap().superseded_by,
            std::slice::from_ref(&second.event.id)
        );
        let history = library.history("RELEASE CADENCE");
        assert_eq!(history.len(), 3, "the whole chain, oldest first");
        assert_eq!(history[0].id, first.event.id);
        assert_eq!(history[2].id, third.event.id);
        assert!(
            library.conflicts().is_empty(),
            "a chain is not a contradiction"
        );

        // A fact that supersedes something that is not there is refused.
        let mut bad = fact("x", "y");
        bad.supersedes = vec!["f-0000000000".into()];
        assert!(remember(channel, HOME, &josh, None, bad).is_err());

        // An agent correcting its own unconfirmed fact replaces it...
        let mine = say(&route, &grouchly, "port", "listens on 7000");
        let mut fix = fact("port", "listens on 7821");
        fix.supersedes = vec![mine.event.id.clone()];
        let fixed = remember(channel, HOME, &grouchly, None, fix).unwrap();
        let library = load(&route);
        assert!(!library.fact(&mine.event.id).unwrap().is_live());
        assert!(library.fact(&fixed.event.id).unwrap().is_live());

        // ...but cannot push a confirmed fact out of sight: both stay, and it is a
        // contradiction for the master.
        let mut rival = fact("release cadence", "releases go out hourly");
        rival.supersedes = vec![third.event.id.clone()];
        let rival = remember(channel, HOME, &grouchly, None, rival).unwrap();
        let library = load(&route);
        assert!(library.fact(&third.event.id).unwrap().is_live());
        assert!(library.fact(&rival.event.id).unwrap().is_live());
        let conflicts = library.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].facts.len(), 2);

        // Once the master confirms the rival, it does replace the old one.
        confirm(channel, HOME, &josh, None, &rival.event.id).unwrap();
        let library = load(&route);
        assert!(!library.fact(&third.event.id).unwrap().is_live());
        assert!(library.conflicts().is_empty());
    }

    #[test]
    fn contradictions_are_put_to_the_master_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        say(
            &route,
            &josh,
            "nvidia key",
            "NVIDIA key: Custodly, name nvidiaapi",
        );
        say(
            &route,
            &grouchly,
            "nvidia key",
            "NVIDIA key: the vault, name nv-main",
        );
        say(&route, &grouchly, "unrelated", "nothing to see");

        let library = load(&route);
        let asked = ask_about_conflicts(&route, &grouchly, &library).unwrap();
        assert_eq!(asked.len(), 1);
        assert!(
            ask_about_conflicts(&route, &grouchly, &library)
                .unwrap()
                .is_empty()
        );
        let pending = crate::questions::pending(&route);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, crate::questions::LIBRARY);
        assert!(pending[0].text.contains("Custodly") && pending[0].text.contains("nv-main"));
        assert!(pending[0].text.contains("confirm"), "{}", pending[0].text);
    }

    #[test]
    fn a_tampered_line_stops_the_chain_and_never_reaches_the_facts() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let one = say(&route, &josh, "one", "the first claim");
        say(&route, &josh, "two", "the second claim");
        say(&route, &josh, "three", "the third claim");

        let path = file_of(&route, &josh);
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 3);
        // Change a word in the middle line.
        let forged = lines[1].replace("the second claim", "the forged claim");
        fs::write(&path, format!("{}\n{forged}\n{}\n", lines[0], lines[2])).unwrap();
        let library = load(&route);
        // What this machine saw before is kept in force, and the file's problem is said.
        assert_eq!(library.facts.len(), 3);
        assert!(library.facts.iter().all(|f| !f.text.contains("forged")));
        assert!(!library.notices.is_empty(), "{:?}", library.notices);
        assert!(library.fact(&one.event.id).is_some());

        // A machine that never saw the good file only believes the lines before the break.
        use_state_dir_for_this_thread(dir.path().join("elsewhere"));
        let stranger = load(&route);
        assert_eq!(stranger.facts.len(), 1, "{:?}", stranger.notices);
        assert!(stranger.notices.iter().any(|n| n.contains("signature")));
    }

    #[test]
    fn a_library_file_that_goes_back_is_held_at_what_this_machine_saw() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        say(&route, &josh, "a", "claim a");
        say(&route, &josh, "b", "claim b");
        say(&route, &josh, "c", "claim c");
        assert!(load(&route).notices.is_empty());
        let path = file_of(&route, &josh);
        let lines = read_lines(&path);

        // Rolled back to two lines.
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 3, "the last good state stays in force");
        assert!(
            library.notices.iter().any(|n| n.contains("went back")),
            "{:?}",
            library.notices
        );
        // Nobody can append on top of a file that went back.
        assert!(
            remember(
                &route.communications,
                HOME,
                &josh,
                None,
                fact("d", "claim d")
            )
            .is_err()
        );

        // Deleted outright.
        fs::remove_file(&path).unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 3);
        assert!(
            library.notices.iter().any(|n| n.contains("gone")),
            "{:?}",
            library.notices
        );

        // Put back whole, the notice goes away.
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 3);
        assert!(library.notices.is_empty(), "{:?}", library.notices);
        remember(
            &route.communications,
            HOME,
            &josh,
            None,
            fact("d", "claim d"),
        )
        .unwrap();
        assert_eq!(load(&route).facts.len(), 4);
    }

    #[test]
    fn a_file_that_no_longer_continues_what_was_seen_is_not_believed() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        say(&route, &josh, "a", "claim a");
        say(&route, &josh, "b", "claim b");
        let path = file_of(&route, &josh);
        // A different, validly signed chain of the same author appears in its place: the
        // same key signing a story this machine never saw.
        let elsewhere = tempfile::tempdir().unwrap();
        let other = {
            let alt = self::route(elsewhere.path(), &[&josh]);
            say(&alt, &josh, "a", "claim A, rewritten");
            say(&alt, &josh, "b", "claim B, rewritten");
            say(&alt, &josh, "c", "claim C, rewritten");
            let text = fs::read_to_string(file_of(&alt, &josh)).unwrap();
            use_state_dir_for_this_thread(dir.path().join("state"));
            text
        };
        fs::write(&path, other).unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 2);
        assert!(library.facts.iter().all(|f| !f.text.contains("rewritten")));
        assert!(
            library
                .notices
                .iter()
                .any(|n| n.contains("no longer continues")),
            "{:?}",
            library.notices
        );
    }

    #[test]
    fn secrets_are_refused_going_in_and_never_believed_coming_out() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let token = format!(
            "ghp_{}",
            ["aB3dE5fG7", "hJ9kL1mN3", "pQ5rS7tU9", "vW1xY3zA5"].concat()
        );
        let error = remember(
            &route.communications,
            HOME,
            &josh,
            None,
            fact("the token", &format!("use {token} for the deploy")),
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains(&token));
        assert!(format!("{error:#}").contains("pointer"));
        for (subject, text) in [
            (
                "nvidia key",
                format!(
                    "NVIDIA_API_KEY={}",
                    "q8Zr3LmX0vB2nC6dF9gH1jK4pT7wY5sA3eR8uI2oP6"
                ),
            ),
            (
                "db",
                format!("{}://admin:s3cretpass9@db.internal/prod", "postgres"),
            ),
        ] {
            assert!(
                remember(
                    &route.communications,
                    HOME,
                    &josh,
                    None,
                    fact(subject, &text)
                )
                .is_err(),
                "{subject}"
            );
        }
        // The pointer form is fine.
        say(
            &route,
            &josh,
            "NVIDIA key",
            "NVIDIA key: Custodly, name nvidiaapi",
        );

        // A roster member who writes the line straight into the file, signed and chained,
        // is still not believed: the reader runs the same guard.
        let path = file_of(&route, &josh);
        let lines = read_lines(&path);
        let mut event = blank(Kind::Fact, HOME, &josh, None);
        event.subject = "sneaky".into();
        event.text = format!("the key is {token}");
        event.seq = lines.len() as u64 + 1;
        event.prev = sha_hex(lines.last().unwrap());
        event.signature = josh.sign_bytes(payload(&event).as_bytes());
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str(&serde_json::to_string(&event).unwrap());
        text.push('\n');
        fs::write(&path, text).unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 1);
        assert!(library.facts.iter().all(|f| !f.text.contains(&token)));
        assert!(
            library.rejected.iter().any(|r| r.contains("looks like")),
            "{:?}",
            library.rejected
        );
        assert!(!serde_json::to_string(&library).unwrap().contains(&token));
    }

    #[test]
    fn someone_claiming_the_masters_word_without_the_scope_is_not_believed() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        let honest = say(&route, &grouchly, "honest", "an honest claim");

        // grouchly writes a fact "on behalf of josh" and a confirm, by hand.
        let path = file_of(&route, &grouchly);
        let mut lines = read_lines(&path);
        for kind in [Kind::Fact, Kind::Confirm] {
            let mut event = blank(kind, HOME, &grouchly, None);
            event.on_behalf_of = Some("josh".into());
            event.seq = lines.len() as u64 + 1;
            event.prev = sha_hex(lines.last().unwrap());
            if kind == Kind::Fact {
                event.subject = "forged".into();
                event.text = "josh says so".into();
            } else {
                event.target = Some(honest.event.id.clone());
            }
            event.signature = grouchly.sign_bytes(payload(&event).as_bytes());
            lines.push(serde_json::to_string(&event).unwrap());
        }
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 1, "the forged fact is not believed");
        assert_eq!(
            library.fact(&honest.event.id).unwrap().status,
            Status::Unconfirmed
        );
        assert_eq!(library.rejected.len(), 2, "{:?}", library.rejected);
    }

    #[test]
    fn a_writer_off_the_roster_is_refused_and_so_is_a_line_from_another_home() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let stranger = person("stranger", 5);
        let route = route(dir.path(), &[&josh]);
        let error =
            remember(&route.communications, HOME, &stranger, None, fact("a", "b")).unwrap_err();
        assert!(format!("{error:#}").contains("roster"));
        // Same name, another key.
        assert!(
            remember(
                &route.communications,
                HOME,
                &person("josh", 9),
                None,
                fact("a", "b")
            )
            .is_err()
        );
        // A line signed for another home project, however validly, is not read.
        let written = say(&route, &josh, "a", "claim a");
        let path = file_of(&route, &josh);
        let text = fs::read_to_string(&path).unwrap();
        let mut event = written.event.clone();
        event.home = "elsewhere".into();
        event.signature = josh.sign_bytes(payload(&event).as_bytes());
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        let library = Library::load(&route.communications, HOME);
        // This machine saw the real line, so it holds to it.
        assert_eq!(library.facts.len(), 1);
        assert!(!library.notices.is_empty());
        fs::write(&path, text).unwrap();
    }

    #[test]
    fn the_mail_tag_map_is_the_masters_to_edit() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;
        let map: BTreeMap<String, String> =
            [("redaktly".to_string(), "redaktly".to_string())].into();
        assert!(set_tag_map(channel, HOME, &grouchly, None, map.clone()).is_err());
        let bad: BTreeMap<String, String> = [("Not A Tag".to_string(), "x".to_string())].into();
        assert!(set_tag_map(channel, HOME, &josh, None, bad).is_err());
        set_tag_map(channel, HOME, &josh, None, map.clone()).unwrap();
        let library = load(&route);
        assert_eq!(library.tag_map.map, map);
        assert_eq!(library.tag_map.set_by.as_deref(), Some("josh"));
        set_tag_map(channel, HOME, &josh, None, BTreeMap::new()).unwrap();
        assert!(load(&route).tag_map.map.is_empty(), "the newest map stands");
    }

    #[test]
    fn two_machines_writing_in_one_sync_window_keep_both_histories() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let here = say(&route, &josh, "from here", "written on this machine");
        // The same author on another machine has a file of its own.
        let path = file_of(&route, &josh);
        let other = dir_of_other_machine(&path, "otherbox");
        let mut event = blank(Kind::Fact, HOME, &josh, None);
        event.machine = "otherbox".into();
        event.subject = "from there".into();
        event.text = "written on the other machine".into();
        event.seq = 1;
        event.signature = josh.sign_bytes(payload(&event).as_bytes());
        fs::write(
            &other,
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        let library = load(&route);
        assert_eq!(library.facts.len(), 2);
        assert!(library.fact(&here.event.id).is_some());
        assert!(library.notices.is_empty(), "{:?}", library.notices);
    }

    fn dir_of_other_machine(path: &Path, machine: &str) -> PathBuf {
        let name = path.file_name().unwrap().to_str().unwrap();
        let (author, _) = name
            .strip_prefix("events.")
            .unwrap()
            .split_once("__")
            .unwrap();
        path.with_file_name(file_name(author, machine))
    }
}

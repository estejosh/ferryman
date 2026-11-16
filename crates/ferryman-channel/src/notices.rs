//! Notices for the operator: one way in, and Ferryman decides what goes out.
//!
//! Tools on a machine (a GPU queue, a render script, a reader, the worker itself) used to
//! hold their own bot tokens and message the operator directly, each on its own schedule,
//! so the same news arrived again and again and nothing could tell it apart from what
//! needed an answer. Now a tool hands Ferryman a notice (`ferry notify`) and Ferryman
//! decides:
//!
//! - `info` goes into the day's digest only;
//! - `act` and `urgent` go to the operator's chat, once: the same source, subject and
//!   state is not sent again until [`Rules::resend_after_hours`] has passed, and a new
//!   state for the same subject updates the message already sent rather than adding one;
//! - a source the operator muted goes into the digest whatever its level, except `urgent`.
//!
//! The notices a tool hands in wait in this machine's state directory (`notices/inbox`),
//! each in its own file, until the worker's next pass takes them. Nothing here sends: the
//! caller delivers what [`Ledger::decide`] says and records it with [`Ledger::sent`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How much a notice asks of the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Worth knowing, not worth a message: the digest.
    Info,
    /// Someone has to do something.
    Act,
    /// Someone has to do something now.
    Urgent,
}

impl Level {
    /// # Errors
    /// Not one of `info`, `act`, `urgent`.
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "act" => Ok(Self::Act),
            "urgent" => Ok(Self::Urgent),
            other => bail!("level '{other}' is not info, act or urgent"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Act => "act",
            Self::Urgent => "urgent",
        }
    }
}

/// One thing a tool wants the operator to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// The tool, as it names itself: `gpu-queue`, `reports/nightly`.
    pub source: String,
    /// What it is about, stable across repeats: `card`, `order 42`.
    pub subject: String,
    /// Where that thing stands: `waiting`, `failed`, `done`. A repeat has the same one.
    pub state: String,
    pub level: Level,
    /// One line for a person.
    pub text: String,
    pub at: DateTime<Utc>,
}

impl Notice {
    fn key(&self) -> String {
        format!("{}\u{1f}{}", self.source, self.subject)
    }

    /// The line the operator reads.
    #[must_use]
    pub fn line(&self) -> String {
        format!("[{}] {}", self.source, self.text)
    }

    /// # Errors
    /// An empty source, subject or text, or a text longer than a message should be.
    pub fn check(&self) -> Result<()> {
        for (name, value) in [
            ("source", &self.source),
            ("subject", &self.subject),
            ("text", &self.text),
        ] {
            if value.trim().is_empty() {
                bail!("a notice needs a {name}");
            }
        }
        if self.text.chars().count() > 1000 {
            bail!("a notice is one line for a person: keep the text under 1000 characters");
        }
        Ok(())
    }
}

/// This machine's notices folder: `<machine state>/notices`.
#[must_use]
pub fn dir() -> Option<PathBuf> {
    crate::licensing::machine_state_dir().map(|dir| dir.join("notices"))
}

/// Hand a notice in. It waits in `dir/inbox` for the worker's next pass.
///
/// # Errors
/// An invalid notice, or the folder could not be written.
pub fn submit(dir: &Path, notice: &Notice) -> Result<PathBuf> {
    notice.check()?;
    let inbox = dir.join("inbox");
    std::fs::create_dir_all(&inbox).with_context(|| format!("create {}", inbox.display()))?;
    let mut raw = [0u8; 6];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut raw);
    let name = format!(
        "{}-{}.json",
        notice.at.format("%Y%m%dT%H%M%S%.3fZ"),
        hex::encode(raw)
    );
    let path = inbox.join(name);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(notice)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Take every notice waiting in `dir/inbox`, oldest first. Each file is removed as it is
/// read; one that does not parse is removed too and reported in the second list.
#[must_use]
pub fn take_inbox(dir: &Path) -> (Vec<Notice>, Vec<String>) {
    let mut notices = Vec::new();
    let mut bad = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir.join("inbox")) else {
        return (notices, bad);
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    for path in paths {
        match std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Notice>(&bytes).ok())
            .filter(|notice| notice.check().is_ok())
        {
            Some(notice) => notices.push(notice),
            None => bad.push(path.display().to_string()),
        }
        let _ = std::fs::remove_file(&path);
    }
    notices.sort_by_key(|notice| notice.at);
    (notices, bad)
}

/// Add `notice` to the day's digest, `dir/digest/<day>.jsonl`.
///
/// # Errors
/// The digest file could not be written.
pub fn append_digest(dir: &Path, notice: &Notice) -> Result<()> {
    use std::io::Write;
    let digest = dir.join("digest");
    std::fs::create_dir_all(&digest)?;
    let path = digest.join(format!("{}.jsonl", notice.at.format("%Y-%m-%d")));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(notice)?)?;
    Ok(())
}

/// The day's digest: what was handed in at `info`, or from a muted source.
#[must_use]
pub fn read_digest(dir: &Path, day: chrono::NaiveDate) -> Vec<Notice> {
    std::fs::read_to_string(dir.join("digest").join(format!("{day}.jsonl")))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// What decides which notices go out. From `[notices]` in the root's `ferry.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rules {
    /// The same source, subject and state is sent again only after this long.
    pub resend_after_hours: i64,
    /// A new state for a subject updates the message sent about it within this long;
    /// after that it is a new message.
    pub update_within_hours: i64,
    /// Sources whose notices go into the digest, whatever their level, except `urgent`.
    pub muted: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            resend_after_hours: 24,
            update_within_hours: 24,
            muted: Vec::new(),
        }
    }
}

impl Rules {
    /// `[notices]` from `<root>/ferry.toml`, or the defaults.
    #[must_use]
    pub fn load(root: &Path) -> Self {
        #[derive(Deserialize, Default)]
        struct File {
            #[serde(default)]
            notices: Option<Rules>,
        }
        std::fs::read_to_string(root.join("ferry.toml"))
            .ok()
            .and_then(|text| toml::from_str::<File>(&text).ok())
            .and_then(|file| file.notices)
            .unwrap_or_default()
    }

    fn muted(&self, source: &str) -> bool {
        self.muted
            .iter()
            .any(|muted| muted.eq_ignore_ascii_case(source))
    }
}

/// What to do with one notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A new message.
    Send { text: String },
    /// Replace the message already sent about this subject.
    Update { message: i64, text: String },
    /// The digest only.
    Digest,
    /// Nothing: it says what was already said.
    Repeat,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Last {
    state: String,
    sent_at: Option<DateTime<Utc>>,
    message: Option<i64>,
    repeats: u32,
}

/// What each source handed in and what became of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Count {
    pub received: u64,
    pub sent: u64,
    pub updated: u64,
    pub digest: u64,
    pub repeats: u64,
}

/// What has been sent, kept in `dir/ledger.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    last: BTreeMap<String, Last>,
    #[serde(default)]
    pub sources: BTreeMap<String, Count>,
}

impl Ledger {
    #[must_use]
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("ledger.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// # Errors
    /// The folder could not be written.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("ledger.json");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Decide what to do with `notice`, and count it.
    pub fn decide(&mut self, notice: &Notice, rules: &Rules, now: DateTime<Utc>) -> Action {
        let count = self.sources.entry(notice.source.clone()).or_default();
        count.received += 1;
        let quiet = notice.level == Level::Info
            || (rules.muted(&notice.source) && notice.level != Level::Urgent);
        if quiet {
            count.digest += 1;
            return Action::Digest;
        }
        let last = self.last.entry(notice.key()).or_default();
        let recent = |hours: i64| {
            last.sent_at
                .is_some_and(|at| now - at < chrono::Duration::hours(hours))
        };
        if last.state == notice.state && recent(rules.resend_after_hours) {
            last.repeats += 1;
            count.repeats += 1;
            return Action::Repeat;
        }
        let text = notice.line();
        match last.message {
            Some(message) if last.state != notice.state && recent(rules.update_within_hours) => {
                count.updated += 1;
                Action::Update { message, text }
            }
            _ => {
                count.sent += 1;
                Action::Send { text }
            }
        }
    }

    /// `notice` went out as `message` (the chat's id for it, when there is one).
    pub fn sent(&mut self, notice: &Notice, message: Option<i64>, now: DateTime<Utc>) {
        let last = self.last.entry(notice.key()).or_default();
        last.state.clone_from(&notice.state);
        last.sent_at = Some(now);
        if message.is_some() {
            last.message = message;
        }
        last.repeats = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(source: &str, state: &str, level: Level, at: DateTime<Utc>) -> Notice {
        Notice {
            source: source.into(),
            subject: "card".into(),
            state: state.into(),
            level,
            text: format!("card is {state}"),
            at,
        }
    }

    #[test]
    fn info_every_quarter_hour_is_digest_only() {
        let now = Utc::now();
        let mut ledger = Ledger::default();
        for i in 0..96 {
            let at = now + chrono::Duration::minutes(15 * i);
            let n = notice("gpu-queue", "held", Level::Info, at);
            assert_eq!(ledger.decide(&n, &Rules::default(), at), Action::Digest);
        }
        let count = &ledger.sources["gpu-queue"];
        assert_eq!((count.received, count.sent, count.digest), (96, 0, 96));
    }

    #[test]
    fn act_is_sent_once_then_updated_when_its_state_changes() {
        let now = Utc::now();
        let rules = Rules::default();
        let mut ledger = Ledger::default();
        let first = notice("worker", "logged-out", Level::Act, now);
        assert!(matches!(
            ledger.decide(&first, &rules, now),
            Action::Send { .. }
        ));
        ledger.sent(&first, Some(77), now);
        // The same news an hour later: nothing.
        let later = now + chrono::Duration::hours(1);
        let again = notice("worker", "logged-out", Level::Act, later);
        assert_eq!(ledger.decide(&again, &rules, later), Action::Repeat);
        // It changed: the message already sent is updated, not a new one.
        let fixed = notice("worker", "back", Level::Act, later);
        assert_eq!(
            ledger.decide(&fixed, &rules, later),
            Action::Update {
                message: 77,
                text: "[worker] card is back".into()
            }
        );
        ledger.sent(&fixed, None, later);
        // A day later the same state is news again.
        let day = later + chrono::Duration::hours(25);
        let old = notice("worker", "back", Level::Act, day);
        assert!(matches!(
            ledger.decide(&old, &rules, day),
            Action::Send { .. }
        ));
    }

    #[test]
    fn a_muted_source_goes_to_the_digest_unless_urgent() {
        let now = Utc::now();
        let rules = Rules {
            muted: vec!["Renders".into()],
            ..Rules::default()
        };
        let mut ledger = Ledger::default();
        let act = notice("renders", "done", Level::Act, now);
        assert_eq!(ledger.decide(&act, &rules, now), Action::Digest);
        let urgent = notice("renders", "disk-full", Level::Urgent, now);
        assert!(matches!(
            ledger.decide(&urgent, &rules, now),
            Action::Send { .. }
        ));
    }

    #[test]
    fn the_inbox_is_taken_once_in_order_and_bad_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let later = notice("a", "x", Level::Act, now + chrono::Duration::seconds(5));
        let first = notice("b", "y", Level::Info, now);
        submit(dir.path(), &later).unwrap();
        submit(dir.path(), &first).unwrap();
        std::fs::write(dir.path().join("inbox").join("zz.json"), "not json").unwrap();
        let (taken, bad) = take_inbox(dir.path());
        assert_eq!(taken, vec![first, later]);
        assert_eq!(bad.len(), 1);
        assert_eq!(take_inbox(dir.path()).0.len(), 0);
        // An empty text is refused at the door.
        let mut empty = notice("a", "x", Level::Act, now);
        empty.text = " ".into();
        assert!(submit(dir.path(), &empty).is_err());
    }

    #[test]
    fn the_digest_keeps_the_days_info() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let n = notice("gpu-queue", "held", Level::Info, now);
        append_digest(dir.path(), &n).unwrap();
        append_digest(dir.path(), &n).unwrap();
        assert_eq!(read_digest(dir.path(), now.date_naive()).len(), 2);
    }

    #[test]
    fn rules_come_from_ferry_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("ferry.toml"),
            "[notices]\nmuted = [\"gpu-queue\"]\nresend_after_hours = 6\n",
        )
        .unwrap();
        let rules = Rules::load(dir.path());
        assert_eq!(rules.muted, vec!["gpu-queue".to_string()]);
        assert_eq!(rules.resend_after_hours, 6);
        assert_eq!(rules.update_within_hours, 24);
        assert_eq!(Rules::load(&dir.path().join("none")), Rules::default());
    }
}

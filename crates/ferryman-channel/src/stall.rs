//! The STALLED convention: a service says which of its numbers must keep moving.
//!
//! A loop that has run out of work and a loop that is wedged look identical from the
//! outside. Both processes are alive, both answer, neither produces anything, and the
//! difference only shows up as "the channel has received zero messages for six days" -
//! noticed, if at all, long after the fact, by a person reading an outbox.
//!
//! The fleet can only tell them apart if the service *says what it expects to keep
//! moving*. So a service with a loop writes one small file per service into the channel,
//! beside its other channel files:
//!
//! ```text
//! stalled/quantly-forward.json
//! {
//!   "service": "quantly-forward",
//!   "expect": {
//!     "positions_opened": { "value": 412, "moved_at": "2026-10-11T09:00:00Z" },
//!     "hypotheses_tested": { "value": 91,  "moved_at": "2026-10-11T09:00:00Z" }
//!   },
//!   "stall_after_hours": 24,
//!   "from": "grouchly",
//!   "since": "2026-09-20T08:00:00Z"
//! }
//! ```
//!
//! `expect` is a promise in the service's own words: these counters only ever go up, and
//! `moved_at` is when the value last *changed* - not when the file was last written, which
//! a healthy loop rewrites every pass and which therefore says nothing at all. The file is
//! rewritten whenever a counter moves, and otherwise at a steady interval, so "nothing
//! changed" is itself the signal.
//!
//! Nothing here is trusted for authority. An expectation decides whether a person is told
//! that a service *looks* stuck, and nothing else: it cannot pause a worker, hold an order
//! or move a ledger. A file that will not parse is skipped rather than guessed at, so a
//! half-synced copy is quiet instead of alarming.
//!
//! Writing one is the service's job. Sign it the way presence is signed
//! ([`crate::receipts::refresh_presence`]) if the service has a key; the reader does not
//! require a signature, because a service that has not been given one is exactly the
//! service most likely to go quiet unnoticed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::ProjectRoute;

/// Where expectations live inside a channel.
pub const DIR: &str = "stalled";
/// How long a counter may stand still before it is called stalled, when the service does
/// not say. A day: long enough that a nightly loop is not nagged, short enough that a
/// week-long silence is caught on the first day of it.
pub const DEFAULT_STALL_AFTER: Duration = Duration::hours(24);
/// How many counters of one service are reported. A service is stalled or it is not, and a
/// list of forty buries the one that moved.
pub const MAX_REPORTED: usize = 8;

/// One number a service promised would move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    /// The value as last written. Only ever compared with the previous write, so its unit
    /// is the service's business.
    pub value: i64,
    /// When the value last *changed*. Falling back to an old `moved_at` is the point: a
    /// service that rewrites the file every pass without moving anything is stalled, and
    /// using the file's mtime would hide exactly that.
    pub moved_at: DateTime<Utc>,
    /// The service's own words about what this counts, shown to a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What one service expects of itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expectation {
    /// The service's name, as a person would say it: `quantly-forward`.
    pub service: String,
    /// The counters it promises will move, by name.
    pub expect: BTreeMap<String, Counter>,
    /// How long any one of them may stand still here, overriding
    /// [`DEFAULT_STALL_AFTER`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stall_after_hours: Option<f64>,
    /// The machine that wrote it, when it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// When this loop started, so a service that was just restarted is not called stalled
    /// by a rule it has not had time to satisfy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
    /// Who signed it, when anyone did. Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One counter that has not moved in long enough to say so out loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stall {
    pub service: String,
    pub counter: String,
    pub value: i64,
    /// How long it has stood still, by its own `moved_at`.
    pub flat_for: Duration,
    /// The limit it broke.
    pub limit: Duration,
    pub note: Option<String>,
}

impl Stall {
    /// The one line a person reads.
    #[must_use]
    pub fn describe(&self) -> String {
        let counted = match &self.note {
            Some(note) => format!("{} ({note})", self.counter),
            None => self.counter.clone(),
        };
        format!(
            "{}: STALLED - {counted} has stayed at {} for {}, past the {} it promised",
            self.service,
            self.value,
            crate::receipts::short_age(self.flat_for),
            crate::receipts::short_age(self.limit)
        )
    }
}

impl Expectation {
    /// How long a counter here may stand still.
    #[must_use]
    pub fn limit(&self) -> Duration {
        match self.stall_after_hours {
            Some(hours) if hours.is_finite() && hours > 0.0 => {
                Duration::milliseconds((hours * 3_600_000.0).round() as i64)
            }
            _ => DEFAULT_STALL_AFTER,
        }
    }

    /// Which of the counters this service promised have stopped moving.
    ///
    /// Pure: it reads nothing but its argument and the clock it is given, so every machine
    /// that sees the same file names the same stalls at the same instant.
    #[must_use]
    pub fn stalled_at(&self, now: DateTime<Utc>) -> Vec<Stall> {
        let limit = self.limit();
        if let Some(since) = self.since
            && now.signed_duration_since(since) < limit
        {
            return Vec::new();
        }
        let mut found: Vec<Stall> = self
            .expect
            .iter()
            .filter_map(|(name, counter)| {
                let flat_for = now.signed_duration_since(counter.moved_at);
                (flat_for > limit).then(|| Stall {
                    service: self.service.clone(),
                    counter: name.clone(),
                    value: counter.value,
                    flat_for,
                    limit,
                    note: counter.note.clone(),
                })
            })
            .collect();
        // Worst first: the counter that has stood still longest is the one to read.
        found.sort_by(|a, b| b.flat_for.cmp(&a.flat_for).then(a.counter.cmp(&b.counter)));
        found.truncate(MAX_REPORTED);
        found
    }
}

/// Every counter in every expectation that has stopped moving, worst first.
#[must_use]
pub fn stalled_at(all: &[Expectation], now: DateTime<Utc>) -> Vec<Stall> {
    let mut found: Vec<Stall> = all
        .iter()
        .flat_map(|expectation| expectation.stalled_at(now))
        .collect();
    found.sort_by(|a, b| {
        b.flat_for
            .cmp(&a.flat_for)
            .then(a.service.cmp(&b.service))
            .then(a.counter.cmp(&b.counter))
    });
    found
}

/// Where one service's expectation lives.
#[must_use]
pub fn path_in(dir: &Path, service: &str) -> PathBuf {
    dir.join(format!("{service}.json"))
}

/// Read every expectation in a channel's [`DIR`].
///
/// A file that cannot be read or parsed is skipped, not reported: a half-synced copy is an
/// ordinary sight on a Syncthing channel, and a fleet taught to cry wolf about one would
/// learn to ignore the real one. A directory that is not there means no service has
/// promised anything, which is the honest answer for a channel that predates this.
#[must_use]
pub fn read(route: &ProjectRoute) -> Vec<Expectation> {
    let Ok(entries) = fs::read_dir(route.communications.join(DIR)) else {
        return Vec::new();
    };
    let mut found: Vec<Expectation> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|kind| kind == "json"))
        .filter_map(|path| {
            let text = fs::read_to_string(&path).ok()?;
            serde_json::from_str::<Expectation>(&text).ok()
        })
        .collect();
    found.sort_by(|a, b| a.service.cmp(&b.service));
    found
}

/// Read one file, for a tool that has the path rather than the route.
///
/// # Errors
/// The file is not there, or is not an expectation.
pub fn read_file(path: &Path) -> Result<Expectation> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}


#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(hours: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 11, 12, 0, 0).unwrap() + Duration::hours(hours)
    }

    fn counter(value: i64, moved_hours_ago: i64) -> Counter {
        Counter {
            value,
            moved_at: at(-moved_hours_ago),
            note: None,
        }
    }

    fn expectation(counters: &[(&str, Counter)]) -> Expectation {
        Expectation {
            service: "quantly-forward".to_string(),
            expect: counters
                .iter()
                .map(|(name, counter)| ((*name).to_string(), counter.clone()))
                .collect(),
            stall_after_hours: None,
            from: Some("grouchly".to_string()),
            since: None,
            signed_by: None,
            signature: None,
        }
    }

    #[test]
    fn a_counter_that_kept_moving_is_not_stalled() {
        let one = expectation(&[("positions_opened", counter(412, 1))]);
        assert!(one.stalled_at(at(0)).is_empty());
    }

    #[test]
    fn a_counter_that_was_rewritten_without_moving_is_stalled() {
        // The whole point of `moved_at`: this file is written by a healthy-looking loop on
        // every pass, and the number inside it has not changed in six days.
        let one = expectation(&[("positions_opened", counter(412, 6 * 24))]);
        let found = one.stalled_at(at(0));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].counter, "positions_opened");
        assert_eq!(found[0].value, 412);
        assert_eq!(found[0].flat_for, Duration::hours(6 * 24));
        assert_eq!(found[0].limit, DEFAULT_STALL_AFTER);
        assert!(
            found[0].describe().contains("STALLED")
                && found[0].describe().contains("positions_opened")
                && found[0].describe().contains("412"),
            "{}",
            found[0].describe()
        );
    }

    #[test]
    fn the_limit_is_the_services_to_set() {
        let mut one = expectation(&[("positions_opened", counter(1, 3))]);
        assert!(one.stalled_at(at(0)).is_empty(), "a day has not passed");
        one.stall_after_hours = Some(2.0);
        let found = one.stalled_at(at(0));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].limit, Duration::hours(2));
        // A nonsense limit is the default, never an alarm about a service with no clock.
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            one.stall_after_hours = Some(bad);
            assert_eq!(one.limit(), DEFAULT_STALL_AFTER, "for {bad}");
            assert_eq!(one.stalled_at(at(0)).len(), 1, "the default still applies");
        }
    }


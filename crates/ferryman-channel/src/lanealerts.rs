//! What the iroh lane is complaining about, remembered on this machine.
//!
//! The lane's health check (in `ferryman-iroh`) decides which peers and relays are in
//! trouble. This module is the part everything else shares, and it knows nothing about
//! iroh: a small list of alerts, each with a stable key, kept in `lane-alerts.json` in the
//! machine state directory so that
//!
//! - an alert is raised once, not on every pass (the key is the identity);
//! - an alert that stops holding is cleared once, and the pass that clears it knows to;
//! - `ferry doctor` and the dashboard can show what is wrong without the worker running
//!   and without linking the QUIC stack.
//!
//! The file is this machine's own and is never synced. The fleet sees an alert only
//! through the signed `lane-health` notice the worker posts for it (see `fleethome`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The file's name in the machine state directory.
pub const FILE: &str = "lane-alerts.json";

/// One thing wrong with the lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// What makes two sightings the same alert: `relay`, or `peer:<endpoint id prefix>`.
    pub key: String,
    pub title: String,
    pub text: String,
    /// When this alert was first raised (kept while it stays raised).
    pub since: DateTime<Utc>,
}

/// The alerts standing now, and when they were last worked out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<DateTime<Utc>>,
    /// The "no good sync for this long" threshold in force, in minutes.
    #[serde(default)]
    pub threshold_minutes: u64,
    #[serde(default)]
    pub active: Vec<Alert>,
}

/// What a check changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Newly raised: say so, once.
    Raised(Alert),
    /// No longer holds: say that, once.
    Cleared(Alert),
}

/// Fold what a check found (`found`: key, title, text) into `previous`.
///
/// An alert already standing keeps its `since` and is not raised again, even when its text
/// changed (the text is refreshed quietly). One that is gone is cleared. Order is stable
/// (by key).
#[must_use]
pub fn reconcile(
    previous: &State,
    found: Vec<(String, String, String)>,
    threshold_minutes: u64,
    now: DateTime<Utc>,
) -> (State, Vec<Transition>) {
    let mut transitions = Vec::new();
    let mut active: Vec<Alert> = Vec::new();
    for (key, title, text) in found {
        if active.iter().any(|have| have.key == key) {
            continue;
        }
        match previous.active.iter().find(|have| have.key == key) {
            Some(standing) => active.push(Alert {
                key,
                title,
                text,
                since: standing.since,
            }),
            None => {
                let alert = Alert {
                    key,
                    title,
                    text,
                    since: now,
                };
                transitions.push(Transition::Raised(alert.clone()));
                active.push(alert);
            }
        }
    }
    for gone in &previous.active {
        if !active.iter().any(|have| have.key == gone.key) {
            transitions.push(Transition::Cleared(gone.clone()));
        }
    }
    active.sort_by(|a, b| a.key.cmp(&b.key));
    (
        State {
            checked: Some(now),
            threshold_minutes,
            active,
        },
        transitions,
    )
}

/// The id of the fleet notice that carries one alert from one machine. Stable, so raising
/// it again replaces the file (no duplicates) and clearing it overwrites the same file.
#[must_use]
pub fn notice_id(machine: &str, key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let short = hex::encode(&digest[..4]);
    let machine: String = machine
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("lane-{machine}-{short}")
}

fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// The alerts last written in `dir` (the machine state directory). `None`: none yet.
#[must_use]
pub fn read(dir: &Path) -> Option<State> {
    serde_json::from_slice(&std::fs::read(path_in(dir)).ok()?).ok()
}

/// [`read`] in this machine's state directory.
#[must_use]
pub fn read_here() -> Option<State> {
    read(&crate::licensing::machine_state_dir()?)
}

/// Write the state, atomically.
///
/// # Errors
/// The directory cannot be made or the file written.
pub fn write(dir: &Path, state: &State) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("make {}", dir.display()))?;
    let path = path_in(dir);
    crate::atomic_json(&path, state).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(key: &str, text: &str) -> Vec<(String, String, String)> {
        vec![(key.into(), format!("title {key}"), text.into())]
    }

    #[test]
    fn a_new_alert_is_raised_once_and_then_only_refreshed() {
        let now = Utc::now();
        let (first, raised) = reconcile(&State::default(), found("relay", "down"), 15, now);
        assert_eq!(raised.len(), 1);
        assert!(matches!(&raised[0], Transition::Raised(a) if a.key == "relay"));
        let later = now + chrono::Duration::minutes(5);
        let (second, again) = reconcile(&first, found("relay", "still down, 5 min"), 15, later);
        assert!(again.is_empty(), "a standing alert is not raised again");
        assert_eq!(second.active[0].since, now, "since is kept");
        assert_eq!(second.active[0].text, "still down, 5 min");
    }

    #[test]
    fn an_alert_that_stops_holding_is_cleared_once() {
        let now = Utc::now();
        let (first, _) = reconcile(&State::default(), found("peer:ab", "quiet"), 15, now);
        let (second, cleared) = reconcile(&first, Vec::new(), 15, now);
        assert!(second.active.is_empty());
        assert_eq!(cleared.len(), 1);
        assert!(matches!(&cleared[0], Transition::Cleared(a) if a.key == "peer:ab"));
        let (_, nothing) = reconcile(&second, Vec::new(), 15, now);
        assert!(nothing.is_empty());
    }

    #[test]
    fn a_repeated_key_in_one_check_counts_once() {
        let mut both = found("relay", "a");
        both.extend(found("relay", "b"));
        let (state, raised) = reconcile(&State::default(), both, 15, Utc::now());
        assert_eq!(state.active.len(), 1);
        assert_eq!(raised.len(), 1);
    }

    #[test]
    fn the_notice_id_is_stable_path_safe_and_per_machine_and_alert() {
        let a = notice_id("Beastly", "relay");
        assert_eq!(a, notice_id("Beastly", "relay"));
        assert_ne!(a, notice_id("Beastly", "peer:ab"));
        assert_ne!(a, notice_id("grouchly", "relay"));
        assert!(crate::is_safe_component(&a), "{a}");
        assert!(notice_id("weird name!", "k").starts_with("lane-weird-name--"));
    }

    #[test]
    fn the_state_survives_a_round_trip_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()), None);
        let (state, _) = reconcile(&State::default(), found("relay", "down"), 15, Utc::now());
        write(dir.path(), &state).unwrap();
        assert_eq!(read(dir.path()), Some(state));
    }
}

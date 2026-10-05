//! What the fleet's own signals say the focus should be, for a project nobody has set.
//!
//! Four signals, read without running anything: recent git activity in the checkout,
//! open and failed orders, how much the last `improve gather` found, and how long the
//! project has been quiet. They combine into a score and a suggested tier with one reason
//! per project. Nothing is signed: a suggestion is shown, and the master signs the tiers
//! they choose with `ferry focus set`, the dashboard or Telegram.
//!
//! # A person's list beats the signals
//!
//! Where the master has said which projects are the focus - a signed record with a focus
//! entry, or a seed list - the signals never promote another project to focus: they say
//! "normal" at best, and can only suggest background for one that has gone quiet. The
//! signals fill in what a person has not said; they do not second-guess what they have.
//!
//! # The seed
//!
//! With no record at all, the suggestion starts from the person's own list: the projects
//! named in `FERRYMAN_FOCUS_SEED` (comma separated), or one per line in `focus-seed` in
//! the ferry root. The list is theirs and lives on their machine; none is built in.

use std::path::Path;
use std::process::Command;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::ProjectRoute;
use crate::focus::{Focus, Pin, Tier};

/// The environment variable that names the seed list.
pub const SEED_ENV: &str = "FERRYMAN_FOCUS_SEED";
/// The file in the ferry root that holds the seed list.
pub const SEED_FILE: &str = "focus-seed";
/// Days of git history counted.
pub const GIT_DAYS: i64 = 30;

/// What was read about one project. Everything is optional: a project whose checkout is
/// not on this machine has no git signal, and that is not the same as no activity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Signals {
    /// Commits in the last [`GIT_DAYS`] days, when the checkout is here.
    pub commits: Option<usize>,
    pub last_commit: Option<DateTime<Utc>>,
    /// Orders that are not finished: open, claimed, waiting for review, sent back.
    pub open_orders: usize,
    /// Of those, the ones that need a person or another try: sent back, refuted, stale.
    pub failed_orders: usize,
    /// Things the last `improve gather` listed under sent back, failed runs and late orders.
    pub evidence_items: Option<usize>,
    /// The newest order issued in the channel.
    pub last_order: Option<DateTime<Utc>>,
}

impl Signals {
    /// Read the signals for the project at `route`.
    #[must_use]
    pub fn gather(route: &ProjectRoute, now: DateTime<Utc>) -> Self {
        let (commits, last_commit) = git_activity(&route.workspace, now);
        let mut signals = Self {
            commits,
            last_commit,
            evidence_items: evidence_items(&route.communications),
            ..Self::default()
        };
        for task in crate::list_tasks(route).unwrap_or_default() {
            signals.last_order = signals.last_order.max(Some(task.order.created_at));
            match task.state_at(now) {
                crate::TaskState::Accepted
                | crate::TaskState::Done
                | crate::TaskState::Killed { .. } => {}
                crate::TaskState::ChangesRequested { .. }
                | crate::TaskState::Refuted { .. }
                | crate::TaskState::Stale { .. } => {
                    signals.open_orders += 1;
                    signals.failed_orders += 1;
                }
                _ => signals.open_orders += 1,
            }
        }
        signals
    }

    /// The most recent thing that happened here: a commit or an order.
    #[must_use]
    pub fn last_activity(&self) -> Option<DateTime<Utc>> {
        self.last_commit.max(self.last_order)
    }

    /// Whole days since [`Self::last_activity`], when there is one.
    #[must_use]
    pub fn quiet_days(&self, now: DateTime<Utc>) -> Option<i64> {
        self.last_activity()
            .map(|at| now.signed_duration_since(at).num_days().max(0))
    }

    /// The signals as a score and the reason for it, in one line.
    #[must_use]
    pub fn score(&self, now: DateTime<Utc>) -> (i32, String) {
        let mut score = 0;
        let mut reasons: Vec<String> = Vec::new();
        match self.commits {
            Some(commits) => {
                score += match commits {
                    0 => 0,
                    1..=4 => 1,
                    5..=19 => 2,
                    _ => 3,
                };
                reasons.push(format!("{commits} commit(s) in {GIT_DAYS} days"));
            }
            None => reasons.push("no checkout here to read git from".to_string()),
        }
        score += match self.open_orders {
            0 => 0,
            1..=2 => 1,
            _ => 2,
        };
        score += i32::try_from(self.failed_orders.min(3)).unwrap_or(3);
        reasons.push(if self.failed_orders > 0 {
            format!(
                "{} open order(s), {} sent back, refuted or stale",
                self.open_orders, self.failed_orders
            )
        } else {
            format!("{} open order(s)", self.open_orders)
        });
        match self.evidence_items {
            Some(items) => {
                score += match items {
                    0 => 0,
                    1..=4 => 1,
                    _ => 2,
                };
                reasons.push(format!("{items} evidence item(s) in the last gather"));
            }
            None => reasons.push("no evidence gathered yet".to_string()),
        }
        match self.quiet_days(now) {
            Some(days) if days > 90 => {
                score -= 3;
                reasons.push(format!("quiet for {days} days"));
            }
            Some(days) if days > 30 => {
                score -= 2;
                reasons.push(format!("quiet for {days} days"));
            }
            Some(days) if days <= 7 => {
                score += 1;
                reasons.push("active this week".to_string());
            }
            Some(days) => reasons.push(format!("last activity {days} days ago")),
            None => reasons.push("no activity on record".to_string()),
        }
        (score, reasons.join("; "))
    }
}

/// The tier a score suggests: focus from 6, normal from 2, otherwise background.
#[must_use]
pub fn tier_for(score: i32) -> Tier {
    match score {
        6.. => Tier::Focus,
        2..=5 => Tier::Normal,
        _ => Tier::Background,
    }
}

/// Commits in the last [`GIT_DAYS`] days and the time of the newest one, from the git
/// checkout at `workspace`. `(None, None)` when it is not a checkout or git is not there.
fn git_activity(workspace: &Path, now: DateTime<Utc>) -> (Option<usize>, Option<DateTime<Utc>>) {
    if !workspace.join(".git").exists() {
        return (None, None);
    }
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let since = (now - Duration::days(GIT_DAYS)).format("%Y-%m-%dT%H:%M:%SZ");
    let commits = git(&["rev-list", "--count", &format!("--since={since}"), "HEAD"])
        .and_then(|count| count.parse::<usize>().ok());
    let last = git(&["log", "-1", "--format=%ct"])
        .and_then(|stamp| stamp.parse::<i64>().ok())
        .and_then(|stamp| DateTime::from_timestamp(stamp, 0));
    (commits, last)
}

/// How many things the newest `improve/<week>/evidence.md` in `channel` lists under sent
/// back, failed engine runs and late orders. `None` when nothing has been gathered.
fn evidence_items(channel: &Path) -> Option<usize> {
    let week = std::fs::read_dir(channel.join("improve"))
        .ok()?
        .flatten()
        .filter(|entry| entry.path().join("evidence.md").is_file())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .max()?;
    let text =
        std::fs::read_to_string(channel.join("improve").join(week).join("evidence.md")).ok()?;
    let mut counted = false;
    let mut items = 0;
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            counted = matches!(
                heading.trim(),
                "Sent back by review" | "Failed engine runs" | "Orders that are late"
            );
        } else if counted && line.starts_with("- ") {
            items += 1;
        }
    }
    Some(items)
}

/// A project to suggest a tier for, with its route when its channel can be read here.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub project: String,
    pub route: Option<ProjectRoute>,
}

/// Every project in this machine's ferry root that is not archived, with its route.
#[must_use]
pub fn candidates_from_root() -> Vec<Candidate> {
    let Some(root) = crate::ferry::find_root() else {
        return Vec::new();
    };
    root.projects()
        .into_iter()
        .map(|entry| {
            let route = crate::route_for(entry.repo.as_deref().unwrap_or(&entry.channel)).ok();
            Candidate {
                project: entry.project_id,
                route,
            }
        })
        .collect()
}

/// The seed list on this machine: `FERRYMAN_FOCUS_SEED`, else `focus-seed` in the ferry
/// root. Empty when there is none.
#[must_use]
pub fn seed_list() -> Vec<String> {
    let text = std::env::var(SEED_ENV)
        .ok()
        .filter(|text| !text.trim().is_empty())
        .or_else(|| {
            let root = crate::ferry::find_root()?;
            std::fs::read_to_string(root.path.join(SEED_FILE)).ok()
        })
        .unwrap_or_default();
    parse_seed(&text)
}

/// Project names from a seed list: separated by commas, spaces or lines, `#` starting a
/// comment, repeats dropped.
#[must_use]
pub fn parse_seed(text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        for name in line.split(|c: char| c == ',' || c.is_whitespace()) {
            let name = name.trim();
            if !name.is_empty() && !names.iter().any(|known| known.eq_ignore_ascii_case(name)) {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// The suggested tier for one project, and why.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub project: String,
    /// The tier suggested.
    pub tier: Tier,
    /// The tier it is in now: its entry, or normal.
    pub now: Tier,
    /// Its entry in the signed record, when it has one that holds.
    pub pinned: Option<String>,
    /// The signals' score; `None` for a project taken from the seed list.
    pub score: Option<i32>,
    /// One line: where the suggestion comes from.
    pub reason: String,
    pub signals: Option<Signals>,
}

/// All the suggestions, and anything about the seed list worth saying.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Suggestions {
    pub rows: Vec<Suggestion>,
    /// Names in the seed list that match no project on this machine.
    pub seed_missing: Vec<String>,
    /// The rows started from the seed list because no record is signed.
    pub seeded: bool,
}

impl Suggestions {
    /// The suggested tiers that differ from what is in force, as the entries to sign.
    #[must_use]
    pub fn changes(&self) -> Vec<(&str, Tier)> {
        self.rows
            .iter()
            .filter(|row| row.pinned.is_none() && row.tier != row.now)
            .map(|row| (row.project.as_str(), row.tier))
            .collect()
    }
}

/// Suggest a tier for each of `candidates`, given the `focus` in force and the `seed` list.
/// Nothing is signed, and a project with an entry that holds keeps it: its row says so.
#[must_use]
pub fn suggest(
    candidates: &[Candidate],
    focus: &Focus,
    seed: &[String],
    now: DateTime<Utc>,
) -> Suggestions {
    suggest_with(candidates, focus, seed, now, |candidate| {
        candidate
            .route
            .as_ref()
            .map(|route| Signals::gather(route, now))
    })
}

/// [`suggest`] with the signals supplied: `gather` says what was read about a candidate.
#[must_use]
pub fn suggest_with(
    candidates: &[Candidate],
    focus: &Focus,
    seed: &[String],
    now: DateTime<Utc>,
    gather: impl Fn(&Candidate) -> Option<Signals>,
) -> Suggestions {
    let seeded = !focus.is_set() && !seed.is_empty();
    let someone_said = seeded
        || focus.setting.as_ref().is_some_and(|setting| {
            setting
                .projects
                .values()
                .any(|pin| pin.tier == Tier::Focus && pin.holds(now))
        });
    let in_seed = |project: &str| seed.iter().any(|name| name.eq_ignore_ascii_case(project));
    let mut rows: Vec<Suggestion> = candidates
        .iter()
        .map(|candidate| {
            let project = candidate.project.clone();
            let pin: Option<&Pin> = focus.pin(&project, now);
            let now_tier = pin.map_or(Tier::Normal, |pin| pin.tier);
            let signals = gather(candidate);
            let scored = signals.as_ref().map(|signals| signals.score(now));
            if let Some(pin) = pin {
                return Suggestion {
                    project,
                    tier: pin.tier,
                    now: now_tier,
                    pinned: Some(pin.describe()),
                    score: scored.as_ref().map(|(score, _)| *score),
                    reason: format!(
                        "set by the master ({}); {}",
                        pin.describe(),
                        scored.map_or("channel not readable here".to_string(), |(_, why)| why)
                    ),
                    signals,
                };
            }
            if seeded && in_seed(&project) {
                return Suggestion {
                    project,
                    tier: Tier::Focus,
                    now: now_tier,
                    pinned: None,
                    score: scored.as_ref().map(|(score, _)| *score),
                    reason: format!(
                        "in your focus seed list; {}",
                        scored.map_or("channel not readable here".to_string(), |(_, why)| why)
                    ),
                    signals,
                };
            }
            let Some((score, why)) = scored else {
                return Suggestion {
                    project,
                    tier: Tier::Normal,
                    now: now_tier,
                    pinned: None,
                    score: None,
                    reason: "its channel cannot be read here, so there is nothing to go on"
                        .to_string(),
                    signals,
                };
            };
            let mut tier = tier_for(score);
            let mut reason = format!("score {score}: {why}");
            if someone_said && tier == Tier::Focus {
                tier = Tier::Normal;
                reason.push_str("; not promoted: you named the focus yourself");
            }
            Suggestion {
                project,
                tier,
                now: now_tier,
                pinned: None,
                score: Some(score),
                reason,
                signals,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.project.cmp(&b.project)));
    let seed_missing = if seeded {
        seed.iter()
            .filter(|name| {
                !candidates
                    .iter()
                    .any(|candidate| candidate.project.eq_ignore_ascii_case(name))
            })
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    Suggestions {
        rows,
        seed_missing,
        seeded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focus::{FocusSetting, pin_project};
    use std::collections::BTreeMap;

    fn busy(now: DateTime<Utc>) -> Signals {
        Signals {
            commits: Some(25),
            last_commit: Some(now - Duration::days(1)),
            open_orders: 4,
            failed_orders: 2,
            evidence_items: Some(6),
            last_order: Some(now - Duration::days(2)),
        }
    }

    fn quiet(now: DateTime<Utc>) -> Signals {
        Signals {
            commits: Some(0),
            last_commit: Some(now - Duration::days(120)),
            open_orders: 0,
            failed_orders: 0,
            evidence_items: Some(0),
            last_order: None,
        }
    }

    fn candidates(names: &[&str]) -> Vec<Candidate> {
        names
            .iter()
            .map(|name| Candidate {
                project: (*name).to_string(),
                route: None,
            })
            .collect()
    }

    fn signed(entries: &[(&str, Tier)]) -> Focus {
        let now = Utc::now();
        let mut projects = BTreeMap::new();
        for (project, tier) in entries {
            pin_project(&mut projects, project, *tier, None, now).unwrap();
        }
        Focus {
            home: "ferryman".into(),
            setting: Some(FocusSetting {
                home: "ferryman".into(),
                projects,
                set_at: now,
                signed_by: "josh".into(),
                signature: String::new(),
                on_behalf_of: None,
                seq: 1,
            }),
            notice: None,
            from_memory: false,
        }
    }

    fn row<'a>(suggestions: &'a Suggestions, project: &str) -> &'a Suggestion {
        suggestions
            .rows
            .iter()
            .find(|row| row.project == project)
            .unwrap()
    }

    #[test]
    fn signals_combine_into_a_score_with_one_reason() {
        let now = Utc::now();
        let (score, why) = busy(now).score(now);
        assert_eq!(score, 3 + 2 + 2 + 2 + 1);
        assert_eq!(tier_for(score), Tier::Focus);
        assert!(
            why.contains("25 commit(s)") && why.contains("2 sent back"),
            "{why}"
        );
        assert!(why.contains("active this week"), "{why}");

        let (score, why) = quiet(now).score(now);
        assert_eq!(score, -3);
        assert_eq!(tier_for(score), Tier::Background);
        assert!(why.contains("quiet for 120 days"), "{why}");

        // No checkout here is not the same as no activity.
        let (_, why) = Signals::default().score(now);
        assert!(why.contains("no checkout here"), "{why}");
        assert!(why.contains("no activity on record"), "{why}");

        assert_eq!(tier_for(6), Tier::Focus);
        assert_eq!(tier_for(5), Tier::Normal);
        assert_eq!(tier_for(2), Tier::Normal);
        assert_eq!(tier_for(1), Tier::Background);
    }

    #[test]
    fn a_seed_list_is_commas_spaces_lines_and_comments() {
        assert_eq!(
            parse_seed("ferryman, redaktly\n# the rest wait\nbullship  Ferryman # again\n\ngraea"),
            ["ferryman", "redaktly", "bullship", "graea"]
        );
        assert!(parse_seed("  \n# nothing\n").is_empty());
    }

    #[test]
    fn with_no_record_the_seed_list_is_what_is_suggested_and_nothing_is_signed() {
        let now = Utc::now();
        let projects = candidates(&["ferryman", "redaktly", "tiny", "other"]);
        let seed: Vec<String> = ["ferryman", "redaktly", "gone"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let suggestions = suggest(&projects, &Focus::default(), &seed, now);
        assert!(suggestions.seeded);
        assert_eq!(row(&suggestions, "ferryman").tier, Tier::Focus);
        assert_eq!(row(&suggestions, "redaktly").tier, Tier::Focus);
        assert_eq!(row(&suggestions, "tiny").tier, Tier::Normal);
        assert!(row(&suggestions, "ferryman").reason.contains("seed list"));
        assert_eq!(
            suggestions.seed_missing,
            ["gone"],
            "named, but not on this machine"
        );
        assert_eq!(
            suggestions.changes(),
            [("ferryman", Tier::Focus), ("redaktly", Tier::Focus)]
        );
        assert_eq!(suggestions.rows[0].tier, Tier::Focus, "focus first");

        // No seed and no record: everything stays normal, and there is nothing to sign.
        let plain = suggest(&projects, &Focus::default(), &[], now);
        assert!(!plain.seeded && plain.changes().is_empty());
        assert!(plain.rows.iter().all(|row| row.tier == Tier::Normal));
    }

    #[test]
    fn the_signals_never_promote_over_a_named_focus_and_never_override_an_entry() {
        let now = Utc::now();
        let projects = candidates(&["named", "hot", "dead", "paused"]);
        let gather = |candidate: &Candidate| {
            Some(match candidate.project.as_str() {
                "hot" => busy(now),
                "dead" => quiet(now),
                _ => busy(now),
            })
        };
        // Nobody has named a focus: a hot project is suggested for it, a dead one background.
        let open = suggest_with(&projects, &Focus::default(), &[], now, gather);
        assert_eq!(row(&open, "hot").tier, Tier::Focus);
        assert_eq!(row(&open, "dead").tier, Tier::Background);

        // The master named one: the hot project is normal at best, and says why.
        let record = signed(&[("named", Tier::Focus), ("paused", Tier::Paused)]);
        let said = suggest_with(&projects, &record, &[], now, gather);
        assert_eq!(row(&said, "hot").tier, Tier::Normal);
        assert!(row(&said, "hot").reason.contains("not promoted"));
        assert_eq!(
            row(&said, "dead").tier,
            Tier::Background,
            "quiet is still said"
        );
        // Their entries are kept as they are, however busy the signals say a project is.
        assert_eq!(row(&said, "named").tier, Tier::Focus);
        assert_eq!(row(&said, "paused").tier, Tier::Paused);
        assert!(row(&said, "paused").pinned.is_some());
        assert!(
            said.changes()
                .iter()
                .all(|(project, _)| *project != "paused" && *project != "named"),
            "an entry is never in the changes proposed"
        );
        assert!(!said.seeded, "a record in force means no seed");
    }
}

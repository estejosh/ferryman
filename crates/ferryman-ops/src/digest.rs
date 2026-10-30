//! The daily improvement digest: what the fleet's improvement loop did yesterday, what
//! a second engine thought of it, and what it cost - written to the home channel and
//! sent to the master as a notice.
//!
//! ```text
//! <home channel>/improve/daily/2026-10-30.md                  the digest
//! <home channel>/improve/daily/2026-10-30.spend-<machine>.json one per machine
//! ```
//!
//! Spending lives in each machine's own engine ledger, so on its first pass of a new UTC
//! day every machine drops what its paid engines spent yesterday beside the digest. From
//! [`WRITE_AFTER_HOUR`] UTC the first machine to pass writes the digest from every spend
//! file there and every project it serves, and asks the master to read it. Once written
//! it is not written again.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, NaiveDate, Timelike, Utc};
use ferryman_channel::{ProjectRoute, Task, evidence, grades::Grade};
use serde::{Deserialize, Serialize};

use crate::{agent::AgentConfig, engines, improve};

/// The digest for a day is written from this hour of the next day, UTC, so every machine
/// has had a pass in which to drop its spending.
pub const WRITE_AFTER_HOUR: u32 = 1;

/// What one machine's paid engines spent on one day.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Spend {
    pub day: String,
    pub machine: String,
    /// (agent, engine, requests, dollars, daily cap)
    pub engines: Vec<(String, String, u64, f64, Option<f64>)>,
}

fn daily_dir(home: &Path) -> PathBuf {
    home.join("improve").join("daily")
}

/// The UTC day before `now`.
#[must_use]
pub fn yesterday(now: DateTime<Utc>) -> String {
    engines::utc_day(now - Duration::days(1))
}

fn day_bounds(day: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let date = NaiveDate::parse_from_str(day, "%Y-%m-%d").ok()?;
    let start = date.and_hms_opt(0, 0, 0)?.and_utc();
    Some((start, start + Duration::days(1)))
}

/// What this machine's paid engines spent on `day`, from its ledgers. Engines that share
/// one account each see the account's spending, so an account is listed once, under
/// the first of its engines, with the requests of all of them.
#[must_use]
pub fn spend_here(configs: &[&AgentConfig], day: &str, now: DateTime<Utc>) -> Spend {
    let mut spend = Spend {
        day: day.to_string(),
        machine: ferryman_channel::receipts::machine_label(),
        engines: Vec::new(),
    };
    let mut seen_agents = BTreeSet::new();
    for config in configs {
        if !seen_agents.insert(config.agent.clone()) {
            continue;
        }
        let ledger = engines::Ledger::load(&config.agent);
        let mut accounts: BTreeMap<String, usize> = BTreeMap::new();
        for spec in &config.engines {
            if !matches!(spec.paid, engines::Paid::Prepaid | engines::Paid::Unknown) {
                continue;
            }
            let Some(figures) = ledger.state(&spec.name).day_figures(day, now) else {
                continue;
            };
            if figures.requests == 0 && figures.spent_usd <= 0.0 {
                continue;
            }
            let account = format!(
                "{}|{}",
                spec.base_url.as_deref().unwrap_or(&spec.name),
                spec.key.as_deref().unwrap_or_default()
            );
            match accounts.get(&account) {
                Some(&index) => {
                    let row = &mut spend.engines[index];
                    row.1 = format!("{}+{}", row.1, spec.name);
                    row.2 += figures.requests;
                    row.3 = row.3.max(figures.spent_usd);
                }
                None => {
                    accounts.insert(account, spend.engines.len());
                    spend.engines.push((
                        config.agent.clone(),
                        spec.name.clone(),
                        figures.requests,
                        figures.spent_usd,
                        spec.daily_usd,
                    ));
                }
            }
        }
    }
    spend
}

/// Drop this machine's spending for yesterday beside the digest, once.
fn drop_spend(home: &Path, configs: &[&AgentConfig], now: DateTime<Utc>) {
    let day = yesterday(now);
    let spend = spend_here(configs, &day, now);
    let safe: String = spend
        .machine
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = daily_dir(home).join(format!("{day}.spend-{safe}.json"));
    if path.exists() {
        return;
    }
    if fs::create_dir_all(daily_dir(home)).is_ok() {
        let _ = fs::write(&path, serde_json::to_vec_pretty(&spend).unwrap_or_default());
    }
}

fn read_spends(home: &Path, day: &str) -> Vec<Spend> {
    let Ok(entries) = fs::read_dir(daily_dir(home)) else {
        return Vec::new();
    };
    let prefix = format!("{day}.spend-");
    let mut spends: Vec<Spend> = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .filter_map(|text| serde_json::from_str(&text).ok())
        .collect();
    spends.sort_by(|a, b| a.machine.cmp(&b.machine));
    spends
}

/// One improvement's line in the digest.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub project: String,
    pub order: String,
    pub title: String,
    /// `accepted`, `done`, `sent back`, `refuted` or `submitted`.
    pub outcome: String,
    pub diff: Option<String>,
    pub commits: usize,
    pub engine: Option<String>,
    pub grade: Option<Grade>,
}

/// What happened to `project`'s improvements inside `[start, end)`.
#[must_use]
pub fn lines_for(
    project: &str,
    tasks: &[Task],
    grades: &[Grade],
    (start, end): (DateTime<Utc>, DateTime<Utc>),
) -> Vec<Line> {
    let within = |at: DateTime<Utc>| at >= start && at < end;
    let mut out = Vec::new();
    for task in tasks.iter().filter(|task| improve::is_improvement(task)) {
        let grade = grades
            .iter()
            .rev()
            .find(|grade| grade.order_id == task.order.id && within(grade.graded_at))
            .cloned();
        let accepted = task
            .reviews
            .iter()
            .any(|review| review.accepted && within(review.reviewed_at));
        let sent_back = task
            .reviews
            .iter()
            .any(|review| !review.accepted && within(review.reviewed_at));
        let submitted: Vec<_> = task
            .results
            .iter()
            .filter(|result| within(result.submitted_at))
            .collect();
        if !accepted && !sent_back && submitted.is_empty() && grade.is_none() {
            continue;
        }
        let latest = task.results.iter().max_by_key(|result| result.revision);
        let refuted =
            latest.is_some_and(|result| evidence::is_refuted(&task.order.payload, result));
        let found = latest.and_then(|result| evidence::of(&task.order.payload, result));
        let outcome = if accepted {
            "accepted"
        } else if refuted {
            "refuted"
        } else if sent_back {
            "sent back"
        } else if !task.order.requires_review && !submitted.is_empty() {
            "done"
        } else if grade.is_some() {
            "graded"
        } else {
            "submitted"
        };
        out.push(Line {
            project: project.to_string(),
            order: task.order.id.clone(),
            title: improve::task_title(task),
            outcome: outcome.to_string(),
            diff: found.as_ref().and_then(|found| found.diff_stat.clone()),
            commits: found.as_ref().map_or(0, |found| found.commits.len()),
            engine: latest.and_then(|result| {
                result
                    .payload
                    .get("engine")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            }),
            grade,
        });
    }
    out.sort_by(|a, b| a.order.cmp(&b.order));
    out
}

/// The digest's markdown, and the short notice for the master's phone.
#[must_use]
pub fn render(day: &str, lines: &[Line], spends: &[Spend]) -> (String, String) {
    let count = |outcome: &str| lines.iter().filter(|line| line.outcome == outcome).count();
    let graded: Vec<&Grade> = lines
        .iter()
        .filter_map(|line| line.grade.as_ref())
        .collect();
    let not_objective = graded.iter().filter(|grade| !grade.objective).count();
    let mean = (!graded.is_empty()).then(|| {
        graded
            .iter()
            .map(|grade| f64::from(grade.score))
            .sum::<f64>()
            / graded.len() as f64
    });
    let spent: f64 = spends
        .iter()
        .flat_map(|spend| spend.engines.iter())
        .map(|row| row.3)
        .sum();
    let mut md = String::new();
    let _ = writeln!(md, "# Improvements, {day}\n");
    let _ = writeln!(
        md,
        "{} accepted, {} done, {} sent back, {} refuted, {} waiting for review.",
        count("accepted"),
        count("done"),
        count("sent back"),
        count("refuted"),
        count("submitted")
    );
    match mean {
        Some(mean) => {
            let _ = writeln!(
                md,
                "{} graded by a second engine: {mean:.1}/10 on average, {not_objective} not an \
                 objective improvement.",
                graded.len()
            );
        }
        None => {
            let _ = writeln!(md, "Nothing was graded.");
        }
    }
    let _ = writeln!(md, "\n## Spending\n");
    if spends.iter().all(|spend| spend.engines.is_empty()) {
        let _ = writeln!(md, "No paid engine spent anything that was recorded.");
    }
    for spend in spends {
        for (agent, engine, requests, dollars, cap) in &spend.engines {
            let _ = writeln!(
                md,
                "- {engine} ({agent} on {}): ${dollars:.2}{} over {requests} request(s)",
                spend.machine,
                cap.map_or_else(String::new, |cap| format!(" of ${cap:.2} a day"))
            );
        }
    }
    let mut by_project: BTreeMap<&str, Vec<&Line>> = BTreeMap::new();
    for line in lines {
        by_project.entry(&line.project).or_default().push(line);
    }
    for (project, lines) in &by_project {
        let _ = writeln!(md, "\n## {project}\n");
        for line in lines {
            let _ = write!(md, "- **{}** - {}", line.title, line.outcome);
            if let Some(diff) = &line.diff {
                let _ = write!(md, "; {diff}");
            }
            if line.commits > 0 {
                let _ = write!(md, "; {} commit(s)", line.commits);
            }
            if let Some(engine) = &line.engine {
                let _ = write!(md, "; built by {engine}");
            }
            let _ = writeln!(md, " (`{}`)", line.order);
            if let Some(grade) = &line.grade {
                let _ = writeln!(
                    md,
                    "  - graded {}/10{} by {}: {}{}",
                    grade.score,
                    if grade.objective {
                        ""
                    } else {
                        ", NOT an objective improvement"
                    },
                    grade.grader,
                    grade.why,
                    if grade.lesson.is_empty() {
                        String::new()
                    } else {
                        format!(" Lesson: {}", grade.lesson)
                    }
                );
            }
        }
    }
    if lines.is_empty() {
        let _ = writeln!(md, "\nNo improvement was built, reviewed or graded.");
    }
    let mut notice = format!(
        "Improvements yesterday ({day}): {} accepted, {} done, {} sent back, {} refuted.",
        count("accepted"),
        count("done"),
        count("sent back"),
        count("refuted")
    );
    if let Some(mean) = mean {
        let _ = write!(
            notice,
            " Graded {mean:.1}/10 on average; {not_objective} of {} not objective.",
            graded.len()
        );
    }
    let _ = write!(notice, " Paid engines spent ${spent:.2}.");
    if let Some(best) = lines
        .iter()
        .filter_map(|line| line.grade.as_ref().map(|grade| (line, grade)))
        .filter(|(_, grade)| grade.passed())
        .max_by_key(|(_, grade)| grade.score)
    {
        let _ = write!(
            notice,
            " Best: {}: {} ({}/10).",
            best.0.project, best.0.title, best.1.score
        );
    }
    let _ = write!(
        notice,
        " The full digest is improve/daily/{day}.md in the home channel."
    );
    (md, notice)
}

/// On every pass: drop this machine's spending for yesterday, and from
/// [`WRITE_AFTER_HOUR`] write yesterday's digest if nobody has and ask the master to read
/// it. Returns a line when it wrote one.
pub fn daily(targets: &[(ProjectRoute, AgentConfig)], now: DateTime<Utc>) -> Option<String> {
    let home_id = ferryman_channel::focus::home_project();
    let home = targets
        .iter()
        .find(|(route, _)| route.project_id == home_id)
        .map(|(route, config)| (route.clone(), config.clone()))?;
    let configs: Vec<&AgentConfig> = targets.iter().map(|(_, config)| config).collect();
    drop_spend(&home.0.communications, &configs, now);
    if now.hour() < WRITE_AFTER_HOUR {
        return None;
    }
    let day = yesterday(now);
    let path = daily_dir(&home.0.communications).join(format!("{day}.md"));
    if path.exists() {
        return None;
    }
    match write(&home, targets, &day, &path) {
        Ok(()) => Some(format!(
            "{}: wrote the improvement digest for {day}",
            home.0.project_id
        )),
        Err(error) => {
            tracing::warn!("could not write the improvement digest: {error:#}");
            None
        }
    }
}

fn write(
    (home, config): &(ProjectRoute, AgentConfig),
    targets: &[(ProjectRoute, AgentConfig)],
    day: &str,
    path: &Path,
) -> Result<()> {
    let bounds = day_bounds(day).context("a day is YYYY-MM-DD")?;
    let mut lines = Vec::new();
    let mut seen = BTreeSet::new();
    for (route, _) in targets {
        if !seen.insert(route.project_id.clone()) {
            continue;
        }
        let tasks = ferryman_channel::list_tasks(route).unwrap_or_default();
        let grades = ferryman_channel::grades::read_all(route);
        lines.extend(lines_for(&route.project_id, &tasks, &grades, bounds));
    }
    let spends = read_spends(&home.communications, day);
    let (md, notice) = render(day, &lines, &spends);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, md).with_context(|| format!("write {}", path.display()))?;
    let identity = improve::signing_identity(home, config)?;
    ferryman_channel::questions::ask(
        home,
        &identity,
        &format!("digest-{day}"),
        ferryman_channel::questions::DIGEST,
        &notice,
        &["Seen".to_string()],
        None,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grade(order: &str, objective: bool, score: u8, at: DateTime<Utc>) -> Grade {
        Grade {
            order_id: order.into(),
            revision: 1,
            project_id: "demo".into(),
            title: "t".into(),
            worker: "w".into(),
            engine: "deepseek-flash".into(),
            kind: None,
            planner: None,
            planner_agent: None,
            grader: "codex".into(),
            objective,
            score,
            why: "a failing test now passes".into(),
            lesson: "say which test".into(),
            graded_at: at,
            signed_by: "w".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn the_digest_says_what_landed_how_it_was_graded_and_what_it_cost() {
        let at = Utc::now();
        let lines = vec![
            Line {
                project: "quantly".into(),
                order: "improve-2026-w44-1".into(),
                title: "Retry the flaky fetch".into(),
                outcome: "accepted".into(),
                diff: Some("2 files changed, 30 insertions(+)".into()),
                commits: 1,
                engine: Some("deepseek-flash".into()),
                grade: Some(grade("improve-2026-w44-1", true, 8, at)),
            },
            Line {
                project: "quantly".into(),
                order: "improve-2026-w44-2".into(),
                title: "Reword the README".into(),
                outcome: "accepted".into(),
                diff: None,
                commits: 1,
                engine: Some("deepseek-flash".into()),
                grade: Some(grade("improve-2026-w44-2", false, 0, at)),
            },
        ];
        let spends = vec![Spend {
            day: "2026-10-30".into(),
            machine: "grouchly".into(),
            engines: vec![(
                "swarm".into(),
                "deepseek-flash+deepseek-pro".into(),
                40,
                0.84,
                Some(1.0),
            )],
        }];
        let (md, notice) = render("2026-10-30", &lines, &spends);
        assert!(md.contains("2 accepted"), "{md}");
        assert!(
            md.contains("4.0/10 on average, 1 not an objective improvement"),
            "{md}"
        );
        assert!(
            md.contains("$0.84 of $1.00 a day over 40 request(s)"),
            "{md}"
        );
        assert!(md.contains("## quantly"), "{md}");
        assert!(md.contains("NOT an objective improvement by codex"), "{md}");
        assert!(
            notice.contains("Best: quantly: Retry the flaky fetch (8/10)"),
            "{notice}"
        );
        assert!(notice.contains("$0.84"), "{notice}");
        let (empty, _) = render("2026-10-30", &[], &[]);
        assert!(empty.contains("No improvement was built"), "{empty}");
    }

    #[test]
    fn a_day_is_bounded_in_utc() {
        let (start, end) = day_bounds("2026-10-30").unwrap();
        assert_eq!(start.to_rfc3339(), "2026-10-30T00:00:00+00:00");
        assert_eq!(end - start, Duration::days(1));
        assert!(day_bounds("yesterday").is_none());
    }
}

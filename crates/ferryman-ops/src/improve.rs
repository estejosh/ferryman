//! The weekly improvement loop: every project a little better every week, without
//! anyone asking for each change.
//!
//! ```text
//! <channel>/improve/2026-W39/
//!   evidence.md    what the last seven days recorded           (ferry improve gather)
//!                  and, marked `unverified-claims`, what an audit's PROBLEMS.md says
//!   plan.json      at most N ranked improvements, and the orders (ferry improve plan)
//!   plan-review.md a judge's reading of a plan no judge wrote    (ferry improve review)
//!   report.md      this week against last week                 (ferry improve report)
//! ```
//!
//! # The division of labour
//!
//! A judge-tier engine turns evidence into a plan and reviews what comes back; build-tier
//! engines do the building, through the ordinary worker loop and its engine fallback.
//! Every improvement is a signed order open to any worker, done on its own branch and
//! reviewed - and a result can only be accepted when the worker's own evidence shows the
//! work exists ([`ferryman_channel::evidence`]).
//!
//! # Audit claims are claims
//!
//! An AI audit that writes PROBLEMS.md into a repository is right some of the time: of
//! eight findings checked by hand, two were wrong (a "missing admin check" where
//! `requireAdmin` was already applied; an "empty repo" that was a stray empty copy). So
//! each claim becomes a verification order first - confirm or refute, citing
//! `file:line` - and only a confirmed finding reaches the planner. Every claim's fate is
//! kept in `improve/claims.json`, so a refuted one is not raised again every week.
//!
//! An archived project is left alone entirely: no evidence, plan, review or switch-on.
//!
//! Nothing here merges, pushes to a main branch or bumps a version: accepted work is
//! listed as ready, and a person merges it.
//!
//! # Never blocking the week
//!
//! Planning takes the best judge that is up. With none up it takes the best builder and
//! marks the plan `unreviewed`, and the next `review` with a judge up reads it. With no
//! engine at all it says so and tries again next run. Each step is safe to repeat: a
//! plan is written once a week, orders have ids derived from the week, and issuing an
//! order that exists is a no-op.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Duration, Utc};
use ferryman_channel::{
    AgentIdentity, Order, ProjectRoute, Task, TaskState, trajectory::Trajectory,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use ferryman_channel::{
    policy::{Policy, Role, Step, Work},
    router::{self, Decision},
};

use crate::{
    Progress,
    agent::AgentConfig,
    engines::{self, EngineSpec, Tier},
};

/// The latest week this loop wrote anything for in a channel, and its steps.
pub use ferryman_channel::ferry::improve_last_run as last_run;

/// Improvements planned per project per week, unless told otherwise.
pub const DEFAULT_MAX: usize = 5;
/// The tag every improvement order carries.
pub const TAG: &str = "improvement";

/// Where one week's files live in a channel.
#[must_use]
pub fn week_dir(route: &ProjectRoute, week: &str) -> PathBuf {
    route.communications.join("improve").join(week)
}

/// Whether a task is one this loop issued.
#[must_use]
pub fn is_improvement(task: &Task) -> bool {
    task.order
        .payload
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(TAG)))
}

fn paused() -> Option<String> {
    crate::governor::paused()
}

// --- gather -----------------------------------------------------------------------------

fn trajectories(route: &ProjectRoute) -> Vec<Trajectory> {
    let Ok(orders) = fs::read_dir(route.communications.join("trajectories")) else {
        return Vec::new();
    };
    orders
        .flatten()
        .filter_map(|order| fs::read_dir(order.path()).ok())
        .flat_map(|runs| runs.flatten())
        .filter_map(|run| fs::read_to_string(run.path()).ok())
        .filter_map(|text| serde_json::from_str::<Trajectory>(&text).ok())
        .collect()
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .chars()
        .take(100)
        .collect()
}

fn tail(text: &str, chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let count = flat.chars().count();
    flat.chars().skip(count.saturating_sub(chars)).collect()
}

fn task_title(task: &Task) -> String {
    task.order
        .payload
        .get("improvement")
        .and_then(|improvement| improvement.get("title"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            first_line(
                task.order
                    .payload
                    .get("task")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
        })
}

/// TODO and FIXME lines in the files git tracks, by file, most first.
fn todo_counts(workspace: &Path) -> Option<(usize, Vec<(String, usize)>)> {
    let listed = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["ls-files", "-z"])
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    let mut counts = Vec::new();
    for file in String::from_utf8_lossy(&listed.stdout).split('\0') {
        if file.is_empty() {
            continue;
        }
        let path = workspace.join(file);
        if fs::metadata(&path).map_or(true, |meta| meta.len() > 1_000_000) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let count = text
            .lines()
            .filter(|line| line.contains("TODO") || line.contains("FIXME"))
            .count();
        if count > 0 {
            counts.push((file.to_string(), count));
        }
    }
    let total = counts.iter().map(|(_, count)| count).sum();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    counts.truncate(15);
    Some((total, counts))
}

/// Collect the last seven days of what this channel recorded into
/// `improve/<week>/evidence.md`. Reads only; runs nothing. Rewritten on every call.
pub fn gather(route: &ProjectRoute, now: DateTime<Utc>) -> Result<PathBuf> {
    let week = engines::iso_week(now);
    let since = now - Duration::days(7);
    let tasks = ferryman_channel::list_tasks(route)?;
    let mut md = String::new();
    let _ = writeln!(md, "# Evidence: {} - {week}\n", route.project_id);
    let _ = writeln!(
        md,
        "Gathered {} from the seven days before it. Read from the channel's files; \
         nothing was run.\n",
        now.format("%Y-%m-%d %H:%M UTC")
    );

    let _ = writeln!(md, "## Sent back by review\n");
    let mut any = false;
    for task in &tasks {
        for review in task
            .reviews
            .iter()
            .filter(|review| !review.accepted && review.reviewed_at >= since)
        {
            any = true;
            let _ = writeln!(
                md,
                "- `{}` r{} ({}): {}",
                task.order.id,
                review.revision,
                task_title(task),
                review.notes.as_deref().unwrap_or("no notes")
            );
        }
        for advice in task
            .recommendations
            .iter()
            .filter(|advice| !advice.accept && advice.recommended_at >= since)
        {
            any = true;
            let _ = writeln!(
                md,
                "- `{}` r{} ({}), recommended back: {}",
                task.order.id,
                advice.revision,
                task_title(task),
                advice.reasoning
            );
        }
    }
    if !any {
        let _ = writeln!(md, "Nothing was sent back.");
    }

    let _ = writeln!(md, "\n## Failed engine runs\n");
    let mut failed: Vec<Trajectory> = trajectories(route)
        .into_iter()
        .filter(|run| !run.ok && run.at >= since)
        .collect();
    failed.sort_by_key(|run| std::cmp::Reverse(run.at));
    if failed.is_empty() {
        let _ = writeln!(md, "No engine run failed.");
    }
    for run in failed.iter().take(30) {
        let _ = writeln!(
            md,
            "- `{}` r{} by {} on {} at {}: {}",
            run.order_id,
            run.revision,
            run.agent,
            run.engine,
            run.at.format("%a %H:%M"),
            tail(&run.output, 300)
        );
    }

    let _ = writeln!(md, "\n## Orders that are late\n");
    let late: Vec<String> = ferryman_channel::receipts::channel_progress(route, now)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|progress| {
            progress
                .warning
                .map(|warning| format!("- `{}`: {warning}", progress.order_id))
        })
        .collect();
    if late.is_empty() {
        let _ = writeln!(md, "None.");
    }
    for line in late {
        let _ = writeln!(md, "{line}");
    }

    let _ = writeln!(md, "\n## Doctor\n");
    // Doctor asks the local Syncthing how it is; a test must not ask anything.
    let doctor = if cfg!(test) {
        crate::doctor::Report {
            project: route.project_id.clone(),
            checks: Vec::new(),
            ready: true,
        }
    } else {
        crate::doctor::examine(&route.workspace)
    };
    let failing: Vec<_> = doctor.checks.iter().filter(|check| !check.ok).collect();
    if failing.is_empty() {
        let _ = writeln!(md, "Every check passed.");
    }
    for check in failing {
        let _ = writeln!(md, "- {}: {}", check.name, check.detail);
    }

    let _ = writeln!(md, "\n## TODO and FIXME\n");
    match todo_counts(&route.workspace) {
        None => {
            let _ = writeln!(md, "The workspace is not a git repository; not counted.");
        }
        Some((total, files)) => {
            let _ = writeln!(md, "{total} line(s) in tracked files.");
            for (file, count) in files {
                let _ = writeln!(md, "- {file}: {count}");
            }
        }
    }

    let _ = writeln!(md, "\n## Engines\n");
    for stats in ferryman_channel::learning::engine_stats(route).unwrap_or_default() {
        let _ = writeln!(md, "- {}", stats.describe());
    }
    for (inventory, _) in ferryman_channel::receipts::list_engines(route).unwrap_or_default() {
        for engine in inventory.engines {
            let _ = writeln!(
                md,
                "- {} on {}: {} ({} tier) is {}{}",
                inventory.agent,
                inventory.machine,
                engine.name,
                engine.tier,
                engine.state,
                engine
                    .reason
                    .map(|why| format!(": {why}"))
                    .unwrap_or_default()
            );
        }
    }

    let _ = writeln!(md, "\n## What the master answered\n");
    let answered: Vec<String> = ferryman_channel::questions::list(route)
        .into_iter()
        .filter_map(|(question, answer)| {
            let answer = answer?;
            (answer.answered_at >= since).then(|| {
                format!(
                    "- {} ({}): \"{}\" - {}",
                    question.id,
                    first_line(&question.text),
                    answer.answer,
                    answer.from()
                )
            })
        })
        .collect();
    if answered.is_empty() {
        let _ = writeln!(md, "Nothing answered this week.");
    }
    for line in answered {
        let _ = writeln!(md, "{line}");
    }

    let claims = refresh_claims(route);
    let _ = writeln!(md, "\n{CLAIMS_HEADING}\n");
    let _ = writeln!(
        md,
        "Marked `unverified-claims`: what an audit wrote, not what is known. Each is checked \
         by a verification order before anything is planned from it.\n"
    );
    let mut any = false;
    for claim in claims.values().filter(|claim| claim.status == PENDING) {
        any = true;
        let _ = writeln!(
            md,
            "- [unverified-claims] `{}` ({}): {}{}",
            claim.id,
            claim.source,
            claim.text,
            claim
                .order
                .as_deref()
                .map(|order| format!(" - being checked by `{order}`"))
                .unwrap_or_default()
        );
    }
    if !any {
        let _ = writeln!(md, "None waiting.");
    }
    let refuted = claims.values().filter(|c| c.status == REFUTED).count();
    let confirmed = claims.values().filter(|c| c.status == CONFIRMED).count();
    if refuted + confirmed > 0 {
        let _ = writeln!(
            md,
            "\n{confirmed} confirmed against the code; {refuted} refuted and not raised again."
        );
    }

    let _ = writeln!(md, "\n## Improvements already open\n");
    let open: Vec<&Task> = tasks
        .iter()
        .filter(|task| is_improvement(task))
        .filter(|task| !matches!(task.state(), TaskState::Accepted | TaskState::Done))
        .collect();
    if open.is_empty() {
        let _ = writeln!(md, "None.");
    }
    for task in open {
        let _ = writeln!(md, "- `{}`: {}", task.order.id, task_title(task));
    }

    let dir = week_dir(route, &week);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("evidence.md");
    fs::write(&path, md).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

// --- claims an audit made ---------------------------------------------------------------

/// The evidence heading audit claims sit under. The planner is never shown this section.
const CLAIMS_HEADING: &str = "## Unverified claims (PROBLEMS.md)";
/// A claim not yet confirmed or refuted.
pub const PENDING: &str = "pending";
pub const CONFIRMED: &str = "confirmed";
pub const REFUTED: &str = "refuted";
/// The tag a verification order carries beside [`TAG`].
pub const VERIFICATION: &str = "verification";
/// The most claims read from one file.
const MAX_CLAIMS: usize = 30;

/// One claim from an audit file, and what became of it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Claim {
    pub id: String,
    pub text: String,
    /// `PROBLEMS.md` or `problems.md`.
    pub source: String,
    /// [`PENDING`], [`CONFIRMED`] or [`REFUTED`].
    pub status: String,
    /// The verification order checking it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub citations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// The week a confirmed finding was handed to the planner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planned_in: Option<String>,
}

fn claims_path(route: &ProjectRoute) -> PathBuf {
    route.communications.join("improve").join("claims.json")
}

/// Every claim this project has seen, by id.
#[must_use]
pub fn load_claims(route: &ProjectRoute) -> BTreeMap<String, Claim> {
    fs::read_to_string(claims_path(route))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_claims(route: &ProjectRoute, claims: &BTreeMap<String, Claim>) -> Result<()> {
    let path = claims_path(route);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(claims)?)
        .with_context(|| format!("write {}", path.display()))
}

/// The audit file at the workspace root, when there is one: its name and text. The name
/// is matched without regard to case (`PROBLEMS.md`, `problems.md`, `Problems.md`), the
/// all-capitals spelling first when a case-sensitive disk holds more than one.
fn problems_file(workspace: &Path) -> Option<(String, String)> {
    let mut names: Vec<String> = fs::read_dir(workspace)
        .ok()?
        .flatten()
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.eq_ignore_ascii_case("problems.md"))
        .collect();
    names.sort();
    names.into_iter().find_map(|name| {
        fs::read_to_string(workspace.join(&name))
            .ok()
            .map(|text| (name, text))
    })
}

fn clip_claim(text: &str) -> String {
    let flat = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("**", "");
    if flat.chars().count() > 400 {
        format!("{}...", flat.chars().take(400).collect::<String>())
    } else {
        flat
    }
}

/// The claims in an audit file. With second- or third-level headings, each heading and
/// the lines under it is one claim (the bullets under a finding are its details, not
/// more findings); without, each top-level list item is one.
#[must_use]
pub fn parse_claims(text: &str) -> Vec<String> {
    fn heading(line: &str) -> Option<&str> {
        line.strip_prefix("### ")
            .or_else(|| line.strip_prefix("## "))
            .map(str::trim)
    }
    let mut claims: Vec<String> = Vec::new();
    if text.lines().any(|line| heading(line).is_some()) {
        let mut current: Option<String> = None;
        for line in text.lines() {
            if let Some(title) = heading(line) {
                claims.extend(current.take());
                current = Some(title.to_string());
            } else if let Some(claim) = current.as_mut()
                && !line.trim().is_empty()
                && !line.starts_with('#')
                && claim.len() < 400
            {
                claim.push_str(if claim.contains(" - ") { " " } else { " - " });
                claim.push_str(line.trim());
            }
        }
        claims.extend(current);
    } else {
        for line in text.lines() {
            let item = line
                .strip_prefix("- ")
                .or_else(|| line.strip_prefix("* "))
                .or_else(|| line.strip_prefix("+ "))
                .or_else(|| {
                    let digits = line.chars().take_while(char::is_ascii_digit).count();
                    (digits > 0)
                        .then(|| &line[digits..])
                        .and_then(|rest| rest.strip_prefix(". ").or(rest.strip_prefix(") ")))
                });
            if let Some(item) = item {
                claims.push(item.trim_start_matches("[ ] ").to_string());
            }
        }
    }
    let mut seen = Vec::new();
    for claim in claims.iter().map(|claim| clip_claim(claim)) {
        if claim.chars().count() >= 8 && !seen.contains(&claim) {
            seen.push(claim);
        }
    }
    seen.truncate(MAX_CLAIMS);
    seen
}

/// A claim's id: from its words, so the same claim in next week's file is the same claim.
fn claim_id(text: &str) -> String {
    let normal = text
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    ferryman_channel::trajectory::digest(&normal)[..12].to_string()
}
/// Bring the claim record up to date: new claims from the audit file, and the verdict of
/// every verification order review has accepted. Claims are never dropped, so a refuted
/// one stays refuted however often the file repeats it.
#[must_use]
pub fn refresh_claims(route: &ProjectRoute) -> BTreeMap<String, Claim> {
    let mut claims = load_claims(route);
    let before = claims.clone();
    if let Some((source, text)) = problems_file(&route.workspace) {
        for text in parse_claims(&text) {
            let id = claim_id(&text);
            claims.entry(id.clone()).or_insert(Claim {
                id,
                text,
                source: source.clone(),
                status: PENDING.to_string(),
                order: None,
                citations: Vec::new(),
                reason: None,
                decided_at: None,
                planned_in: None,
            });
        }
    }
    for claim in claims.values_mut().filter(|claim| claim.status == PENDING) {
        let Some(task) = claim
            .order
            .as_deref()
            .and_then(|order| ferryman_channel::read_task(route, order).ok())
        else {
            continue;
        };
        if task.state() != TaskState::Accepted {
            continue;
        }
        let accepted = task.reviews.iter().rev().find(|review| review.accepted);
        let Some((verdict, citations, reason)) = accepted
            .and_then(|review| task.results.iter().find(|r| r.revision == review.revision))
            .and_then(|result| result.payload.get("output").and_then(Value::as_str))
            .and_then(ferryman_channel::evidence::verdict_of)
        else {
            continue;
        };
        claim.status = if verdict == CONFIRMED {
            CONFIRMED
        } else {
            REFUTED
        }
        .to_string();
        claim.citations = citations;
        claim.reason = (!reason.is_empty()).then_some(reason);
        claim.decided_at = accepted.map(|review| review.reviewed_at);
    }
    if claims != before
        && let Err(error) = save_claims(route, &claims)
    {
        tracing::warn!("could not save the claim record: {error:#}");
    }
    claims
}

fn verification_text(project: &str, claim: &Claim) -> String {
    format!(
        "Verify a claim an automated audit made about {project}, before anyone acts on \
         it.\n\nThe claim (from {}, not established):\n{}\n\nRead the code and decide \
         whether it is true. Confirm it only if the code shows it; refute it if the code \
         shows otherwise - for example, a check it says is missing is applied somewhere \
         else, or a file it names is a stray copy. Cite file:line for every statement, as \
         paths relative to the repository root; the citations are checked.\n\nDo not change \
         any files.\n\nReply with exactly one JSON object and nothing else:\n\
         {{\"verdict\": \"confirmed\" | \"refuted\", \"citations\": [\"path/to/file:123\"], \
         \"reason\": \"one or two sentences\"}}",
        claim.source, claim.text
    )
}

/// Issue a verification order for every pending claim that has none. Returns the ids
/// issued. The order id comes from the claim, so each claim is checked once, ever.
fn verify_claims(
    route: &ProjectRoute,
    config: &AgentConfig,
    identity: &AgentIdentity,
    week: &str,
) -> Result<Vec<String>> {
    let mut claims = refresh_claims(route);
    let mut issued = Vec::new();
    for claim in claims
        .values_mut()
        .filter(|claim| claim.status == PENDING && claim.order.is_none())
    {
        let id = format!("verify-{}", claim.id);
        if ferryman_channel::read_task(route, &id).is_err() {
            let mut order = Order {
                id: id.clone(),
                project_id: route.project_id.clone(),
                issued_by: config.agent.clone(),
                assigned_to: None,
                created_at: Utc::now(),
                payload: json!({
                    "task": verification_text(&route.project_id, claim),
                    "tags": [TAG, VERIFICATION],
                    "tier": Tier::Build.as_str(),
                    "improvement": {
                        "kind": VERIFICATION,
                        "week": week,
                        "title": format!("Verify: {}", first_line(&claim.text)),
                        "claim": claim.text,
                        "claim_id": claim.id,
                        "source": claim.source,
                    },
                }),
                requires_review: true,
                requires_approval: false,
                depends_on: Vec::new(),
                signed_by: None,
                signature: None,
                result_contract: None,
                interface: None,
                touches: Vec::new(),
                needs: None,
                allow_overlap: false,
            };
            identity.sign_order(&mut order);
            match ferryman_channel::issue_order(route, &order) {
                Ok(_) => issued.push(id.clone()),
                Err(error) if format!("{error}").contains("already exists") => {}
                Err(error) => return Err(error),
            }
        }
        claim.order = Some(id);
    }
    save_claims(route, &claims)?;
    Ok(issued)
}

/// What the planner reads: the evidence without the audit's unverified claims, plus the
/// findings verification confirmed that no earlier week has planned from.
#[must_use]
pub fn planner_evidence(evidence: &str, claims: &BTreeMap<String, Claim>, week: &str) -> String {
    let mut text = match evidence.find(CLAIMS_HEADING) {
        Some(start) => {
            let after = start + CLAIMS_HEADING.len();
            let end = evidence[after..]
                .find("\n## ")
                .map_or(evidence.len(), |at| after + at + 1);
            format!("{}{}", &evidence[..start], &evidence[end..])
        }
        None => evidence.to_string(),
    };
    let confirmed: Vec<&Claim> = claims
        .values()
        .filter(|claim| {
            claim.status == CONFIRMED && claim.planned_in.as_deref().is_none_or(|w| w == week)
        })
        .collect();
    if !confirmed.is_empty() {
        text.push_str(
            "\n## Confirmed findings\n\nAn audit's claims, each confirmed against the code by a \
             verification order. Plan from an audit only through these.\n\n",
        );
        for claim in confirmed {
            let _ = writeln!(
                text,
                "- {} (cites {})",
                claim.text,
                if claim.citations.is_empty() {
                    "nothing".to_string()
                } else {
                    claim.citations.join(", ")
                }
            );
        }
    }
    text
}

/// Mark the confirmed findings the planner was shown this week as planned from.
fn mark_planned(route: &ProjectRoute, week: &str) -> Result<()> {
    let mut claims = load_claims(route);
    let mut changed = false;
    for claim in claims
        .values_mut()
        .filter(|claim| claim.status == CONFIRMED && claim.planned_in.is_none())
    {
        claim.planned_in = Some(week.to_string());
        changed = true;
    }
    if changed {
        save_claims(route, &claims)?;
    }
    Ok(())
}
// --- plan -------------------------------------------------------------------------------

/// One improvement as the planner wrote it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Improvement {
    pub title: String,
    pub why: String,
    /// The tests or checks that define done.
    pub acceptance: Vec<String>,
}

/// A week's plan, written once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanFile {
    pub week: String,
    pub project: String,
    pub planned_at: DateTime<Utc>,
    /// The engine that wrote it.
    pub engine: String,
    /// Written by a build-tier engine because no judge was up. A judge reads it at the
    /// next review.
    pub unreviewed: bool,
    pub improvements: Vec<Improvement>,
    pub orders: Vec<String>,
    /// What a judge said about an unreviewed plan, once one has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
}

fn read_plan(route: &ProjectRoute, week: &str) -> Option<PlanFile> {
    fs::read_to_string(week_dir(route, week).join("plan.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

fn write_plan(route: &ProjectRoute, plan: &PlanFile) -> Result<()> {
    let dir = week_dir(route, &plan.week);
    fs::create_dir_all(&dir)?;
    let path = dir.join("plan.json");
    fs::write(&path, serde_json::to_vec_pretty(plan)?)
        .with_context(|| format!("write {}", path.display()))
}

/// What `plan` did.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanOutcome {
    /// This week already has a plan; `issued` orders it named were missing and issued.
    AlreadyPlanned {
        orders: usize,
        issued: usize,
        /// Verification orders issued for audit claims that arrived since.
        verifications: usize,
    },
    Planned {
        engine: String,
        unreviewed: bool,
        orders: Vec<String>,
        /// Verification orders issued for audit claims: confirm or refute first.
        verifications: Vec<String>,
    },
    /// No engine could plan. Not an error: the next run tries again.
    NoEngine(String),
    /// Nothing the engine policy allows can plan, or its weekly cap is spent. The plan
    /// waits - never on a blocked engine - and the master is asked once a week.
    Held(String),
    /// The engine policy runs this project's self-improve on other machines.
    NotHere(String),
    Paused(String),
    /// The project is archived: the loop leaves it alone.
    Archived,
}

/// The order id for one improvement: derived from the week, so a second plan in the same
/// week can only name orders that already exist.
#[must_use]
pub fn order_id(week: &str, rank: usize) -> String {
    format!("improve-{}-{rank}", week.to_ascii_lowercase())
}

/// Pull the first JSON object out of whatever an engine printed around it.
fn extract_json(text: &str) -> Option<Value> {
    let end = text.rfind('}')?;
    text.match_indices('{')
        .map(|(start, _)| start)
        .filter(|start| *start < end)
        .find_map(|start| serde_json::from_str::<Value>(&text[start..=end]).ok())
}

fn parse_improvements(text: &str, max: usize) -> Vec<Improvement> {
    let Some(value) = extract_json(text) else {
        return Vec::new();
    };
    value
        .get("improvements")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let title = item.get("title")?.as_str()?.trim().to_string();
            if title.is_empty() {
                return None;
            }
            Some(Improvement {
                title,
                why: item
                    .get("why")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                acceptance: item
                    .get("acceptance")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect(),
            })
        })
        .take(max)
        .collect()
}

fn plan_prompt(project: &str, evidence: &str, max: usize) -> String {
    format!(
        "You are planning this week's improvements to the project '{project}'. Below is \
         what the project's coordination channel recorded over the last seven days.\n\n\
         Choose at most {max} improvements that would most reduce failures, send-backs \
         and stuck work next week, ranked most valuable first. Each must be small enough \
         for one engine to finish on one branch, and must say how a reviewer will know \
         it is done: tests to add or pass, or checks to run.\n\n\
         If something only the project's owner can answer would change what you plan, \
         add at most two short questions, each with a few answers to choose from; leave \
         \"questions\" out otherwise. Plan anyway: the owner answers on their phone, and \
         next week's plan reads the answers.\n\n\
         Reply with exactly one JSON object and nothing else:\n\
         {{\"improvements\": [{{\"title\": \"...\", \"why\": \"...\", \
         \"acceptance\": [\"...\"]}}], \"questions\": [{{\"text\": \"...\", \
         \"options\": [\"...\"]}}]}}\n\n---\n\n{evidence}"
    )
}

/// The clarifying questions a planner asked, at most two, each with its options.
fn parse_questions(text: &str) -> Vec<(String, Vec<String>)> {
    let Some(value) = extract_json(text) else {
        return Vec::new();
    };
    value
        .get("questions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let text = item.get("text")?.as_str()?.trim().to_string();
            (!text.is_empty()).then(|| {
                let options = item
                    .get("options")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(|option| option.trim().chars().take(40).collect::<String>())
                    .filter(|option| !option.is_empty())
                    .take(4)
                    .collect();
                (text, options)
            })
        })
        .take(2)
        .collect()
}

/// Tell the master, through the channel, that an improvement holds both keys - the
/// review engine's and their own - and is approved, ready to merge. A notice with
/// buttons, never an action: nothing here merges, pushes or bumps a version.
///
/// When the project's engine policy says `auto_merge = "low-risk"`, an improvement
/// with both keys is first authorized - a signed record - for the worker that built it
/// to merge on its own if every file it changes is docs, tests or dependency versions
/// ([`ferryman_channel::automerge`]). The master hears about it only when that worker
/// held it back - code or config, a conflict, a failed push - or has not acted in a day.
/// Asked once per order. Returns how many were asked.
pub fn request_merges(route: &ProjectRoute, config: &AgentConfig) -> Result<usize> {
    let tasks: Vec<Task> = ferryman_channel::list_tasks(route)?
        .into_iter()
        .filter(|task| {
            ferryman_channel::gate::gated(&task.order.payload)
                && ferryman_channel::gate::approved_for_live(route, task)
        })
        .collect();
    if tasks.is_empty() {
        return Ok(0);
    }
    let identity = signing_identity(route, config)?;
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    let auto = policy.auto_merge == ferryman_channel::policy::AutoMerge::LowRisk;
    let mut asked = 0;
    for task in tasks {
        let mut why_not_auto = None;
        let revision = task.latest_revision().unwrap_or_default();
        let blocked =
            ferryman_channel::adversary::unresolved_block(route, &policy, &task.order.id, revision);
        if auto && let Some(block) = &blocked {
            // Auto-merge never carries a Block nobody answered: it becomes a manual-merge
            // question that says so, and the master decides.
            why_not_auto = Some(format!(
                "the adversary blocked it ({})",
                block.finding.describe()
            ));
        } else if auto
            && let Some(why) =
                ferryman_channel::adversary::merge_refusal(route, &policy, &task.order.id, revision)
        {
            // `blocking` mode never merges past a revision no eligible adversary read.
            why_not_auto = Some(why);
        } else if auto {
            use ferryman_channel::automerge::{self, Stage};
            match automerge::stage(route, &task.order.id, revision) {
                Stage::Open => {
                    match automerge::authorize(route, &identity, &task) {
                        Ok(_) => continue,
                        // Refused (the order's contract, the adversary): the master decides,
                        // and is told why, rather than the whole pass failing.
                        Err(error) => why_not_auto = Some(format!("{error:#}")),
                    }
                }
                Stage::Merged(_) => continue,
                Stage::Authorized(record)
                    if Utc::now().signed_duration_since(record.at) < Duration::days(1) =>
                {
                    continue;
                }
                Stage::Authorized(_) => {
                    why_not_auto =
                        Some("the worker that built it has not merged it in a day".to_string());
                }
                Stage::Held(record) => why_not_auto = Some(record.note),
            }
        }
        let reviewer = task
            .reviews
            .iter()
            .rev()
            .find(|review| review.accepted)
            .map(|review| {
                ferryman_channel::delegation::label(
                    &review.reviewer,
                    review.signed_by.as_deref().unwrap_or_default(),
                )
            })
            .unwrap_or_else(|| "review".to_string());
        let engine = ferryman_channel::gate::gate(route, &task, &policy)
            .engine
            .map(|review| review.describe())
            .unwrap_or_default();
        let mut text = format!(
            "Ready to merge: {}\n\nOrder {} holds both keys: the review engine ({engine}) and \
             {reviewer}. Approved, ready to merge - the work is on its own branch",
            task_title(&task),
            task.order.id
        );
        match why_not_auto {
            Some(why) => text.push_str(&format!(
                ". Auto-merge is on, but fm did not merge this one on its own: {why}. Merge it \
                 when you are happy with it."
            )),
            None => text
                .push_str(" and nothing merges on its own. Merge it when you are happy with it."),
        }
        if let (false, Some(block)) = (auto, &blocked) {
            text.push_str(&format!(
                "\n\nThe adversary blocked it and nobody has overridden that: {}",
                block.finding.describe()
            ));
        }
        if ferryman_channel::questions::ask(
            route,
            &identity,
            &format!("merge-{}", task.order.id),
            ferryman_channel::questions::MERGE,
            &text,
            &["I will merge it".to_string(), "Not yet".to_string()],
            Some(&task.order.id),
        )? {
            asked += 1;
        }
    }
    Ok(asked)
}

fn order_text(
    project: &str,
    week: &str,
    rank: usize,
    total: usize,
    item: &Improvement,
    unreviewed: bool,
) -> String {
    let mut text = format!("Improvement {rank} of {total} for {project}, week {week}");
    if unreviewed {
        text.push_str(
            " (UNREVIEWED PLAN: written by a build-tier engine while no judge was available; \
             a judge will check it)",
        );
    }
    let _ = write!(
        text,
        "\n\n{}\n\nWhy: {}\n\nDone when:\n",
        item.title, item.why
    );
    if item.acceptance.is_empty() {
        text.push_str("- the reviewer agrees the title is achieved and nothing else broke\n");
    }
    for check in &item.acceptance {
        let _ = writeln!(text, "- {check}");
    }
    text.push_str(
        "\nWork on this task's own branch. Do not merge, push to a main branch, or bump the \
         version: a reviewer checks the result and a person merges it.",
    );
    text
}

/// Issue every order the plan names that does not exist yet. Returns how many.
fn issue_missing(
    route: &ProjectRoute,
    config: &AgentConfig,
    identity: &AgentIdentity,
    plan: &PlanFile,
) -> Result<usize> {
    let mut issued = 0;
    let total = plan.improvements.len();
    for (index, (item, id)) in plan.improvements.iter().zip(&plan.orders).enumerate() {
        if ferryman_channel::read_task(route, id).is_ok() {
            continue;
        }
        let rank = index + 1;
        let mut order = Order {
            id: id.clone(),
            project_id: route.project_id.clone(),
            issued_by: config.agent.clone(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({
                "task": order_text(&route.project_id, &plan.week, rank, total, item, plan.unreviewed),
                "tags": [TAG],
                "tier": Tier::Build.as_str(),
                "improvement": {
                    "week": plan.week,
                    "rank": rank,
                    "title": item.title,
                    "why": item.why,
                    "acceptance": item.acceptance,
                    "plan": if plan.unreviewed { "unreviewed" } else { "judged" },
                    "planned_by": plan.engine,
                },
            }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        identity.sign_order(&mut order);
        match ferryman_channel::issue_order(route, &order) {
            Ok(_) => issued += 1,
            // Another machine got there first: the order exists, which is the point.
            Err(error) if format!("{error}").contains("already exists") => {}
            Err(error) => return Err(error),
        }
    }
    Ok(issued)
}

fn signing_identity(route: &ProjectRoute, config: &AgentConfig) -> Result<AgentIdentity> {
    AgentIdentity::load_existing(&config.agent, &route.attachment)?.with_context(|| {
        format!(
            "no key for '{}' in {}, so nothing could be signed",
            config.agent,
            route.attachment.display()
        )
    })
}

/// What asking for a plan came to.
enum Asked {
    /// The answer, the engine, whether it is a judge, what it cost, and why that engine.
    Answered(String, Box<EngineSpec>, bool, f64, Box<Decision>),
    /// Nothing the engine policy allows could be asked: the work waits.
    Held(String),
    /// Every allowed engine was asked and none answered.
    Failed(String),
}

/// Ask the engine the policy puts first for planning, falling through engines that are
/// out of credit or fail - never to one the policy blocks. A judge plans first; with no
/// judge allowed and up, a builder does and the plan is marked unreviewed.
async fn ask_best(
    route: &ProjectRoute,
    config: &AgentConfig,
    policy: &Policy,
    prompt: &str,
    report: &dyn Progress,
) -> Asked {
    let machine = ferryman_channel::receipts::machine_label();
    let mut tried = Vec::new();
    loop {
        let ledger = engines::Ledger::load(&config.agent);
        let (engine, decision) = match engines::choose_routed(
            &config.engines,
            &ledger,
            Utc::now(),
            policy,
            (Role::Plan, Tier::Judge, Work::Background),
            &router::needs_for_role(Role::Plan),
            (&[], &tried),
            (&config.agent, &machine),
        ) {
            Ok(chosen) => chosen,
            Err(why) if tried.is_empty() => return Asked::Held(why),
            Err(why) => return Asked::Failed(why),
        };
        tried.push(engine.name.clone());
        let judge = engines::effective_tier(&engine, &ledger.state(&engine.name)) == Tier::Judge;
        let effort = policy.effort_for(Role::Plan);
        match crate::agent::ask_costed(
            route,
            &config.with_engine_effort(&engine, Some(effort)),
            prompt,
        )
        .await
        {
            Ok((answer, cost)) => {
                return Asked::Answered(answer, Box::new(engine), judge, cost, Box::new(decision));
            }
            Err(error) => {
                if let Some(skip) = error.downcast_ref::<engines::Unavailable>() {
                    crate::agent::note_unavailable(route, config, skip);
                }
                report.warn(&format!(
                    "  {}: {} could not answer, trying the next engine: {error:#}",
                    route.project_id, engine.name
                ));
            }
        }
    }
}

/// Record one step of this week's loop, signed by this agent. Best effort.
#[allow(clippy::too_many_arguments)]
fn note_step(
    route: &ProjectRoute,
    config: &AgentConfig,
    week: &str,
    step: &str,
    role: Option<Role>,
    engine: Option<&EngineSpec>,
    cost: Option<f64>,
    outcome: &str,
) {
    note_step_routed(
        route,
        config,
        week,
        step,
        role,
        (engine, None),
        cost,
        outcome,
    );
}

/// [`note_step`] with the smart router's decision beside the engine, when it chose it.
#[allow(clippy::too_many_arguments)]
fn note_step_routed(
    route: &ProjectRoute,
    config: &AgentConfig,
    week: &str,
    step: &str,
    role: Option<Role>,
    (engine, decision): (Option<&EngineSpec>, Option<&Decision>),
    cost: Option<f64>,
    outcome: &str,
) {
    let Ok(identity) = signing_identity(route, config) else {
        return;
    };
    let record = Step {
        step: step.to_string(),
        role: role.map(|role| role.as_str().to_string()),
        at: Utc::now(),
        agent: config.agent.clone(),
        machine: ferryman_channel::receipts::machine_label(),
        engine: engine.map(|engine| engine.name.clone()),
        model: engine.and_then(|engine| engine.model.clone()),
        cost_usd: cost,
        order: None,
        effort: role.and_then(|role| engines::effort_used(route, role, engine)),
        route: decision.cloned(),
        outcome: outcome.to_string(),
    };
    if let Err(error) = ferryman_channel::policy::record_step(route, &identity, week, record) {
        tracing::warn!("could not record the {step} step: {error:#}");
    }
}

/// Background work the policy leaves nothing to do: record why, and ask the master -
/// once per role per week, however many machines and hours it stays held.
fn hold(
    route: &ProjectRoute,
    config: &AgentConfig,
    role: Role,
    week: &str,
    why: &str,
    report: &dyn Progress,
) {
    report.warn(&format!(
        "  {}: {} work held: {why}",
        route.project_id,
        role.as_str()
    ));
    match signing_identity(route, config)
        .and_then(|identity| ferryman_channel::policy::ask_hold(route, &identity, role, week, why))
    {
        Ok(true) => {
            // Recorded with the question, once, not every hour it stays held.
            note_step(
                route,
                config,
                week,
                role.as_str(),
                Some(role),
                None,
                None,
                &format!("held: {why}"),
            );
            report.info(&format!(
                "  {}: asked the master what to do about the held {} work",
                route.project_id,
                role.as_str()
            ));
        }
        Ok(false) => {}
        Err(error) => report.warn(&format!(
            "  {}: could not ask the master: {error:#}",
            route.project_id
        )),
    }
}

/// Improvement orders nobody has claimed, when the fleet - as its signed engine
/// inventories describe it - has no engine the policy allows to build them, on no
/// machine it names, or the build cap is spent: held, and the master asked once a week.
///
/// Workers already leave such orders unclaimed rather than fall back; this is what makes
/// the wait visible. With no inventory at all nothing is known, and nothing is said.
fn hold_unbuildable(
    route: &ProjectRoute,
    config: &AgentConfig,
    week: &str,
    now: DateTime<Utc>,
    report: &dyn Progress,
) {
    let waiting: Vec<Tier> = ferryman_channel::list_tasks(route)
        .unwrap_or_default()
        .iter()
        .filter(|task| is_improvement(task))
        .filter(|task| matches!(task.state(), TaskState::Open | TaskState::Offered { .. }))
        .map(|task| {
            task.order.payload["tier"]
                .as_str()
                .and_then(|tier| Tier::parse(tier).ok())
                .unwrap_or(Tier::Build)
        })
        .collect();
    if waiting.is_empty() {
        return;
    }
    let fleet = ferryman_channel::policy::fleet(route, now);
    if fleet.is_empty() {
        return;
    }
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    let mut tiers = waiting;
    tiers.sort();
    tiers.dedup();
    for tier in tiers {
        let role = Role::for_order_tier(tier.as_str());
        let why = ferryman_channel::policy::over_cap(route, &policy, week, role).or_else(|| {
            let ranking = ferryman_channel::policy::rank(
                &policy,
                role,
                tier.as_str(),
                ferryman_channel::policy::Work::Background,
                &fleet,
            );
            ranking
                .order
                .is_empty()
                .then(|| ranking.why_none(role, &fleet))
        });
        if let Some(why) = why {
            hold(route, config, role, week, &why, report);
        }
    }
}

/// This agent and machine, when the project's engine policy lets them run its
/// self-improve work; otherwise why not.
fn here(route: &ProjectRoute, config: &AgentConfig, policy: &Policy) -> Result<(), String> {
    let machine = ferryman_channel::receipts::machine_label();
    if policy.allows_machine(&config.agent, &machine) {
        Ok(())
    } else {
        Err(crate::agent::not_here(&config.agent, &machine, policy))
    }
    .map_err(|why| format!("{}: {why}", route.project_id))
}

/// Turn this week's evidence into at most `max` ranked improvements, each issued as a
/// signed order tagged `improvement`, open to any worker.
///
/// Written once a week: a second call finds the plan and issues only orders it names
/// that are missing, which after a completed first call is none.
pub async fn plan(
    route: &ProjectRoute,
    config: &AgentConfig,
    max: usize,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> Result<PlanOutcome> {
    let week = engines::iso_week(now);
    if ferryman_channel::ferry::is_archived(&route.communications, &route.project_id) {
        return Ok(PlanOutcome::Archived);
    }
    if let Some(existing) = read_plan(route, &week) {
        let identity = signing_identity(route, config)?;
        let issued = issue_missing(route, config, &identity, &existing)?;
        let verifications = verify_claims(route, config, &identity, &week)?.len();
        return Ok(PlanOutcome::AlreadyPlanned {
            orders: existing.orders.len(),
            issued,
            verifications,
        });
    }
    if let Some(why) = paused() {
        return Ok(PlanOutcome::Paused(why));
    }
    let identity = signing_identity(route, config)?;
    // An audit's claims are checked before anything is planned from them, and need no
    // engine to be issued: they go out even in a week no engine can plan.
    let verifications = verify_claims(route, config, &identity, &week)?;
    for id in &verifications {
        report.info(&format!(
            "  {}: {id} checks an audit claim before anything is planned from it",
            route.project_id
        ));
    }
    let evidence_path = week_dir(route, &week).join("evidence.md");
    if !evidence_path.is_file() {
        gather(route, now)?;
    }
    let evidence = planner_evidence(
        &fs::read_to_string(&evidence_path)
            .with_context(|| format!("read {}", evidence_path.display()))?,
        &load_claims(route),
        &week,
    );
    let max = max.max(1);
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    if let Err(why) = here(route, config, &policy) {
        return Ok(PlanOutcome::NotHere(why));
    }
    if let Some(why) = ferryman_channel::policy::over_cap(route, &policy, &week, Role::Plan) {
        hold(route, config, Role::Plan, &week, &why, report);
        return Ok(PlanOutcome::Held(why));
    }
    let (answer, engine, judged, cost, plan_route) = match ask_best(
        route,
        config,
        &policy,
        &plan_prompt(&route.project_id, &evidence, max),
        report,
    )
    .await
    {
        Asked::Answered(answer, engine, judged, cost, decision) => {
            (answer, *engine, judged, cost, *decision)
        }
        Asked::Held(why) => {
            hold(route, config, Role::Plan, &week, &why, report);
            return Ok(PlanOutcome::Held(why));
        }
        Asked::Failed(why) => {
            note_step(
                route,
                config,
                &week,
                "plan",
                Some(Role::Plan),
                None,
                None,
                &format!("failed: {why}"),
            );
            return Ok(PlanOutcome::NoEngine(
                engines::all_exhausted(&config.engines, &engines::Ledger::load(&config.agent), now)
                    .unwrap_or(why),
            ));
        }
    };
    note_step_routed(
        route,
        config,
        &week,
        "plan",
        Some(Role::Plan),
        (Some(&engine), Some(&plan_route)),
        Some(cost),
        if judged { "done" } else { "done (unreviewed)" },
    );
    let improvements = parse_improvements(&answer, max);
    if improvements.is_empty() {
        bail!(
            "{} answered, but not with the improvements JSON asked for; nothing was issued \
             and the next run will ask again",
            engine.name
        )
    }
    let plan = PlanFile {
        orders: (1..=improvements.len())
            .map(|rank| order_id(&week, rank))
            .collect(),
        week,
        project: route.project_id.clone(),
        planned_at: now,
        engine: engine.name.clone(),
        unreviewed: !judged,
        improvements,
        reviewed_by: None,
    };
    // The plan is written before the orders, so an interrupted run re-issues from the
    // same plan rather than asking again and planning something different.
    write_plan(route, &plan)?;
    issue_missing(route, config, &identity, &plan)?;
    mark_planned(route, &plan.week)?;
    for (rank, (text, options)) in parse_questions(&answer).into_iter().enumerate() {
        let id = format!("clarify-{}-{}", plan.week.to_ascii_lowercase(), rank + 1);
        match ferryman_channel::questions::ask(
            route,
            &identity,
            &id,
            ferryman_channel::questions::CLARIFY,
            &text,
            &options,
            None,
        ) {
            Ok(true) => report.info(&format!("  {}: asked {id}: {text}", route.project_id)),
            Ok(false) => {}
            Err(error) => report.warn(&format!(
                "  {}: could not ask {id}: {error:#}",
                route.project_id
            )),
        }
    }
    Ok(PlanOutcome::Planned {
        engine: engine.name,
        unreviewed: plan.unreviewed,
        orders: plan.orders,
        verifications,
    })
}

// --- review -----------------------------------------------------------------------------

fn awaiting_improvement_review(route: &ProjectRoute) -> bool {
    ferryman_channel::list_tasks(route)
        .unwrap_or_default()
        .iter()
        .any(|task| {
            is_improvement(task)
                && match task.state() {
                    TaskState::AwaitingReview { .. } => true,
                    TaskState::Refuted { .. } => task.order.requires_review,
                    _ => false,
                }
                && task.pending_recommendation().is_none()
        })
}

/// One improvement result, as verification classed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub order: String,
    pub revision: u32,
    pub worker: String,
    /// `verified`, `unverified` or `refuted`.
    pub status: String,
    pub reasons: Vec<String>,
}

/// Check the newest result of every improvement against its evidence, and record each
/// verdict signed by `identity` - beside the result and in the ledger, never in the
/// worker's own file. Needs no engine: the decision is read from recorded facts. A
/// result already checked by this agent is neither recorded nor returned again, so an
/// hourly run reports each verdict once.
pub fn verify_results(route: &ProjectRoute, identity: &AgentIdentity) -> Vec<Checked> {
    let mut checked = Vec::new();
    for task in ferryman_channel::list_tasks(route).unwrap_or_default() {
        if !is_improvement(&task) {
            continue;
        }
        let Some(revision) = task.latest_revision() else {
            continue;
        };
        let already = ferryman_channel::evidence::read_verifications(route, &task.order.id)
            .iter()
            .any(|record| {
                record.revision == revision && record.verifier.eq_ignore_ascii_case(identity.name())
            });
        if already {
            continue;
        }
        match ferryman_channel::evidence::record(route, &task, revision, identity) {
            Ok(Some(record)) => checked.push(Checked {
                order: record.order_id,
                revision,
                worker: record.worker,
                status: record.status,
                reasons: record.reasons,
            }),
            Ok(None) => {}
            Err(error) => tracing::warn!(
                "could not record the verification of {}: {error:#}",
                task.order.id
            ),
        }
    }
    checked
}

/// With a judge-tier engine up: read an unreviewed plan, and judge improvement results
/// nobody has judged yet, through the ordinary review mechanism. Returns how many things
/// were judged. Without a judge up it does nothing, cheaply.
pub async fn review(
    route: &ProjectRoute,
    config: &AgentConfig,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> Result<usize> {
    if let Some(why) = paused() {
        report.info(&format!(
            "  {}: paused ({why}); not reviewing",
            route.project_id
        ));
        return Ok(0);
    }
    // Evidence before opinion, and with no engine: every improvement result is classed
    // verified, unverified or refuted from what its worker recorded, and the class is
    // recorded, signed, before any judge reads the claim.
    if let Ok(identity) = signing_identity(route, config) {
        for found in verify_results(route, &identity)
            .iter()
            .filter(|found| found.status == ferryman_channel::evidence::Status::Refuted.class())
        {
            report.warn(&format!(
                "  {}: {} r{} by {} is refuted - {}; it does not count as done",
                route.project_id,
                found.order,
                found.revision,
                found.worker,
                found.reasons.join("; ")
            ));
        }
    }
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    // The adversary reads contracts waiting for a lock and improvements waiting for the
    // review engine before the judge does, so its finding is there to be shown beside the
    // keys. It has its own engine choice and its own hold; a judge that is down does not
    // stop it, and it does not stop an advisory judge. It runs before the engine policy's
    // `where` is consulted, and whatever that says: `where` is the engine policy's - which
    // a delegate signs - and must not be able to keep the check off the work.
    let challenged = crate::adversary::pass(route, config, &policy, now, report).await;
    if let Err(why) = here(route, config, &policy) {
        report.info(&format!("  {why}; not reviewing here"));
        return Ok(challenged);
    }
    let week = engines::iso_week(now);
    let waiting = read_plan(route, &week).is_some_and(|plan| plan.unreviewed)
        || awaiting_improvement_review(route);
    let ledger = engines::Ledger::load(&config.agent);
    let machine = ferryman_channel::receipts::machine_label();
    let chosen = match ferryman_channel::policy::over_cap(route, &policy, &week, Role::Review) {
        Some(why) => Err(why),
        None => engines::choose_routed(
            &config.engines,
            &ledger,
            now,
            &policy,
            (Role::Review, Tier::Judge, Work::Background),
            &router::needs_for_role(Role::Review),
            (&[], &[]),
            (&config.agent, &machine),
        ),
    };
    let (judge, judge_route) = match chosen {
        Ok(chosen) => chosen,
        Err(why) if waiting => {
            hold(route, config, Role::Review, &week, &why, report);
            return Ok(0);
        }
        Err(_) => {
            report.info(&format!(
                "  {}: no judge-tier engine the policy allows is up; review waits",
                route.project_id
            ));
            return Ok(0);
        }
    };
    let spent_before = ledger.state(&judge.name);
    let mut judged = 0;
    match request_merges(route, config) {
        Ok(0) => {}
        Ok(count) => report.info(&format!(
            "  {}: {count} improvement(s) ready to merge; asked the master",
            route.project_id
        )),
        Err(error) => report.warn(&format!(
            "  {}: could not ask about merging: {error:#}",
            route.project_id
        )),
    }

    if let Some(mut plan) = read_plan(route, &week).filter(|plan| plan.unreviewed) {
        let prompt = format!(
            "A build-tier engine wrote this week's improvement plan for '{}' while no judge \
             was available. Read it against the evidence and say which items are worth \
             doing.\n\nReply in markdown: for each item, keep or drop and one sentence why.\
             \n\nPlan:\n{}\n\n---\n\n{}",
            route.project_id,
            serde_json::to_string_pretty(&plan.improvements)?,
            fs::read_to_string(week_dir(route, &week).join("evidence.md")).unwrap_or_default()
        );
        let effort = policy.effort_for(Role::Review);
        match crate::agent::ask(
            route,
            &config.with_engine_effort(&judge, Some(effort)),
            &prompt,
        )
        .await
        {
            Ok(answer) => {
                let path = week_dir(route, &week).join("plan-review.md");
                fs::write(
                    &path,
                    format!("# Plan review by {}\n\n{answer}\n", judge.name),
                )
                .with_context(|| format!("write {}", path.display()))?;
                plan.unreviewed = false;
                plan.reviewed_by = Some(judge.name.clone());
                write_plan(route, &plan)?;
                judged += 1;
            }
            Err(error) => {
                return Ok(settle(
                    config,
                    &error,
                    judged,
                    route,
                    (&judge, &spent_before, &week),
                    report,
                ));
            }
        }
    }

    if awaiting_improvement_review(route) {
        // With a blocking adversary, the judge waits for it: no judge is paid for an
        // engine key the gate would refuse.
        let wanted =
            |task: &Task| is_improvement(task) && crate::adversary::may_judge(route, &policy, task);
        let reviewer = config.with_engine_effort(&judge, Some(policy.effort_for(Role::Review)));
        match crate::agent::review_where(route, &reviewer, report, wanted).await {
            Ok(count) => judged += count,
            Err(error) => {
                return Ok(settle(
                    config,
                    &error,
                    judged,
                    route,
                    (&judge, &spent_before, &week),
                    report,
                ));
            }
        }
    }
    if judged > 0 {
        note_step_routed(
            route,
            config,
            &week,
            "review",
            Some(Role::Review),
            (Some(&judge), Some(&judge_route)),
            Some(spent_since(config, &judge, &spent_before, now)),
            &format!("judged {judged}"),
        );
    }
    Ok(judged + challenged)
}

/// What an engine spent since `before` was read from the ledger, this week.
fn spent_since(
    config: &AgentConfig,
    engine: &EngineSpec,
    before: &engines::EngineState,
    now: DateTime<Utc>,
) -> f64 {
    let after = engines::Ledger::load(&config.agent).state(&engine.name);
    if before.week == after.week {
        (after.spend_usd - before.spend_usd).max(0.0)
    } else if after.week == engines::iso_week(now) {
        after.spend_usd
    } else {
        0.0
    }
}

/// A judge that failed mid-review: mark it if it ran out of credit, say so, keep what
/// was done.
fn settle(
    config: &AgentConfig,
    error: &anyhow::Error,
    judged: usize,
    route: &ProjectRoute,
    (judge, before, week): (&EngineSpec, &engines::EngineState, &str),
    report: &dyn Progress,
) -> usize {
    if let Some(skip) = error.downcast_ref::<engines::Unavailable>() {
        crate::agent::note_unavailable(route, config, skip);
    }
    note_step(
        route,
        config,
        week,
        "review",
        Some(Role::Review),
        Some(judge),
        Some(spent_since(config, judge, before, Utc::now())),
        &format!("stopped after {judged}: {error:#}"),
    );
    report.warn(&format!(
        "  {}: review stopped: {error:#}",
        route.project_id
    ));
    judged
}

// --- report -----------------------------------------------------------------------------

/// Monday 00:00 UTC of the week `at` falls in.
fn week_start(at: DateTime<Utc>) -> DateTime<Utc> {
    let days = i64::from(at.weekday().num_days_from_monday());
    (at.date_naive() - Duration::days(days))
        .and_hms_opt(0, 0, 0)
        .map_or(at, |midnight| midnight.and_utc())
}

/// One week's numbers for one project.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct WeekNumbers {
    pub done: usize,
    pub runs: usize,
    pub runs_ok: usize,
    pub reviews: usize,
    pub sent_back: usize,
    /// Results submitted in the week that their own evidence, or their emptiness,
    /// refutes. Never counted in `done`.
    pub refuted: usize,
    pub median_claim_minutes: Option<i64>,
    /// At list prices, from the runs whose engine reported usage.
    pub cost_usd: Option<f64>,
}

fn finished_at(task: &Task) -> Option<DateTime<Utc>> {
    match task.state() {
        TaskState::Accepted => task
            .reviews
            .iter()
            .filter(|review| review.accepted)
            .map(|review| review.reviewed_at)
            .max(),
        TaskState::Done => task.results.iter().map(|result| result.submitted_at).max(),
        _ => None,
    }
}

/// The numbers for `[start, start + 7 days)`.
#[must_use]
pub fn numbers(
    tasks: &[Task],
    runs: &[Trajectory],
    rates: &ferryman_channel::cost::Rates,
    start: DateTime<Utc>,
) -> WeekNumbers {
    let end = start + Duration::days(7);
    let within = |at: DateTime<Utc>| at >= start && at < end;
    let mut claims: Vec<i64> = tasks
        .iter()
        .filter(|task| within(task.order.created_at))
        .filter_map(|task| {
            task.claims
                .iter()
                .map(|claim| claim.claimed_at)
                .min()
                .map(|claimed| (claimed - task.order.created_at).num_minutes().max(0))
        })
        .collect();
    claims.sort_unstable();
    let mut cost = None;
    for run in runs.iter().filter(|run| within(run.at)) {
        if let Some(usage) = run.usage {
            let price = rates.price_for(&run.engine);
            *cost.get_or_insert(0.0) += (usage.prompt_tokens as f64 * price.prompt_per_million
                + usage.completion_tokens as f64 * price.completion_per_million)
                / 1_000_000.0;
        }
    }
    let reviews: Vec<_> = tasks
        .iter()
        .flat_map(|task| task.reviews.iter())
        .filter(|review| within(review.reviewed_at))
        .collect();
    // A run whose result is refuted did not succeed, whatever the engine's exit code.
    let refuted: Vec<(&str, u32)> = tasks
        .iter()
        .flat_map(|task| {
            task.results
                .iter()
                .filter(|result| {
                    ferryman_channel::evidence::is_refuted(&task.order.payload, result)
                })
                .map(|result| (result.order_id.as_str(), result.revision))
                .collect::<Vec<_>>()
        })
        .collect();
    let refuted_run = |run: &Trajectory| refuted.contains(&(run.order_id.as_str(), run.revision));
    WeekNumbers {
        done: tasks
            .iter()
            .filter(|task| finished_at(task).is_some_and(within))
            .count(),
        runs: runs.iter().filter(|run| within(run.at)).count(),
        runs_ok: runs
            .iter()
            .filter(|run| run.ok && within(run.at) && !refuted_run(run))
            .count(),
        reviews: reviews.len(),
        sent_back: reviews.iter().filter(|review| !review.accepted).count(),
        refuted: tasks
            .iter()
            .flat_map(|task| {
                task.results
                    .iter()
                    .filter(|result| within(result.submitted_at))
                    .filter(|result| refuted.contains(&(result.order_id.as_str(), result.revision)))
            })
            .count(),
        median_claim_minutes: claims.get(claims.len() / 2).copied(),
        cost_usd: cost,
    }
}

fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        "-".to_string()
    } else {
        format!(
            "{:.0}% ({part}/{whole})",
            part as f64 * 100.0 / whole as f64
        )
    }
}

/// What self-improve spent in `week`, per engine and machine, from the signed step
/// records: (engine, machine, dollars), most first.
#[must_use]
pub fn spend_by_engine(route: &ProjectRoute, week: &str) -> Vec<(String, String, f64)> {
    let mut sums: BTreeMap<(String, String), f64> = BTreeMap::new();
    for step in ferryman_channel::policy::read_steps(route, week) {
        if let (Some(engine), Some(cost)) = (step.engine, step.cost_usd) {
            *sums.entry((engine, step.machine)).or_default() += cost;
        }
    }
    let mut out: Vec<(String, String, f64)> = sums
        .into_iter()
        .map(|((engine, machine), usd)| (engine, machine, usd))
        .collect();
    out.sort_by(|a, b| b.2.total_cmp(&a.2).then(a.0.cmp(&b.0)));
    out
}

/// Write `improve/<week>/report.md` for the week `at` falls in, against the week before.
pub fn report(route: &ProjectRoute, at: DateTime<Utc>) -> Result<PathBuf> {
    let week = engines::iso_week(at);
    let start = week_start(at);
    let tasks = ferryman_channel::list_tasks(route)?;
    let runs = trajectories(route);
    let rates = ferryman_channel::cost::Rates::load(route);
    let this = numbers(&tasks, &runs, &rates, start);
    let last = numbers(&tasks, &runs, &rates, start - Duration::days(7));
    let mut md = String::new();
    let _ = writeln!(md, "# {} - week {week}\n", route.project_id);
    let _ = writeln!(md, "| | this week | last week |\n|---|---|---|");
    let _ = writeln!(md, "| tasks done | {} | {} |", this.done, last.done);
    let _ = writeln!(
        md,
        "| results refuted by their own evidence (not done) | {} | {} |",
        this.refuted, last.refuted
    );
    let _ = writeln!(
        md,
        "| engine runs that succeeded | {} | {} |",
        percent(this.runs_ok, this.runs),
        percent(last.runs_ok, last.runs)
    );
    let _ = writeln!(
        md,
        "| reviews that sent work back | {} | {} |",
        percent(this.sent_back, this.reviews),
        percent(last.sent_back, last.reviews)
    );
    let minutes = |value: Option<i64>| value.map_or("-".to_string(), |m| format!("{m} min"));
    let _ = writeln!(
        md,
        "| median time to claim | {} | {} |",
        minutes(this.median_claim_minutes),
        minutes(last.median_claim_minutes)
    );
    let dollars = |value: Option<f64>| value.map_or("unknown".to_string(), |v| format!("${v:.2}"));
    let _ = writeln!(
        md,
        "| cost at list prices, where engines report usage | {} | {} |",
        dollars(this.cost_usd),
        dollars(last.cost_usd)
    );

    let _ = writeln!(md, "\n## Improvements\n");
    let mut ready = Vec::new();
    let mut listed = false;
    let mut improvements: Vec<&Task> = tasks.iter().filter(|task| is_improvement(task)).collect();
    improvements.sort_by(|a, b| a.order.id.cmp(&b.order.id));
    for task in improvements {
        let plan = task.order.payload["improvement"]["plan"]
            .as_str()
            .unwrap_or("judged");
        let state = task.state();
        let branch = task
            .results
            .last()
            .and_then(|result| result.payload.get("worktree_branch"))
            .and_then(Value::as_str)
            .unwrap_or("no branch yet");
        if task.order.created_at >= start - Duration::days(7) {
            listed = true;
            let _ = writeln!(
                md,
                "- `{}` {} - {:?}{}",
                task.order.id,
                task_title(task),
                state,
                if plan == "unreviewed" {
                    " (unreviewed plan)"
                } else {
                    ""
                }
            );
        }
        let advised = task
            .pending_recommendation()
            .is_some_and(|advice| advice.accept);
        // An improvement is ready only with both keys: the review engine's and the
        // master's. Anything else is what it always was: accepted.
        let live = if ferryman_channel::gate::gated(&task.order.payload) {
            ferryman_channel::gate::approved_for_live(route, task)
        } else {
            matches!(state, TaskState::Accepted)
        };
        if live || advised {
            ready.push(format!(
                "- `{}` on `{branch}`{}: {}",
                task.order.id,
                if live {
                    ""
                } else {
                    " (the review engine keeps it; waiting for your approval: 'ferry improve \
                     approve')"
                },
                task_title(task)
            ));
        }
    }
    if !listed {
        let _ = writeln!(md, "None issued this week or last.");
    }
    let _ = writeln!(md, "\n## Ready to merge\n");
    let _ = writeln!(
        md,
        "Approved with both keys - the review engine's and the master's. Nothing here merges \
         by itself; a person merges it.\n"
    );
    if ready.is_empty() {
        let _ = writeln!(md, "Nothing yet.");
    }
    for line in ready {
        let _ = writeln!(md, "{line}");
    }
    md.push_str(&crate::adversary::report_section(route));

    let _ = writeln!(md, "\n## Who did each step\n");
    let _ = writeln!(
        md,
        "The newest signed record of each step: which engine and model, on which machine.\n"
    );
    let steps = ferryman_channel::policy::latest_steps(route, &week);
    if steps.is_empty() {
        let _ = writeln!(md, "Nothing recorded.");
    }
    for step in &steps {
        let _ = writeln!(md, "- {}", step.describe());
    }
    let _ = writeln!(md, "\n## Self-improve spend per engine\n");
    let spend = spend_by_engine(route, &week);
    if spend.is_empty() {
        let _ = writeln!(md, "Nothing recorded.");
    }
    for (engine, machine, usd) in spend {
        let _ = writeln!(md, "- {engine} on {machine}: ${usd:.2}");
    }

    let dir = week_dir(route, &week);
    fs::create_dir_all(&dir)?;
    let path = dir.join("report.md");
    fs::write(&path, md).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

// --- run --------------------------------------------------------------------------------

/// Run whichever steps are due for every project given that its master has switched on
/// ([`ferryman_channel::ferry::self_improve_enabled`]), and say what was done. A project
/// that is switched off is passed over without reading anything else.
///
/// - gather and plan: once a week per project, when this week has no evidence or plan;
/// - review: whenever a judge-tier engine is up and there is an unreviewed plan or an
///   improvement result nobody has judged;
/// - report: once a week, for the week just finished, when it has no report yet.
///
/// Each check is a file existence test or a directory read, so a run with nothing due
/// costs no engine call. Nothing at all while the machine is paused.
pub async fn run(
    targets: &[(ProjectRoute, AgentConfig)],
    max: usize,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> Vec<String> {
    let mut done = Vec::new();
    if let Some(why) = paused() {
        report.info(&format!(
            "paused ({why}); ferry improve does nothing until 'ferry resume'"
        ));
        return done;
    }
    let week = engines::iso_week(now);
    let last_week = engines::iso_week(now - Duration::days(7));
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for (route, config) in targets {
        if seen.insert(route.project_id.clone(), ()).is_some()
            || !ferryman_channel::ferry::self_improve_enabled(
                &route.communications,
                &route.project_id,
            )
        {
            continue;
        }
        let project = &route.project_id;
        // An engine policy that went back or vanished from the channel: this machine keeps
        // the last one the master signed, and the master is asked once.
        if let Ok(identity) = signing_identity(route, config)
            && let Ok(true) = ferryman_channel::policy::ask_rollback(route, &identity)
        {
            report.warn(&format!(
                "{project}: the engine policy in the channel went back or vanished; \
                 keeping the last one signed, and asked the master"
            ));
        }
        let dir = week_dir(route, &week);
        if !dir.join("evidence.md").is_file() {
            match gather(route, now) {
                Ok(_) => {
                    note_step(route, config, &week, "gather", None, None, None, "done");
                    done.push(format!("{project}: gathered {week}"));
                }
                Err(error) => report.warn(&format!("{project}: gather failed: {error:#}")),
            }
        }
        if !dir.join("plan.json").is_file() {
            match plan(route, config, max, now, report).await {
                Ok(PlanOutcome::Planned {
                    engine,
                    unreviewed,
                    orders,
                    ..
                }) => done.push(format!(
                    "{project}: planned {} improvement(s) with {engine}{}",
                    orders.len(),
                    if unreviewed { " (unreviewed)" } else { "" }
                )),
                Ok(PlanOutcome::NoEngine(why)) => {
                    report.warn(&format!("{project}: no engine could plan: {why}"));
                }
                Ok(_) => {}
                Err(error) => report.warn(&format!("{project}: plan failed: {error:#}")),
            }
        }
        let plan_unreviewed = read_plan(route, &week).is_some_and(|plan| plan.unreviewed);
        hold_unbuildable(route, config, &week, now, report);
        match request_merges(route, config) {
            Ok(0) => {}
            Ok(count) => done.push(format!("{project}: {count} ready to merge, asked")),
            Err(error) => report.warn(&format!("{project}: merge notice failed: {error:#}")),
        }
        // Evidence needs no engine: every new improvement result is classed and the
        // verdict recorded, signed, whether or not a judge is up to read it after.
        if let Ok(identity) = signing_identity(route, config) {
            for found in verify_results(route, &identity)
                .iter()
                .filter(|found| found.status == REFUTED)
            {
                done.push(format!(
                    "{project}: {} r{} by {} refuted, not done - {}",
                    found.order,
                    found.revision,
                    found.worker,
                    found.reasons.join("; ")
                ));
            }
        }
        // Review picks its judge through the engine policy, and holds - asking the
        // master once - when there is work to judge and nothing allowed to judge it.
        if plan_unreviewed || awaiting_improvement_review(route) {
            match review(route, config, now, report).await {
                Ok(0) => {}
                Ok(count) => done.push(format!("{project}: judged {count}")),
                Err(error) => report.warn(&format!("{project}: review failed: {error:#}")),
            }
        }
        if !week_dir(route, &last_week).join("report.md").is_file() {
            match self::report(route, now - Duration::days(7)) {
                Ok(_) => done.push(format!("{project}: reported {last_week}")),
                Err(error) => report.warn(&format!("{project}: report failed: {error:#}")),
            }
        }
    }
    done
}

/// Whether the worker's own hourly call to [`run`] is due: at most once an hour per
/// machine, remembered in the machine state directory so a restart does not reset it.
#[must_use]
pub fn hourly_due(now: DateTime<Utc>) -> bool {
    let Some(path) =
        ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("improve-last-run"))
    else {
        return false;
    };
    let last = fs::read_to_string(&path)
        .ok()
        .and_then(|text| DateTime::parse_from_rfc3339(text.trim()).ok())
        .map(|at| at.with_timezone(&Utc));
    if last.is_some_and(|at| {
        let since = now.signed_duration_since(at);
        since >= Duration::zero() && since < Duration::hours(1)
    }) {
        return false;
    }
    let _ = fs::write(&path, now.to_rfc3339());
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{EngineSpec, Kind, Paid};

    const PLAN: &str = r#"Here is the plan.
{"improvements": [
  {"title": "Retry sync on a stale folder", "why": "three orders sat unread", "acceptance": ["cargo test -p ferryman-channel passes", "a stale folder is re-registered"]},
  {"title": "Name the engine in every failure", "why": "failures were anonymous", "acceptance": []}
]}"#;

    fn hermetic() {
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            std::env::temp_dir().join(format!("ferryman-ops-improve-{}", std::process::id())),
        );
    }

    fn engine(name: &str, tier: Tier, url: &str) -> EngineSpec {
        EngineSpec {
            name: name.into(),
            kind: Kind::Http,
            tier,
            paid: Paid::Prepaid,
            command: String::new(),
            args: Vec::new(),
            model: Some("m".into()),
            base_url: Some(url.into()),
            key: None,
            env: Vec::new(),
            probe_chat: false,
            weekly_requests: None,
            weekly_usd: None,
            provider: None,
            route: Vec::new(),
            class: None,
            effort_args: std::collections::BTreeMap::new(),
            supports_effort: false,
            declared: ferryman_channel::capability::Declared::default(),
        }
    }

    /// A channel whose roster knows wisp, with wisp's key held here, and a config
    /// running `engines`.
    fn channel(dir: &Path, engines: Vec<EngineSpec>) -> (ProjectRoute, AgentConfig) {
        let workspace = dir.join("demo-ferryman");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(communications.join("agents")).unwrap();
        let slash = |path: &Path| path.display().to_string().replace('\\', "/");
        fs::write(
            attachment.join("bridge.toml"),
            format!(
                "project = \"demo\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
                slash(&workspace),
                slash(&attachment),
                slash(&communications)
            ),
        )
        .unwrap();
        fs::create_dir_all(attachment.join("keys")).unwrap();
        fs::write(attachment.join("keys").join("wisp.key"), "07".repeat(32)).unwrap();
        fs::write(
            attachment.join("agent.toml"),
            "agent = \"wisp\"\ncommand = \"ferryman-no-such-engine\"\nreview = \"auto\"\n",
        )
        .unwrap();
        let mut route = ferryman_channel::route_for(&workspace).unwrap();
        let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
        route.agents = vec![ferryman_channel::AgentRoute {
            name: "wisp".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(wisp.public_key_hex()),
            encryption_key: None,
        }];
        let mut config = AgentConfig::load(&attachment).unwrap();
        config.engines = engines;
        (route, config)
    }

    /// Make josh the channel's master and have him switch self-improve on.
    fn switch_on(route: &ProjectRoute) {
        let josh = AgentIdentity::from_seed("josh", [9; 32]);
        ferryman_channel::register_agent(
            route,
            &ferryman_channel::AgentRoute {
                name: "josh".into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(josh.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        ferryman_channel::master::initialize_master(route, &josh, "josh").unwrap();
        assert!(
            ferryman_channel::ferry::set_self_improve(
                &route.communications,
                &route.project_id,
                true,
                &josh
            )
            .unwrap()
        );
    }

    fn improvements(route: &ProjectRoute) -> Vec<Task> {
        ferryman_channel::list_tasks(route)
            .unwrap()
            .into_iter()
            .filter(is_improvement)
            .collect()
    }

    #[test]
    fn a_planner_may_ask_at_most_two_questions_with_their_options() {
        let text = r#"{"improvements": [], "questions": [
            {"text": "Keep Windows 7 support?", "options": ["Yes", "No"]},
            {"text": "  "},
            {"text": "Which CI?", "options": []},
            {"text": "A third", "options": ["x"]}
        ]}"#;
        let asked = parse_questions(text);
        assert_eq!(
            asked,
            vec![
                (
                    "Keep Windows 7 support?".to_string(),
                    vec!["Yes".to_string(), "No".to_string()]
                ),
                ("Which CI?".to_string(), Vec::new()),
            ]
        );
        assert!(parse_questions(PLAN).is_empty(), "questions are optional");
    }

    /// An improvement is announced as ready to merge only with both keys - the review
    /// engine's and the master's - once, and nothing is merged.
    #[test]
    fn accepted_improvements_become_one_merge_notice_each() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (mut route, config) = channel(dir.path(), Vec::new());
        switch_on(&route);
        // The route as a worker loads it: the roster, the master included.
        route.agents.push(ferryman_channel::AgentRoute {
            name: "josh".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(AgentIdentity::from_seed("josh", [9; 32]).public_key_hex()),
            encryption_key: None,
        });
        let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
        let mut order = Order {
            id: "improve-2026-w39-1".into(),
            project_id: "demo".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "x", "tags": [TAG], "improvement": { "title": "Name the engine" } }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        wisp.sign_order(&mut order);
        ferryman_channel::issue_order(&route, &order).unwrap();
        assert_eq!(
            request_merges(&route, &config).unwrap(),
            0,
            "nothing accepted yet"
        );
        let mut result = ferryman_channel::TaskResult {
            order_id: order.id.clone(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({
                "output": "done",
                "evidence": { "recorded_by": "worker", "git": true, "commits": ["abc1234 name the engine"] },
            }),
            signed_by: None,
            signature: None,
        };
        wisp.sign_result(&mut result);
        ferryman_channel::claim_order(&route, &order.id, "wisp").unwrap();
        ferryman_channel::submit_result(&route, &result).unwrap();
        let mut review = ferryman_channel::Review {
            order_id: order.id.clone(),
            revision: 1,
            reviewer: "wisp".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        wisp.sign_review(&mut review);
        assert!(
            ferryman_channel::submit_review(&route, &review).is_err(),
            "an agent never accepts an improvement"
        );
        let josh = AgentIdentity::from_seed("josh", [9; 32]);
        assert!(
            ferryman_channel::gate::decide(&route, &order.id, true, None, "josh", &josh).is_err(),
            "not before the review engine"
        );
        ferryman_channel::gate::record_engine_review(
            &route,
            &wisp,
            ferryman_channel::gate::EngineReview {
                order_id: order.id.clone(),
                revision: 1,
                reviewer: "wisp".into(),
                machine: "grouchly".into(),
                engine: "deepseek".into(),
                model: None,
                tier: "judge".into(),
                paid: "prepaid".into(),
                host: None,
                route: Vec::new(),
                accept: true,
                summary: "names the engine in every failure".into(),
                reviewed_at: Utc::now(),
                signed_by: None,
                signature: None,
            },
        )
        .unwrap();
        assert_eq!(request_merges(&route, &config).unwrap(), 0, "one key");
        ferryman_channel::gate::decide(&route, &order.id, true, None, "josh", &josh).unwrap();

        assert_eq!(request_merges(&route, &config).unwrap(), 1);
        assert_eq!(request_merges(&route, &config).unwrap(), 0, "asked once");
        let pending = ferryman_channel::questions::pending(&route);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, ferryman_channel::questions::MERGE);
        assert!(
            pending[0]
                .text
                .starts_with("Ready to merge: Name the engine")
        );
        assert!(
            pending[0].text.contains("holds both keys"),
            "{}",
            pending[0].text
        );
        assert_eq!(
            ferryman_channel::read_task(&route, &order.id)
                .unwrap()
                .state(),
            TaskState::Accepted,
            "a notice changes nothing"
        );
    }

    #[tokio::test]
    async fn a_second_plan_in_the_same_week_issues_nothing() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let judge = engine("claude", Tier::Judge, &format!("fake://ok:{PLAN}"));
        let (route, config) = channel(dir.path(), vec![judge]);
        let now = Utc::now();

        let first = plan(&route, &config, DEFAULT_MAX, now, &crate::Silent)
            .await
            .unwrap();
        let PlanOutcome::Planned {
            engine,
            unreviewed,
            orders,
            ..
        } = first
        else {
            panic!("expected a plan, got {first:?}")
        };
        assert_eq!(engine, "claude");
        assert!(!unreviewed, "a judge wrote it");
        assert_eq!(orders.len(), 2);
        let issued = improvements(&route);
        assert_eq!(issued.len(), 2);
        for task in &issued {
            assert_eq!(
                ferryman_channel::verify_order(&task.order, &route.agents),
                ferryman_channel::SignatureCheck::Valid
            );
            assert!(
                task.order.requires_review,
                "an improvement is always reviewed"
            );
            assert!(task.order.assigned_to.is_none(), "open to any worker");
            assert_eq!(task.order.payload["improvement"]["plan"], "judged");
        }
        assert!(
            week_dir(&route, &engines::iso_week(now))
                .join("evidence.md")
                .is_file()
        );

        let second = plan(&route, &config, DEFAULT_MAX, now, &crate::Silent)
            .await
            .unwrap();
        assert_eq!(
            second,
            PlanOutcome::AlreadyPlanned {
                orders: 2,
                issued: 0,
                verifications: 0
            }
        );
        assert_eq!(improvements(&route).len(), 2, "no duplicate orders");
    }

    #[tokio::test]
    async fn with_no_judge_up_a_builder_plans_and_the_plan_is_marked_unreviewed() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, mut config) = channel(
            dir.path(),
            vec![
                engine("claude", Tier::Judge, "fake://quota"),
                engine("nvidia", Tier::Build, &format!("fake://ok:{PLAN}")),
            ],
        );
        let now = Utc::now();
        let outcome = plan(&route, &config, 1, now, &crate::Silent).await.unwrap();
        assert!(
            matches!(&outcome, PlanOutcome::Planned { engine, unreviewed: true, orders, .. } if engine == "nvidia" && orders.len() == 1),
            "{outcome:?}"
        );
        assert!(
            engines::Ledger::load("wisp")
                .state("claude")
                .exhausted_until
                .is_some(),
            "the judge that ran out of credit is marked"
        );
        let issued = improvements(&route);
        assert_eq!(issued[0].order.payload["improvement"]["plan"], "unreviewed");
        assert!(
            issued[0].order.payload["task"]
                .as_str()
                .unwrap()
                .contains("UNREVIEWED PLAN")
        );

        // No judge up: review does nothing, and says so cheaply.
        assert_eq!(
            review(&route, &config, now, &crate::Silent).await.unwrap(),
            0
        );

        // The judge is back: it reads the plan nobody judged.
        engines::update("wisp", |ledger| {
            ledger.engines.remove("claude");
        });
        config.engines[0] = engine("claude", Tier::Judge, "fake://ok:keep both");
        assert_eq!(
            review(&route, &config, now, &crate::Silent).await.unwrap(),
            1
        );
        let week = engines::iso_week(now);
        assert!(week_dir(&route, &week).join("plan-review.md").is_file());
        assert!(!read_plan(&route, &week).unwrap().unreviewed);
    }

    #[tokio::test]
    async fn run_twice_does_the_week_once_and_nothing_while_paused() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let judge = engine("claude", Tier::Judge, &format!("fake://ok:{PLAN}"));
        let (route, config) = channel(dir.path(), vec![judge]);
        let targets = vec![(route.clone(), config)];
        let now = Utc::now();
        switch_on(&route);

        let marker = crate::governor::pause_marker().unwrap();
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, "testing the pause").unwrap();
        assert!(
            run(&targets, DEFAULT_MAX, now, &crate::Silent)
                .await
                .is_empty()
        );
        let _ = fs::remove_file(&marker);
        assert!(
            improvements(&route).is_empty(),
            "a paused machine plans nothing"
        );

        let first = run(&targets, DEFAULT_MAX, now, &crate::Silent).await;
        assert_eq!(first.len(), 3, "gathered, planned, reported: {first:?}");
        assert_eq!(improvements(&route).len(), 2);
        let last_week = engines::iso_week(now - Duration::days(7));
        assert!(week_dir(&route, &last_week).join("report.md").is_file());

        let second = run(&targets, DEFAULT_MAX, now, &crate::Silent).await;
        assert!(second.is_empty(), "nothing was due: {second:?}");
        assert_eq!(improvements(&route).len(), 2);
        let (week, steps) = last_run(&route.communications).unwrap();
        assert_eq!(week, engines::iso_week(now));
        assert_eq!(steps, vec!["evidence", "plan"]);
    }

    /// With no engine at all, a run still classes improvement results from their
    /// evidence and records the verdict, signed - and says so once, not every hour.
    #[tokio::test]
    async fn run_records_a_refuted_result_with_no_engine_up_and_reports_it_once() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = channel(dir.path(), Vec::new());
        let targets = vec![(route.clone(), config)];
        switch_on(&route);
        let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
        let mut order = Order {
            id: "improve-2026-w39-1".into(),
            project_id: "demo".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "x", "tags": [TAG], "improvement": { "title": "t" } }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        wisp.sign_order(&mut order);
        ferryman_channel::issue_order(&route, &order).unwrap();
        ferryman_channel::claim_order(&route, &order.id, "wisp").unwrap();
        let mut result = ferryman_channel::TaskResult {
            order_id: order.id.clone(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "better suited to 'claw'\n1. no output\n2. no output" }),
            signed_by: None,
            signature: None,
        };
        wisp.sign_result(&mut result);
        ferryman_channel::submit_result(&route, &result).unwrap();

        let first = run(&targets, DEFAULT_MAX, Utc::now(), &crate::Silent).await;
        assert_eq!(
            first
                .iter()
                .filter(|line| line.contains("improve-2026-w39-1 r1 by wisp refuted, not done"))
                .count(),
            1,
            "{first:?}"
        );
        let records = ferryman_channel::evidence::read_verifications(&route, &order.id);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, REFUTED);

        let second = run(&targets, DEFAULT_MAX, Utc::now(), &crate::Silent).await;
        assert!(
            !second.iter().any(|line| line.contains("refuted")),
            "{second:?}"
        );
        assert_eq!(
            ferryman_channel::evidence::read_verifications(&route, &order.id).len(),
            1,
            "recorded once"
        );
    }

    #[tokio::test]
    async fn run_passes_over_a_project_its_master_has_not_switched_on() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let judge = engine("claude", Tier::Judge, &format!("fake://ok:{PLAN}"));
        let (route, config) = channel(dir.path(), vec![judge]);
        let targets = vec![(route.clone(), config)];

        let done = run(&targets, DEFAULT_MAX, Utc::now(), &crate::Silent).await;

        assert!(done.is_empty(), "{done:?}");
        assert!(improvements(&route).is_empty());
        assert!(last_run(&route.communications).is_none(), "nothing written");
    }

    #[test]
    fn the_report_compares_the_week_with_the_one_before() {
        let start = Utc::now() - Duration::days(3);
        let run = |days: i64, ok: bool| Trajectory {
            order_id: "t".into(),
            agent: "wisp".into(),
            engine: "deepseek".into(),
            revision: 1,
            at: start + Duration::days(days),
            ok,
            prompt_digest: String::new(),
            output: String::new(),
            usage: Some(ferryman_channel::trajectory::TokenUsage {
                prompt_tokens: 1_000_000,
                completion_tokens: 0,
            }),
        };
        let runs = vec![run(0, true), run(1, false), run(-5, true)];
        let rates = ferryman_channel::cost::Rates::default();
        let this = numbers(&[], &runs, &rates, start);
        assert_eq!((this.runs, this.runs_ok), (2, 1));
        assert!(this.cost_usd.is_some_and(|cost| cost > 0.0));
        let last = numbers(&[], &runs, &rates, start - Duration::days(7));
        assert_eq!((last.runs, last.runs_ok), (1, 1));
    }

    /// An audit's PROBLEMS.md is read as claims. Each becomes a verification order, not
    /// an improvement; the planner never sees an unverified claim; a refuted claim is
    /// recorded and not raised again; only a confirmed one reaches the planner.
    #[tokio::test]
    async fn problems_md_claims_become_verification_orders_not_improvements() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let judge = engine("claude", Tier::Judge, &format!("fake://ok:{PLAN}"));
        let (route, config) = channel(dir.path(), vec![judge]);
        fs::write(
            route.workspace.join("PROBLEMS.md"),
            "# Audit\n\n## Missing admin check\ndeleteUser in src/admin.ts has no requireAdmin.\n\
             - Severity: high\n\n## Empty repository\nThe repo old-copy has no commits.\n",
        )
        .unwrap();
        fs::create_dir_all(route.workspace.join("src")).unwrap();
        fs::write(
            route.workspace.join("src").join("admin.ts"),
            "import { requireAdmin } from './auth';\nrouter.delete('/user', requireAdmin, deleteUser);\n",
        )
        .unwrap();
        let now = Utc::now();
        let week = engines::iso_week(now);

        let evidence = fs::read_to_string(gather(&route, now).unwrap()).unwrap();
        assert!(evidence.contains("[unverified-claims]"), "{evidence}");
        assert!(evidence.contains("Missing admin check - deleteUser in src/admin.ts"));
        assert!(
            !evidence.contains("Severity: high -"),
            "details are not claims"
        );
        let shown = planner_evidence(&evidence, &load_claims(&route), &week);
        assert!(
            !shown.contains("Missing admin check") && !shown.contains("unverified-claims"),
            "the planner never reads an unverified claim: {shown}"
        );

        let outcome = plan(&route, &config, DEFAULT_MAX, now, &crate::Silent)
            .await
            .unwrap();
        let PlanOutcome::Planned { verifications, .. } = &outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(verifications.len(), 2);
        let tasks = improvements(&route);
        let checks: Vec<&Task> = tasks
            .iter()
            .filter(|task| ferryman_channel::evidence::is_verification(&task.order.payload))
            .collect();
        assert_eq!(checks.len(), 2);
        assert_eq!(tasks.len(), 4, "two verifications and the plan's two");
        for task in &checks {
            let text = task.order.payload["task"].as_str().unwrap();
            assert!(text.contains("file:line") && text.contains("Do not change any files"));
            assert!(!ferryman_channel::evidence::requires_changes(
                &task.order.payload
            ));
            assert_eq!(
                ferryman_channel::verify_order(&task.order, &route.agents),
                ferryman_channel::SignatureCheck::Valid
            );
        }

        // A worker refutes the admin claim, citing the line, and confirms the other.
        let wisp = AgentIdentity::from_seed("wisp", [7; 32]);
        for task in &checks {
            let claim = task.order.payload["improvement"]["claim"].as_str().unwrap();
            let output = if claim.starts_with("Missing admin check") {
                r#"{"verdict": "refuted", "citations": ["src/admin.ts:2"], "reason": "requireAdmin is applied on the route"}"#
            } else {
                r#"{"verdict": "confirmed", "citations": ["src/admin.ts:1"], "reason": "no commits"}"#
            };
            let mut found = ferryman_channel::evidence::Evidence {
                recorded_by: "worker".into(),
                ..Default::default()
            };
            ferryman_channel::evidence::cite(&mut found, &route.workspace, output);
            let mut result = ferryman_channel::TaskResult {
                order_id: task.order.id.clone(),
                agent: "wisp".into(),
                revision: 1,
                submitted_at: Utc::now(),
                payload: json!({ "output": output, "evidence": found }),
                signed_by: None,
                signature: None,
            };
            wisp.sign_result(&mut result);
            ferryman_channel::claim_order(&route, &task.order.id, "wisp").unwrap();
            ferryman_channel::submit_result(&route, &result).unwrap();
            let mut review = ferryman_channel::Review {
                order_id: task.order.id.clone(),
                revision: 1,
                reviewer: "wisp".into(),
                reviewed_at: Utc::now(),
                accepted: true,
                notes: None,
                signed_by: None,
                signature: None,
            };
            wisp.sign_review(&mut review);
            ferryman_channel::submit_review(&route, &review).unwrap();
        }

        let next = now + Duration::days(7);
        let next_week = engines::iso_week(next);
        let evidence = fs::read_to_string(gather(&route, next).unwrap()).unwrap();
        assert!(
            evidence.contains("1 confirmed against the code; 1 refuted and not raised again"),
            "{evidence}"
        );
        assert!(!evidence.contains("[unverified-claims]"));
        let claims = load_claims(&route);
        let refuted: Vec<&Claim> = claims.values().filter(|c| c.status == REFUTED).collect();
        assert_eq!(refuted.len(), 1);
        assert!(refuted[0].text.starts_with("Missing admin check"));
        assert_eq!(refuted[0].citations, vec!["src/admin.ts:2".to_string()]);
        let shown = planner_evidence(&evidence, &claims, &next_week);
        assert!(shown.contains("## Confirmed findings") && shown.contains("Empty repository"));
        assert!(
            !shown.contains("Missing admin check"),
            "refuted: never planned from"
        );

        let outcome = plan(&route, &config, DEFAULT_MAX, next, &crate::Silent)
            .await
            .unwrap();
        assert!(
            matches!(&outcome, PlanOutcome::Planned { verifications, .. } if verifications.is_empty()),
            "the same file next week raises nothing again: {outcome:?}"
        );
        assert_eq!(
            load_claims(&route)
                .values()
                .find(|c| c.status == CONFIRMED)
                .and_then(|c| c.planned_in.clone()),
            Some(next_week)
        );
    }

    /// Josh archived btcpc, pc-agent-bridge and bullship-bridge: the loop leaves an
    /// archived project alone, and it cannot be switched back on while archived.
    #[tokio::test]
    async fn an_archived_project_is_skipped_and_cannot_be_switched_on() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let judge = engine("claude", Tier::Judge, &format!("fake://ok:{PLAN}"));
        let (route, config) = channel(dir.path(), vec![judge]);
        let targets = vec![(route.clone(), config.clone())];
        switch_on(&route);
        let josh = AgentIdentity::from_seed("josh", [9; 32]);
        assert!(
            ferryman_channel::ferry::set_archived(&route.communications, "demo", true, &josh)
                .unwrap()
        );

        assert!(!ferryman_channel::ferry::self_improve_enabled(
            &route.communications,
            "demo"
        ));
        let done = run(&targets, DEFAULT_MAX, Utc::now(), &crate::Silent).await;
        assert!(done.is_empty(), "{done:?}");
        assert_eq!(
            plan(&route, &config, DEFAULT_MAX, Utc::now(), &crate::Silent)
                .await
                .unwrap(),
            PlanOutcome::Archived
        );
        assert!(improvements(&route).is_empty());
        let error =
            ferryman_channel::ferry::set_self_improve(&route.communications, "demo", true, &josh)
                .unwrap_err();
        assert!(format!("{error:#}").contains("archived"), "{error:#}");

        // Brought back, it is on again: archiving did not rewrite the setting.
        assert!(
            ferryman_channel::ferry::set_archived(&route.communications, "demo", false, &josh)
                .unwrap()
        );
        assert!(ferryman_channel::ferry::self_improve_enabled(
            &route.communications,
            "demo"
        ));

        // Switched off while archived, it stays off when it is brought back.
        ferryman_channel::ferry::set_archived(&route.communications, "demo", true, &josh).unwrap();
        assert!(
            ferryman_channel::ferry::set_self_improve(&route.communications, "demo", false, &josh)
                .unwrap(),
            "off is written even though an archived project already reads as off"
        );
        ferryman_channel::ferry::set_archived(&route.communications, "demo", false, &josh).unwrap();
        assert!(!ferryman_channel::ferry::self_improve_enabled(
            &route.communications,
            "demo"
        ));
    }

    /// The audit file as an LLM really writes it (X:\pc-secrets\PROBLEMS.md): a title, a
    /// preamble, then one `##` section per finding with bold labels. Each section is one
    /// claim; the preamble is none. The file is found whatever its case.
    #[test]
    fn an_audit_file_is_read_one_claim_per_section_whatever_its_name_case() {
        let text = "# PROBLEMS.md - PC Secrets\n\nWritten by an AI audit pass on 2026-09-27 \
                    while building a knowledge vault.\nFindings came from reading the source.\n\n\
                    ## Live secret leak: posting key in plaintext\n**Severity:** SECURITY - fix \
                    this one first\n**What we found:** `ferryman.env` holds a posting key outside \
                    the encrypted tier.\n**Suggested fix:** Move it into the vault and rotate \
                    it.\n\n## Stale copy of the repo\n**What we found:** old-copy has no \
                    commits.\n";
        let claims = parse_claims(text);
        assert_eq!(claims.len(), 2, "{claims:?}");
        assert!(claims[0].starts_with("Live secret leak: posting key in plaintext - Severity:"));
        assert!(
            claims[0].contains("What we found: `ferryman.env`"),
            "{}",
            claims[0]
        );
        assert!(!claims.iter().any(|claim| claim.contains("AI audit pass")));
        assert!(claims[1].starts_with("Stale copy of the repo"));
        assert_ne!(claim_id(&claims[0]), claim_id(&claims[1]));
        assert_eq!(
            claim_id(&claims[0]),
            claim_id(&claims[0].to_uppercase()),
            "the same claim next week is the same claim"
        );

        // A flat list is read item by item.
        let flat = parse_claims("- the admin route has no auth check\n- tests are skipped on CI\n");
        assert_eq!(flat.len(), 2);

        let dir = tempfile::tempdir().unwrap();
        assert!(problems_file(dir.path()).is_none());
        fs::write(dir.path().join("Problems.md"), text).unwrap();
        fs::create_dir(dir.path().join("problems")).unwrap();
        let (name, read) = problems_file(dir.path()).unwrap();
        assert_eq!(name, "Problems.md");
        assert_eq!(read, text);
    }

    /// Only a subscription judge is configured: planning holds rather than spend it,
    /// records why once, and asks the master once - however often the loop runs.
    #[tokio::test]
    async fn planning_holds_on_a_subscription_and_asks_the_master_once() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let mut claude = engine("claude", Tier::Judge, &format!("fake://ok:{PLAN}"));
        claude.paid = Paid::Subscription;
        let (route, config) = channel(dir.path(), vec![claude]);
        switch_on(&route);
        let now = Utc::now();
        let week = engines::iso_week(now);

        for _ in 0..3 {
            let outcome = plan(&route, &config, DEFAULT_MAX, now, &crate::Silent)
                .await
                .unwrap();
            assert!(
                matches!(&outcome, PlanOutcome::Held(why) if why.contains("subscription")),
                "{outcome:?}"
            );
        }
        assert!(improvements(&route).is_empty(), "nothing fell back");
        assert!(read_plan(&route, &week).is_none());
        let asked = ferryman_channel::questions::pending(&route);
        assert_eq!(asked.len(), 1, "one question, not one an hour: {asked:?}");
        assert_eq!(asked[0].kind, ferryman_channel::questions::POLICY);
        assert_eq!(
            asked[0].options[0],
            ferryman_channel::policy::ACCEPT_RECOMMENDED
        );
        let steps = ferryman_channel::policy::read_steps(&route, &week);
        assert_eq!(steps.len(), 1, "{steps:?}");
        assert!(steps[0].outcome.starts_with("held: "));

        // The master lets it spend the subscription after all: it plans.
        let josh = AgentIdentity::from_seed("josh", [9; 32]);
        ferryman_channel::policy::set_policy(
            &route.communications,
            "demo",
            Some(Policy {
                protect_subscriptions: false,
                ..Policy::default()
            }),
            &josh,
        )
        .unwrap();
        let outcome = plan(&route, &config, DEFAULT_MAX, now, &crate::Silent)
            .await
            .unwrap();
        assert!(
            matches!(&outcome, PlanOutcome::Planned { engine, .. } if engine == "claude"),
            "{outcome:?}"
        );
    }

    /// The policy's order decides who plans and who reviews, `never` is never used, and
    /// each step is recorded with its engine, model and machine.
    #[tokio::test]
    async fn the_policy_picks_the_planner_and_the_judge_and_each_step_is_recorded() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let mut nemotron = engine("nemotron", Tier::Build, &format!("fake://ok:{PLAN}"));
        nemotron.paid = Paid::FreeTier;
        nemotron.model = Some("nvidia/nemotron-70b".into());
        let (route, mut config) = channel(
            dir.path(),
            vec![
                engine("claude", Tier::Judge, "fake://ok:should never be asked"),
                engine("deepseek", Tier::Judge, "fake://ok:keep both"),
                nemotron,
            ],
        );
        switch_on(&route);
        let josh = AgentIdentity::from_seed("josh", [9; 32]);
        let mut policy = Policy::default();
        policy.move_to_top("deepseek");
        policy.move_to_top("nemotron");
        policy.never.push("claude".into());
        ferryman_channel::policy::set_policy(&route.communications, "demo", Some(policy), &josh)
            .unwrap();
        let now = Utc::now();
        let week = engines::iso_week(now);

        let outcome = plan(&route, &config, 1, now, &crate::Silent).await.unwrap();
        assert!(
            matches!(&outcome, PlanOutcome::Planned { engine, unreviewed: true, .. } if engine == "nemotron"),
            "the operator's first choice plans, marked unreviewed as a builder: {outcome:?}"
        );
        // Review is a judge's: deepseek, never claude.
        assert_eq!(
            review(&route, &config, now, &crate::Silent).await.unwrap(),
            1
        );
        assert!(
            fs::read_to_string(week_dir(&route, &week).join("plan-review.md"))
                .unwrap()
                .contains("by deepseek")
        );
        let steps = ferryman_channel::policy::latest_steps(&route, &week);
        let plan_step = steps.iter().find(|s| s.step == "plan").unwrap();
        assert_eq!(plan_step.engine.as_deref(), Some("nemotron"));
        assert_eq!(plan_step.model.as_deref(), Some("nvidia/nemotron-70b"));
        assert_eq!(
            plan_step.machine,
            ferryman_channel::receipts::machine_label()
        );
        assert_eq!(plan_step.cost_usd, Some(0.0), "a free tier costs nothing");
        let review_step = steps.iter().find(|s| s.step == "review").unwrap();
        assert_eq!(review_step.engine.as_deref(), Some("deepseek"));
        let report = fs::read_to_string(self::report(&route, now).unwrap()).unwrap();
        assert!(report.contains("## Who did each step"), "{report}");
        assert!(
            report.contains("plan: nemotron (nvidia/nemotron-70b) on"),
            "{report}"
        );

        // A policy that names another machine: this one plans and reviews nothing.
        let elsewhere = Policy {
            machines: vec!["grouchly-only".into()],
            ..Policy::default()
        };
        ferryman_channel::policy::set_policy(&route.communications, "demo", Some(elsewhere), &josh)
            .unwrap();
        config.engines.truncate(2);
        let later = now + Duration::days(7);
        assert!(matches!(
            plan(&route, &config, 1, later, &crate::Silent)
                .await
                .unwrap(),
            PlanOutcome::NotHere(_)
        ));
        assert_eq!(
            review(&route, &config, later, &crate::Silent)
                .await
                .unwrap(),
            0
        );
    }

    /// A refuted result is never done: not in the report's done count, not a run that
    /// succeeded, and counted on a line of its own.
    #[test]
    fn the_report_never_counts_a_refuted_result_as_done() {
        let start = week_start(Utc::now());
        let at = start + Duration::hours(1);
        let order = |id: &str| ferryman_channel::Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "boss".into(),
            assigned_to: Some("ichabod".into()),
            created_at: at,
            payload: json!({ "task": "run the checks and paste the output" }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        let task = |id: &str, output: &str| Task {
            order: order(id),
            claims: Vec::new(),
            results: vec![ferryman_channel::TaskResult {
                order_id: id.into(),
                agent: "ichabod".into(),
                revision: 1,
                submitted_at: at,
                payload: json!({ "output": output }),
                signed_by: None,
                signature: None,
            }],
            reviews: Vec::new(),
            recommendations: Vec::new(),
            heartbeats: Vec::new(),
            releases: Vec::new(),
            kills: Vec::new(),
        };
        let tasks = vec![
            task(
                "fabricated",
                "better suited to 'deepseek'\n1. no output\n2. no output",
            ),
            task("real", "1. root 812 node bridge.js\n2. no output"),
        ];
        let run = |id: &str| Trajectory {
            order_id: id.into(),
            agent: "ichabod".into(),
            engine: "cline".into(),
            revision: 1,
            at,
            ok: true,
            prompt_digest: String::new(),
            output: String::new(),
            usage: None,
        };
        let runs = vec![run("fabricated"), run("real")];
        let week = numbers(
            &tasks,
            &runs,
            &ferryman_channel::cost::Rates::default(),
            start,
        );
        assert_eq!(week.done, 1, "{week:?}");
        assert_eq!(week.refuted, 1);
        assert_eq!((week.runs, week.runs_ok), (2, 1));
    }

    // --- auto-merge: low-risk work, after both keys, by the worker that built it -------

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=tester",
                "-c",
                "user.email=tester@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn josh() -> AgentIdentity {
        AgentIdentity::from_seed("josh", [9; 32])
    }

    fn wisp() -> AgentIdentity {
        AgentIdentity::from_seed("wisp", [7; 32])
    }

    /// The adversary: an agent that did not build the work, whose signed inventory lists qwen.
    fn fang() -> AgentIdentity {
        AgentIdentity::from_seed("fang", [5; 32])
    }

    /// A git workspace on `main` - a library, its tests, docs and a lockfile, with the
    /// channel inside it as on a real machine - josh its master and wisp its worker, and
    /// the engine policy auto-merging low-risk work when `auto`.
    fn merge_fixture(dir: &Path, auto: bool) -> (ProjectRoute, AgentConfig) {
        let (mut route, config) = channel(dir, Vec::new());
        switch_on(&route);
        route.agents.push(ferryman_channel::AgentRoute {
            name: "josh".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(josh().public_key_hex()),
            encryption_key: None,
        });
        let adversary = ferryman_channel::AgentRoute {
            name: "fang".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(fang().public_key_hex()),
            encryption_key: None,
        };
        ferryman_channel::register_agent(&route, &adversary).unwrap();
        route.agents.push(adversary);
        ferryman_channel::receipts::refresh_engines(
            &route,
            &fang(),
            "grouchly",
            "0.0.0",
            vec![ferryman_channel::receipts::EngineReport {
                name: "qwen".into(),
                kind: "http".into(),
                model: None,
                tier: "judge".into(),
                paid: "prepaid".into(),
                state: "up".into(),
                until: None,
                reason: None,
                latency_ms: None,
                balance: None,
                checked_at: None,
                trust: None,
                billing: None,
                class: None,
                capabilities: None,
            }],
            Utc::now(),
        )
        .unwrap();
        let repo = route.workspace.clone();
        git(&repo, &["init", "-q", "-b", "main"]);
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::create_dir_all(repo.join("tests")).unwrap();
        fs::write(repo.join(".gitignore"), ".ferryman/\n").unwrap();
        fs::write(
            repo.join("src/lib.rs"),
            "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n",
        )
        .unwrap();
        fs::write(repo.join("README.md"), "# demo\n").unwrap();
        fs::write(repo.join("tests/add.rs"), "#[test]\nfn adds() {}\n").unwrap();
        fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "base"]);
        if auto {
            assert!(
                ferryman_channel::policy::set_policy(
                    &route.communications,
                    &route.project_id,
                    Some(Policy {
                        auto_merge: ferryman_channel::policy::AutoMerge::LowRisk,
                        ..Policy::default()
                    }),
                    &josh(),
                )
                .unwrap()
            );
        }
        (route, config)
    }

    /// An improvement wisp built on its own branch, changing `files`, with its signed
    /// result naming the branch tip - and the review engine's key and the master's when
    /// asked for. Returns the tip.
    fn built(
        route: &ProjectRoute,
        id: &str,
        files: &[(&str, &str)],
        engine_key: bool,
        master_key: bool,
    ) -> String {
        built_with(route, id, files, engine_key, master_key, None)
    }

    /// [`built`] for an order that requires its result to carry what `result_contract` says.
    fn built_with(
        route: &ProjectRoute,
        id: &str,
        files: &[(&str, &str)],
        engine_key: bool,
        master_key: bool,
        result_contract: Option<ferryman_channel::contract::ResultContract>,
    ) -> String {
        let repo = route.workspace.clone();
        let branch = ferryman_channel::worktree::branch_name(id, "wisp");
        git(&repo, &["branch", &branch, "main"]);
        let dir = repo.parent().unwrap().join(format!("wt-{id}"));
        git(
            &repo,
            &["worktree", "add", "-q", dir.to_str().unwrap(), &branch],
        );
        for (path, text) in files {
            let path = dir.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-q", "-m", id]);
        let tip = git(&dir, &["rev-parse", "HEAD"]);
        git(
            &repo,
            &["worktree", "remove", "--force", dir.to_str().unwrap()],
        );

        let mut order = Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "x", "tags": [TAG], "improvement": { "title": format!("Improve {id}") } }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        };
        wisp().sign_order(&mut order);
        ferryman_channel::issue_order(route, &order).unwrap();
        ferryman_channel::claim_order(route, id, "wisp").unwrap();
        let mut result = ferryman_channel::TaskResult {
            order_id: id.into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({
                "output": "done",
                "worktree_head": tip,
                "evidence": { "recorded_by": "worker", "git": true, "commits": [format!("{} {id}", &tip[..7])] },
            }),
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        ferryman_channel::submit_result(route, &result).unwrap();
        if engine_key {
            ferryman_channel::gate::record_engine_review(
                route,
                &wisp(),
                ferryman_channel::gate::EngineReview {
                    order_id: id.into(),
                    revision: 1,
                    reviewer: "wisp".into(),
                    machine: "grouchly".into(),
                    engine: "deepseek".into(),
                    model: None,
                    tier: "judge".into(),
                    paid: "prepaid".into(),
                    host: None,
                    route: Vec::new(),
                    accept: true,
                    summary: "does what it says".into(),
                    reviewed_at: Utc::now(),
                    signed_by: None,
                    signature: None,
                },
            )
            .unwrap();
        }
        if master_key {
            let decided = ferryman_channel::gate::decide(route, id, true, None, "josh", &josh());
            assert_eq!(
                decided.is_ok(),
                engine_key,
                "the master's key only after the engine's: {decided:?}"
            );
        }
        tip
    }

    /// An authorization a peer wrote, whether or not anything earned it.
    fn forge_authorization(route: &ProjectRoute, id: &str, tip: &str) {
        ferryman_channel::automerge::record(
            route,
            &wisp(),
            ferryman_channel::automerge::MergeRecord {
                order_id: id.into(),
                revision: 1,
                status: ferryman_channel::automerge::AUTHORIZED.into(),
                branch: Some(ferryman_channel::worktree::branch_name(id, "wisp")),
                head: Some(tip.into()),
                into: None,
                commit: None,
                pushed: None,
                files: Vec::new(),
                note: "forged".into(),
                by: "wisp".into(),
                at: Utc::now(),
                signed_by: None,
                signature: None,
            },
        )
        .unwrap();
    }

    fn merges(route: &ProjectRoute, config: &AgentConfig) -> usize {
        crate::agent::merge_approved(route, config, &wisp(), &crate::Silent)
    }

    fn is_ancestor(repo: &Path, commit: &str, of: &str) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["merge-base", "--is-ancestor", commit, of])
            .status()
            .unwrap()
            .success()
    }

    /// Docs-only, tests-only and lockfile-only improvements merge on their own once they
    /// hold both keys and the policy says low-risk: by the worker that built them, beside
    /// the person's checkout, once each, and with nothing to ask the master.
    #[test]
    fn docs_tests_and_lockfile_improvements_merge_on_their_own_after_both_keys() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        // The person is working on another branch: the merge happens beside them.
        git(&repo, &["checkout", "-q", "-b", "wip"]);
        let docs = built(
            &route,
            "improve-2026-w40-1",
            &[
                ("README.md", "# demo\n\nHow to add.\n"),
                ("docs/guide.md", "Adding numbers.\n"),
            ],
            true,
            true,
        );
        let tests = built(
            &route,
            "improve-2026-w40-2",
            &[(
                "tests/add.rs",
                "#[test]\nfn adds() {}\n\n#[test]\nfn adds_zero() {}\n",
            )],
            true,
            true,
        );
        let lock = built(
            &route,
            "improve-2026-w40-3",
            &[("Cargo.lock", "version = 4\n")],
            true,
            true,
        );
        assert_eq!(
            request_merges(&route, &config).unwrap(),
            0,
            "authorized for the worker, not asked"
        );
        assert_eq!(merges(&route, &config), 3);
        for tip in [&docs, &tests, &lock] {
            assert!(is_ancestor(&repo, tip, "main"), "{tip} is on main");
        }
        let merged = ferryman_channel::automerge::merged(&route);
        assert_eq!(merged.len(), 3, "{merged:?}");
        assert!(
            merged
                .iter()
                .all(|record| record.into.as_deref() == Some("main") && record.pushed.is_none()),
            "{merged:?}"
        );
        assert_eq!(merges(&route, &config), 0, "merged once");
        assert_eq!(request_merges(&route, &config).unwrap(), 0);
        assert!(
            ferryman_channel::questions::pending(&route).is_empty(),
            "nothing to ask the master"
        );
        assert_eq!(
            git(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]),
            "wip",
            "the checkout is left as it was"
        );
    }

    /// A worker that pushes for the project pushes the merged default branch - plainly,
    /// never forced - and one that does not, does not.
    #[test]
    fn a_worker_that_pushes_pushes_the_merge() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, mut config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        let remote = dir.path().join("remote.git");
        git(
            dir.path(),
            &["init", "-q", "--bare", remote.to_str().unwrap()],
        );
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&repo, &["push", "-q", "origin", "main"]);
        config.push = Some("origin".to_string());
        let tip = built(
            &route,
            "improve-2026-w40-9",
            &[("docs/guide.md", "Adding numbers.\n")],
            true,
            true,
        );
        assert_eq!(request_merges(&route, &config).unwrap(), 0);
        assert_eq!(merges(&route, &config), 1);
        assert_eq!(
            git(&remote, &["rev-parse", "main"]),
            tip,
            "a fast-forward, pushed"
        );
        let merged = ferryman_channel::automerge::merged(&route);
        assert_eq!(merged[0].pushed.as_deref(), Some("origin"));
    }

    /// Code alongside docs is not low risk: it stops at "approved, ready to merge" and
    /// the master is told why.
    #[test]
    fn code_with_docs_does_not_merge_on_its_own() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        let main = git(&repo, &["rev-parse", "main"]);
        built(
            &route,
            "improve-2026-w40-4",
            &[
                ("README.md", "# demo\n\nNow wrapping.\n"),
                (
                    "src/lib.rs",
                    "pub fn add(a: u32, b: u32) -> u32 {\n    a.wrapping_add(b)\n}\n",
                ),
            ],
            true,
            true,
        );
        assert_eq!(request_merges(&route, &config).unwrap(), 0);
        assert_eq!(merges(&route, &config), 0);
        assert_eq!(git(&repo, &["rev-parse", "main"]), main, "main untouched");
        let pending = ferryman_channel::questions::pending(&route);
        assert_eq!(pending.len(), 1, "the master is asked instead");
        assert!(
            pending[0]
                .text
                .contains("did not merge this one on its own")
                && pending[0].text.contains("src/lib.rs"),
            "{}",
            pending[0].text
        );
    }

    /// One key is never enough - not even with an authorization a peer wrote for it -
    /// and a policy that does not say low-risk merges nothing, keys or not.
    #[test]
    fn one_key_or_auto_merge_off_never_merges() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        let main = git(&repo, &["rev-parse", "main"]);
        let docs = [("README.md", "# demo\n\nMore.\n")];
        let engine_only = built(&route, "improve-2026-w40-5", &docs, true, false);
        // The master alone cannot even give the key: approval needs the engine's first.
        let master_only = built(&route, "improve-2026-w40-6", &docs, false, true);
        forge_authorization(&route, "improve-2026-w40-5", &engine_only);
        forge_authorization(&route, "improve-2026-w40-6", &master_only);
        assert_eq!(request_merges(&route, &config).unwrap(), 0);
        assert_eq!(merges(&route, &config), 0);
        assert_eq!(git(&repo, &["rev-parse", "main"]), main);

        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), false);
        let repo = route.workspace.clone();
        let main = git(&repo, &["rev-parse", "main"]);
        let both = built(&route, "improve-2026-w40-7", &docs, true, true);
        forge_authorization(&route, "improve-2026-w40-7", &both);
        assert_eq!(merges(&route, &config), 0, "auto_merge = none");
        assert_eq!(git(&repo, &["rev-parse", "main"]), main);
        assert_eq!(
            request_merges(&route, &config).unwrap(),
            1,
            "the master merges it, as ever"
        );
    }

    /// A merge that does not apply cleanly is aborted, leaves main as it was, and falls
    /// back to the master with the reason.
    #[test]
    fn a_failed_merge_falls_back_to_the_master() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        built(
            &route,
            "improve-2026-w40-8",
            &[("README.md", "# demo\n\nFrom the branch.\n")],
            true,
            true,
        );
        // main moved on meanwhile, in the same lines.
        fs::write(repo.join("README.md"), "# demo\n\nFrom main.\n").unwrap();
        git(&repo, &["commit", "-q", "-am", "main moves on"]);
        let main = git(&repo, &["rev-parse", "main"]);
        assert_eq!(request_merges(&route, &config).unwrap(), 0);
        assert_eq!(merges(&route, &config), 0);
        assert_eq!(git(&repo, &["rev-parse", "main"]), main);
        assert!(
            git(&repo, &["status", "--porcelain", "--untracked-files=no"]).is_empty(),
            "the conflict was aborted"
        );
        match ferryman_channel::automerge::stage(&route, "improve-2026-w40-8", 1) {
            ferryman_channel::automerge::Stage::Held(record) => {
                assert!(record.note.contains("the merge failed"), "{}", record.note);
            }
            other => panic!("not held: {other:?}"),
        }
        let pending = ferryman_channel::questions::pending(&route);
        assert_eq!(pending.len(), 1);
        assert!(
            pending[0].text.contains("the merge failed"),
            "{}",
            pending[0].text
        );
    }

    /// Auto-merge never carries an adversary Block nobody answered, in any mode: the work
    /// is announced to the master as a manual merge that says so, nothing is authorized,
    /// and an authorization a peer wrote does not merge it either - until the master
    /// overrides the Block.
    #[test]
    fn auto_merge_refuses_a_revision_with_an_unresolved_adversary_block_until_it_is_overridden() {
        use ferryman_channel::adversary::{
            self, AdversaryFinding, Issue, Severity, Trigger, Verdict,
        };
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        let main = git(&repo, &["rev-parse", "main"]);
        let id = "improve-2026-w40-9";
        let tip = built(
            &route,
            id,
            &[("README.md", "# demo\n\nMore.\n")],
            true,
            true,
        );
        adversary::record(
            &route,
            &fang(),
            AdversaryFinding {
                order_id: id.into(),
                revision: 1,
                trigger: Trigger::PreDone,
                subject: id.into(),
                engine: "qwen".into(),
                model: None,
                machine: "grouchly".into(),
                same_engine: false,
                verdict: Verdict::Block,
                findings: vec![Issue {
                    severity: Severity::High,
                    title: "the docs claim a flag that does not exist".into(),
                    detail: "README.md".into(),
                    location: None,
                }],
                created_at: Utc::now(),
                result_digest: String::new(),
                signed_by: String::new(),
                signature: String::new(),
            },
        )
        .unwrap();

        // Advisory (the default) did not stop the keys, but it stops the machine merging.
        assert_eq!(
            request_merges(&route, &config).unwrap(),
            1,
            "the master is asked"
        );
        assert!(matches!(
            ferryman_channel::automerge::stage(&route, id, 1),
            ferryman_channel::automerge::Stage::Open
        ));
        let pending = ferryman_channel::questions::pending(&route);
        assert_eq!(pending.len(), 1);
        assert!(
            pending[0].text.contains("the adversary blocked it"),
            "{}",
            pending[0].text
        );
        // Even an authorization a peer wrote does not make the worker merge it.
        forge_authorization(&route, id, &tip);
        assert_eq!(merges(&route, &config), 0);
        assert_eq!(git(&repo, &["rev-parse", "main"]), main, "main untouched");
        let tasks = ferryman_channel::list_tasks(&route).unwrap();
        let (policy, _) =
            ferryman_channel::policy::effective(&route.communications, &route.project_id);
        let error = ferryman_channel::automerge::authorize(&route, &wisp(), &tasks[0])
            .unwrap_err()
            .to_string();
        assert!(error.contains("unresolved adversary Block"), "{error}");
        assert!(adversary::unresolved_block(&route, &policy, id, 1).is_some());

        // The master overrides it: now it is an ordinary low-risk merge.
        let seen = adversary::finding_seen(&route, id, 1, Trigger::PreDone);
        adversary::override_block(
            &route,
            id,
            1,
            Trigger::PreDone,
            &seen,
            Some("docs only"),
            "josh",
            &josh(),
        )
        .unwrap();
        assert!(adversary::unresolved_block(&route, &policy, id, 1).is_none());
        assert_eq!(merges(&route, &config), 1);
        assert_ne!(git(&repo, &["rev-parse", "main"]), main, "merged");
    }

    /// A result that breaks its order's contract is not merged on its own, whatever else
    /// says yes: the master's click is refused, the engine's key does not count, and an
    /// authorization a peer wrote for it merges nothing.
    #[test]
    fn auto_merge_never_carries_a_result_that_breaks_its_orders_contract() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let repo = route.workspace.clone();
        let main = git(&repo, &["rev-parse", "main"]);
        let id = "improve-2026-w40-12";
        let tip = built_with(
            &route,
            id,
            &[("README.md", "# demo\n\nMore.\n")],
            false,
            false,
            Some(ferryman_channel::contract::ResultContract {
                required: vec!["summary".into()],
                schema: None,
            }),
        );
        ferryman_channel::gate::record_engine_review(
            &route,
            &wisp(),
            ferryman_channel::gate::EngineReview {
                order_id: id.into(),
                revision: 1,
                reviewer: "wisp".into(),
                machine: "grouchly".into(),
                engine: "deepseek".into(),
                model: None,
                tier: "judge".into(),
                paid: "prepaid".into(),
                host: None,
                route: Vec::new(),
                accept: true,
                summary: "does what it says".into(),
                reviewed_at: Utc::now(),
                signed_by: None,
                signature: None,
            },
        )
        .unwrap();
        let error =
            ferryman_channel::gate::decide(&route, id, true, None, "josh", &josh()).unwrap_err();
        assert!(
            format!("{error:#}").contains("breaks the order's contract")
                || format!("{error:#}").contains("review engine has not reviewed it"),
            "{error:#}"
        );
        forge_authorization(&route, id, &tip);
        let tasks = ferryman_channel::list_tasks(&route).unwrap();
        assert!(ferryman_channel::automerge::authorize(&route, &wisp(), &tasks[0]).is_err());
        assert_eq!(merges(&route, &config), 0);
        assert_eq!(git(&repo, &["rev-parse", "main"]), main, "main untouched");
    }
    /// In `blocking` mode auto-merge fails closed: both keys are not enough until an eligible
    /// adversary - one that did not build the work - has read exactly this revision. The
    /// builder's own Pass does not count.
    #[test]
    fn auto_merge_in_blocking_mode_waits_for_an_adversary_that_did_not_build_the_work() {
        use ferryman_channel::adversary::{self, AdversaryFinding, Trigger, Verdict};
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let id = "improve-2026-w40-11";
        built(
            &route,
            id,
            &[("README.md", "# demo\n\nMore.\n")],
            true,
            true,
        );
        assert!(
            ferryman_channel::policy::set_policy(
                &route.communications,
                &route.project_id,
                Some(Policy {
                    auto_merge: ferryman_channel::policy::AutoMerge::LowRisk,
                    adversary: ferryman_channel::policy::AdversaryMode::Blocking,
                    ..Policy::default()
                }),
                &josh(),
            )
            .unwrap()
        );
        let pass = |engine: &str| AdversaryFinding {
            order_id: id.into(),
            revision: 1,
            trigger: Trigger::PreDone,
            subject: id.into(),
            engine: engine.into(),
            model: None,
            machine: "grouchly".into(),
            same_engine: false,
            verdict: Verdict::Pass,
            findings: Vec::new(),
            created_at: Utc::now(),
            result_digest: String::new(),
            signed_by: String::new(),
            signature: String::new(),
        };
        let tasks = ferryman_channel::list_tasks(&route).unwrap();
        // No adversary has read it: nothing is authorized, and nothing merges.
        let error = ferryman_channel::automerge::authorize(&route, &wisp(), &tasks[0])
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not hold both keys"), "{error}");
        assert_eq!(merges(&route, &config), 0);
        // The builder's own Pass is not an adversary's.
        adversary::record(&route, &wisp(), pass("qwen")).unwrap();
        assert!(ferryman_channel::automerge::authorize(&route, &wisp(), &tasks[0]).is_err());
        // An agent that did not build it, with a signed inventory listing the engine, reads it.
        adversary::record(&route, &fang(), pass("qwen")).unwrap();
        assert!(ferryman_channel::automerge::authorize(&route, &wisp(), &tasks[0]).is_ok());
    }

    /// With the adversary off, a Block on file means nothing to auto-merge.
    #[test]
    fn an_off_adversary_does_not_hold_back_auto_merge() {
        use ferryman_channel::adversary::{self, AdversaryFinding, Trigger, Verdict};
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = merge_fixture(dir.path(), true);
        let id = "improve-2026-w40-10";
        let tip = built(
            &route,
            id,
            &[("README.md", "# demo\n\nMore.\n")],
            true,
            true,
        );
        adversary::record(
            &route,
            &fang(),
            AdversaryFinding {
                order_id: id.into(),
                revision: 1,
                trigger: Trigger::PreDone,
                subject: id.into(),
                engine: "qwen".into(),
                model: None,
                machine: "grouchly".into(),
                same_engine: false,
                verdict: Verdict::Block,
                findings: Vec::new(),
                created_at: Utc::now(),
                result_digest: String::new(),
                signed_by: String::new(),
                signature: String::new(),
            },
        )
        .unwrap();
        assert!(
            ferryman_channel::policy::set_policy(
                &route.communications,
                &route.project_id,
                Some(Policy {
                    auto_merge: ferryman_channel::policy::AutoMerge::LowRisk,
                    adversary: ferryman_channel::policy::AdversaryMode::Off,
                    ..Policy::default()
                }),
                &josh(),
            )
            .unwrap()
        );
        forge_authorization(&route, id, &tip);
        assert_eq!(merges(&route, &config), 1);
    }
}

//! The weekly improvement loop: every project a little better every week, without
//! anyone asking for each change.
//!
//! ```text
//! <channel>/improve/2026-W39/
//!   evidence.md    what the last seven days recorded           (ferry improve gather)
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
//! reviewed. Nothing here merges, pushes to a main branch or bumps a version: accepted
//! work is listed as ready, and a person merges it.
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
    },
    Planned {
        engine: String,
        unreviewed: bool,
        orders: Vec<String>,
    },
    /// No engine could plan. Not an error: the next run tries again.
    NoEngine(String),
    Paused(String),
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
         Reply with exactly one JSON object and nothing else:\n\
         {{\"improvements\": [{{\"title\": \"...\", \"why\": \"...\", \
         \"acceptance\": [\"...\"]}}]}}\n\n---\n\n{evidence}"
    )
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

/// The engines to ask, best first: judges that are up, then builders (whose answer is
/// marked unreviewed). Exhausted engines are left out.
fn askers<'a>(
    specs: &'a [EngineSpec],
    ledger: &engines::Ledger,
    now: DateTime<Utc>,
    tried: &[String],
) -> Option<(&'a EngineSpec, bool)> {
    let left: Vec<EngineSpec> = specs
        .iter()
        .filter(|spec| !tried.contains(&spec.name))
        .cloned()
        .collect();
    let chosen = engines::best_up(&left, ledger, now, Tier::Judge)
        .map(|spec| (spec.name.clone(), false))
        .or_else(|| {
            engines::best_up(&left, ledger, now, Tier::Build).map(|spec| (spec.name.clone(), true))
        })?;
    specs
        .iter()
        .find(|spec| spec.name == chosen.0)
        .map(|spec| (spec, chosen.1))
}

/// Ask the best engine available, falling through engines that are out of credit or
/// fail. Returns the answer, the engine, and whether it was a judge.
async fn ask_best(
    route: &ProjectRoute,
    config: &AgentConfig,
    prompt: &str,
    judges_only: bool,
    report: &dyn Progress,
) -> Option<(String, EngineSpec, bool)> {
    let mut tried = Vec::new();
    loop {
        let ledger = engines::Ledger::load(&config.agent);
        let (engine, unreviewed) = askers(&config.engines, &ledger, Utc::now(), &tried)?;
        if judges_only && unreviewed {
            return None;
        }
        let engine = engine.clone();
        tried.push(engine.name.clone());
        match crate::agent::ask(route, &config.with_engine(&engine), prompt).await {
            Ok(answer) => return Some((answer, engine, !unreviewed)),
            Err(error) => {
                if let Some(skip) = error.downcast_ref::<engines::Unavailable>()
                    && let Some(until) = skip.until
                {
                    engines::mark_exhausted(&config.agent, &skip.engine, until, &skip.reason);
                }
                report.warn(&format!(
                    "  {}: {} could not answer, trying the next engine: {error:#}",
                    route.project_id, engine.name
                ));
            }
        }
    }
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
    if let Some(existing) = read_plan(route, &week) {
        let identity = signing_identity(route, config)?;
        let issued = issue_missing(route, config, &identity, &existing)?;
        return Ok(PlanOutcome::AlreadyPlanned {
            orders: existing.orders.len(),
            issued,
        });
    }
    if let Some(why) = paused() {
        return Ok(PlanOutcome::Paused(why));
    }
    let identity = signing_identity(route, config)?;
    let evidence_path = week_dir(route, &week).join("evidence.md");
    if !evidence_path.is_file() {
        gather(route, now)?;
    }
    let evidence = fs::read_to_string(&evidence_path)
        .with_context(|| format!("read {}", evidence_path.display()))?;
    let max = max.max(1);
    let Some((answer, engine, judged)) = ask_best(
        route,
        config,
        &plan_prompt(&route.project_id, &evidence, max),
        false,
        report,
    )
    .await
    else {
        return Ok(PlanOutcome::NoEngine(
            engines::all_exhausted(&config.engines, &engines::Ledger::load(&config.agent), now)
                .unwrap_or_else(|| "no judge- or build-tier engine answered".to_string()),
        ));
    };
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
    Ok(PlanOutcome::Planned {
        engine: engine.name,
        unreviewed: plan.unreviewed,
        orders: plan.orders,
    })
}

// --- review -----------------------------------------------------------------------------

fn awaiting_improvement_review(route: &ProjectRoute) -> bool {
    ferryman_channel::list_tasks(route)
        .unwrap_or_default()
        .iter()
        .any(|task| {
            is_improvement(task)
                && matches!(task.state(), TaskState::AwaitingReview { .. })
                && task.pending_recommendation().is_none()
        })
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
    let ledger = engines::Ledger::load(&config.agent);
    let Some(judge) = engines::best_up(&config.engines, &ledger, now, Tier::Judge).cloned() else {
        report.info(&format!(
            "  {}: no judge-tier engine is up; review waits",
            route.project_id
        ));
        return Ok(0);
    };
    let mut judged = 0;

    let week = engines::iso_week(now);
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
        match crate::agent::ask(route, &config.with_engine(&judge), &prompt).await {
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
            Err(error) => return Ok(settle(config, &error, judged, route, report)),
        }
    }

    if awaiting_improvement_review(route) {
        match crate::agent::review_where(route, &config.with_engine(&judge), report, is_improvement)
            .await
        {
            Ok(count) => judged += count,
            Err(error) => return Ok(settle(config, &error, judged, route, report)),
        }
    }
    Ok(judged)
}

/// A judge that failed mid-review: mark it if it ran out of credit, say so, keep what
/// was done.
fn settle(
    config: &AgentConfig,
    error: &anyhow::Error,
    judged: usize,
    route: &ProjectRoute,
    report: &dyn Progress,
) -> usize {
    if let Some(skip) = error.downcast_ref::<engines::Unavailable>()
        && let Some(until) = skip.until
    {
        engines::mark_exhausted(&config.agent, &skip.engine, until, &skip.reason);
    }
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
    WeekNumbers {
        done: tasks
            .iter()
            .filter(|task| finished_at(task).is_some_and(within))
            .count(),
        runs: runs.iter().filter(|run| within(run.at)).count(),
        runs_ok: runs.iter().filter(|run| run.ok && within(run.at)).count(),
        reviews: reviews.len(),
        sent_back: reviews.iter().filter(|review| !review.accepted).count(),
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
        if matches!(state, TaskState::Accepted) || advised {
            ready.push(format!(
                "- `{}` on `{branch}`{}: {}",
                task.order.id,
                if advised {
                    " (a reviewer recommends it; confirm with 'ferry channel review')"
                } else {
                    ""
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
        "Reviewed and accepted. Nothing here merges by itself; a person merges it.\n"
    );
    if ready.is_empty() {
        let _ = writeln!(md, "Nothing yet.");
    }
    for line in ready {
        let _ = writeln!(md, "{line}");
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
        let dir = week_dir(route, &week);
        if !dir.join("evidence.md").is_file() {
            match gather(route, now) {
                Ok(_) => done.push(format!("{project}: gathered {week}")),
                Err(error) => report.warn(&format!("{project}: gather failed: {error:#}")),
            }
        }
        if !dir.join("plan.json").is_file() {
            match plan(route, config, max, now, report).await {
                Ok(PlanOutcome::Planned {
                    engine,
                    unreviewed,
                    orders,
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
        let judge_up = engines::best_up(
            &config.engines,
            &engines::Ledger::load(&config.agent),
            now,
            Tier::Judge,
        )
        .is_some();
        if judge_up && (plan_unreviewed || awaiting_improvement_review(route)) {
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
                issued: 0
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
            matches!(&outcome, PlanOutcome::Planned { engine, unreviewed: true, orders } if engine == "nvidia" && orders.len() == 1),
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
}

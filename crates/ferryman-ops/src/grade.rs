//! Grading finished improvements with a second engine, and counting failing grades
//! against the engines that planned and built them. See [`ferryman_channel::grades`].
//!
//! Each improve pass grades at most [`MAX_PER_PASS`] improvements that were accepted or
//! done and have no grade yet. The grader is chosen by the engine policy for review work,
//! with the engine that built the improvement ruled out: no engine grades its own work,
//! and with no other engine up the improvement waits for one. The grader is told what
//! the order promised, what the worker recorded (commits, diff, checks that ran) and the
//! diff itself when this machine has the commits, and answers whether anything
//! objectively improved and what it was worth.
//!
//! Every machine then reads the project's grades and, for each failing one it has not
//! counted yet, counts a refuted result against its own engine that built the work (for
//! that kind of work, which the smart router learns from) and against its own engine
//! that planned it. So an engine whose "improvements" are not objective improvements
//! loses trust exactly as one whose work is refuted by its own evidence does, and is
//! demoted to chore work after enough of them.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::{DateTime, Utc};
use ferryman_channel::{
    ProjectRoute, Task, TaskResult, TaskState,
    evidence::{Evidence, Status},
    grades::{self, Grade},
    policy::{Role, Work},
    router,
};
use serde_json::Value;

use crate::{
    Progress,
    agent::AgentConfig,
    engines::{self, Tier},
    improve,
};

/// Improvements graded per project per pass, so grading never eats the day's budget.
pub const MAX_PER_PASS: usize = 3;
/// The most of a diff the grader is shown.
const MAX_DIFF_CHARS: usize = 12_000;
/// The most of the worker's answer the grader is shown.
const MAX_ANSWER_CHARS: usize = 3_000;

fn clip(text: &str, chars: usize) -> String {
    let count = text.chars().count();
    if count <= chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(chars).collect();
    out.push_str(&format!(
        "\n[... {} more characters not shown]",
        count - chars
    ));
    out
}

/// The engine that built a result, as its worker recorded it.
fn builder(result: &TaskResult) -> Option<String> {
    result
        .payload
        .get("engine")
        .and_then(Value::as_str)
        .filter(|engine| !engine.is_empty())
        .map(str::to_string)
}

/// The kind of work a result was routed as, when it says.
fn kind(result: &TaskResult) -> Option<String> {
    result
        .payload
        .get("routing")
        .and_then(|routing| routing.get("kind"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Improvements finished and not graded yet, oldest first: (task, its newest result).
#[must_use]
pub fn ungraded(route: &ProjectRoute, now: DateTime<Utc>) -> Vec<(Task, TaskResult)> {
    let mut found: Vec<(Task, TaskResult)> = ferryman_channel::list_tasks(route)
        .unwrap_or_default()
        .into_iter()
        .filter(improve::is_improvement)
        .filter(|task| matches!(task.state_at(now), TaskState::Accepted | TaskState::Done))
        .filter_map(|task| {
            let revision = task.latest_revision()?;
            let result = task
                .results
                .iter()
                .rev()
                .find(|result| result.revision == revision)?
                .clone();
            builder(&result)?;
            (!grades::exists(route, &task.order.id, revision)).then_some((task, result))
        })
        .collect();
    found.sort_by_key(|(_, result)| result.submitted_at);
    found
}

/// The diff a result's commits made, when this machine has them.
fn diff(workspace: &Path, evidence: &Evidence) -> Option<String> {
    let (before, after) = (
        evidence.head_before.as_deref()?,
        evidence.head_after.as_deref()?,
    );
    if before == after {
        return None;
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["diff", "--no-color", before, after])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).to_string())
        .filter(|text| !text.trim().is_empty())
}

/// What the grader is asked.
#[must_use]
pub fn prompt(project: &str, task: &Task, result: &TaskResult, diff: Option<&str>) -> String {
    let improvement = task.order.payload.get("improvement");
    let field = |name: &str| {
        improvement
            .and_then(|value| value.get(name))
            .map(|value| match value {
                Value::String(text) => text.clone(),
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|item| format!("- {item}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    let evidence = ferryman_channel::evidence::of(&task.order.payload, result);
    let mut recorded = String::new();
    if let Some(evidence) = &evidence {
        recorded.push_str(&format!("- {}\n", evidence.describe()));
        for commit in &evidence.commits {
            recorded.push_str(&format!("- commit {commit}\n"));
        }
        if let Some(stat) = &evidence.diff_stat {
            recorded.push_str(&format!("- diff: {stat}\n"));
        }
        for check in &evidence.checks {
            recorded.push_str(&format!(
                "- check `{}` exited {}\n",
                check.command,
                check
                    .exit_code
                    .map_or_else(|| "without a code".to_string(), |code| code.to_string())
            ));
        }
    }
    if recorded.is_empty() {
        recorded.push_str("- nothing recorded\n");
    }
    let answer = result
        .payload
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or_default();
    format!(
        "You are grading one finished improvement to the project '{project}'. Another \
         engine built it; you did not. Judge only what the record and the diff show, not \
         what the answer claims.\n\n\
         An objective improvement makes something measurably better: a test that failed \
         and now passes, a bug that was reproduced and is fixed, a number that moved \
         (speed, size, memory, error rate), a failure that can no longer happen, a check \
         that now runs and passes. Rewording, renaming, reformatting, comments, notes and \
         documentation that change nothing anyone can measure are NOT objective \
         improvements, however tidy they are. Work that does not do what the order \
         promised is not an improvement either.\n\n\
         Reply with exactly one JSON object and nothing else:\n\
         {{\"objective\": true or false, \"score\": 0-10 (how much it was worth; 0 when not \
         objective), \"why\": \"what objectively improved, or why nothing did, in one or \
         two sentences\", \"lesson\": \"one sentence the next planner should take from \
         this\"}}\n\n\
         ## What was ordered\n\nTitle: {title}\n\nWhy: {why}\n\nDone when:\n{acceptance}\n\n\
         ## What the worker recorded\n\n{recorded}\n## The worker's answer\n\n{answer}\n\n\
         ## The diff\n\n{diff}\n",
        title = improve::task_title(task),
        why = field("why"),
        acceptance = field("acceptance"),
        answer = clip(answer, MAX_ANSWER_CHARS),
        diff = diff.map_or_else(
            || "(not on this machine: judge from the record above)".to_string(),
            |diff| format!("```diff\n{}\n```", clip(diff, MAX_DIFF_CHARS)),
        ),
    )
}

/// A grader's answer: (objective, score, why, lesson). `None` when it is not the JSON
/// asked for. A score is clamped to 0-10, and an answer that says the work was not
/// objective scores 0 whatever number it gave.
#[must_use]
pub fn parse(answer: &str) -> Option<(bool, u8, String, String)> {
    let value = improve::extract_json(answer, "objective")?;
    let objective = value.get("objective")?.as_bool()?;
    let score = value.get("score")?.as_f64()?.round().clamp(0.0, 10.0) as u8;
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .chars()
            .take(400)
            .collect::<String>()
    };
    Some((
        objective,
        if objective { score } else { 0 },
        text("why"),
        text("lesson"),
    ))
}

/// Grade up to [`MAX_PER_PASS`] finished improvements with an engine that did not build
/// them. Returns a line per grade.
pub async fn pass(
    route: &ProjectRoute,
    config: &AgentConfig,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> Vec<String> {
    let mut lines = Vec::new();
    if crate::governor::paused().is_some() {
        return lines;
    }
    let waiting = ungraded(route, now);
    if waiting.is_empty() {
        return lines;
    }
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    if improve::here(route, config, &policy).is_err() {
        return lines;
    }
    let week = engines::iso_week(now);
    if let Some(why) = ferryman_channel::policy::over_cap(route, &policy, &week, Role::Review) {
        report.info(&format!("  {}: grading waits: {why}", route.project_id));
        return lines;
    }
    let Ok(identity) = improve::signing_identity(route, config) else {
        return lines;
    };
    let machine = ferryman_channel::receipts::machine_label();
    for (task, result) in waiting.into_iter().take(MAX_PER_PASS) {
        let Some(built_by) = builder(&result) else {
            continue;
        };
        let ledger = engines::Ledger::load(&config.agent);
        let chosen = engines::choose_routed(
            &config.engines,
            &ledger,
            now,
            &policy,
            (Role::Review, Tier::Judge, Work::Background),
            &router::needs_for_role(Role::Review),
            (&[], std::slice::from_ref(&built_by)),
            (&config.agent, &machine),
        );
        let grader = match chosen {
            Ok((grader, _)) if !grader.name.eq_ignore_ascii_case(&built_by) => grader,
            _ => {
                report.info(&format!(
                    "  {}: {} waits for an engine other than {built_by} to grade it",
                    route.project_id, task.order.id
                ));
                continue;
            }
        };
        let evidence = ferryman_channel::evidence::of(&task.order.payload, &result);
        let diff = evidence
            .as_ref()
            .and_then(|evidence| diff(&route.workspace, evidence));
        let asked = crate::agent::ask(
            route,
            &config.with_engine_effort(&grader, Some(policy.effort_for(Role::Review))),
            &prompt(&route.project_id, &task, &result, diff.as_deref()),
        )
        .await;
        let answer = match asked {
            Ok(answer) => answer,
            Err(error) => {
                report.warn(&format!(
                    "  {}: {} could not grade {}: {error:#}",
                    route.project_id, grader.name, task.order.id
                ));
                break;
            }
        };
        let Some((objective, score, why, lesson)) = parse(&answer) else {
            report.warn(&format!(
                "  {}: {} answered, but not with the grade asked for; {} waits",
                route.project_id, grader.name, task.order.id
            ));
            continue;
        };
        let plan = task
            .order
            .payload
            .get("improvement")
            .and_then(|improvement| improvement.get("week"))
            .and_then(Value::as_str)
            .and_then(|week| improve::read_plan(route, week));
        let grade = Grade {
            order_id: task.order.id.clone(),
            revision: result.revision,
            project_id: route.project_id.clone(),
            title: improve::task_title(&task),
            worker: result.agent.clone(),
            engine: built_by,
            kind: kind(&result),
            planner: plan.as_ref().map(|plan| plan.engine.clone()),
            planner_agent: plan.and_then(|plan| plan.planned_by_agent),
            grader: grader.name.clone(),
            objective,
            score,
            why,
            lesson,
            graded_at: now,
            signed_by: String::new(),
            signature: String::new(),
        };
        match grades::record(route, &identity, grade.clone()) {
            Ok(true) => lines.push(format!(
                "{}: {} graded {}/10{} by {} (built by {})",
                route.project_id,
                task.order.id,
                grade.score,
                if grade.objective {
                    ""
                } else {
                    ", not an objective improvement"
                },
                grade.grader,
                grade.engine
            )),
            Ok(false) => {}
            Err(error) => report.warn(&format!(
                "  {}: could not record the grade of {}: {error:#}",
                route.project_id, task.order.id
            )),
        }
    }
    lines
}

/// What a failing grade counts against on the machine of `agent`: its own engine that
/// built the work, for the kind of work it was, and its own engine that planned it.
/// `(engine, kind)` pairs; a passing grade counts against nothing.
#[must_use]
pub fn failures_for(agent: &str, engines: &[String], grade: &Grade) -> Vec<(String, String)> {
    if grade.passed() {
        return Vec::new();
    }
    let ours = |name: &str| {
        engines
            .iter()
            .any(|engine| engine.eq_ignore_ascii_case(name))
    };
    let mut out = Vec::new();
    if grade.worker.eq_ignore_ascii_case(agent) && ours(&grade.engine) {
        out.push((
            grade.engine.clone(),
            grade
                .kind
                .clone()
                .unwrap_or_else(|| "code-change".to_string()),
        ));
    }
    if let (Some(planner), Some(planner_agent)) = (&grade.planner, &grade.planner_agent)
        && planner_agent.eq_ignore_ascii_case(agent)
        && ours(planner)
    {
        out.push((planner.clone(), "plan".to_string()));
    }
    out
}

fn applied_path() -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("grades-counted.json"))
}

/// Count every failing grade in the project that this machine has not counted yet
/// against this agent's engines ([`failures_for`]). Returns how many results were
/// counted against an engine.
pub fn apply(route: &ProjectRoute, config: &AgentConfig, now: DateTime<Utc>) -> usize {
    let Some(path) = applied_path() else {
        return 0;
    };
    let mut counted: BTreeSet<String> = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let names: Vec<String> = config
        .engines
        .iter()
        .map(|spec| spec.name.clone())
        .collect();
    let mut against = 0;
    let mut changed = false;
    for grade in grades::read_all(route) {
        let key = format!("{}/{}/{}", config.agent, route.project_id, grade.id());
        if counted.contains(&key) {
            continue;
        }
        for (engine, kind) in failures_for(&config.agent, &names, &grade) {
            engines::record_verification_for(
                &config.agent,
                &engine,
                Some(&kind),
                Status::Refuted,
                now,
            );
            against += 1;
        }
        counted.insert(key);
        changed = true;
    }
    if changed {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, serde_json::to_vec(&counted).unwrap_or_default());
    }
    against
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grade(objective: bool, score: u8) -> Grade {
        Grade {
            order_id: "improve-2026-w44-1".into(),
            revision: 1,
            project_id: "demo".into(),
            title: "t".into(),
            worker: "grouchly-swarm".into(),
            engine: "deepseek-flash".into(),
            kind: Some("docs".into()),
            planner: Some("deepseek-pro".into()),
            planner_agent: Some("grouchly-swarm".into()),
            grader: "codex".into(),
            objective,
            score,
            why: String::new(),
            lesson: String::new(),
            graded_at: Utc::now(),
            signed_by: "grouchly-swarm".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_failing_grade_counts_against_the_builder_and_the_planner_on_their_own_machine() {
        let engines = vec!["deepseek-flash".to_string(), "deepseek-pro".to_string()];
        assert_eq!(
            failures_for("grouchly-swarm", &engines, &grade(false, 0)),
            vec![
                ("deepseek-flash".to_string(), "docs".to_string()),
                ("deepseek-pro".to_string(), "plan".to_string())
            ]
        );
        assert!(
            failures_for("grouchly-swarm", &engines, &grade(true, 8)).is_empty(),
            "a pass counts against nothing"
        );
        assert_eq!(
            failures_for("grouchly-swarm", &engines, &grade(true, 3)).len(),
            2,
            "objective but worth too little is still a failing grade"
        );
        assert!(
            failures_for("beastly-swarm", &engines, &grade(false, 0)).is_empty(),
            "another machine's engine is that machine's to count"
        );
        assert!(failures_for("grouchly-swarm", &["codex".into()], &grade(false, 0)).is_empty());
    }

    #[test]
    fn a_grade_is_read_from_the_json_and_not_objective_scores_nothing() {
        assert_eq!(
            parse(
                "sure:\n{\"objective\": true, \"score\": 7.4, \"why\": \"w\", \"lesson\": \"l\"}"
            ),
            Some((true, 7, "w".into(), "l".into()))
        );
        assert_eq!(
            parse("{\"objective\": false, \"score\": 6, \"why\": \"renamed\", \"lesson\": \"\"}"),
            Some((false, 0, "renamed".into(), String::new()))
        );
        assert_eq!(
            parse("{\"objective\": true, \"score\": 42}").map(|g| g.1),
            Some(10)
        );
        assert_eq!(parse("it was fine"), None);
        assert_eq!(parse("{\"score\": 5}"), None);
    }

    #[test]
    fn the_grader_is_told_what_counts_and_shown_the_diff_when_there_is_one() {
        let order = ferryman_channel::Order {
            id: "improve-2026-w44-1".into(),
            project_id: "demo".into(),
            issued_by: "w".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: serde_json::json!({
                "task": "x",
                "tags": ["improvement"],
                "improvement": {"week": "2026-W44", "title": "Retry the flaky fetch",
                    "why": "it fails one run in five", "acceptance": ["a test that retries"]},
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
            priority: None,
        };
        let task = Task {
            order,
            claims: Vec::new(),
            results: Vec::new(),
            reviews: Vec::new(),
            recommendations: Vec::new(),
            heartbeats: Vec::new(),
            releases: Vec::new(),
            kills: Vec::new(),
            offers: Vec::new(),
        };
        let result = TaskResult {
            order_id: "improve-2026-w44-1".into(),
            agent: "w".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: serde_json::json!({"output": "added a retry", "engine": "deepseek-flash"}),
            signed_by: None,
            signature: None,
        };
        let text = prompt("demo", &task, &result, Some("+retry()"));
        assert!(text.contains("Retry the flaky fetch"));
        assert!(text.contains("- a test that retries"));
        assert!(text.contains("NOT objective"));
        assert!(text.contains("+retry()"));
        assert!(prompt("demo", &task, &result, None).contains("not on this machine"));
    }
}

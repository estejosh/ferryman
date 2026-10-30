//! Grades: a second engine's verdict on whether an improvement objectively improved
//! anything.
//!
//! The evidence check ([`crate::evidence`]) answers "does the work exist": a commit, a
//! diff, checks that ran. A reviewer answers "is it acceptable". Neither asks whether the
//! project is measurably better for it - and an improvement loop left to itself drifts
//! into rewording comments, renaming things and adding notes, work that exists, passes
//! review and changes nothing anyone can measure. So once an improvement is accepted or
//! done, an engine other than the one that built it grades it: was there an objective
//! improvement (a test that now passes and failed before, a reproduced bug that is
//! fixed, a number that moved, a failure mode that cannot happen any more), and how much
//! was it worth, 0 to 10.
//!
//! A failing grade - not objective, or under [`PASS_MARK`] - counts against the engine
//! that built it, on the machine that ran it, exactly as a refuted result does: its trust
//! falls and the smart router learns that kind of work went badly there. It counts against
//! the engine that planned it too. And every grade, with the grader's one-line lesson, is
//! read by the next week's planner, so the plans themselves get better over time.
//!
//! ```text
//! <channel>/improve/grades/<order>-r<revision>.json   one per graded result, signed
//! ```
//!
//! A grade is signed by the agent whose engine graded it and checked against the
//! roster before anything counts it: a grade nobody can verify moves no trust.

use std::{fs, path::PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature};

/// A grade below this, out of ten, is a failing grade even when the work was objective.
pub const PASS_MARK: u8 = 5;

/// One graded improvement result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grade {
    pub order_id: String,
    pub revision: u32,
    pub project_id: String,
    /// The improvement's title, for people and for the next plan.
    pub title: String,
    /// The agent whose engine built it, and that engine.
    pub worker: String,
    pub engine: String,
    /// The kind of work it was routed as (`code-change`, `docs`, ...), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The engine that planned it, and the agent it ran as, when the plan says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planner_agent: Option<String>,
    /// The engine that graded it. Never `engine`.
    pub grader: String,
    /// Whether anything objectively improved.
    pub objective: bool,
    /// 0 to 10: how much it was worth.
    pub score: u8,
    /// What objectively improved, or why nothing did.
    pub why: String,
    /// One sentence for the next planner.
    pub lesson: String,
    pub graded_at: DateTime<Utc>,
    pub signed_by: String,
    #[serde(default)]
    pub signature: String,
}

impl Grade {
    /// Whether the grade passes: objective, and at least [`PASS_MARK`].
    #[must_use]
    pub fn passed(&self) -> bool {
        self.objective && self.score >= PASS_MARK
    }

    /// The id the file is stored under.
    #[must_use]
    pub fn id(&self) -> String {
        id(&self.order_id, self.revision)
    }
}

/// `<order>-r<revision>`.
#[must_use]
pub fn id(order_id: &str, revision: u32) -> String {
    format!("{order_id}-r{revision}")
}

fn dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("improve").join("grades")
}

fn path(route: &ProjectRoute, order_id: &str, revision: u32) -> PathBuf {
    dir(route).join(format!("{}.json", id(order_id, revision)))
}

/// What a grade's signature covers: every field but the signature.
fn payload(grade: &Grade) -> String {
    let body = serde_json::to_string(&(
        &grade.title,
        &grade.kind,
        &grade.planner,
        &grade.planner_agent,
        &grade.why,
        &grade.lesson,
    ))
    .unwrap_or_default();
    format!(
        "ferryman-grade-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        grade.order_id,
        grade.revision,
        grade.project_id,
        grade.worker,
        grade.engine,
        grade.grader,
        grade.objective,
        grade.score,
        grade.graded_at.to_rfc3339(),
        grade.signed_by,
        hex::encode(Sha256::digest(body.as_bytes()))
    )
}

/// Whether this result has a grade on file, verified or not.
#[must_use]
pub fn exists(route: &ProjectRoute, order_id: &str, revision: u32) -> bool {
    path(route, order_id, revision).is_file()
}

/// Sign `grade` as `identity` and write it, once. Returns false when the result was
/// graded already: the first grade stands.
///
/// # Errors
/// An order id that is not path-safe, a grade that grades its own engine's work, a
/// score over ten, or the file could not be written.
pub fn record(route: &ProjectRoute, identity: &AgentIdentity, mut grade: Grade) -> Result<bool> {
    if !crate::is_safe_component(&grade.order_id) {
        bail!("an order id must be a path-safe identifier");
    }
    if grade.grader.eq_ignore_ascii_case(&grade.engine) {
        bail!(
            "{} cannot grade its own work; another engine grades it",
            grade.engine
        );
    }
    if grade.score > 10 {
        bail!("a grade is 0 to 10, not {}", grade.score);
    }
    let path = path(route, &grade.order_id, grade.revision);
    if path.exists() {
        return Ok(false);
    }
    grade.project_id.clone_from(&route.project_id);
    grade.signed_by = identity.name().to_string();
    grade.signature = identity.sign_bytes(payload(&grade).as_bytes());
    crate::atomic_json(&path, &grade)?;
    Ok(true)
}

/// Whether a grade's signature holds against the project's roster.
#[must_use]
pub fn holds(route: &ProjectRoute, grade: &Grade) -> bool {
    grade.project_id == route.project_id
        && check_signature(
            Some(&grade.signed_by),
            Some(&grade.signature),
            &payload(grade),
            &route.agents,
        ) == SignatureCheck::Valid
}

/// Every grade in the project whose signature holds, oldest first.
#[must_use]
pub fn read_all(route: &ProjectRoute) -> Vec<Grade> {
    let Ok(entries) = fs::read_dir(dir(route)) else {
        return Vec::new();
    };
    let mut grades: Vec<Grade> = entries
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .filter_map(|text| serde_json::from_str::<Grade>(&text).ok())
        .filter(|grade| holds(route, grade))
        .collect();
    grades.sort_by(|a, b| a.graded_at.cmp(&b.graded_at).then(a.id().cmp(&b.id())));
    grades
}

/// The grades given since `since`.
#[must_use]
pub fn since(route: &ProjectRoute, since: DateTime<Utc>) -> Vec<Grade> {
    read_all(route)
        .into_iter()
        .filter(|grade| grade.graded_at >= since)
        .collect()
}

/// What the grades since `since` come to, as a 0-to-1 rate: the mean score over ten,
/// with an improvement that was not objective counting as zero. `None` with no grades.
#[must_use]
pub fn landed_rate(grades: &[Grade]) -> Option<f64> {
    if grades.is_empty() {
        return None;
    }
    let total: f64 = grades
        .iter()
        .map(|grade| {
            if grade.objective {
                f64::from(grade.score.min(10)) / 10.0
            } else {
                0.0
            }
        })
        .sum();
    Some(total / grades.len() as f64)
}

/// The grades as the next planner reads them: newest first, at most `max`, one line
/// each with the lesson.
#[must_use]
pub fn for_planner(grades: &[Grade], max: usize) -> String {
    let mut lines = Vec::new();
    for grade in grades.iter().rev().take(max) {
        lines.push(format!(
            "- {} - {}/10, {} (built by {}, graded by {}): {}{}",
            grade.title,
            grade.score,
            if grade.objective {
                "objective"
            } else {
                "NOT an objective improvement"
            },
            grade.engine,
            grade.grader,
            grade.why,
            if grade.lesson.is_empty() {
                String::new()
            } else {
                format!(" Lesson: {}", grade.lesson)
            }
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;
    use std::path::Path;

    fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
        let communications = dir.join("demo-ferryman");
        fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: "demo".into(),
            workspace: dir.join("demo"),
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
                role: "agent".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        route
    }

    fn grade(order: &str, engine: &str, grader: &str, objective: bool, score: u8) -> Grade {
        Grade {
            order_id: order.into(),
            revision: 1,
            project_id: String::new(),
            title: format!("{order} title"),
            worker: "grouchly".into(),
            engine: engine.into(),
            kind: Some("code-change".into()),
            planner: Some("deepseek-pro".into()),
            planner_agent: Some("grouchly".into()),
            grader: grader.into(),
            objective,
            score,
            why: "a test that failed now passes".into(),
            lesson: "name the failing test in the plan".into(),
            graded_at: Utc::now(),
            signed_by: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_grade_is_signed_written_once_and_never_by_the_engine_that_built_it() {
        let dir = tempfile::tempdir().unwrap();
        let wisp = AgentIdentity::from_seed("wisp", [4; 32]);
        let route = route(dir.path(), &[&wisp]);
        assert!(
            record(&route, &wisp, grade("improve-1", "flash", "flash", true, 9)).is_err(),
            "no engine grades its own work"
        );
        assert!(record(&route, &wisp, grade("improve-1", "flash", "codex", true, 8)).unwrap());
        assert!(
            !record(
                &route,
                &wisp,
                grade("improve-1", "flash", "codex", false, 0)
            )
            .unwrap(),
            "the first grade stands"
        );
        assert!(
            record(
                &route,
                &wisp,
                grade("improve-2", "flash", "codex", true, 11)
            )
            .is_err()
        );
        let all = read_all(&route);
        assert_eq!(all.len(), 1);
        assert!(all[0].passed());
        assert_eq!(all[0].project_id, "demo");
    }

    #[test]
    fn a_tampered_or_unknown_grade_counts_for_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let wisp = AgentIdentity::from_seed("wisp", [4; 32]);
        let stranger = AgentIdentity::from_seed("stranger", [5; 32]);
        let route = route(dir.path(), &[&wisp]);
        record(
            &route,
            &wisp,
            grade("improve-1", "flash", "codex", false, 2),
        )
        .unwrap();
        // Flipped to a pass by hand: the signature no longer holds.
        let file = path(&route, "improve-1", 1);
        let mut edited: Grade = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        edited.objective = true;
        edited.score = 10;
        fs::write(&file, serde_json::to_string(&edited).unwrap()).unwrap();
        // Signed by someone the roster does not know.
        record(
            &route,
            &stranger,
            grade("improve-2", "flash", "codex", true, 9),
        )
        .unwrap();
        assert!(read_all(&route).is_empty());
    }

    #[test]
    fn the_landed_rate_counts_what_was_not_objective_as_nothing() {
        let grades = vec![
            grade("a", "flash", "codex", true, 8),
            grade("b", "flash", "codex", false, 7),
            grade("c", "flash", "codex", true, 6),
        ];
        let rate = landed_rate(&grades).unwrap();
        assert!((rate - (0.8 + 0.0 + 0.6) / 3.0).abs() < 1e-9, "{rate}");
        assert_eq!(landed_rate(&[]), None);
        assert!(!grades[1].passed());
        assert!(!grade("d", "flash", "codex", true, PASS_MARK - 1).passed());
        let text = for_planner(&grades, 2);
        assert!(text.starts_with("- c title"), "newest first: {text}");
        assert!(!text.contains("a title"), "at most two: {text}");
        assert!(text.contains("NOT an objective improvement"), "{text}");
    }
}

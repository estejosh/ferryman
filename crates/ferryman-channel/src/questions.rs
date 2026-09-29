//! Questions the fleet asks the project's master, and the master's signed answers.
//!
//! ```text
//! <channel>/questions/
//!   clarify-2026-w39-1.json          asked by an agent, signed by it
//!   clarify-2026-w39-1.answer.json   answered by the master, or by their delegate
//! ```
//!
//! The improve loop asks two kinds: a clarifying question while planning, and a "ready to
//! merge" notice once an improvement is accepted. Neither makes anything happen on its
//! own - above all, nothing merges. An answer is a signed statement the loop reads on its
//! next run. Only the master's answer counts: their own signature, or a delegate's under
//! their `improve` delegation, recorded as "josh via telegram-grouchly".

use std::{fs, path::PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature, delegation};

/// A question that shapes a plan.
pub const CLARIFY: &str = "clarify";
/// Accepted work that a person may now merge. A notice; nothing merges on its own.
pub const MERGE: &str = "merge";
/// Background work held by the engine policy, or a free tier that asked for money.
/// Answered with the policy's buttons; see [`crate::policy`].
pub const POLICY: &str = "engine-policy";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Question {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    pub text: String,
    #[serde(default)]
    pub options: Vec<String>,
    /// The order it is about, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    pub asked_by: String,
    pub asked_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Answer {
    pub question_id: String,
    pub project_id: String,
    pub answer: String,
    /// Whose answer it is: the master.
    pub by: String,
    pub answered_at: DateTime<Utc>,
    /// Who signed it: the master, or their delegate.
    pub signed_by: String,
    pub signature: String,
}

impl Answer {
    /// `josh`, or `josh via telegram-grouchly`.
    #[must_use]
    pub fn from(&self) -> String {
        delegation::label(&self.by, &self.signed_by)
    }
}

fn question_payload(question: &Question) -> String {
    let body = serde_json::to_string(&(&question.text, &question.options)).unwrap_or_default();
    format!(
        "ferryman-question-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        question.id,
        question.project_id,
        question.kind,
        question.order_id.as_deref().unwrap_or_default(),
        question.asked_by,
        question.asked_at.to_rfc3339(),
        hex::encode(Sha256::digest(body.as_bytes()))
    )
}

fn answer_payload(answer: &Answer) -> String {
    format!(
        "ferryman-answer-v1\n{}\n{}\n{}\n{}\n{}",
        answer.question_id,
        answer.project_id,
        answer.by,
        answer.answered_at.to_rfc3339(),
        answer.answer
    )
}

fn dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("questions")
}

fn question_path(route: &ProjectRoute, id: &str) -> PathBuf {
    dir(route).join(format!("{id}.json"))
}

fn answer_path(route: &ProjectRoute, id: &str) -> PathBuf {
    dir(route).join(format!("{id}.answer.json"))
}

/// Ask, once. Returns false when a question with this id is already there.
pub fn ask(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    id: &str,
    kind: &str,
    text: &str,
    options: &[String],
    order_id: Option<&str>,
) -> Result<bool> {
    if !crate::is_safe_component(id) {
        bail!("a question id must be a path-safe identifier");
    }
    if text.trim().is_empty() {
        bail!("a question needs words");
    }
    let path = question_path(route, id);
    if path.exists() {
        return Ok(false);
    }
    let mut question = Question {
        id: id.to_string(),
        project_id: route.project_id.clone(),
        kind: kind.to_string(),
        text: text.trim().to_string(),
        options: options
            .iter()
            .map(|option| option.trim().to_string())
            .filter(|option| !option.is_empty())
            .collect(),
        order_id: order_id.map(str::to_string),
        asked_by: identity.name().to_string(),
        asked_at: Utc::now(),
        signed_by: identity.name().to_string(),
        signature: String::new(),
    };
    question.signature = identity.sign_bytes(question_payload(&question).as_bytes());
    crate::atomic_json(&path, &question)?;
    Ok(true)
}

fn question_holds(route: &ProjectRoute, question: &Question) -> bool {
    question.project_id == route.project_id
        && question.asked_by.eq_ignore_ascii_case(&question.signed_by)
        && check_signature(
            Some(&question.signed_by),
            Some(&question.signature),
            &question_payload(question),
            &route.agents,
        ) == SignatureCheck::Valid
}

fn answer_holds(route: &ProjectRoute, question: &Question, answer: &Answer) -> bool {
    let Ok(Some(master)) = crate::master::read_master(route) else {
        return false;
    };
    answer.question_id == question.id
        && answer.project_id == route.project_id
        && answer.by.eq_ignore_ascii_case(&master.master)
        && delegation::authority(
            &route.communications,
            &route.project_id,
            &answer.by,
            &answer.signed_by,
            delegation::IMPROVE,
            Utc::now(),
        )
        .allowed()
        && check_signature(
            Some(&answer.signed_by),
            Some(&answer.signature),
            &answer_payload(answer),
            &route.agents,
        ) == SignatureCheck::Valid
}

/// One question by id, when it verifies.
#[must_use]
pub fn read(route: &ProjectRoute, id: &str) -> Option<Question> {
    let question: Question =
        serde_json::from_slice(&fs::read(question_path(route, id)).ok()?).ok()?;
    question_holds(route, &question).then_some(question)
}

/// The master's answer to a question, when there is one that verifies.
#[must_use]
pub fn answer_to(route: &ProjectRoute, question: &Question) -> Option<Answer> {
    let answer: Answer =
        serde_json::from_slice(&fs::read(answer_path(route, &question.id)).ok()?).ok()?;
    answer_holds(route, question, &answer).then_some(answer)
}

/// Every question that verifies, oldest first, each with its answer if it has one.
#[must_use]
pub fn list(route: &ProjectRoute) -> Vec<(Question, Option<Answer>)> {
    let Ok(entries) = fs::read_dir(dir(route)) else {
        return Vec::new();
    };
    let mut out: Vec<(Question, Option<Answer>)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let id = name.strip_suffix(".json")?;
            (!id.ends_with(".answer") && !id.contains(".sync-conflict-")).then(|| id.to_string())
        })
        .filter_map(|id| read(route, &id))
        .map(|question| {
            let answer = answer_to(route, &question);
            (question, answer)
        })
        .collect();
    out.sort_by(|a, b| a.0.asked_at.cmp(&b.0.asked_at).then(a.0.id.cmp(&b.0.id)));
    out
}

/// Questions still waiting for the master.
#[must_use]
pub fn pending(route: &ProjectRoute) -> Vec<Question> {
    list(route)
        .into_iter()
        .filter(|(_, answer)| answer.is_none())
        .map(|(question, _)| question)
        .collect()
}

/// Record `by`'s answer, signed by `signer`: the master, or their `improve` delegate.
/// Written once; a second answer is refused.
pub fn answer(
    route: &ProjectRoute,
    question_id: &str,
    text: &str,
    by: &str,
    signer: &AgentIdentity,
) -> Result<Answer> {
    let Some(question) = read(route, question_id) else {
        bail!("there is no question {question_id} in {}", route.project_id);
    };
    if answer_to(route, &question).is_some() {
        bail!("{question_id} is already answered");
    }
    let Some(master) = crate::master::read_master(route)? else {
        bail!("{} has no master to answer it", route.project_id);
    };
    if !by.eq_ignore_ascii_case(&master.master) {
        bail!(
            "only {}, the master, answers the fleet's questions",
            master.master
        );
    }
    if let delegation::Authority::Refused(why) = delegation::authority(
        &route.communications,
        &route.project_id,
        by,
        signer.name(),
        delegation::IMPROVE,
        Utc::now(),
    ) {
        bail!("{} cannot answer for {by}: {why}", signer.name());
    }
    if text.trim().is_empty() {
        bail!("an answer needs words");
    }
    let mut answer = Answer {
        question_id: question.id.clone(),
        project_id: route.project_id.clone(),
        answer: text.trim().to_string(),
        by: master.master.clone(),
        answered_at: Utc::now(),
        signed_by: signer.name().to_string(),
        signature: String::new(),
    };
    answer.signature = signer.sign_bytes(answer_payload(&answer).as_bytes());
    crate::atomic_json(&answer_path(route, &question.id), &answer)?;
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;
    use std::path::Path;

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

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

    #[test]
    fn a_question_is_answered_once_by_the_master_or_their_improve_delegate() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &wisp, &bridge]);
        let options = vec!["Yes".to_string(), "No".to_string()];
        assert!(
            ask(
                &route,
                &wisp,
                "clarify-w39-1",
                CLARIFY,
                "Drop Windows 7?",
                &options,
                None
            )
            .unwrap()
        );
        assert!(
            !ask(
                &route,
                &wisp,
                "clarify-w39-1",
                CLARIFY,
                "again",
                &options,
                None
            )
            .unwrap()
        );
        assert_eq!(pending(&route).len(), 1);

        // A worker answering in josh's name, and the bridge before it is delegated.
        assert!(answer(&route, "clarify-w39-1", "Yes", "josh", &wisp).is_err());
        assert!(answer(&route, "clarify-w39-1", "Yes", "josh", &bridge).is_err());
        crate::delegation::grant(
            &route.communications,
            "demo",
            &josh,
            "telegram-grouchly",
            &["orders".to_string()],
            None,
        )
        .unwrap();
        assert!(
            answer(&route, "clarify-w39-1", "Yes", "josh", &bridge).is_err(),
            "orders is not improve"
        );
        crate::delegation::grant(
            &route.communications,
            "demo",
            &josh,
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        let answered = answer(&route, "clarify-w39-1", "Yes", "josh", &bridge).unwrap();
        assert_eq!(answered.from(), "josh via telegram-grouchly");
        assert!(pending(&route).is_empty());
        assert!(
            answer(&route, "clarify-w39-1", "No", "josh", &josh).is_err(),
            "once"
        );
    }

    #[test]
    fn a_forged_answer_or_question_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let route = route(dir.path(), &[&josh, &wisp]);
        ask(&route, &wisp, "q1", CLARIFY, "Which license?", &[], None).unwrap();
        // The worker writes an "answer from josh" itself.
        let mut forged = Answer {
            question_id: "q1".into(),
            project_id: "demo".into(),
            answer: "MIT".into(),
            by: "josh".into(),
            answered_at: Utc::now(),
            signed_by: "wisp".into(),
            signature: String::new(),
        };
        forged.signature = wisp.sign_bytes(answer_payload(&forged).as_bytes());
        crate::atomic_json(&answer_path(&route, "q1"), &forged).unwrap();
        assert_eq!(pending(&route).len(), 1, "a forged answer answers nothing");
        // An edited question stops verifying.
        let mut question = read(&route, "q1").unwrap();
        question.text = "Merge everything?".into();
        crate::atomic_json(&question_path(&route, "q1"), &question).unwrap();
        assert!(list(&route).is_empty());
    }
}

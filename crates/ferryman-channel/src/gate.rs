//! Two keys before an improvement goes live.
//!
//! ```text
//! <channel>/gates/<order>/r<revision>.<agent>.json   the review engine's signed verdict
//! <channel>/tasks/<order>/review.<revision>.json     the master's signed approval
//! ```
//!
//! An improvement the self-improve loop built is "approved for live" - ready to merge,
//! deploy or release - only when both keys exist for its newest revision:
//!
//! 1. **The engine key**: a signed verdict accepting it from the review engine the
//!    project's engine policy allows (a judge-tier engine it does not block, on a machine
//!    it names, and one of its review preferences when it lists any), on a result whose
//!    own evidence passes verification and that no verifier refuted.
//! 2. **The master key**: a signed approval from the project's master, or from a
//!    delegate holding their `review` delegation acting on the master's click.
//!
//! Neither alone is enough. The review engine never accepts an improvement on its own -
//! it records its verdict and recommends - and the master cannot approve one the engine
//! has not reviewed: [`check_acceptance`] refuses it inside
//! [`crate::submit_review`], so no surface can skip it. When the review engine is
//! blocked or out, the improve loop holds and asks; it never skips the review and never
//! approves by itself.
//!
//! With both keys the improvement becomes "approved, ready to merge", and merging is the
//! master's own act - unless the project's engine policy says `auto_merge = "low-risk"`,
//! and then only docs, tests and dependency bumps merge on their own; see
//! [`crate::automerge`].
//!
//! Audit verification orders are not gated: they change nothing and never go live.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AgentIdentity, AgentRoute, ProjectRoute, Review, SignatureCheck, Task,
    policy::{Candidate, Policy, Role, Work},
};

/// The tag the improve loop puts on every order it issues.
pub const TAG: &str = "improvement";

/// Whether an order is an improvement that must pass both keys before going live.
#[must_use]
pub fn gated(payload: &Value) -> bool {
    payload
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(TAG)))
        && !crate::evidence::is_verification(payload)
}

/// The review engine's verdict on one revision, signed by the agent that ran it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineReview {
    pub order_id: String,
    pub revision: u32,
    /// The agent that ran the engine.
    pub reviewer: String,
    pub machine: String,
    pub engine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The tier it worked at: only a `judge` reviews.
    pub tier: String,
    /// How it is paid for, as its worker publishes it.
    pub paid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Where a gateway engine (OmniRoute) routes it: the underlying provider/models.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route: Vec<String>,
    pub accept: bool,
    pub summary: String,
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl EngineReview {
    fn payload(&self) -> String {
        let bare = Self {
            signed_by: None,
            signature: None,
            ..self.clone()
        };
        format!(
            "ferryman-engine-review-v1\n{}",
            serde_jcs::to_string(&bare).unwrap_or_default()
        )
    }

    /// The engine as the policy sees it.
    #[must_use]
    pub fn candidate(&self) -> Candidate {
        Candidate {
            agent: self.reviewer.clone(),
            machine: self.machine.clone(),
            name: self.engine.clone(),
            model: self.model.clone(),
            tier: self.tier.clone(),
            paid: self.paid.clone(),
            host: self.host.clone(),
            route: self.route.clone(),
            state: "up".to_string(),
            ..Candidate::default()
        }
    }

    /// `deepseek (deepseek-chat) on grouchly: keep - the tests cover the change`
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{}{} on {}: {} - {}",
            self.engine,
            self.model
                .as_deref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default(),
            self.machine,
            if self.accept { "keep" } else { "send back" },
            self.summary
        )
    }
}

fn gate_dir(route: &ProjectRoute, order_id: &str) -> PathBuf {
    route.communications.join("gates").join(order_id)
}

/// Record the review engine's verdict, signed by `identity`, the agent that ran it.
pub fn record_engine_review(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    mut review: EngineReview,
) -> Result<()> {
    if !crate::is_safe_component(&review.order_id) || !crate::is_safe_component(identity.name()) {
        bail!("order and agent must be path-safe");
    }
    if review.summary.trim().is_empty() {
        bail!("an engine review must say why");
    }
    review.reviewer = identity.name().to_string();
    review.signed_by = None;
    review.signature = None;
    let signature = identity.sign_bytes(review.payload().as_bytes());
    review.signed_by = Some(identity.name().to_string());
    review.signature = Some(signature);
    let path = gate_dir(route, &review.order_id).join(format!(
        "r{}.{}.json",
        review.revision,
        identity.name()
    ));
    crate::atomic_json(&path, &review).with_context(|| format!("writing {}", path.display()))
}

/// The roster to check a signature against: the channel's, and the route's own.
pub(crate) fn roster(route: &ProjectRoute) -> Vec<AgentRoute> {
    let mut all = crate::read_agent_roster(&route.communications).unwrap_or_default();
    for agent in &route.agents {
        if !all
            .iter()
            .any(|known| known.name.eq_ignore_ascii_case(&agent.name))
        {
            all.push(agent.clone());
        }
    }
    all
}

/// Every engine verdict on this revision that verifies as its reviewer's, newest first.
#[must_use]
pub fn engine_reviews(route: &ProjectRoute, order_id: &str, revision: u32) -> Vec<EngineReview> {
    let Ok(entries) = std::fs::read_dir(gate_dir(route, order_id)) else {
        return Vec::new();
    };
    let roster = roster(route);
    let prefix = format!("r{revision}.");
    let mut found: Vec<EngineReview> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".json"))
        })
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<EngineReview>(&bytes).ok())
        .filter(|review| {
            review.order_id == order_id
                && review.revision == revision
                && review
                    .signed_by
                    .as_deref()
                    .is_some_and(|signer| signer.eq_ignore_ascii_case(&review.reviewer))
                && crate::check_signature(
                    review.signed_by.as_ref(),
                    review.signature.as_ref(),
                    &review.payload(),
                    &roster,
                ) == SignatureCheck::Valid
        })
        .collect();
    found.sort_by_key(|review| std::cmp::Reverse(review.reviewed_at));
    found
}

/// The engine key for `revision`: the review engine's accepting verdict, when there is
/// one that counts, or why there is none.
pub fn engine_key(
    route: &ProjectRoute,
    task: &Task,
    policy: &Policy,
    revision: u32,
) -> std::result::Result<EngineReview, String> {
    let Some(result) = task.results.iter().find(|r| r.revision == revision) else {
        return Err(format!("there is no result r{revision}"));
    };
    if let Some(why) = crate::evidence::blocking_reason(&task.order.payload, result) {
        return Err(format!("the result does not pass verification - {why}"));
    }
    if let Some(refuted) = crate::evidence::read_verifications(route, &task.order.id)
        .iter()
        .find(|record| record.revision == revision && record.status == "refuted")
    {
        return Err(format!(
            "{} refuted it - {}",
            refuted.verifier,
            refuted.reasons.join("; ")
        ));
    }
    let reviews = engine_reviews(route, &task.order.id, revision);
    if reviews.is_empty() {
        return Err("the review engine has not reviewed it yet".to_string());
    }
    let listed = policy.preferences(Role::Review);
    let mut why = Vec::new();
    for review in reviews {
        let engine = review.candidate();
        let not_counted = if engine.tier != "judge" {
            Some(format!("{} is not a judge-tier engine", review.engine))
        } else if !policy.allows_machine(&review.reviewer, &review.machine) {
            Some(format!(
                "{} is not where the policy runs it",
                review.machine
            ))
        } else if let Some(blocked) = policy.blocked(&engine, Work::Background) {
            Some(format!("{} is {blocked}", review.engine))
        } else if !listed.is_empty() && policy.preference(Role::Review, &engine).is_none() {
            Some(format!(
                "{} is not the policy's review engine",
                review.engine
            ))
        } else {
            None
        };
        match not_counted {
            Some(reason) => why.push(reason),
            None if review.accept => return Ok(review),
            None => {
                return Err(format!(
                    "the review engine sent it back: {}",
                    review.describe()
                ));
            }
        }
    }
    Err(format!("no review that counts - {}", why.join("; ")))
}

/// The master key for `revision`: an accepting verdict by the master, signed by them or
/// by their `review` delegate, that verifies.
pub fn master_key(
    route: &ProjectRoute,
    task: &Task,
    revision: u32,
) -> std::result::Result<Review, String> {
    let master = crate::ferry::master_of(&route.communications)
        .ok()
        .flatten()
        .ok_or_else(|| format!("{} has no master to approve it", route.project_id))?;
    let Some(review) = task
        .reviews
        .iter()
        .rev()
        .find(|review| review.revision == revision && review.accepted)
    else {
        return Err(format!("{master} has not approved it"));
    };
    if !review.reviewer.eq_ignore_ascii_case(&master) {
        return Err(format!(
            "it was accepted by {}, not by {master}, the master",
            review.reviewer
        ));
    }
    if crate::verify_review(review, &roster(route)) != SignatureCheck::Valid
        || !crate::review_authority(route, review).allowed()
    {
        return Err(format!("the approval in {master}'s name does not verify"));
    }
    Ok(review.clone())
}

/// Where one improvement stands against the two keys.
#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
    pub revision: Option<u32>,
    pub engine: std::result::Result<EngineReview, String>,
    pub master: std::result::Result<Review, String>,
}

impl Gate {
    /// Both keys: approved, ready to merge - by the master, or for low-risk work under
    /// `auto_merge = "low-risk"`, by fm ([`crate::automerge`]).
    #[must_use]
    pub fn approved(&self) -> bool {
        self.engine.is_ok() && self.master.is_ok()
    }

    /// `approved, ready to merge` or what it is waiting for.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.engine, &self.master) {
            (Ok(_), Ok(_)) => "approved, ready to merge".to_string(),
            (Err(why), _) => format!("waiting for the review engine: {why}"),
            (Ok(_), Err(why)) => format!("waiting for your approval: {why}"),
        }
    }
}

/// Where the newest revision of an improvement stands.
#[must_use]
pub fn gate(route: &ProjectRoute, task: &Task, policy: &Policy) -> Gate {
    match task.latest_revision() {
        None => Gate {
            revision: None,
            engine: Err("no result yet".to_string()),
            master: Err("no result yet".to_string()),
        },
        Some(revision) => Gate {
            revision: Some(revision),
            engine: engine_key(route, task, policy, revision),
            master: master_key(route, task, revision),
        },
    }
}

/// Whether work may go live: for an improvement, both keys; for anything else, what it
/// always was - accepted.
#[must_use]
pub fn approved_for_live(route: &ProjectRoute, task: &Task) -> bool {
    if !gated(&task.order.payload) {
        return task.state() == crate::TaskState::Accepted;
    }
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    gate(route, task, &policy).approved()
}

/// Refuse accepting an improvement unless it is the master's verdict and the review
/// engine's key is already there. Called by [`crate::submit_review`], so every surface -
/// the CLI, the dashboard, the phone, an agent - is held to it.
pub fn check_acceptance(route: &ProjectRoute, task: &Task, review: &Review) -> Result<()> {
    if !review.accepted || !gated(&task.order.payload) {
        return Ok(());
    }
    let master = crate::ferry::master_of(&route.communications)?.with_context(|| {
        format!(
            "{} is an improvement and needs its master's approval, but {} has no master",
            review.order_id, route.project_id
        )
    })?;
    if !review.reviewer.eq_ignore_ascii_case(&master) {
        bail!(
            "{} is an improvement: only {master}, the master, approves it for live - after \
             the review engine has; {} may recommend, not accept",
            review.order_id,
            review.reviewer
        );
    }
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    if let Err(why) = engine_key(route, task, &policy, review.revision) {
        bail!(
            "{} r{} cannot be approved yet: {why}. Both keys are needed - the review engine's \
             and yours - and the engine's comes first",
            review.order_id,
            review.revision
        );
    }
    Ok(())
}

/// One improvement waiting on a key.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Waiting {
    pub order_id: String,
    pub title: String,
    pub revision: u32,
    pub worker: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_stat: Option<String>,
    /// What the worker's evidence says, as verification classes it.
    pub evidence: String,
    /// The review engine's verdict, when it counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineReview>,
    /// `true`: only the master's approval is missing.
    pub ready_for_you: bool,
    pub waiting_for: String,
}

/// Every improvement whose newest result is not yet approved for live, nor sent back.
#[must_use]
pub fn waiting(route: &ProjectRoute) -> Vec<Waiting> {
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    let mut out = Vec::new();
    for task in crate::list_tasks(route).unwrap_or_default() {
        if !gated(&task.order.payload) {
            continue;
        }
        let Some(revision) = task.latest_revision() else {
            continue;
        };
        if task
            .reviews
            .iter()
            .any(|review| review.revision == revision && !review.accepted)
        {
            continue;
        }
        let state = gate(route, &task, &policy);
        if state.approved() {
            continue;
        }
        let Some(result) = task.results.iter().find(|r| r.revision == revision) else {
            continue;
        };
        let found = crate::evidence::classify(&task.order.payload, result);
        out.push(Waiting {
            order_id: task.order.id.clone(),
            title: title(&task),
            revision,
            worker: result.agent.clone(),
            diff_stat: crate::evidence::of(&task.order.payload, result)
                .and_then(|evidence| evidence.diff_stat),
            evidence: found.describe(),
            engine: state.engine.clone().ok(),
            ready_for_you: state.engine.is_ok(),
            waiting_for: state.describe(),
        });
    }
    out
}

pub(crate) fn title(task: &Task) -> String {
    task.order.payload["improvement"]["title"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| {
            task.order.payload["task"]
                .as_str()
                .unwrap_or_default()
                .lines()
                .next()
                .unwrap_or_default()
                .chars()
                .take(100)
                .collect()
        })
}

/// The master's decision on an improvement's newest revision, signed by `signer` - the
/// master, or their `review` delegate - in `by`'s name. Approving needs the engine key
/// first; sending back needs notes. Returns the revision decided.
pub fn decide(
    route: &ProjectRoute,
    order_id: &str,
    accept: bool,
    notes: Option<&str>,
    by: &str,
    signer: &AgentIdentity,
) -> Result<u32> {
    let task = crate::read_task(route, order_id)?;
    if !gated(&task.order.payload) {
        bail!("{order_id} is not an improvement; review it the ordinary way");
    }
    let revision = task
        .latest_revision()
        .with_context(|| format!("{order_id} has no result to decide on"))?;
    let mut review = Review {
        order_id: order_id.to_string(),
        revision,
        reviewer: by.to_string(),
        reviewed_at: Utc::now(),
        accepted: accept,
        notes: notes
            .map(str::trim)
            .filter(|notes| !notes.is_empty())
            .map(str::to_string),
        signed_by: None,
        signature: None,
    };
    signer.sign_review(&mut review);
    crate::submit_review(route, &review)?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Order, TaskResult};
    use serde_json::json;
    use std::path::Path;

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    fn josh() -> AgentIdentity {
        person("josh", 1)
    }

    fn wisp() -> AgentIdentity {
        person("wisp", 2)
    }

    fn bridge() -> AgentIdentity {
        person("telegram-grouchly", 3)
    }

    fn route(dir: &Path) -> ProjectRoute {
        let communications = dir.join("demo-ferryman");
        std::fs::create_dir_all(&communications).unwrap();
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
        for member in [josh(), wisp(), bridge()] {
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
        crate::master::initialize_master(&route, &josh(), "josh").unwrap();
        route
    }

    /// An improvement order, done by wisp with evidence that it committed.
    fn improvement(route: &ProjectRoute, id: &str, output: &str) {
        let mut order = Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": "make it better", "tags": [TAG], "improvement": { "title": "Better" } }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
        };
        wisp().sign_order(&mut order);
        crate::issue_order(route, &order).unwrap();
        crate::claim_order(route, id, "wisp").unwrap();
        let mut result = TaskResult {
            order_id: id.into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            // A made-up success carries no evidence; real work carries the worker's.
            payload: if output.contains("no output") {
                json!({ "output": output })
            } else {
                json!({
                    "output": output,
                    "evidence": { "recorded_by": "worker", "git": true, "commits": ["abc1234 better"], "diff_stat": "1 file changed, 3 insertions(+)" },
                })
            },
            signed_by: None,
            signature: None,
        };
        wisp().sign_result(&mut result);
        crate::submit_result(route, &result).unwrap();
    }

    fn engine_review(route: &ProjectRoute, id: &str, engine: &str, paid: &str, accept: bool) {
        record_engine_review(
            route,
            &wisp(),
            EngineReview {
                order_id: id.into(),
                revision: 1,
                reviewer: "wisp".into(),
                machine: "grouchly".into(),
                engine: engine.into(),
                model: Some("deepseek-chat".into()),
                tier: "judge".into(),
                paid: paid.into(),
                host: None,
                route: Vec::new(),
                accept,
                summary: "the change is covered by a test".into(),
                reviewed_at: Utc::now(),
                signed_by: None,
                signature: None,
            },
        )
        .unwrap();
    }

    fn task(route: &ProjectRoute, id: &str) -> Task {
        crate::read_task(route, id).unwrap()
    }

    fn accept_as(
        route: &ProjectRoute,
        id: &str,
        reviewer: &str,
        signer: &AgentIdentity,
    ) -> Result<PathBuf> {
        let mut review = Review {
            order_id: id.into(),
            revision: 1,
            reviewer: reviewer.into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        signer.sign_review(&mut review);
        crate::submit_review(route, &review)
    }

    #[test]
    fn the_engine_alone_is_not_enough() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        improvement(&route, "improve-1", "done: committed abc1234");
        engine_review(&route, "improve-1", "deepseek", "prepaid", true);
        // The engine's agent cannot accept it, even with its own key.
        let error = accept_as(&route, "improve-1", "wisp", &wisp()).unwrap_err();
        assert!(format!("{error:#}").contains("only josh"), "{error:#}");
        let state = gate(&route, &task(&route, "improve-1"), &Policy::default());
        assert!(state.engine.is_ok(), "{state:?}");
        assert!(!state.approved());
        assert!(!approved_for_live(&route, &task(&route, "improve-1")));
        assert!(state.describe().starts_with("waiting for your approval"));
        let waiting = waiting(&route);
        assert_eq!(waiting.len(), 1);
        assert!(waiting[0].ready_for_you);
        assert_eq!(
            waiting[0].diff_stat.as_deref(),
            Some("1 file changed, 3 insertions(+)")
        );
    }

    #[test]
    fn the_master_alone_is_not_enough() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        improvement(&route, "improve-1", "done: committed abc1234");
        let error = decide(&route, "improve-1", true, None, "josh", &josh()).unwrap_err();
        assert!(
            format!("{error:#}").contains("review engine has not reviewed it"),
            "{error:#}"
        );
        assert!(
            task(&route, "improve-1").reviews.is_empty(),
            "nothing was written"
        );
        // Sent back by the engine: still no engine key, and the master cannot override it.
        engine_review(&route, "improve-1", "deepseek", "prepaid", false);
        let error = decide(&route, "improve-1", true, None, "josh", &josh()).unwrap_err();
        assert!(format!("{error:#}").contains("sent it back"), "{error:#}");
        assert!(!waiting(&route)[0].ready_for_you);
    }

    #[test]
    fn both_keys_approve_it_and_nothing_else_does() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        improvement(&route, "improve-1", "done: committed abc1234");
        engine_review(&route, "improve-1", "deepseek", "prepaid", true);
        // The phone, acting on josh's click, needs his review delegation.
        assert!(decide(&route, "improve-1", true, None, "josh", &bridge()).is_err());
        crate::delegation::grant(
            &route.communications,
            "demo",
            &josh(),
            "telegram-grouchly",
            &["review".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(
            decide(&route, "improve-1", true, None, "josh", &bridge()).unwrap(),
            1
        );
        let done = task(&route, "improve-1");
        assert!(approved_for_live(&route, &done));
        let state = gate(&route, &done, &Policy::default());
        assert_eq!(state.describe(), "approved, ready to merge");
        assert!(waiting(&route).is_empty());
    }

    #[test]
    fn an_engine_the_policy_does_not_allow_turns_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        improvement(&route, "improve-1", "done: committed abc1234");
        // A subscription reviewed it: under protect_subscriptions that is no key.
        engine_review(&route, "improve-1", "claude", "subscription", true);
        let why =
            engine_key(&route, &task(&route, "improve-1"), &Policy::default(), 1).unwrap_err();
        assert!(why.contains("subscription"), "{why}");
        // A policy naming deepseek as the review engine counts only deepseek.
        let mut policy = Policy::default();
        policy
            .prefer
            .insert("review".into(), vec!["name:deepseek".into()]);
        crate::policy::set_policy(&route.communications, "demo", Some(policy.clone()), &josh())
            .unwrap();
        engine_review(&route, "improve-1", "nemotron", "free-tier", true);
        let why = engine_key(&route, &task(&route, "improve-1"), &policy, 1).unwrap_err();
        assert!(why.contains("not the policy's review engine"), "{why}");
        assert!(decide(&route, "improve-1", true, None, "josh", &josh()).is_err());
    }

    #[test]
    fn a_refuted_result_carries_no_engine_key() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        // An answer that is no answer: refuted by its own words.
        improvement(&route, "improve-1", "1. no output\n2. no output");
        engine_review(&route, "improve-1", "deepseek", "prepaid", true);
        let why =
            engine_key(&route, &task(&route, "improve-1"), &Policy::default(), 1).unwrap_err();
        assert!(why.contains("does not pass verification"), "{why}");
        assert!(decide(&route, "improve-1", true, None, "josh", &josh()).is_err());
    }

    #[test]
    fn a_forged_approval_or_engine_review_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        improvement(&route, "improve-1", "done: committed abc1234");
        // An engine review in wisp's name, signed by somebody else.
        let mut forged = EngineReview {
            order_id: "improve-1".into(),
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
            summary: "fine".into(),
            reviewed_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        forged.signature = Some(josh().sign_bytes(forged.payload().as_bytes()));
        forged.signed_by = Some("wisp".into());
        crate::atomic_json(&gate_dir(&route, "improve-1").join("r1.wisp.json"), &forged).unwrap();
        assert!(engine_reviews(&route, "improve-1", 1).is_empty());

        // A real engine key, and an approval in josh's name written straight to the file
        // by wisp: it does not verify, so it is no master key.
        engine_review(&route, "improve-1", "deepseek", "prepaid", true);
        let mut approval = Review {
            order_id: "improve-1".into(),
            revision: 1,
            reviewer: "josh".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        wisp().sign_review(&mut approval);
        approval.signed_by = Some("josh".into());
        crate::write_task_file(
            &crate::task_dir(&route, "improve-1").join("review.001.json"),
            &approval,
        )
        .unwrap();
        let task = task(&route, "improve-1");
        assert!(master_key(&route, &task, 1).is_err());
        assert!(!approved_for_live(&route, &task));
    }
}

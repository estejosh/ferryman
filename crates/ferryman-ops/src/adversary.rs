//! Asking the adversary: the engine call, its prompts, and the three moments it runs.
//!
//! The data - the signed finding, its override, what each mode makes of it, the tampering
//! scan - is in [`ferryman_channel::adversary`] and [`ferryman_channel::tamper`]. This
//! module is the part that costs money: choosing an engine that did not build the work,
//! asking it, reading what it says, and recording the answer.
//!
//! # The engine
//!
//! Background work rules apply (`never`, protected subscriptions, caps, `where`), the
//! adversary role's own preferences come first, and then the diversity rule
//! ([`ferryman_channel::policy::diversify`]): never the engine that built the work if any
//! other is allowed, and a different model family from the builder when one is. When the
//! only engine allowed is the builder's own it runs anyway and the finding says so
//! (`same_engine`).
//!
//! # What it is asked
//!
//! Three questions, each with the facts a model would otherwise have to guess - see
//! [`contract_prompt`], [`repeat_prompt`] and [`pre_done_prompt`] - and each ends with the
//! same demand: a final fenced JSON block. A reply that does not carry one is a
//! [`Verdict::Concern`] with what was said as its detail, never a silent pass
//! ([`parse_reply`]).
//!
//! # What does not need asking
//!
//! A provider's payload that does not fit the contract it proposes, and a diff that
//! deletes tests, are facts. They are checked first, deterministically, and the model is
//! shown them. A deterministic High at the repeat-failure moment blocks even when no
//! engine is available to ask: the finding is then recorded as the scan's own.

use std::{path::Path, process::Command};

use anyhow::Result;
use chrono::{DateTime, Utc};
use ferryman_channel::{
    AgentIdentity, ProjectRoute, Task, TaskResult, TaskState,
    adversary::{
        self as data, AdversaryFinding, ContractContext, Issue, RepeatFailure, Severity, Trigger,
        Verdict,
    },
    interface::{self},
    policy::{AdversaryMode, Builder, Policy, Role, Step},
    questions, tamper,
};
use serde_json::Value;

use crate::{
    Progress,
    agent::AgentConfig,
    engines::{self, EngineSpec},
};

/// What the model is told to end with.
const REPLY_FORMAT: &str = "\
End your reply with exactly one fenced JSON block, and nothing after it:\n\
```json\n\
{\"verdict\": \"pass\" | \"concern\" | \"block\",\n \
\"findings\": [{\"severity\": \"low\" | \"medium\" | \"high\", \"title\": \"short\", \
\"detail\": \"what is wrong, specifically, and what would fix it\", \
\"location\": \"file:line, a contract field, or null\"}]}\n\
```\n\
pass: nothing worth stopping for. concern: read this before going on. block: do not go on. \
Be specific and cite what you saw; a finding with no evidence in what you were shown is \
noise. Do not praise the work.";

const ADVERSARY_STANCE: &str = "\
You are the adversary. You did not build this and you are not here to be agreeable: the \
builders were cheaper models and a second, independent reading exists to catch what they \
and their reviewer overlooked. Challenge it.\n\n";

/// How much of one thing (a diff, a check's output) goes into a prompt.
const DIFF_CHARS: usize = 24_000;
const TAIL_CHARS: usize = 1_500;
const TEXT_CHARS: usize = 3_000;
/// The most the scan reads of a diff.
const SCAN_BYTES: usize = 2 * 1024 * 1024;

fn clip(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit).collect();
    format!(
        "{kept}\n... [{} more characters not shown]",
        text.chars().count() - limit
    )
}

fn tail(text: &str, limit: usize) -> String {
    let count = text.chars().count();
    if count <= limit {
        return text.trim().to_string();
    }
    let kept: String = text.chars().skip(count - limit).collect();
    format!("...{}", kept.trim())
}

// --- reading a reply ---------------------------------------------------------------------

/// What the adversary's reply came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub verdict: Verdict,
    pub issues: Vec<Issue>,
    /// `false` when the reply carried no readable verdict, and `verdict` is the Concern
    /// that stands in for it.
    pub readable: bool,
}

/// Every top-level `{...}` in `text`, string-aware, in order.
fn balanced_objects(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let (mut depth, mut start, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for (index, c) in text.char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' if depth > 0 => in_string = true,
            '{' => {
                if depth == 0 {
                    start = index;
                }
                depth += 1;
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    found.push(&text[start..=index]);
                }
            }
            _ => {}
        }
    }
    found
}

/// The bodies of the fenced blocks in `text`, in order.
fn fenced_blocks(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("```") {
        let after = &rest[open + 3..];
        // Skip the language tag on the opening line.
        let body_start = after.find('\n').map_or(0, |newline| newline + 1);
        let body = &after[body_start..];
        let Some(close) = body.find("```") else {
            break;
        };
        found.push(&body[..close]);
        rest = &body[close + 3..];
    }
    found
}

fn issue_from(value: &Value) -> Option<Issue> {
    let object = value.as_object()?;
    let text = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    };
    let title = text("title")
        .or_else(|| text("summary"))
        .or_else(|| text("detail"))?;
    Some(Issue {
        severity: text("severity")
            .and_then(|severity| Severity::parse(severity).ok())
            .unwrap_or(Severity::Medium),
        title: clip(title, 200),
        detail: clip(
            text("detail").or_else(|| text("description")).unwrap_or(""),
            TAIL_CHARS,
        ),
        location: text("location").map(|place| clip(place, 200)),
    })
}

fn reply_from(value: &Value) -> Option<Reply> {
    let verdict = Verdict::parse(value.get("verdict")?.as_str()?).ok()?;
    let issues: Vec<Issue> = value
        .get("findings")
        .or_else(|| value.get("issues"))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(issue_from).take(12).collect())
        .unwrap_or_default();
    // A pass that lists a High finding says two things at once; the louder one stands.
    let verdict = if verdict == Verdict::Pass
        && issues.iter().any(|issue| issue.severity == Severity::High)
    {
        Verdict::Concern
    } else {
        verdict
    };
    Some(Reply {
        verdict,
        issues,
        readable: true,
    })
}

/// Read the adversary's reply: the last fenced JSON block (or, failing that, the last
/// JSON object) that carries a verdict. A reply that has none is a Concern holding the
/// end of what was said - never a Pass, because "could not read it" is not "found nothing".
#[must_use]
pub fn parse_reply(text: &str) -> Reply {
    let mut candidates: Vec<&str> = fenced_blocks(text);
    candidates.extend(balanced_objects(text));
    // The last one wins: a model that thinks aloud may draft one earlier.
    for candidate in candidates.into_iter().rev() {
        if let Ok(value) = serde_json::from_str::<Value>(candidate.trim())
            && let Some(reply) = reply_from(&value)
        {
            return reply;
        }
    }
    Reply {
        verdict: Verdict::Concern,
        issues: vec![Issue {
            severity: Severity::Medium,
            title: "the adversary's reply could not be read".to_string(),
            detail: if text.trim().is_empty() {
                "the reply was empty".to_string()
            } else {
                format!(
                    "it carried no JSON block with a verdict. The end of it: {}",
                    tail(text, TAIL_CHARS)
                )
            },
            location: None,
        }],
        readable: false,
    }
}

// --- the prompts -------------------------------------------------------------------------

fn order_text(task: &Task) -> String {
    let payload = &task.order.payload;
    let mut text = payload
        .get("task")
        .and_then(Value::as_str)
        .map_or_else(|| payload.to_string(), str::to_string);
    let acceptance = ferryman_channel::evidence::acceptance(payload);
    if !acceptance.is_empty() {
        text.push_str("\n\nAcceptance criteria:\n");
        for line in acceptance {
            text.push_str(&format!("- {line}\n"));
        }
    }
    clip(&text, TEXT_CHARS)
}

/// The prompt for the moment before a contract locks.
#[must_use]
pub fn contract_prompt(context: &ContractContext) -> String {
    let contract = &context.contract;
    let pretty = |shape: &Option<ferryman_channel::contract::Shape>| {
        shape.as_ref().map_or_else(
            || "(none)".to_string(),
            |shape| serde_json::to_string_pretty(shape).unwrap_or_default(),
        )
    };
    let mut text = format!(
        "{ADVERSARY_STANCE}Moment: an interface contract is about to be LOCKED by the master. \
         After that it never changes - a change is a new version - and two sets of builders \
         will build to it in parallel.\n\n\
         Contract {} proposed by {}.\n{}\n\n\
         Request shape:\n{}\n\n\
         Response shape:\n{}\n\n",
        contract.reference(),
        contract.proposed_by,
        clip(contract.description.trim(), TEXT_CHARS),
        pretty(&contract.request),
        serde_json::to_string_pretty(&contract.response).unwrap_or_default(),
    );
    match &context.provider_result {
        Some(result) => {
            text.push_str(&format!(
                "The provider's order {} has a result (r{}). What it returns:\n{}\n\n",
                context.order_id,
                context.revision,
                clip(
                    &serde_json::to_string_pretty(result.get("response").unwrap_or(result))
                        .unwrap_or_default(),
                    TEXT_CHARS
                )
            ));
            if context.precheck.is_empty() {
                text.push_str("A mechanical check of that response against the proposed response shape found nothing wrong.\n\n");
            } else {
                text.push_str("A mechanical check of that response against the proposed response shape FAILED:\n");
                for line in &context.precheck {
                    text.push_str(&format!("- {line}\n"));
                }
                text.push('\n');
            }
        }
        None => text.push_str(
            "No provider has returned a result yet, so there is nothing to compare: review the \
             contract's shapes on their own.\n\n",
        ),
    }
    if context.consumers.is_empty() {
        text.push_str("No consumer order references this contract yet.\n\n");
    } else {
        text.push_str("What the consumers are building (their orders, in their own words):\n");
        for (id, order) in &context.consumers {
            text.push_str(&format!("--- consumer {id}\n{}\n", clip(order, TEXT_CHARS)));
        }
        text.push('\n');
    }
    text.push_str(
        "Question: does what the provider will return match what the consumers expect? Look \
         for fields a consumer needs that the response lacks, types and nullability that \
         differ from what the consumer's text assumes, enums that will not stay closed, \
         missing error and empty shapes, pagination and ordering the consumers rely on, and \
         anything ambiguous enough that two builders would read it two ways. Prefer a few \
         real mismatches over a long list.\n\n",
    );
    text.push_str(REPLY_FORMAT);
    text
}

/// The prompt for the order that has now failed twice.
#[must_use]
pub fn repeat_prompt(
    task: &Task,
    repeat: &RepeatFailure,
    hits: &[tamper::Hit],
    diff: Option<&str>,
) -> String {
    let mut text = format!(
        "{ADVERSARY_STANCE}Moment: this order has now failed {} times, and another attempt is \
         about to start. Before it does: is the work fixing the cause, or hiding the symptom?\n\n\
         The order:\n{}\n\n",
        repeat.failures.len(),
        order_text(task)
    );
    let required = ferryman_channel::evidence::required_checks(&task.order.payload);
    if !required.is_empty() {
        text.push_str("Checks the order requires (the worker runs them itself):\n");
        for argv in &required {
            text.push_str(&format!("- `{}`\n", argv.join(" ")));
        }
        text.push('\n');
    }
    for failed in &repeat.failures {
        text.push_str(&format!(
            "Revision {}{}:\n",
            failed.revision,
            failed
                .builder
                .as_ref()
                .map(|builder| format!(" (built by {})", builder.engine))
                .unwrap_or_default()
        ));
        for reason in &failed.reasons {
            text.push_str(&format!("- {}\n", clip(reason, 600)));
        }
        for (command, code, output) in &failed.checks {
            text.push_str(&format!(
                "  `{command}` {}; the end of what it printed:\n{}\n",
                code.map_or_else(
                    || "did not finish".to_string(),
                    |code| format!("exited {code}")
                ),
                tail(output, TAIL_CHARS)
            ));
        }
        text.push('\n');
    }
    if hits.is_empty() {
        text.push_str(
            "A deterministic scan of the branch's diff for test tampering found nothing.\n\n",
        );
    } else {
        text.push_str("A deterministic scan of the branch's diff for test tampering found:\n");
        for line in tamper::describe(hits) {
            text.push_str(&format!("- {line}\n"));
        }
        text.push('\n');
    }
    match diff {
        Some(diff) if !diff.trim().is_empty() => text.push_str(&format!(
            "The order's branch against its base:\n```diff\n{}\n```\n\n",
            clip(diff, DIFF_CHARS)
        )),
        _ => text.push_str("The branch's diff was not available on this machine.\n\n"),
    }
    text.push_str(
        "Question: is this fixing the cause or hiding the symptom? A fix changes the code \
         the failing check exercises. Hiding changes what the check sees: tests deleted, \
         skipped or loosened, assertions weakened, a command that can no longer fail, a \
         special case that returns the expected value. Say which this is, and for a block, \
         what the next attempt must do instead. Block when the failures are being hidden \
         rather than fixed.\n\n",
    );
    text.push_str(REPLY_FORMAT);
    text
}

/// The prompt for the moment before an improvement is called done.
#[must_use]
pub fn pre_done_prompt(
    task: &Task,
    result: &TaskResult,
    hits: &[tamper::Hit],
    diff: Option<&str>,
) -> String {
    let mut text = format!(
        "{ADVERSARY_STANCE}Moment: this improvement is about to be called DONE. The review \
         engine will read it next and then its master. Before that: what attack surface or \
         edge case did everyone overlook?\n\nThe order:\n{}\n\n",
        order_text(task)
    );
    let answer = result
        .payload
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or_default();
    text.push_str(&format!(
        "What the builder said it did (r{}, engine {}):\n{}\n\n",
        result.revision,
        result
            .payload
            .get("engine")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        clip(answer, TEXT_CHARS)
    ));
    if let Some(evidence) = ferryman_channel::evidence::of(&task.order.payload, result) {
        text.push_str(&format!(
            "What the worker process recorded itself (not written by the model): {}\n",
            evidence.describe()
        ));
        if !evidence.touched_files.is_empty() {
            text.push_str(&format!(
                "Files the commit changed: {}\n",
                evidence.touched_files.join(", ")
            ));
        }
        for note in &evidence.notes {
            text.push_str(&format!("Scope note: {note}\n"));
        }
        for check in &evidence.checks {
            text.push_str(&format!(
                "`{}` {}:\n{}\n",
                check.command,
                check.exit_code.map_or_else(
                    || "did not finish".to_string(),
                    |code| format!("exited {code}")
                ),
                tail(&check.tail, TAIL_CHARS)
            ));
        }
        text.push('\n');
    }
    if !hits.is_empty() {
        text.push_str("A deterministic scan of the diff for test tampering found:\n");
        for line in tamper::describe(hits) {
            text.push_str(&format!("- {line}\n"));
        }
        text.push('\n');
    }
    match diff {
        Some(diff) if !diff.trim().is_empty() => text.push_str(&format!(
            "The final diff against the base:\n```diff\n{}\n```\n\n",
            clip(diff, DIFF_CHARS)
        )),
        _ => text.push_str("The diff was not available on this machine.\n\n"),
    }
    text.push_str(
        "Question: what did everyone overlook? Think like someone attacking this or using it \
         badly: unvalidated input, injection, paths that escape a directory, secrets in logs, \
         authorization that is checked on one path and not another, races and ordering, \
         unbounded growth, error paths that leave state half-written, behaviour that breaks \
         callers who relied on the old one, and tests that pass without proving the claim. \
         Check that the change matches the order's scope - files outside it deserve a reason.\n\n",
    );
    text.push_str(REPLY_FORMAT);
    text
}

// --- the engine --------------------------------------------------------------------------

/// The allowed engine to ask next, skipping those `tried`, and whether it is one that
/// built the work: or why there is none. Never an engine the policy blocks.
pub fn choose(
    config: &AgentConfig,
    policy: &Policy,
    built_by: &[Builder],
    tried: &[String],
    now: DateTime<Utc>,
) -> std::result::Result<(EngineSpec, bool), String> {
    let machine = ferryman_channel::receipts::machine_label();
    let ledger = engines::Ledger::load(&config.agent);
    let specs = engines::effective_specs(&config.engines, &ledger);
    let all = engines::candidates(&config.agent, &machine, &specs, &ledger, now);
    let ranked = ferryman_channel::policy::rank_adversary(policy, built_by, &all);
    ranked
        .ranking
        .order
        .iter()
        .zip(&ranked.same_engine)
        .map(|(index, same)| (&specs[*index], *same))
        .find(|(spec, _)| !tried.contains(&spec.name))
        .map(|(spec, same)| (spec.clone(), same))
        .ok_or_else(|| {
            if ranked.ranking.order.is_empty() {
                ranked.ranking.why_none(Role::Adversary, &all)
            } else {
                format!(
                    "every allowed engine for adversary work was tried ({})",
                    tried.join(", ")
                )
            }
        })
}

fn signing_identity(route: &ProjectRoute, config: &AgentConfig) -> Result<AgentIdentity> {
    AgentIdentity::load_existing(&config.agent, &route.attachment)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no key for '{}' in {}, so nothing could be signed",
            config.agent,
            route.attachment.display()
        )
    })
}

/// One challenge to run.
#[derive(Debug, Clone)]
pub struct Request {
    pub subject: String,
    pub order_id: String,
    pub revision: u32,
    pub trigger: Trigger,
    pub built_by: Vec<Builder>,
    pub prompt: String,
    /// What no model was needed to find, shown first.
    pub known: Vec<Issue>,
    /// The verdict is at least this, whatever the model says.
    pub floor: Verdict,
}

/// What asking came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The policy's adversary is `off`.
    Off,
    /// A genuine finding was already there; nothing was asked.
    Existing(Box<AdversaryFinding>),
    /// Nothing the policy allows could be asked: the work waits, and the master was asked
    /// once this week.
    Held(String),
    /// Every allowed engine was asked and none answered.
    Failed(String),
    /// This agent's word on the subject would not count - it built the work, has no signed
    /// engine inventory listing the engine, is outside the policy's `where`, or the revision
    /// is not a real one - so nothing was paid for. Why, in the words `ferry adversary show`
    /// uses for an ignored finding.
    Ineligible(String),
    /// Asked, and recorded.
    Recorded(Box<AdversaryFinding>),
}

impl Outcome {
    /// The finding, when there is one.
    #[must_use]
    pub fn finding(&self) -> Option<&AdversaryFinding> {
        match self {
            Self::Existing(finding) | Self::Recorded(finding) => Some(finding),
            _ => None,
        }
    }
}

fn note_step(
    route: &ProjectRoute,
    config: &AgentConfig,
    identity: &AgentIdentity,
    week: &str,
    subject: &str,
    engine: Option<(&EngineSpec, f64)>,
    outcome: String,
) {
    let step = Step {
        step: "adversary".to_string(),
        role: Some(Role::Adversary.as_str().to_string()),
        at: Utc::now(),
        agent: config.agent.clone(),
        machine: ferryman_channel::receipts::machine_label(),
        engine: engine.map(|(engine, _)| engine.name.clone()),
        model: engine.and_then(|(engine, _)| engine.model.clone()),
        cost_usd: engine.map(|(_, cost)| cost),
        order: Some(subject.to_string()),
        effort: engines::effort_used(route, Role::Adversary, engine.map(|(engine, _)| engine)),
        outcome,
    };
    if let Err(error) = ferryman_channel::policy::record_step(route, identity, week, step) {
        tracing::warn!("could not record the adversary step: {error:#}");
    }
}

/// Adversary work the policy leaves nothing to do: say why, and ask the master - once per
/// week, however many machines and hours it stays held.
fn hold(route: &ProjectRoute, config: &AgentConfig, week: &str, why: &str, report: &dyn Progress) {
    report.warn(&format!(
        "  {}: adversary work held: {why}",
        route.project_id
    ));
    if let Ok(identity) = signing_identity(route, config)
        && let Ok(true) =
            ferryman_channel::policy::ask_hold(route, &identity, Role::Adversary, week, why)
    {
        report.info(&format!(
            "  {}: asked the master what to do about the held adversary work",
            route.project_id
        ));
    }
}

/// Run one challenge: ask the best engine that did not build the work, fall through the
/// ones that are out of credit or fail, and record what it says, signed by this agent.
/// Idempotent - a genuine finding for the same (subject, revision, trigger) is returned
/// as it is - and silent when the adversary is off.
pub async fn challenge(
    route: &ProjectRoute,
    config: &AgentConfig,
    policy: &Policy,
    request: Request,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> Outcome {
    if policy.adversary == AdversaryMode::Off {
        return Outcome::Off;
    }
    let identity = match signing_identity(route, config) {
        Ok(identity) => identity,
        Err(error) => return Outcome::Failed(format!("{error:#}")),
    };
    if let Some(existing) = data::read(
        route,
        &request.subject,
        request.revision,
        request.trigger,
        identity.name(),
    ) {
        return Outcome::Existing(Box::new(existing));
    }
    // Whether this agent would be heard at all, before any engine is paid for: a finding
    // that would be ignored is money spent on nothing.
    if let Err(why) = data::eligibility(
        route,
        &request.subject,
        request.revision,
        request.trigger,
        identity.name(),
        None,
    ) {
        return Outcome::Ineligible(why);
    }
    let week = engines::iso_week(now);
    if let Some(why) = ferryman_channel::policy::over_cap(route, policy, &week, Role::Adversary) {
        hold(route, config, &week, &why, report);
        return Outcome::Held(why);
    }
    let mut tried: Vec<String> = Vec::new();
    loop {
        let (engine, same_engine) = match choose(config, policy, &request.built_by, &tried, now) {
            Ok(chosen) => chosen,
            Err(why) if tried.is_empty() => {
                hold(route, config, &week, &why, report);
                return Outcome::Held(why);
            }
            Err(why) => {
                note_step(
                    route,
                    config,
                    &identity,
                    &week,
                    &request.subject,
                    None,
                    format!("{}: failed: {why}", request.trigger.as_str()),
                );
                return Outcome::Failed(why);
            }
        };
        tried.push(engine.name.clone());
        // The finding names its engine, and counts only if this agent's signed inventory
        // lists it: an engine that is not there is not one to ask.
        if let Err(why) = data::eligibility(
            route,
            &request.subject,
            request.revision,
            request.trigger,
            identity.name(),
            Some(&engine.name),
        ) {
            report.warn(&format!(
                "  {}: not asking {} about {}: {why}",
                route.project_id, engine.name, request.subject
            ));
            continue;
        }
        let effort = policy.effort_for(Role::Adversary);
        let asked = crate::agent::ask_costed(
            route,
            &config.with_engine_effort(&engine, Some(effort)),
            &request.prompt,
        )
        .await;
        let (answer, cost) = match asked {
            Ok(answered) => answered,
            Err(error) => {
                if let Some(skip) = error.downcast_ref::<engines::Unavailable>() {
                    crate::agent::note_unavailable(route, config, skip);
                }
                report.warn(&format!(
                    "  {}: {} could not challenge {}, trying the next engine: {error:#}",
                    route.project_id, engine.name, request.subject
                ));
                continue;
            }
        };
        let reply = parse_reply(&answer);
        let mut findings = request.known.clone();
        findings.extend(reply.issues);
        let finding = AdversaryFinding {
            order_id: request.order_id.clone(),
            revision: request.revision,
            trigger: request.trigger,
            subject: request.subject.clone(),
            engine: engine.name.clone(),
            model: engine.model.clone().or_else(|| config.model.clone()),
            machine: ferryman_channel::receipts::machine_label(),
            same_engine,
            verdict: reply.verdict.max(request.floor),
            findings,
            created_at: Utc::now(),
            signed_by: String::new(),
            signature: String::new(),
        };
        return record(
            route,
            config,
            &identity,
            &week,
            finding,
            Some((&engine, cost)),
            report,
        );
    }
}

/// Write `finding`, note the step, and say so.
fn record(
    route: &ProjectRoute,
    config: &AgentConfig,
    identity: &AgentIdentity,
    week: &str,
    finding: AdversaryFinding,
    engine: Option<(&EngineSpec, f64)>,
    report: &dyn Progress,
) -> Outcome {
    match data::record(route, identity, finding.clone()) {
        Ok(_) => {}
        Err(error) => return Outcome::Failed(format!("could not record the finding: {error:#}")),
    }
    note_step(
        route,
        config,
        identity,
        week,
        &finding.subject,
        engine,
        format!(
            "{}: {} - {} finding(s)",
            finding.trigger.as_str(),
            finding.verdict.as_str(),
            finding.findings.len()
        ),
    );
    let line = format!(
        "  {}: adversary on {} ({}): {}",
        route.project_id,
        finding.subject,
        finding.trigger.label(),
        finding.describe()
    );
    if finding.verdict == Verdict::Block {
        report.warn(&line);
    } else {
        report.info(&line);
    }
    // Read back what was written, so the caller sees what every machine will see.
    let stored = data::read(
        route,
        &finding.subject,
        finding.revision,
        finding.trigger,
        identity.name(),
    )
    .unwrap_or(finding);
    Outcome::Recorded(Box::new(stored))
}

// --- the diff ----------------------------------------------------------------------------

fn git_output(workspace: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| {
        let bytes = &out.stdout[..out.stdout.len().min(SCAN_BYTES)];
        String::from_utf8_lossy(bytes).into_owned()
    })
}

/// The order branch's diff against its base, as this machine's repository has it: the
/// reviewed commit the result names, else the branch, else the branch on `origin`. `None`
/// when the workspace is not a git repository or none of them is here.
#[must_use]
pub fn order_diff(route: &ProjectRoute, result: &TaskResult) -> Option<String> {
    let workspace = &route.workspace;
    if !ferryman_channel::worktree::is_git_repo(workspace) {
        return None;
    }
    let (base, _) = ferryman_channel::worktree::task_base(workspace);
    let branch = ferryman_channel::worktree::branch_name(&result.order_id, &result.agent);
    let mut tips: Vec<String> = Vec::new();
    if let Some(head) = result.payload.get("worktree_head").and_then(Value::as_str) {
        tips.push(head.to_string());
    }
    tips.push(branch.clone());
    tips.push(format!("origin/{branch}"));
    tips.into_iter().find_map(|tip| {
        git_output(
            workspace,
            &[
                "diff",
                "--no-color",
                "-M",
                "-U3",
                &format!("{base}...{tip}"),
                "--",
                ".",
                ":(exclude).ferryman",
            ],
        )
    })
}

/// Whether nothing is left for `me` to ask at (subject, revision, trigger): this agent has
/// already run, or an eligible adversary's finding already stands there. Each eligible
/// adversary may run its own pass ([`data::done`] is per signer), but a moment that has a
/// finding that counts is not paid for again by every worker in the fleet.
fn settled(route: &ProjectRoute, subject: &str, revision: u32, trigger: Trigger, me: &str) -> bool {
    data::done(route, subject, revision, trigger, me)
        || data::standing(route, subject, revision, trigger).is_some()
}

// --- moment 1: before a contract locks --------------------------------------------------------

fn precheck_issues(context: &ContractContext) -> Vec<Issue> {
    context
        .precheck
        .iter()
        .map(|line| Issue {
            severity: Severity::High,
            title: "the provider's response does not fit the proposed shape".to_string(),
            detail: line.clone(),
            location: Some(context.contract.reference()),
        })
        .collect()
}

/// Challenge every contract waiting for its lock that the adversary has not yet read at
/// its newest provider result: with the shapes, the provider's result (if any), the
/// consumers' orders and the mechanical check of one against the other. Returns how many
/// were challenged now.
pub async fn contract_pass(
    route: &ProjectRoute,
    config: &AgentConfig,
    policy: &Policy,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> usize {
    let Ok(pending) = interface::pending_locks(route) else {
        return 0;
    };
    let Ok(identity) = signing_identity(route, config) else {
        return 0;
    };
    let mut challenged = 0;
    for contract in pending {
        let Ok(context) = data::contract_context(route, &contract) else {
            continue;
        };
        let reference = contract.reference();
        if settled(
            route,
            &reference,
            context.revision,
            Trigger::ContractLock,
            identity.name(),
        ) {
            continue;
        }
        let request = Request {
            subject: reference,
            order_id: context.order_id.clone(),
            revision: context.revision,
            trigger: Trigger::ContractLock,
            built_by: context.builders.clone(),
            prompt: contract_prompt(&context),
            known: precheck_issues(&context),
            // A response that does not fit the shape it is meant to fit is a fact.
            floor: if context.precheck.is_empty() {
                Verdict::Pass
            } else {
                Verdict::Block
            },
        };
        match challenge(route, config, policy, request, now, report).await {
            Outcome::Recorded(_) => challenged += 1,
            Outcome::Held(_)
            | Outcome::Failed(_)
            | Outcome::Ineligible(_)
            | Outcome::Off
            | Outcome::Existing(_) => {}
        }
    }
    challenged
}

// --- moment 3: before an improvement is called done --------------------------------------------

fn required_of(task: &Task) -> Vec<Vec<String>> {
    ferryman_channel::evidence::required_checks(&task.order.payload)
}

/// Challenge every improvement result that is waiting for the review engine and that the
/// adversary has not yet read at this revision. Results the worker's own evidence already
/// refutes are not asked about: they are sent back without a model. Returns how many were
/// challenged now.
pub async fn pre_done_pass(
    route: &ProjectRoute,
    config: &AgentConfig,
    policy: &Policy,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> usize {
    let Ok(identity) = signing_identity(route, config) else {
        return 0;
    };
    let mut challenged = 0;
    for task in ferryman_channel::list_tasks(route).unwrap_or_default() {
        if !ferryman_channel::gate::gated(&task.order.payload) {
            continue;
        }
        let TaskState::AwaitingReview { revision, .. } = task.state() else {
            continue;
        };
        let Some(result) = task.results.iter().find(|r| r.revision == revision) else {
            continue;
        };
        if ferryman_channel::evidence::blocking_reason(&task.order.payload, result).is_some()
            || task.contract_refusal(route, revision).is_some()
            || settled(
                route,
                &task.order.id,
                revision,
                Trigger::PreDone,
                identity.name(),
            )
        {
            continue;
        }
        let diff = order_diff(route, result);
        let hits = diff
            .as_deref()
            .map(|diff| tamper::scan(diff, &required_of(&task)))
            .unwrap_or_default();
        let request = Request {
            subject: task.order.id.clone(),
            order_id: task.order.id.clone(),
            revision,
            trigger: Trigger::PreDone,
            built_by: Builder::from_payload(&result.payload).into_iter().collect(),
            prompt: pre_done_prompt(&task, result, &hits, diff.as_deref()),
            known: hits.iter().map(tamper::Hit::issue).collect(),
            floor: Verdict::Pass,
        };
        if let Outcome::Recorded(_) = challenge(route, config, policy, request, now, report).await {
            challenged += 1;
        }
    }
    challenged
}

/// Whether the review engine may judge `task` now. Always, unless the policy's adversary
/// is `blocking` and an improvement's newest result has either not been read by the
/// adversary yet or has a Block nobody overrode: then the judge waits, and no judge is
/// paid for a key that would not count.
#[must_use]
pub fn may_judge(route: &ProjectRoute, policy: &Policy, task: &Task) -> bool {
    if policy.adversary != AdversaryMode::Blocking
        || !ferryman_channel::gate::gated(&task.order.payload)
    {
        return true;
    }
    let Some(result) = task
        .latest_revision()
        .and_then(|revision| task.results.iter().find(|r| r.revision == revision))
    else {
        return true;
    };
    // Sent back on the worker's own evidence, with no model: nothing to wait for.
    if ferryman_channel::evidence::blocking_reason(&task.order.payload, result).is_some() {
        return true;
    }
    // The one question the engine key asks too: an eligible adversary's finding on exactly
    // this revision that holds nothing back, or the master's waiver.
    data::engine_key_refusal(route, policy, &task.order.id, result.revision).is_none()
}

/// Every moment the improve loop's review pass owns: contracts waiting for a lock, and
/// improvements waiting for the review engine. Returns how many were challenged now.
pub async fn pass(
    route: &ProjectRoute,
    config: &AgentConfig,
    policy: &Policy,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> usize {
    if policy.adversary == AdversaryMode::Off {
        return 0;
    }
    contract_pass(route, config, policy, now, report).await
        + pre_done_pass(route, config, policy, now, report).await
}

// --- moment 2: the order has failed twice --------------------------------------------------------

/// What the worker does with an order after the adversary has had its say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Go ahead; the next attempt's prompt carries any Block.
    Proceed,
    /// Do not start: the master took the order over.
    Hold(String),
}

/// The answer that takes the order out of the fleet's hands.
pub const TAKE_OVER: &str = "I'll take it from here";
/// The answer that lets the next attempt go ahead with the finding in its prompt.
pub const UNDERSTOOD: &str = "Understood";

fn block_question(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    finding: &AdversaryFinding,
) -> Result<bool> {
    let mut text = format!(
        "{} has failed twice and the adversary ({}) blocked the next attempt as it stood.\n",
        finding.subject, finding.engine
    );
    for line in finding.lines(3) {
        text.push_str(&format!("{line}\n"));
    }
    text.push_str(
        "\nThe next attempt is told what the adversary found and must fix the cause. Let it \
         go on, or take the order over yourself.",
    );
    questions::ask(
        route,
        identity,
        &format!("adversary-block-{}-r{}", finding.subject, finding.revision),
        questions::ADVERSARY,
        &text,
        &[UNDERSTOOD.to_string(), TAKE_OVER.to_string()],
        Some(&finding.subject),
    )
}

/// Before the next attempt at `task` starts: when it has failed twice, scan the branch's
/// diff for test tampering, ask the adversary whether the work fixes the cause or hides
/// the symptom, and record its finding. A Block - or any High tampering hit, even when the
/// adversary is only advisory, even with no engine to ask - is carried into the next
/// attempt's prompt ([`ferryman_channel::adversary::attempt_notice`]) and put to the
/// master once, with buttons.
pub async fn before_attempt(
    route: &ProjectRoute,
    config: &AgentConfig,
    task: &Task,
    now: DateTime<Utc>,
    report: &dyn Progress,
) -> Gate {
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    if policy.adversary == AdversaryMode::Off
        || !matches!(task.state(), TaskState::ChangesRequested { .. })
    {
        return Gate::Proceed;
    }
    let Some(repeat) = data::repeat_failure(task) else {
        return Gate::Proceed;
    };
    let id = task.order.id.clone();
    let revision = repeat.latest;
    // One paid look per failed attempt: when this agent has run, or an eligible adversary's
    // finding already stands, nothing is asked again.
    let me = signing_identity(route, config).ok();
    let asked = me.as_ref().is_some_and(|identity| {
        settled(
            route,
            &id,
            revision,
            Trigger::RepeatFailure,
            identity.name(),
        )
    });
    if !asked {
        let result = task.results.iter().find(|r| r.revision == revision);
        let diff = result.and_then(|result| order_diff(route, result));
        let hits = diff
            .as_deref()
            .map(|diff| tamper::scan(diff, &required_of(task)))
            .unwrap_or_default();
        let tampered = tamper::has_high(&hits);
        let request = Request {
            subject: id.clone(),
            order_id: id.clone(),
            revision,
            trigger: Trigger::RepeatFailure,
            built_by: repeat
                .failures
                .iter()
                .filter_map(|failed| failed.builder.clone())
                .collect(),
            prompt: repeat_prompt(task, &repeat, &hits, diff.as_deref()),
            known: hits.iter().map(tamper::Hit::issue).collect(),
            floor: if tampered {
                Verdict::Block
            } else {
                Verdict::Pass
            },
        };
        match challenge(route, config, &policy, request, now, report).await {
            Outcome::Off => return Gate::Proceed,
            Outcome::Held(why) | Outcome::Failed(why) | Outcome::Ineligible(why) if tampered => {
                // No engine could be asked, but the scan found what it found.
                scan_only(route, config, &id, revision, &hits, &why, report);
            }
            Outcome::Recorded(_)
            | Outcome::Existing(_)
            | Outcome::Held(_)
            | Outcome::Failed(_)
            | Outcome::Ineligible(_) => {}
        }
    }
    // What counts is what an eligible adversary said about exactly this failed attempt.
    let Some(standing) = data::standing(route, &id, revision, Trigger::RepeatFailure) else {
        return Gate::Proceed;
    };
    if standing.verdict() != Verdict::Block {
        return Gate::Proceed;
    }
    let finding = standing.finding.clone();
    if let Ok(identity) = signing_identity(route, config) {
        match block_question(route, &identity, &finding) {
            Ok(true) => report.info(&format!(
                "  {id}: asked the master about the adversary's Block"
            )),
            Ok(false) => {}
            Err(error) => report.warn(&format!(
                "  {id}: could not ask the master about the Block: {error:#}"
            )),
        }
    }
    let question = format!("adversary-block-{}-r{}", finding.subject, finding.revision);
    let taken = questions::read(route, &question)
        .and_then(|asked| questions::answer_to(route, &asked))
        .is_some_and(|answer| answer.answer == TAKE_OVER);
    if taken {
        return Gate::Hold(format!(
            "the master took {id} over after the adversary blocked it ({})",
            finding.describe()
        ));
    }
    report.warn(&format!(
        "  {id}: the adversary blocked the next attempt as it stood; the attempt is told why"
    ));
    Gate::Proceed
}

/// The deterministic finding for a diff whose scan found a High hit when no engine could be
/// asked: signed by this agent, with the scan as the engine.
fn scan_only(
    route: &ProjectRoute,
    config: &AgentConfig,
    id: &str,
    revision: u32,
    hits: &[tamper::Hit],
    why: &str,
    report: &dyn Progress,
) -> Option<AdversaryFinding> {
    let identity = signing_identity(route, config).ok()?;
    let mut findings: Vec<Issue> = hits.iter().map(tamper::Hit::issue).collect();
    findings.push(Issue {
        severity: Severity::Low,
        title: "no adversary engine was asked".to_string(),
        detail: why.to_string(),
        location: None,
    });
    let finding = AdversaryFinding {
        order_id: id.to_string(),
        revision,
        trigger: Trigger::RepeatFailure,
        subject: id.to_string(),
        engine: data::TAMPER_SCAN.to_string(),
        model: None,
        machine: ferryman_channel::receipts::machine_label(),
        same_engine: false,
        verdict: Verdict::Block,
        findings,
        created_at: Utc::now(),
        signed_by: String::new(),
        signature: String::new(),
    };
    match record(
        route,
        config,
        &identity,
        &engines::iso_week(Utc::now()),
        finding,
        None,
        report,
    ) {
        Outcome::Recorded(finding) => Some(*finding),
        _ => None,
    }
}

// --- what it found, for status and the weekly report -------------------------------------------

/// What the adversary has found in one project, counted: for `ferry improve status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Summary {
    /// `off`, `advisory` or `blocking`.
    pub mode: String,
    pub findings: usize,
    pub blocks: usize,
    pub concerns: usize,
    pub passes: usize,
    /// Blocks nobody has overridden: `t-1 r2 (pre-done)`.
    pub unresolved: Vec<String>,
    /// Genuine findings that do not count (their signer built the work, has no signed
    /// inventory listing the engine, ...): see `ferry adversary show`.
    pub ignored: usize,
}

/// Count the project's genuine findings and list the Blocks still standing.
#[must_use]
pub fn summary(route: &ProjectRoute) -> Summary {
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    let mut summary = Summary {
        mode: policy.adversary.as_str().to_string(),
        ..Summary::default()
    };
    let survey = data::list_standings(route);
    for standing in &survey.standings {
        for voice in &standing.voices {
            summary.findings += 1;
            match voice.finding.verdict {
                Verdict::Pass => summary.passes += 1,
                Verdict::Concern => summary.concerns += 1,
                Verdict::Block => summary.blocks += 1,
            }
        }
        if standing.unresolved_block() {
            summary.unresolved.push(format!(
                "{} r{} ({})",
                standing.finding.subject,
                standing.finding.revision,
                standing.finding.trigger.as_str()
            ));
        }
    }
    summary.ignored = survey.ignored.len();
    summary
}

/// The weekly report's adversary section, in markdown: the mode, the counts and the newest
/// findings with what was done about each Block.
#[must_use]
pub fn report_section(route: &ProjectRoute) -> String {
    use std::fmt::Write as _;
    let summary = summary(route);
    let mut md = String::from("\n## Adversary\n\n");
    let _ = writeln!(
        md,
        "Mode: {}. {} finding(s): {} block, {} concern, {} pass.\n",
        summary.mode, summary.findings, summary.blocks, summary.concerns, summary.passes
    );
    let survey = data::list_standings(route);
    if survey.standings.is_empty() {
        let _ = writeln!(md, "Nothing has been challenged yet.");
    }
    for standing in survey.standings.iter().take(15) {
        let finding = &standing.finding;
        let status = match &standing.overridden {
            Some(over) => format!(" - overridden by {}", over.from()),
            None if standing.unresolved_block() => " - unresolved".to_string(),
            None => String::new(),
        };
        let _ = writeln!(
            md,
            "- `{}` r{}, {}: {}{status}",
            finding.subject,
            finding.revision,
            finding.trigger.label(),
            finding.describe()
        );
    }
    if !survey.ignored.is_empty() {
        let _ = writeln!(
            md,
            "\n{} finding(s) were ignored because their signer could not be heard (see `ferry adversary show`).",
            survey.ignored.len()
        );
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{Kind, Paid, Tier};
    use ferryman_channel::{Order, Review};
    use serde_json::json;
    use std::fs;

    fn hermetic() {
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            std::env::temp_dir().join(format!("ferryman-ops-adversary-{}", std::process::id())),
        );
    }

    fn engine(name: &str, model: &str, url: &str) -> EngineSpec {
        EngineSpec {
            name: name.into(),
            kind: Kind::Http,
            tier: Tier::Judge,
            paid: Paid::Prepaid,
            command: String::new(),
            args: Vec::new(),
            model: Some(model.into()),
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
        }
    }

    /// A reply the way a model gives one: some thinking, then the fenced block.
    fn says(verdict: &str, findings: &str) -> String {
        format!(
            "fake://ok:Reading it closely.\n```json\n{{\"verdict\": \"{verdict}\", \"findings\": [{findings}]}}\n```"
        )
    }

    const HIGH: &str = r#"{"severity": "high", "title": "the fix special-cases the test", "detail": "returns 4 for input 2", "location": "src/lib.rs:2"}"#;

    fn josh() -> AgentIdentity {
        AgentIdentity::from_seed("josh", [9; 32])
    }

    fn wisp() -> AgentIdentity {
        AgentIdentity::from_seed("wisp", [7; 32])
    }

    /// The agent that builds the work in these tests. `wisp`, whose key the config holds,
    /// plays the adversary - the signer of a finding is never the builder of what it judges.
    fn fang() -> AgentIdentity {
        AgentIdentity::from_seed("fang", [5; 32])
    }

    /// Publish wisp's signed engine inventory, listing `names`.
    fn publish_engines(route: &ProjectRoute, names: &[String]) {
        let reports = names
            .iter()
            .map(|name| ferryman_channel::receipts::EngineReport {
                name: name.clone(),
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
            })
            .collect();
        ferryman_channel::receipts::refresh_engines(
            route,
            &wisp(),
            "fixture-machine",
            "0.0.0",
            reports,
            Utc::now(),
        )
        .unwrap();
    }

    /// A channel whose master is josh and whose worker wisp has its key here, running
    /// `engines`; the workspace is a git repository on `main` holding a library and a test.
    fn fixture(dir: &Path, engines: Vec<EngineSpec>) -> (ProjectRoute, AgentConfig) {
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
        for (who, role) in [(wisp(), "worker"), (fang(), "worker"), (josh(), "operator")] {
            let agent = ferryman_channel::AgentRoute {
                name: who.name().into(),
                role: role.into(),
                capabilities: Vec::new(),
                public_key: Some(who.public_key_hex()),
                encryption_key: None,
            };
            ferryman_channel::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        ferryman_channel::master::initialize_master(&route, &josh(), "josh").unwrap();
        publish_engines(
            &route,
            &engines
                .iter()
                .map(|engine| engine.name.clone())
                .collect::<Vec<_>>(),
        );
        let mut config = AgentConfig::load(&attachment).unwrap();
        config.engines = engines;

        let repo = route.workspace.clone();
        git(&repo, &["init", "-q", "-b", "main"]);
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::create_dir_all(repo.join("tests")).unwrap();
        fs::write(repo.join(".gitignore"), ".ferryman/\n").unwrap();
        fs::write(
            repo.join("src/lib.rs"),
            "pub fn double(a: u32) -> u32 {\n    a * 2\n}\n",
        )
        .unwrap();
        fs::write(
            repo.join("tests/double.rs"),
            "#[test]\nfn doubles() {\n    assert_eq!(demo::double(2), 4);\n}\n",
        )
        .unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "base"]);
        (route, config)
    }

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

    fn set_mode(route: &ProjectRoute, adversary: AdversaryMode) {
        let policy = Policy {
            adversary,
            ..Policy::default()
        };
        ferryman_channel::policy::set_policy(
            &route.communications,
            &route.project_id,
            Some(policy),
            &josh(),
        )
        .unwrap();
    }

    fn policy_of(route: &ProjectRoute) -> Policy {
        ferryman_channel::policy::effective(&route.communications, &route.project_id).0
    }

    fn order(id: &str) -> Order {
        let mut order = Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "wisp".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({
                "task": "make double() correct",
                "tags": ["improvement"],
                "improvement": { "title": "double", "acceptance": ["`cargo test` passes"] }
            }),
            requires_review: true,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            allow_overlap: false,
        };
        wisp().sign_order(&mut order);
        order
    }

    fn result(id: &str, revision: u32, builder: &str, exit: i32) -> ferryman_channel::TaskResult {
        let mut result = ferryman_channel::TaskResult {
            order_id: id.into(),
            agent: "fang".into(),
            revision,
            submitted_at: Utc::now(),
            payload: json!({
                "output": "I changed double()",
                "engine": builder,
                "model": "builder-model",
                "evidence": {
                    "recorded_by": "worker", "git": true, "commits": ["abc1234 change"],
                    "checks": [{ "command": "cargo test", "exit_code": exit, "seconds": 2,
                                 "tail": if exit == 0 { "test result: ok" } else { "test result: FAILED. 1 failed" } }]
                }
            }),
            signed_by: None,
            signature: None,
        };
        fang().sign_result(&mut result);
        result
    }

    fn send_back(route: &ProjectRoute, id: &str, revision: u32) {
        let mut review = Review {
            order_id: id.into(),
            revision,
            reviewer: "wisp".into(),
            reviewed_at: Utc::now(),
            accepted: false,
            notes: Some("the test still fails".into()),
            signed_by: None,
            signature: None,
        };
        wisp().sign_review(&mut review);
        ferryman_channel::submit_review(route, &review).unwrap();
    }

    /// An order that has failed `revisions` times, built each time by `builder`.
    fn failed(route: &ProjectRoute, id: &str, builder: &str, revisions: u32) -> Task {
        ferryman_channel::issue_order(route, &order(id)).unwrap();
        ferryman_channel::claim_order(route, id, "fang").unwrap();
        for revision in 1..=revisions {
            ferryman_channel::submit_result(route, &result(id, revision, builder, 101)).unwrap();
            send_back(route, id, revision);
        }
        ferryman_channel::read_task(route, id).unwrap()
    }

    /// The order's branch: `files` written, `removed` deleted, one commit on `main`.
    fn branch(route: &ProjectRoute, id: &str, files: &[(&str, &str)], removed: &[&str]) {
        let repo = route.workspace.clone();
        let name = ferryman_channel::worktree::branch_name(id, "fang");
        git(&repo, &["checkout", "-q", "-b", &name, "main"]);
        for (path, text) in files {
            fs::write(repo.join(path), text).unwrap();
        }
        for path in removed {
            fs::remove_file(repo.join(path)).unwrap();
        }
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "attempt"]);
        git(&repo, &["checkout", "-q", "main"]);
    }

    // --- reading what the adversary said ------------------------------------------------

    #[test]
    fn the_last_fenced_json_block_with_a_verdict_is_the_reply() {
        let reply = parse_reply(
            "Thinking.\n```json\n{\"verdict\": \"pass\", \"findings\": []}\n```\nOn reflection:\n\
             ```json\n{\"verdict\": \"BLOCK\", \"findings\": [{\"severity\": \"High\", \
             \"title\": \"tests deleted\", \"detail\": \"two\", \"location\": \"tests/a.rs\"}]}\n```\n",
        );
        assert!(reply.readable);
        assert_eq!(reply.verdict, Verdict::Block);
        assert_eq!(reply.issues.len(), 1);
        assert_eq!(reply.issues[0].severity, Severity::High);
        assert_eq!(reply.issues[0].title, "tests deleted");
        assert_eq!(reply.issues[0].location.as_deref(), Some("tests/a.rs"));
    }

    #[test]
    fn a_bare_json_object_and_loose_field_names_are_read() {
        let reply = parse_reply(
            "{\"verdict\": \"concern\", \"issues\": [{\"summary\": \"no limit\", \"description\": \"unbounded\"}, 5]}",
        );
        assert!(reply.readable);
        assert_eq!(reply.verdict, Verdict::Concern);
        assert_eq!(reply.issues.len(), 1, "a non-object entry is skipped");
        assert_eq!(reply.issues[0].title, "no limit");
        assert_eq!(reply.issues[0].detail, "unbounded");
        assert_eq!(
            reply.issues[0].severity,
            Severity::Medium,
            "unlabelled is medium"
        );
    }

    #[test]
    fn a_pass_that_lists_a_high_finding_is_a_concern() {
        let reply = parse_reply(
            "```json\n{\"verdict\": \"pass\", \"findings\": [{\"severity\": \"high\", \"title\": \"x\"}]}\n```",
        );
        assert_eq!(reply.verdict, Verdict::Concern);
    }

    #[test]
    fn a_reply_that_cannot_be_read_is_a_concern_holding_what_was_said_never_a_pass() {
        for text in [
            "I looked and it seems fine to me.",
            "```json\n{\"verdict\": \"fine\"}\n```",
            "```json\n{not json at all\n```",
            "{\"findings\": []}",
        ] {
            let reply = parse_reply(text);
            assert!(!reply.readable, "{text}");
            assert_eq!(reply.verdict, Verdict::Concern, "{text}");
            assert_eq!(reply.issues.len(), 1);
            assert!(
                reply.issues[0].detail.contains("could not")
                    || reply.issues[0].detail.contains("no JSON"),
                "{:?}",
                reply.issues[0]
            );
        }
        let long = format!("{}THE END OF IT", "x".repeat(5_000));
        let reply = parse_reply(&long);
        assert!(
            reply.issues[0].detail.contains("THE END OF IT"),
            "the raw tail is kept"
        );
        assert!(reply.issues[0].detail.len() < 2_000, "and only the tail");
        let empty = parse_reply("  ");
        assert_eq!(empty.verdict, Verdict::Concern);
        assert!(empty.issues[0].detail.contains("empty"));
    }

    // --- choosing who asks ---------------------------------------------------------------

    #[test]
    fn the_engine_that_built_the_work_is_not_asked_while_another_is_allowed() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let engines = vec![
            engine("deepseek", "deepseek-chat", "fake://ok:x"),
            engine("qwen", "qwen-max", "fake://ok:x"),
        ];
        let (route, config) = fixture(dir.path(), engines);
        let policy = policy_of(&route);
        let builder = Builder {
            engine: "deepseek".into(),
            model: Some("deepseek-chat".into()),
        };
        let (chosen, same) = choose(
            &config,
            &policy,
            std::slice::from_ref(&builder),
            &[],
            Utc::now(),
        )
        .unwrap();
        assert_eq!(chosen.name, "qwen");
        assert!(!same);
        // Having asked it, the builder is the only one left: asked, and marked.
        let (chosen, same) = choose(
            &config,
            &policy,
            std::slice::from_ref(&builder),
            &["qwen".to_string()],
            Utc::now(),
        )
        .unwrap();
        assert_eq!(chosen.name, "deepseek");
        assert!(same, "the builder's own engine says so");
        let error = choose(
            &config,
            &policy,
            &[builder],
            &["qwen".to_string(), "deepseek".to_string()],
            Utc::now(),
        )
        .unwrap_err();
        assert!(error.contains("every allowed engine"), "{error}");
    }

    #[test]
    fn the_only_allowed_engine_runs_against_its_own_work_and_marks_the_finding() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("deepseek", "deepseek-chat", &says("pass", ""))],
        );
        awaiting(&route, "t-1", "deepseek");
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            Request {
                subject: "t-1".into(),
                order_id: "t-1".into(),
                revision: 1,
                trigger: Trigger::PreDone,
                built_by: vec![Builder {
                    engine: "deepseek".into(),
                    model: Some("deepseek-chat".into()),
                }],
                prompt: "challenge it".into(),
                known: Vec::new(),
                floor: Verdict::Pass,
            },
            Utc::now(),
            &crate::Silent,
        ));
        let finding = outcome.finding().expect("it ran");
        assert!(finding.same_engine);
        assert_eq!(finding.engine, "deepseek");
        assert!(
            finding.describe().contains("built it"),
            "{}",
            finding.describe()
        );
    }

    #[test]
    fn engines_the_policy_never_allows_are_not_asked_and_nothing_allowed_holds_the_work() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        awaiting(&route, "t-1", "deepseek");
        let mut policy = policy_of(&route);
        policy.never.push("name:qwen".into());
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy,
            Request {
                subject: "t-1".into(),
                order_id: "t-1".into(),
                revision: 1,
                trigger: Trigger::PreDone,
                built_by: Vec::new(),
                prompt: "challenge it".into(),
                known: Vec::new(),
                floor: Verdict::Pass,
            },
            Utc::now(),
            &crate::Silent,
        ));
        assert!(matches!(outcome, Outcome::Held(_)), "{outcome:?}");
        assert!(data::read(&route, "t-1", 1, Trigger::PreDone, "wisp").is_none());
        // The master was asked once about the held work.
        let pending = ferryman_channel::questions::pending(&route);
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert_eq!(pending[0].kind, ferryman_channel::questions::POLICY);
    }

    fn futures_lite_block<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    // --- the challenge: signed, costed, idempotent, silent when off --------------------------

    fn simple(subject: &str, trigger: Trigger) -> Request {
        Request {
            subject: subject.into(),
            order_id: subject.into(),
            revision: 1,
            trigger,
            built_by: vec![Builder {
                engine: "deepseek".into(),
                model: None,
            }],
            prompt: "challenge it".into(),
            known: Vec::new(),
            floor: Verdict::Pass,
        }
    }

    #[test]
    fn a_challenge_is_recorded_signed_with_its_engine_machine_and_cost() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let reply = says("concern", HIGH).replace("fake://ok:", "fake://paid:");
        let (route, config) = fixture(dir.path(), vec![engine("qwen", "qwen-max", &reply)]);
        awaiting(&route, "t-1", "deepseek");
        let now = Utc::now();
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-1", Trigger::PreDone),
            now,
            &crate::Silent,
        ));
        let finding = outcome.finding().unwrap();
        assert_eq!(
            finding.verdict,
            Verdict::Concern,
            "a High under a pass-less verdict stays"
        );
        assert_eq!(finding.engine, "qwen");
        assert_eq!(finding.model.as_deref(), Some("qwen-max"));
        assert_eq!(finding.signed_by, "wisp");
        assert!(!finding.same_engine);
        assert!(!finding.machine.is_empty());
        assert_eq!(finding.findings[0].title, "the fix special-cases the test");
        // On disk, readable by anyone on the roster.
        assert!(data::read(&route, "t-1", 1, Trigger::PreDone, "wisp").is_some());

        // The ledger-side record: an adversary step with the engine, model, machine, cost.
        let steps = ferryman_channel::policy::read_steps(&route, &engines::iso_week(now));
        let step = steps
            .iter()
            .find(|step| step.step == "adversary")
            .unwrap_or_else(|| panic!("no adversary step in {steps:?}"));
        assert_eq!(step.role.as_deref(), Some("adversary"));
        assert_eq!(step.engine.as_deref(), Some("qwen"));
        assert_eq!(step.model.as_deref(), Some("qwen-max"));
        assert_eq!(step.order.as_deref(), Some("t-1"));
        assert_eq!(step.cost_usd, Some(0.01));
        assert!(!step.machine.is_empty());
        assert!(
            step.outcome.contains("pre-done") || step.outcome.contains("pre_done"),
            "{}",
            step.outcome
        );
        // And the engine's own ledger shows what it spent.
        assert!(engines::Ledger::load("wisp").state("qwen").spend_usd > 0.0);
    }

    #[test]
    fn asking_again_for_the_same_subject_revision_and_trigger_returns_the_finding_unchanged() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        awaiting(&route, "t-1", "deepseek");
        let run = |config: &AgentConfig| {
            futures_lite_block(challenge(
                &route,
                config,
                &policy_of(&route),
                simple("t-1", Trigger::PreDone),
                Utc::now(),
                &crate::Silent,
            ))
        };
        let first = run(&config);
        assert!(matches!(first, Outcome::Recorded(_)));
        let path_before = fs::read(
            ferryman_channel::adversary::finding_path(&route, "t-1", 1, Trigger::PreDone, "wisp")
                .unwrap(),
        )
        .unwrap();
        // Even a different answer from a different engine changes nothing.
        let mut other = config.clone();
        other.engines = vec![engine("qwen", "qwen-max", &says("pass", ""))];
        let second = run(&other);
        assert!(matches!(second, Outcome::Existing(_)), "{second:?}");
        assert_eq!(second.finding().unwrap().verdict, Verdict::Block);
        let path_after = fs::read(
            ferryman_channel::adversary::finding_path(&route, "t-1", 1, Trigger::PreDone, "wisp")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(path_before, path_after);
        // Another trigger, same subject and revision, is another question.
        let third = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-1", Trigger::RepeatFailure),
            Utc::now(),
            &crate::Silent,
        ));
        assert!(matches!(third, Outcome::Recorded(_)));
    }

    #[test]
    fn with_the_adversary_off_nothing_is_asked_and_nothing_is_written() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        set_mode(&route, AdversaryMode::Off);
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-1", Trigger::PreDone),
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(outcome, Outcome::Off);
        assert!(data::list(&route).is_empty());
        assert_eq!(
            futures_lite_block(pass(
                &route,
                &config,
                &policy_of(&route),
                Utc::now(),
                &crate::Silent
            )),
            0
        );
        assert!(may_judge(
            &route,
            &policy_of(&route),
            &failed(&route, "t-9", "qwen", 1)
        ));
    }

    #[test]
    fn an_unreadable_reply_is_recorded_as_a_concern_with_the_raw_tail() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine(
                "qwen",
                "qwen-max",
                "fake://ok:Looks fine to me, ship it.",
            )],
        );
        awaiting(&route, "t-1", "deepseek");
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-1", Trigger::PreDone),
            Utc::now(),
            &crate::Silent,
        ));
        let finding = outcome.finding().unwrap();
        assert_eq!(finding.verdict, Verdict::Concern, "never a silent pass");
        assert!(
            finding.findings[0]
                .detail
                .contains("Looks fine to me, ship it."),
            "{:?}",
            finding.findings
        );
    }

    #[test]
    fn a_floor_raises_the_verdict_but_never_lowers_it() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        awaiting(&route, "t-1", "deepseek");
        let mut request = simple("t-1", Trigger::PreDone);
        request.floor = Verdict::Block;
        request.known = vec![Issue {
            severity: Severity::High,
            title: "a test was deleted".into(),
            detail: "tests/double.rs".into(),
            location: None,
        }];
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            request,
            Utc::now(),
            &crate::Silent,
        ));
        let finding = outcome.finding().unwrap();
        assert_eq!(finding.verdict, Verdict::Block);
        assert_eq!(
            finding.findings[0].title, "a test was deleted",
            "known first"
        );
    }

    // --- whose word counts, settled before anything is paid for --------------------------------

    #[test]
    fn an_agent_that_built_the_work_asks_no_engine_and_writes_nothing() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        // wisp, who runs the adversary here, built this one itself.
        ferryman_channel::issue_order(&route, &order("t-own")).unwrap();
        let mut mine = result("t-own", 1, "deepseek", 0);
        mine.agent = "wisp".into();
        mine.signed_by = None;
        mine.signature = None;
        wisp().sign_result(&mut mine);
        ferryman_channel::submit_result(&route, &mine).unwrap();
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-own", Trigger::PreDone),
            Utc::now(),
            &crate::Silent,
        ));
        match &outcome {
            Outcome::Ineligible(why) => {
                assert!(why.contains("built the work it judged"), "{why}");
            }
            other => panic!("not ineligible: {other:?}"),
        }
        assert!(data::list(&route).is_empty(), "nothing was written");
        assert_eq!(
            futures_lite_block(pass(
                &route,
                &config,
                &policy_of(&route),
                Utc::now(),
                &crate::Silent
            )),
            0,
            "and the pass asks no one"
        );
    }

    #[test]
    fn an_engine_the_agents_signed_inventory_does_not_list_is_not_asked() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        // The inventory the fleet can verify lists some other engine than the one configured.
        fs::remove_file(route.communications.join("engines").join("wisp.json")).unwrap();
        publish_engines(&route, &["gpt".to_string()]);
        awaiting(&route, "t-1", "deepseek");
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-1", Trigger::PreDone),
            Utc::now(),
            &crate::Silent,
        ));
        assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
        assert!(
            data::list(&route).is_empty(),
            "no finding that would be ignored"
        );
    }

    #[test]
    fn a_revision_that_does_not_exist_is_not_challenged() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        awaiting(&route, "t-1", "deepseek");
        let mut request = simple("t-1", Trigger::PreDone);
        request.revision = 999;
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            request,
            Utc::now(),
            &crate::Silent,
        ));
        match &outcome {
            Outcome::Ineligible(why) => assert!(why.contains("no result r999"), "{why}"),
            other => panic!("not ineligible: {other:?}"),
        }
    }

    #[test]
    fn a_waiver_lets_the_judge_through_when_no_adversary_could_read_the_work() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(dir.path(), Vec::new());
        set_mode(&route, AdversaryMode::Blocking);
        let task = awaiting(&route, "t-1", "deepseek");
        let policy = policy_of(&route);
        assert_eq!(
            futures_lite_block(pass(&route, &config, &policy, Utc::now(), &crate::Silent)),
            0,
            "there is no engine to ask"
        );
        assert!(!may_judge(&route, &policy, &task), "blocking fails closed");
        let seen = data::finding_seen(&route, "t-1", 1, Trigger::PreDone);
        assert_eq!(seen, data::NO_FINDING);
        data::waive(
            &route,
            "t-1",
            1,
            Trigger::PreDone,
            &seen,
            Some("no adversary is available"),
            "josh",
            &josh(),
        )
        .unwrap();
        assert!(may_judge(&route, &policy, &task), "the master waived it");
    }
    // --- moment 2: the order has failed twice --------------------------------------------------

    #[test]
    fn one_failure_is_not_challenged() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        let task = failed(&route, "t-1", "deepseek", 1);
        let gate = futures_lite_block(before_attempt(
            &route,
            &config,
            &task,
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(gate, Gate::Proceed);
        assert!(data::list(&route).is_empty());
    }

    #[test]
    fn a_second_failure_is_challenged_with_both_check_tails_and_a_clean_pass_goes_on() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        branch(
            &route,
            "t-1",
            &[(
                "src/lib.rs",
                "pub fn double(a: u32) -> u32 {\n    a + a\n}\n",
            )],
            &[],
        );
        let task = failed(&route, "t-1", "deepseek", 2);
        let gate = futures_lite_block(before_attempt(
            &route,
            &config,
            &task,
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(gate, Gate::Proceed);
        let finding =
            data::read(&route, "t-1", 2, Trigger::RepeatFailure, "wisp").expect("challenged");
        assert_eq!(finding.verdict, Verdict::Pass);
        assert!(
            ferryman_channel::questions::pending(&route).is_empty(),
            "nothing to ask"
        );
        assert!(ferryman_channel::adversary::attempt_notice(&route, "t-1").is_none());

        // What the adversary is shown: both failures' tails, the diff, the scan's word.
        let repeat = data::repeat_failure(&task).unwrap();
        let diff = order_diff(&route, task.results.last().unwrap()).expect("the branch is here");
        assert!(diff.contains("a + a"), "{diff}");
        let hits = tamper::scan(&diff, &required_of(&task));
        assert!(hits.is_empty(), "{hits:?}");
        let prompt = repeat_prompt(&task, &repeat, &hits, Some(&diff));
        assert!(prompt.contains("failed 2 times"), "{prompt}");
        assert_eq!(
            prompt.matches("test result: FAILED. 1 failed").count(),
            2,
            "{prompt}"
        );
        assert!(prompt.contains("Revision 1") && prompt.contains("Revision 2"));
        assert!(prompt.contains("`cargo test`"));
        assert!(prompt.contains("a + a"), "the diff is in it");
        assert!(prompt.contains("found nothing"), "the scan's word");
        assert!(prompt.contains("fixing the cause or hiding the symptom"));
        assert!(prompt.contains("```json"), "the reply format is demanded");
    }

    #[test]
    fn a_block_goes_into_the_next_attempts_prompt_and_is_put_to_the_master_once() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        let task = failed(&route, "t-1", "deepseek", 2);
        let run = || {
            futures_lite_block(before_attempt(
                &route,
                &config,
                &task,
                Utc::now(),
                &crate::Silent,
            ))
        };
        assert_eq!(
            run(),
            Gate::Proceed,
            "the next attempt goes ahead, told why"
        );
        let notice = ferryman_channel::adversary::attempt_notice(&route, "t-1").expect("a Block");
        assert!(
            notice.contains("the fix special-cases the test"),
            "{notice}"
        );
        assert!(notice.contains("Do not delete, skip"), "{notice}");

        let pending = ferryman_channel::questions::pending(&route);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, ferryman_channel::questions::ADVERSARY);
        assert_eq!(pending[0].id, "adversary-block-t-1-r2");
        assert_eq!(pending[0].options, [UNDERSTOOD, TAKE_OVER]);
        assert!(pending[0].text.contains("the fix special-cases the test"));
        // Asking again, as every poll does, asks nothing more.
        assert_eq!(run(), Gate::Proceed);
        assert_eq!(ferryman_channel::questions::pending(&route).len(), 1);
        assert_eq!(data::list(&route).len(), 1);
    }

    #[test]
    fn the_master_taking_the_order_over_holds_the_next_attempt() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        let task = failed(&route, "t-1", "deepseek", 2);
        let run = || {
            futures_lite_block(before_attempt(
                &route,
                &config,
                &task,
                Utc::now(),
                &crate::Silent,
            ))
        };
        assert_eq!(run(), Gate::Proceed);
        ferryman_channel::questions::answer(
            &route,
            "adversary-block-t-1-r2",
            TAKE_OVER,
            "josh",
            &josh(),
        )
        .unwrap();
        match run() {
            Gate::Hold(why) => assert!(why.contains("took t-1 over"), "{why}"),
            other => panic!("not held: {other:?}"),
        }
    }

    #[test]
    fn tampering_blocks_even_when_the_adversary_is_advisory_and_says_pass() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        assert_eq!(policy_of(&route).adversary, AdversaryMode::Advisory);
        // The "fix": the failing test is deleted.
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let task = failed(&route, "t-1", "deepseek", 2);
        let gate = futures_lite_block(before_attempt(
            &route,
            &config,
            &task,
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(gate, Gate::Proceed);
        let finding = data::read(&route, "t-1", 2, Trigger::RepeatFailure, "wisp").unwrap();
        assert_eq!(
            finding.verdict,
            Verdict::Block,
            "the scan's High is a Block"
        );
        assert!(
            finding
                .findings
                .iter()
                .any(|issue| issue.severity == Severity::High),
            "{:?}",
            finding.findings
        );
        let notice = ferryman_channel::adversary::attempt_notice(&route, "t-1").unwrap();
        assert!(notice.contains("tests/double.rs"), "{notice}");
        assert_eq!(ferryman_channel::questions::pending(&route).len(), 1);
    }

    #[test]
    fn a_high_tamper_hit_blocks_with_no_engine_to_ask() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(dir.path(), Vec::new());
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let task = failed(&route, "t-1", "deepseek", 2);
        let gate = futures_lite_block(before_attempt(
            &route,
            &config,
            &task,
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(gate, Gate::Proceed);
        let finding =
            data::read(&route, "t-1", 2, Trigger::RepeatFailure, "wisp").expect("the scan's own");
        assert_eq!(finding.engine, "tamper-scan");
        assert_eq!(finding.verdict, Verdict::Block);
        assert!(
            finding
                .findings
                .iter()
                .any(|issue| issue.title.contains("no adversary engine")),
            "{:?}",
            finding.findings
        );
        assert!(ferryman_channel::adversary::attempt_notice(&route, "t-1").is_some());

        // No tampering and no engine: nothing to say, the attempt goes on unchallenged.
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(dir.path(), Vec::new());
        let task = failed(&route, "t-2", "deepseek", 2);
        let gate = futures_lite_block(before_attempt(
            &route,
            &config,
            &task,
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(gate, Gate::Proceed);
        assert!(data::list(&route).is_empty());
    }

    #[test]
    fn an_off_adversary_does_not_even_scan() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(dir.path(), Vec::new());
        set_mode(&route, AdversaryMode::Off);
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let task = failed(&route, "t-1", "deepseek", 2);
        let gate = futures_lite_block(before_attempt(
            &route,
            &config,
            &task,
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(gate, Gate::Proceed);
        assert!(data::list(&route).is_empty());
        assert!(ferryman_channel::questions::pending(&route).is_empty());
    }

    // --- moment 3: before an improvement is called done ----------------------------------------

    fn awaiting(route: &ProjectRoute, id: &str, builder: &str) -> Task {
        ferryman_channel::issue_order(route, &order(id)).unwrap();
        ferryman_channel::claim_order(route, id, "fang").unwrap();
        ferryman_channel::submit_result(route, &result(id, 1, builder, 0)).unwrap();
        ferryman_channel::read_task(route, id).unwrap()
    }

    #[test]
    fn the_pre_done_pass_reads_a_result_waiting_for_the_review_engine_once() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("concern", HIGH))],
        );
        awaiting(&route, "t-1", "deepseek");
        let challenged = futures_lite_block(pass(
            &route,
            &config,
            &policy_of(&route),
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(challenged, 1);
        let finding = data::read(&route, "t-1", 1, Trigger::PreDone, "wisp").unwrap();
        assert_eq!(finding.verdict, Verdict::Concern);
        assert_eq!(finding.engine, "qwen");
        assert_eq!(
            futures_lite_block(pass(
                &route,
                &config,
                &policy_of(&route),
                Utc::now(),
                &crate::Silent
            )),
            0,
            "once per revision"
        );
        // Advisory: the judge is never made to wait for it.
        let task = ferryman_channel::read_task(&route, "t-1").unwrap();
        assert!(may_judge(&route, &policy_of(&route), &task));
    }

    #[test]
    fn the_pre_done_prompt_carries_the_order_the_evidence_the_scan_and_the_diff() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let task = awaiting(&route, "t-1", "deepseek");
        let result = task.results.last().unwrap();
        let diff = order_diff(&route, result).unwrap();
        let hits = tamper::scan(&diff, &required_of(&task));
        let prompt = pre_done_prompt(&task, result, &hits, Some(&diff));
        assert!(prompt.contains("make double() correct"), "{prompt}");
        assert!(
            prompt.contains("`cargo test` passes"),
            "the acceptance criteria"
        );
        assert!(
            prompt.contains("test result: ok"),
            "the worker's own evidence"
        );
        assert!(prompt.contains("deterministic scan"), "{prompt}");
        assert!(prompt.contains("tests/double.rs"), "the diff");
        assert!(prompt.contains("attack"), "the question");
        assert!(prompt.contains("```json"));
    }

    #[test]
    fn a_blocking_adversary_makes_the_judge_wait_until_it_has_read_and_a_block_is_overridden() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        set_mode(&route, AdversaryMode::Blocking);
        let task = awaiting(&route, "t-1", "deepseek");
        let policy = policy_of(&route);
        assert!(
            !may_judge(&route, &policy, &task),
            "not read yet: the judge waits"
        );

        futures_lite_block(pass(&route, &config, &policy, Utc::now(), &crate::Silent));
        assert!(
            !may_judge(&route, &policy, &task),
            "a Block nobody overrode"
        );

        let seen = data::finding_seen(&route, "t-1", 1, Trigger::PreDone);
        data::override_block(
            &route,
            "t-1",
            1,
            Trigger::PreDone,
            &seen,
            Some("accepted"),
            "josh",
            &josh(),
        )
        .unwrap();
        assert!(may_judge(&route, &policy, &task), "overridden");
    }

    #[test]
    fn a_blocking_adversary_that_passes_lets_the_judge_through() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        set_mode(&route, AdversaryMode::Blocking);
        let task = awaiting(&route, "t-1", "deepseek");
        let policy = policy_of(&route);
        futures_lite_block(pass(&route, &config, &policy, Utc::now(), &crate::Silent));
        assert!(may_judge(&route, &policy, &task));
    }

    // --- moment 1: before a contract locks -----------------------------------------------------

    fn contract_world(route: &ProjectRoute, response: Option<serde_json::Value>) {
        let shape = ferryman_channel::contract::Shape::parse(&json!({
            "type": "object",
            "required": ["id", "name"],
            "properties": { "id": { "type": "integer" }, "name": { "type": "string" } }
        }))
        .unwrap();
        ferryman_channel::interface::propose(route, &wisp(), "user-api", "1", "users", None, shape)
            .unwrap();
        for (id, side, text) in [
            (
                "front",
                ferryman_channel::interface::Side::Consumes,
                "show the user's name",
            ),
            (
                "back",
                ferryman_channel::interface::Side::Provides,
                "serve users",
            ),
        ] {
            let mut order = Order {
                id: id.into(),
                project_id: "demo".into(),
                issued_by: "josh".into(),
                assigned_to: None,
                created_at: Utc::now(),
                payload: json!({ "task": text }),
                requires_review: false,
                requires_approval: false,
                depends_on: Vec::new(),
                signed_by: None,
                signature: None,
                result_contract: None,
                interface: Some(ferryman_channel::interface::InterfaceRef {
                    name: "user-api".into(),
                    version: "1".into(),
                    side,
                }),
                touches: Vec::new(),
                allow_overlap: false,
            };
            josh().sign_order(&mut order);
            ferryman_channel::issue_order(route, &order).unwrap();
        }
        if let Some(response) = response {
            let mut result = ferryman_channel::TaskResult {
                order_id: "back".into(),
                agent: "fang".into(),
                revision: 1,
                submitted_at: Utc::now(),
                payload: json!({ "engine": "deepseek", "response": response }),
                signed_by: None,
                signature: None,
            };
            fang().sign_result(&mut result);
            ferryman_channel::submit_result(route, &result).unwrap();
        }
    }

    #[test]
    fn a_contract_waiting_for_its_lock_is_challenged_once_with_no_provider_yet_and_again_at_its_result()
     {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        contract_world(&route, None);
        let policy = policy_of(&route);
        let run = || {
            futures_lite_block(contract_pass(
                &route,
                &config,
                &policy,
                Utc::now(),
                &crate::Silent,
            ))
        };
        assert_eq!(run(), 1);
        let first = data::read(&route, "user-api@1", 0, Trigger::ContractLock, "wisp")
            .expect("shapes alone");
        assert_eq!(first.verdict, Verdict::Pass);
        assert_eq!(run(), 0, "once");

        // The provider returns a result: the contract is read again, at that revision.
        let mut result = ferryman_channel::TaskResult {
            order_id: "back".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "engine": "deepseek", "response": { "id": 7, "name": "ada" } }),
            signed_by: None,
            signature: None,
        };
        fang().sign_result(&mut result);
        ferryman_channel::claim_order(&route, "back", "fang").unwrap();
        ferryman_channel::submit_result(&route, &result).unwrap();
        assert_eq!(run(), 1);
        assert!(data::read(&route, "user-api@1", 1, Trigger::ContractLock, "wisp").is_some());
        assert_eq!(run(), 0);
    }

    #[test]
    fn a_provider_response_that_does_not_fit_the_shape_blocks_whatever_the_model_says() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        contract_world(&route, Some(json!({ "id": "seven" })));
        let policy = policy_of(&route);
        assert_eq!(
            futures_lite_block(contract_pass(
                &route,
                &config,
                &policy,
                Utc::now(),
                &crate::Silent
            )),
            1
        );
        let finding = data::read(&route, "user-api@1", 1, Trigger::ContractLock, "wisp").unwrap();
        assert_eq!(finding.verdict, Verdict::Block, "the shape check is a fact");
        assert!(
            finding
                .findings
                .iter()
                .any(|issue| issue.detail.contains("result.response.id")),
            "{:?}",
            finding.findings
        );
        assert_eq!(finding.engine, "qwen");
        // Blocking mode: the lock is refused until the master overrides.
        set_mode(&route, AdversaryMode::Blocking);
        let seen = ferryman_channel::interface::current_digest(&route, "user-api", "1").unwrap();
        let error =
            ferryman_channel::interface::lock(&route, "user-api", "1", &seen, "josh", &josh())
                .unwrap_err()
                .to_string();
        assert!(error.contains("blocks locking"), "{error}");
        // Advisory: it locks.
        set_mode(&route, AdversaryMode::Advisory);
        assert!(
            ferryman_channel::interface::lock(&route, "user-api", "1", &seen, "josh", &josh())
                .unwrap()
                .is_locked()
        );
    }

    #[test]
    fn the_contract_prompt_carries_shapes_the_providers_result_the_consumers_and_the_precheck() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        contract_world(&route, Some(json!({ "id": "seven" })));
        let contract = ferryman_channel::interface::read_contract(&route, "user-api", "1").unwrap();
        let context = data::contract_context(&route, &contract).unwrap();
        let prompt = contract_prompt(&context);
        assert!(prompt.contains("user-api@1"), "{prompt}");
        assert!(prompt.contains("Response shape"), "{prompt}");
        assert!(prompt.contains("seven"), "the provider's result");
        assert!(
            prompt.contains("show the user's name"),
            "the consumer's order"
        );
        assert!(prompt.contains("FAILED"), "the mechanical check, loudly");
        assert!(prompt.contains("result.response.id"));
        assert!(prompt.contains("```json"));
    }
}

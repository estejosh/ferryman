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
//! same demand: a final fenced JSON block. Only a block at the very end of the reply counts
//! ([`parse_reply`]); a reply without one is not recorded at all - it is a failure the next
//! pass tries again - because a Concern written for it would be a signed finding the
//! adversary never made, and would satisfy `blocking` mode for work it never judged.
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
    worktree::END_OF_OPTIONS,
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

/// The reply's JSON when it has the keys that were asked for: a `verdict` that is one of
/// pass, concern or block, and a `findings` list.
fn reply_from(value: &Value) -> Option<Reply> {
    let verdict = Verdict::parse(value.get("verdict")?.as_str()?).ok()?;
    let issues: Vec<Issue> = value
        .get("findings")?
        .as_array()?
        .iter()
        .filter_map(issue_from)
        .take(12)
        .collect();
    // A pass that lists a High finding says two things at once; the louder one stands.
    let verdict = if verdict == Verdict::Pass
        && issues.iter().any(|issue| issue.severity == Severity::High)
    {
        Verdict::Concern
    } else {
        verdict
    };
    Some(Reply { verdict, issues })
}

/// Read the adversary's reply: the one fenced JSON block at the very end of it, with only
/// whitespace after its closing fence, carrying a `verdict` and `findings`. `None` for
/// anything else - an empty or garbled reply, a truncated block, a reply that ends in
/// prose, a block without the keys.
///
/// Nothing earlier in the reply is looked at as a verdict. A diff or a quotation the
/// model echoed can contain `{"verdict": "pass"}`, and "the last JSON object wins" would
/// let it decide; only what the model signed off with counts. And an unreadable reply is
/// not a finding at all (the caller records nothing and asks again later): a Concern
/// written for it would be a signed, eligible word that satisfies `blocking` mode for a
/// revision the adversary never judged.
#[must_use]
pub fn parse_reply(text: &str) -> Option<Reply> {
    let body = text.trim_end().strip_suffix("```")?;
    // The closing fence is the last one; the opening fence is the nearest one before it
    // that leaves JSON between them. (A string inside the JSON may itself hold a fence.)
    let mut upto = body.len();
    while let Some(open) = body[..upto].rfind("```") {
        let inner = &body[open + 3..];
        // The opening line is the language tag: `json`, or nothing.
        if let Some((tag, json)) = inner.split_once('\n')
            && matches!(tag.trim().to_ascii_lowercase().as_str(), "" | "json")
            && let Ok(value) = serde_json::from_str::<Value>(json.trim())
        {
            return reply_from(&value);
        }
        upto = open;
    }
    None
}

/// Why a reply could not be read, for the warning and the failure that is reported: the
/// end of what was said.
fn unreadable(text: &str) -> String {
    if text.trim().is_empty() {
        "the reply was empty".to_string()
    } else {
        format!(
            "it did not end with a fenced JSON block carrying a verdict and findings. The end \
             of it: {}",
            tail(text, 400)
        )
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
    /// The digest of the result being judged ([`data::result_digest`]; empty for a contract
    /// reviewed on its own): signed into the finding so it counts for that result only.
    pub result_digest: String,
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
        // The adversary is never routed: its engine comes from its own policy order.
        route: None,
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
    let mut unreadable_from: Vec<String> = Vec::new();
    loop {
        let (engine, same_engine) = match choose(config, policy, &request.built_by, &tried, now) {
            Ok(chosen) => chosen,
            Err(why) if tried.is_empty() => {
                hold(route, config, &week, &why, report);
                return Outcome::Held(why);
            }
            Err(mut why) => {
                if !unreadable_from.is_empty() {
                    why = format!(
                        "{why}; replies that could not be read and were not recorded: {}",
                        unreadable_from.join("; ")
                    );
                }
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
        let Some(reply) = parse_reply(&answer) else {
            // Not a finding: nothing is recorded, so nothing is signed that an eligible
            // adversary never said. The next engine is asked, and what is left over is
            // a failure the next pass tries again.
            let why = unreadable(&answer);
            report.warn(&format!(
                "  {}: {} answered about {} but {why}; recording nothing, trying the next engine",
                route.project_id, engine.name, request.subject
            ));
            unreadable_from.push(format!("{} ({why})", engine.name));
            continue;
        };
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
            result_digest: request.result_digest.clone(),
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

/// The most of one file's diff the scan reads. A file with more is read as far as this and
/// named in a High finding: what the scan did not read, it did not clear.
const FILE_SCAN_BYTES: usize = 256 * 1024;
/// The most one line of a diff keeps (a minified bundle is a single line).
const LINE_SCAN_BYTES: usize = 16 * 1024;
/// The most of a whole diff the scan reads, however many files it spans.
const TOTAL_SCAN_BYTES: usize = 16 * 1024 * 1024;
/// How many unread files a finding names.
const NAMED_SKIPPED: usize = 8;
/// How long a fetch from `origin` may take before the scan gives up on it.
const FETCH_SECONDS: u64 = 30;

/// A diff as the scan read it: every file's header and as much of its body as the caps allow,
/// and the files (or "the rest of the diff") it did not read in full.
#[derive(Debug, Default)]
struct DiffRead {
    text: String,
    skipped: Vec<String>,
}

/// Files nobody reviews line by line: a cut diff of one is not worth a finding.
fn is_generated(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.ends_with(".lock")
        || matches!(
            name,
            "go.sum" | "package-lock.json" | "pnpm-lock.yaml" | "npm-shrinkwrap.json"
        )
}

/// The path a `diff --git a/x b/x` header names (the new side).
fn header_path(header: &str) -> String {
    let rest = header
        .trim_end()
        .strip_prefix("diff --git ")
        .unwrap_or(header);
    rest.rsplit_once(" b/")
        .map_or(rest, |(_, new)| new)
        .trim_matches('"')
        .to_string()
}

/// One line, keeping at most `cap` bytes of it and dropping the rest; the returned flag says
/// whether anything was dropped. `None` at the end of the stream.
fn read_capped_line<R: std::io::BufRead>(
    reader: &mut R,
    keep: &mut Vec<u8>,
    cap: usize,
) -> std::io::Result<Option<bool>> {
    keep.clear();
    let mut any = false;
    let mut cut = false;
    loop {
        let buffered = reader.fill_buf()?;
        if buffered.is_empty() {
            return Ok(any.then_some(cut));
        }
        any = true;
        let (chunk, ended) = match buffered.iter().position(|byte| *byte == b'\n') {
            Some(at) => (&buffered[..=at], true),
            None => (buffered, false),
        };
        let room = cap.saturating_sub(keep.len());
        if chunk.len() > room {
            cut = true;
            keep.extend_from_slice(&chunk[..room]);
        } else {
            keep.extend_from_slice(chunk);
        }
        let used = chunk.len();
        reader.consume(used);
        if ended {
            if cut && keep.last() != Some(&b'\n') {
                keep.push(b'\n');
            }
            return Ok(Some(cut));
        }
    }
}

/// `git diff <spec>` read file by file, each file capped on its own so one huge file cannot
/// push the rest out of the scan. `None` when git fails.
fn read_diff(workspace: &Path, spec: &str) -> Option<DiffRead> {
    use std::io::BufReader;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args([
            "diff",
            "--no-color",
            "-M",
            "-U3",
            END_OF_OPTIONS,
            spec,
            "--",
            ".",
            ":(exclude).ferryman",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut reader = BufReader::with_capacity(64 * 1024, child.stdout.take()?);
    let mut bytes: Vec<u8> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut file = String::new();
    let mut file_bytes = 0_usize;
    let mut file_cut = false;
    let mut line: Vec<u8> = Vec::new();
    let mut ran_out = false;
    let mut failed = false;
    let finish = |file: &str, cut: bool, skipped: &mut Vec<String>| {
        if cut && !file.is_empty() && !is_generated(file) {
            skipped.push(file.to_string());
        }
    };
    loop {
        match read_capped_line(&mut reader, &mut line, LINE_SCAN_BYTES) {
            Ok(Some(line_cut)) => {
                let header = line.starts_with(b"diff --git ");
                if header {
                    finish(&file, file_cut, &mut skipped);
                    file = header_path(&String::from_utf8_lossy(&line));
                    file_bytes = 0;
                    file_cut = false;
                }
                if bytes.len() >= TOTAL_SCAN_BYTES {
                    ran_out = true;
                    break;
                }
                if line_cut {
                    file_cut = true;
                }
                if !header && file_bytes + line.len() > FILE_SCAN_BYTES {
                    file_cut = true;
                    continue;
                }
                file_bytes += line.len();
                bytes.extend_from_slice(&line);
            }
            Ok(None) => break,
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    finish(&file, file_cut || ran_out, &mut skipped);
    if ran_out {
        skipped.push("the rest of the diff".to_string());
        let _ = child.kill();
    }
    let status = child.wait().ok()?;
    if failed || (!ran_out && !status.success()) {
        return None;
    }
    Some(DiffRead {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        skipped,
    })
}

fn git_ok(workspace: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether this checkout has `rev` as a commit. Only a full object id is ever asked about:
/// what a result's payload names is never handed to git as anything else (see
/// [`ferryman_channel::worktree::commit_of`]).
fn has_commit(workspace: &Path, rev: &str) -> bool {
    ferryman_channel::worktree::commit_of(workspace, rev).is_some()
}

/// The commit a ref names here, when it names one.
fn tip_of(workspace: &Path, refname: &str) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "--verify", "--quiet", END_OF_OPTIONS])
        .arg(format!("{refname}^{{commit}}"))
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && ferryman_channel::worktree::is_object_id(&line)).then_some(line)
}

/// Fetch `what` from `origin`, quietly, without ever prompting, and give up after
/// [`FETCH_SECONDS`]. A missing remote or a failed fetch is just `false`. `what` is a
/// branch this crate derived from an order id or a full object id; anything else is
/// refused, and `--end-of-options` stands before it regardless, so a value such as
/// `--upload-pack=<command>` can never be an option of `git fetch`.
fn fetch_from_origin(workspace: &Path, what: &str) -> bool {
    if what.trim().is_empty() || what.starts_with('-') || what.contains(['\0', '\n', '\r']) {
        return false;
    }
    if !git_ok(workspace, &["remote", "get-url", "origin"]) {
        return false;
    }
    let Ok(mut child) = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args([
            "fetch",
            "--quiet",
            "--no-tags",
            END_OF_OPTIONS,
            "origin",
            what,
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if started.elapsed().as_secs() < FETCH_SECONDS => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// What reading an order's branch came to.
enum OrderRead {
    /// Not a git repository, or no branch and no commit to read: nothing to scan.
    Nothing,
    Read(DiffRead),
    /// The result names a commit this machine cannot read. Never replaced by an older tip.
    Unreadable(String),
}

/// What a result's `worktree_head` is allowed to be, said once: `value` is the payload's
/// text, so it is shown only as printable characters and never longer than a line.
fn shown(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .take(24)
        .collect()
}

/// Read the order's branch. `gated` orders (the ones the adversary exists to check) are
/// never read as "nothing to scan" when this is a git workspace: a result with no readable
/// commit is a diff nobody read, and says so.
fn read_order(route: &ProjectRoute, result: &TaskResult, gated: bool) -> OrderRead {
    let workspace = &route.workspace;
    if !ferryman_channel::worktree::is_git_repo(workspace) {
        return OrderRead::Nothing;
    }
    let (base, _) = ferryman_channel::worktree::task_base(workspace);
    let branch = ferryman_channel::worktree::branch_name(&result.order_id, &result.agent);
    let diff_to = |tip: &str| read_diff(workspace, &format!("{base}...{tip}"));
    let named = result
        .payload
        .get("worktree_head")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|head| !head.is_empty());
    if let Some(head) = named {
        // The payload is a peer's word. Only a full object id is ever given to git:
        // not `HEAD`, not `origin/main` (whose diff against the base is empty), not
        // `--upload-pack=...`. Nothing is fetched for anything else.
        if !ferryman_channel::worktree::is_object_id(head) {
            return OrderRead::Unreadable(format!(
                "the result names {:?} as its commit, which is not a full commit id (40 or 64 \
                 hex digits), so nothing was fetched and its diff was not read",
                shown(head)
            ));
        }
        // The reviewed commit is the one that counts. Fetch it if it is not here; an older
        // tip of the same branch is a different diff and would clear what it never read.
        if !has_commit(workspace, head) {
            fetch_from_origin(workspace, &branch);
        }
        if !has_commit(workspace, head) {
            fetch_from_origin(workspace, head);
        }
        let short: String = head.chars().take(12).collect();
        if !has_commit(workspace, head) {
            return OrderRead::Unreadable(format!(
                "the result names commit {short}, which is neither in this checkout nor on \
                 origin, so its diff was not read (an older tip of {branch} would be a \
                 different diff)"
            ));
        }
        // The commit must be this order's work: the tip of its branch, or a commit that
        // descends from the base the order started from. Any other commit's diff against
        // the base is somebody else's, or empty.
        let on_branch = [
            format!("refs/heads/{branch}"),
            format!("refs/remotes/origin/{branch}"),
        ]
        .iter()
        .any(|name| tip_of(workspace, name).as_deref() == Some(head));
        if !on_branch && !ferryman_channel::worktree::descends_from(workspace, &base, head) {
            return OrderRead::Unreadable(format!(
                "the result names commit {short}, which is not the tip of {branch} and does \
                 not descend from {base}, so it is not this order's work and its diff was \
                 not read"
            ));
        }
        return match diff_to(head) {
            Some(read) => OrderRead::Read(read),
            None => OrderRead::Unreadable(format!(
                "git could not diff the base against commit {short}, so it was not read"
            )),
        };
    }
    // No commit named: the branch itself is read, from origin first - a local branch left
    // behind is an older diff than the one that was reviewed.
    let fetched = fetch_from_origin(workspace, &branch);
    let local = format!("refs/heads/{branch}");
    let remote = format!("refs/remotes/origin/{branch}");
    let tips = if fetched {
        [remote, local]
    } else {
        [local, remote]
    };
    if let Some(read) = tips.iter().find_map(|tip| diff_to(tip)) {
        return OrderRead::Read(read);
    }
    if gated {
        return OrderRead::Unreadable(format!(
            "the result names no commit and {branch} is not readable here or on origin, so \
             what it changed was not read"
        ));
    }
    OrderRead::Nothing
}

/// The order branch's diff against its base, as this machine's repository has it (the
/// text of what the scan read, capped per file). `None` when the workspace is not a git
/// repository or the diff could not be read.
#[must_use]
pub fn order_diff(route: &ProjectRoute, result: &TaskResult) -> Option<String> {
    match read_order(route, result, false) {
        OrderRead::Read(read) => Some(read.text),
        _ => None,
    }
}

/// What reading and scanning an order's branch found.
#[derive(Debug, Default)]
pub struct OrderScan {
    pub diff: Option<String>,
    pub hits: Vec<tamper::Hit>,
}

impl OrderScan {
    /// Whether the scan found High tampering (not merely a part it could not read).
    #[must_use]
    pub fn tampered(&self) -> bool {
        tamper::has_high(&self.hits)
    }

    /// Whether any of the diff went unread.
    #[must_use]
    pub fn unscanned(&self) -> bool {
        self.hits
            .iter()
            .any(|hit| hit.kind == tamper::Kind::Unscanned)
    }

    /// The least verdict this scan allows: Block on High tampering, Concern when part of the
    /// diff was not read (it is not cleared), else Pass.
    #[must_use]
    pub fn floor(&self) -> Verdict {
        if self.tampered() {
            Verdict::Block
        } else if self.unscanned() {
            Verdict::Concern
        } else {
            Verdict::Pass
        }
    }
}

/// Read the order's branch and scan it for tampering. A diff too large to read in full, or a
/// commit that cannot be read at all, is a finding of its own - and so, for a `gated`
/// order in a git workspace, is a result that names no readable commit.
#[must_use]
pub fn scan_order(
    route: &ProjectRoute,
    result: &TaskResult,
    required: &[Vec<String>],
    gated: bool,
) -> OrderScan {
    match read_order(route, result, gated) {
        OrderRead::Nothing => OrderScan::default(),
        OrderRead::Unreadable(why) => OrderScan {
            diff: None,
            hits: vec![tamper::Hit {
                kind: tamper::Kind::Unscanned,
                severity: Severity::Medium,
                file: ferryman_channel::worktree::branch_name(&result.order_id, &result.agent),
                detail: why,
            }],
        },
        OrderRead::Read(read) => {
            let mut hits = tamper::scan(&read.text, required);
            if !read.skipped.is_empty() {
                let files: Vec<&str> = read
                    .skipped
                    .iter()
                    .take(NAMED_SKIPPED)
                    .map(String::as_str)
                    .collect();
                let more = read.skipped.len().saturating_sub(NAMED_SKIPPED);
                let tail = if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                };
                hits.push(tamper::Hit {
                    kind: tamper::Kind::Unscanned,
                    severity: Severity::High,
                    file: files[0].to_string(),
                    detail: format!(
                        "diff too large to scan: {}{tail}; what was not read was not cleared",
                        files.join(", ")
                    ),
                });
                hits.sort_by_key(|hit| std::cmp::Reverse(hit.severity));
            }
            OrderScan {
                diff: Some(read.text),
                hits,
            }
        }
    }
}

/// Whether nothing is left for `me` to ask at (subject, revision, trigger): this agent has
/// already recorded a finding for it - and only that. Every eligible adversary runs its own
/// pass ([`data::done`] is per signer), so one adversary's Pass does not stand in for
/// another's look: an eligible Block from any of them dominates, and an adversary that
/// would have blocked is not silenced by whoever got there first. (An agent that would not
/// be heard - it built the work, or the master's adversary policy does not allow it - is
/// stopped earlier, by [`data::eligibility`], before anything is paid for.)
fn settled(route: &ProjectRoute, subject: &str, revision: u32, trigger: Trigger, me: &str) -> bool {
    data::done(route, subject, revision, trigger, me)
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
            result_digest: context.result_digest.clone(),
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
        let scan = scan_order(route, result, &required_of(&task), true);
        let request = Request {
            subject: task.order.id.clone(),
            order_id: task.order.id.clone(),
            revision,
            result_digest: data::result_digest(result),
            trigger: Trigger::PreDone,
            built_by: Builder::from_payload(&result.payload).into_iter().collect(),
            prompt: pre_done_prompt(&task, result, &scan.hits, scan.diff.as_deref()),
            known: scan.hits.iter().map(tamper::Hit::issue).collect(),
            // Tampering is a fact whatever the model says; so is a diff nobody read.
            floor: scan.floor(),
        };
        match challenge(route, config, policy, request, now, report).await {
            Outcome::Recorded(_) => challenged += 1,
            Outcome::Held(why) | Outcome::Failed(why) | Outcome::Ineligible(why)
                if scan.tampered() =>
            {
                // No engine could be asked, but the scan found what it found.
                if scan_only(
                    route,
                    config,
                    &task.order.id,
                    revision,
                    Trigger::PreDone,
                    &data::result_digest(result),
                    &scan.hits,
                    &why,
                    report,
                )
                .is_some()
                {
                    challenged += 1;
                }
            }
            Outcome::Held(_)
            | Outcome::Failed(_)
            | Outcome::Ineligible(_)
            | Outcome::Off
            | Outcome::Existing(_) => {}
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
    // One paid look per failed attempt per adversary: when this agent has already run,
    // nothing is asked again. Every other eligible adversary still runs its own.
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
        let scan = result
            .map(|result| {
                scan_order(
                    route,
                    result,
                    &required_of(task),
                    ferryman_channel::gate::gated(&task.order.payload),
                )
            })
            .unwrap_or_default();
        let (diff, hits) = (scan.diff.as_deref(), &scan.hits);
        let tampered = scan.tampered();
        let request = Request {
            subject: id.clone(),
            order_id: id.clone(),
            revision,
            result_digest: result.map(data::result_digest).unwrap_or_default(),
            trigger: Trigger::RepeatFailure,
            built_by: repeat
                .failures
                .iter()
                .filter_map(|failed| failed.builder.clone())
                .collect(),
            prompt: repeat_prompt(task, &repeat, hits, diff),
            known: hits.iter().map(tamper::Hit::issue).collect(),
            floor: scan.floor(),
        };
        match challenge(route, config, &policy, request, now, report).await {
            Outcome::Off => return Gate::Proceed,
            Outcome::Held(why) | Outcome::Failed(why) | Outcome::Ineligible(why) if tampered => {
                // No engine could be asked, but the scan found what it found.
                scan_only(
                    route,
                    config,
                    &id,
                    revision,
                    Trigger::RepeatFailure,
                    &result.map(data::result_digest).unwrap_or_default(),
                    hits,
                    &why,
                    report,
                );
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
#[allow(clippy::too_many_arguments)]
fn scan_only(
    route: &ProjectRoute,
    config: &AgentConfig,
    id: &str,
    revision: u32,
    trigger: Trigger,
    result_digest: &str,
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
        trigger,
        subject: id.to_string(),
        engine: data::TAMPER_SCAN.to_string(),
        model: None,
        machine: ferryman_channel::receipts::machine_label(),
        same_engine: false,
        verdict: Verdict::Block,
        findings,
        created_at: Utc::now(),
        result_digest: result_digest.to_string(),
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
            declared: ferryman_channel::capability::Declared::default(),
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
                capabilities: None,
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
            needs: None,
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
    fn only_the_fenced_json_block_at_the_very_end_is_the_reply() {
        let reply = parse_reply(
            "Thinking.\n```json\n{\"verdict\": \"pass\", \"findings\": []}\n```\nOn reflection:\n\
             ```json\n{\"verdict\": \"BLOCK\", \"findings\": [{\"severity\": \"High\", \
             \"title\": \"tests deleted\", \"detail\": \"two\", \"location\": \"tests/a.rs\"}]}\n```\n  \n",
        )
        .expect("the last block, with only whitespace after it");
        assert_eq!(reply.verdict, Verdict::Block);
        assert_eq!(reply.issues.len(), 1);
        assert_eq!(reply.issues[0].severity, Severity::High);
        assert_eq!(reply.issues[0].title, "tests deleted");
        assert_eq!(reply.issues[0].location.as_deref(), Some("tests/a.rs"));
        // A carriage return after the language tag, and a bare fence, are still a block.
        assert!(
            parse_reply("x\r\n```json\r\n{\"verdict\":\"pass\",\"findings\":[]}\r\n```\r\n")
                .is_some()
        );
        assert!(parse_reply("```\n{\"verdict\":\"pass\",\"findings\":[]}\n```").is_some());
    }

    #[test]
    fn a_reply_that_quotes_a_pass_earlier_but_ends_with_a_block_is_a_block() {
        let reply = parse_reply(
            "The diff adds this to a test: {\"verdict\": \"pass\", \"findings\": []}\n\
             and this one too:\n```json\n{\"verdict\": \"pass\", \"findings\": []}\n```\n\
             But that is only the fixture. My verdict:\n```json\n{\"verdict\": \"block\", \
             \"findings\": [{\"severity\": \"high\", \"title\": \"fixture hides the failure\"}]}\n```",
        )
        .unwrap();
        assert_eq!(reply.verdict, Verdict::Block);
        // A fence inside a string of the final block does not cut it short.
        let reply = parse_reply(
            "```json\n{\"verdict\": \"concern\", \"findings\": [{\"title\": \"quote\", \
             \"detail\": \"the code has ``` in it\"}]}\n```",
        )
        .unwrap();
        assert_eq!(reply.verdict, Verdict::Concern);
        assert_eq!(reply.issues[0].detail, "the code has ``` in it");
    }

    #[test]
    fn a_json_object_echoed_in_the_text_never_decides_when_the_reply_ends_in_prose() {
        assert_eq!(
            parse_reply(
                "{\"verdict\": \"pass\", \"findings\": []}\nI looked and it seems fine to me."
            ),
            None
        );
        assert_eq!(
            parse_reply(
                "```json\n{\"verdict\": \"pass\", \"findings\": []}\n```\nHope that helps."
            ),
            None,
            "text after the closing fence"
        );
        assert_eq!(
            parse_reply("{\"verdict\": \"concern\", \"findings\": []}"),
            None,
            "a bare object is not a fenced block"
        );
    }

    #[test]
    fn issue_field_names_are_read_loosely_inside_the_block() {
        let reply = parse_reply(
            "```json\n{\"verdict\": \"concern\", \"findings\": [{\"summary\": \"no limit\", \
             \"description\": \"unbounded\"}, 5]}\n```",
        )
        .unwrap();
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
        )
        .unwrap();
        assert_eq!(reply.verdict, Verdict::Concern);
    }

    #[test]
    fn a_reply_that_cannot_be_read_is_not_a_reply() {
        for text in [
            "I looked and it seems fine to me.",
            "",
            "   \n",
            "```json\n{\"verdict\": \"fine\", \"findings\": []}\n```",
            "```json\n{not json at all\n```",
            "```json\n{\"findings\": []}\n```",
            "```json\n{\"verdict\": \"pass\"}\n```",
            "```json\n{\"verdict\": \"pass\", \"findings\": \"none\"}\n```",
            "Reading it.\n```json\n{\"verdict\": \"blo",
            "Reading it.\n```json\n{\"verdict\": \"block\", \"findings\": []}",
            "```json\n[{\"verdict\": \"pass\", \"findings\": []}]\n```",
        ] {
            assert_eq!(parse_reply(text), None, "{text:?}");
        }
        assert!(unreadable("  ").contains("empty"));
        let long = format!("{}THE END OF IT", "x".repeat(5_000));
        assert!(
            unreadable(&long).contains("THE END OF IT"),
            "the tail is kept"
        );
        assert!(unreadable(&long).len() < 800, "and only the tail");
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
                result_digest: String::new(),
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
        // The adversary's own `never`: the engine policy's does not reach it.
        policy.adversary_never.push("name:qwen".into());
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy,
            Request {
                subject: "t-1".into(),
                order_id: "t-1".into(),
                revision: 1,
                result_digest: String::new(),
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
            result_digest: String::new(),
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
    fn an_unreadable_reply_is_never_recorded_so_it_cannot_clear_blocking_mode() {
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
        set_mode(&route, AdversaryMode::Blocking);
        awaiting(&route, "t-n4-1", "deepseek");
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-n4-1", Trigger::PreDone),
            Utc::now(),
            &crate::Silent,
        ));
        match outcome {
            Outcome::Failed(why) => assert!(
                why.contains("could not be read") && why.contains("qwen"),
                "{why}"
            ),
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(
            data::list(&route).is_empty(),
            "nothing was signed: {:?}",
            data::list(&route)
        );
        assert!(data::standing(&route, "t-n4-1", 1, Trigger::PreDone).is_none());
        // So blocking mode still holds the review engine's key: no adversary has read it.
        let why =
            data::engine_key_refusal(&route, &policy_of(&route), "t-n4-1", 1).expect("still held");
        assert!(why.contains("no adversary has read"), "{why}");
        // And a reply that quotes a pass but ends with a block is the block.
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine(
                "qwen",
                "qwen-max",
                "fake://ok:The test says {\"verdict\": \"pass\", \"findings\": []}.\n```json\n{\"verdict\": \"block\", \"findings\": [{\"severity\": \"high\", \"title\": \"hidden\"}]}\n```",
            )],
        );
        awaiting(&route, "t-n4-2", "deepseek");
        let outcome = futures_lite_block(challenge(
            &route,
            &config,
            &policy_of(&route),
            simple("t-n4-2", Trigger::PreDone),
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(outcome.finding().unwrap().verdict, Verdict::Block);
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

    #[test]
    fn the_engine_policys_where_list_does_not_keep_the_adversary_off_the_work() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        // The engine policy runs this project's work on another machine only. The
        // adversary is not the engine policy's to place: it still reads the work here.
        ferryman_channel::policy::set_policy(
            &route.communications,
            &route.project_id,
            Some(Policy {
                machines: vec!["somewhere-else".into()],
                adversary: AdversaryMode::Blocking,
                ..Policy::default()
            }),
            &josh(),
        )
        .unwrap();
        let task = awaiting(&route, "t-n2-1", "deepseek");
        let policy = policy_of(&route);
        assert!(!may_judge(&route, &policy, &task), "not read yet");
        let done = futures_lite_block(crate::improve::review(
            &route,
            &config,
            Utc::now(),
            &crate::Silent,
        ))
        .unwrap();
        assert_eq!(
            done, 1,
            "the adversary challenged it before `where` stopped the judge"
        );
        assert!(data::read(&route, "t-n2-1", 1, Trigger::PreDone, "wisp").is_some());
    }

    #[test]
    fn every_eligible_adversary_runs_and_an_eligible_block_dominates() {
        use ferryman_channel::AgentIdentity;
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("block", HIGH))],
        );
        // A second adversary, which has already passed this work.
        let scout = AgentIdentity::from_seed("scout", [11; 32]);
        let mut route = route;
        let agent = ferryman_channel::AgentRoute {
            name: "scout".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(scout.public_key_hex()),
            encryption_key: None,
        };
        ferryman_channel::register_agent(&route, &agent).unwrap();
        route.agents.push(agent);
        let report = |name: &str| ferryman_channel::receipts::EngineReport {
            name: name.into(),
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
        };
        ferryman_channel::receipts::refresh_engines(
            &route,
            &scout,
            "scout-machine",
            "0.0.0",
            vec![report("qwen")],
            Utc::now(),
        )
        .unwrap();
        awaiting(&route, "t-n3-1", "deepseek");
        let mut passed = finding("t-n3-1", Verdict::Pass);
        passed.engine = "qwen".into();
        data::record(&route, &scout, passed).unwrap();
        assert!(
            data::standing(&route, "t-n3-1", 1, Trigger::PreDone).is_some(),
            "scout's Pass counts"
        );

        // wisp is eligible too, so it runs - one adversary's Pass is not another's look.
        let policy = policy_of(&route);
        assert_eq!(
            futures_lite_block(pass(&route, &config, &policy, Utc::now(), &crate::Silent)),
            1
        );
        assert!(data::read(&route, "t-n3-1", 1, Trigger::PreDone, "wisp").is_some());
        let standing = data::standing(&route, "t-n3-1", 1, Trigger::PreDone).unwrap();
        assert_eq!(standing.verdict(), Verdict::Block, "the Block dominates");
        // Asked once each: running again records nothing new.
        assert_eq!(
            futures_lite_block(pass(&route, &config, &policy, Utc::now(), &crate::Silent)),
            0
        );
    }

    fn finding(subject: &str, verdict: Verdict) -> AdversaryFinding {
        AdversaryFinding {
            order_id: subject.into(),
            revision: 1,
            trigger: Trigger::PreDone,
            subject: subject.into(),
            engine: "qwen".into(),
            model: None,
            machine: "fixture-machine".into(),
            same_engine: false,
            verdict,
            findings: Vec::new(),
            created_at: Utc::now(),
            result_digest: String::new(),
            signed_by: String::new(),
            signature: String::new(),
        }
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
                needs: None,
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

    // --- reading the diff: caps per file, a missing commit, the floor ----------------------------

    fn kinds(scan: &OrderScan) -> Vec<tamper::Kind> {
        scan.hits.iter().map(|hit| hit.kind).collect()
    }

    #[test]
    fn a_huge_early_file_cannot_push_a_later_test_deletion_out_of_the_scan() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        // Sorts before tests/double.rs and is bigger than the old global cap on its own.
        let big = "let x = 1;\n".repeat(300_000);
        branch(&route, "t-1", &[("a_big.rs", &big)], &["tests/double.rs"]);
        let scan = scan_order(&route, &result("t-1", 1, "deepseek", 0), &[], true);
        let kinds = kinds(&scan);
        assert!(
            kinds.contains(&tamper::Kind::DeletedTest),
            "the deletion after the big file is found: {:?}",
            scan.hits
        );
        let unscanned = scan
            .hits
            .iter()
            .find(|hit| hit.kind == tamper::Kind::Unscanned)
            .expect("the file that was not read in full is named");
        assert_eq!(unscanned.severity, Severity::High);
        assert!(
            unscanned
                .detail
                .starts_with("diff too large to scan: a_big.rs"),
            "{}",
            unscanned.detail
        );
        assert_eq!(scan.floor(), Verdict::Block, "the deletion is tampering");
        assert!(
            scan.diff.as_deref().unwrap().len() < 1024 * 1024,
            "one file is kept to its own cap"
        );
    }

    #[test]
    fn a_diff_too_big_to_read_and_nothing_else_is_a_concern_not_a_pass_and_a_lockfile_is_not() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        let big = "let x = 1;\n".repeat(60_000);
        branch(&route, "t-1", &[("src/big.rs", &big)], &[]);
        let scan = scan_order(&route, &result("t-1", 1, "deepseek", 0), &[], true);
        assert!(scan.unscanned() && !scan.tampered(), "{:?}", scan.hits);
        assert_eq!(scan.floor(), Verdict::Concern);

        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        let lock = "name = \"x\"\n".repeat(60_000);
        branch(&route, "t-2", &[("Cargo.lock", &lock)], &[]);
        let scan = scan_order(&route, &result("t-2", 1, "deepseek", 0), &[], true);
        assert!(scan.hits.is_empty(), "{:?}", scan.hits);
        assert_eq!(scan.floor(), Verdict::Pass);
    }

    #[test]
    fn a_commit_the_result_names_that_is_not_here_is_a_concern_never_the_older_branch_tip() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        // The branch tip here deletes a test; the commit the result names is not here.
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let mut named = result("t-1", 1, "deepseek", 0);
        named.payload["worktree_head"] = json!("0123456789abcdef0123456789abcdef01234567");
        assert!(order_diff(&route, &named).is_none(), "no stand-in diff");
        let scan = scan_order(&route, &named, &[], true);
        assert!(scan.diff.is_none());
        assert!(
            !scan.tampered(),
            "it did not read the older tip: {:?}",
            scan.hits
        );
        assert_eq!(scan.floor(), Verdict::Concern);
        assert!(
            scan.hits[0].detail.contains("0123456789ab")
                && scan.hits[0].detail.contains("not read"),
            "{:?}",
            scan.hits
        );
    }

    #[test]
    fn a_commit_that_is_only_on_origin_is_fetched_before_it_is_read() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        let repo = route.workspace.clone();
        let origin = dir.path().join("origin.git");
        run_origin(&origin);
        git(
            &repo,
            &["remote", "add", "origin", &origin.display().to_string()],
        );
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let name = ferryman_channel::worktree::branch_name("t-1", "fang");
        let head = git(&repo, &["rev-parse", &name]);
        git(&repo, &["push", "-q", "origin", &name]);
        // Forget it locally: the branch, its remote-tracking ref and the object itself.
        git(&repo, &["branch", "-q", "-D", &name]);
        git(
            &repo,
            &["update-ref", "-d", &format!("refs/remotes/origin/{name}")],
        );
        git(&repo, &["reflog", "expire", "--expire=now", "--all"]);
        git(&repo, &["gc", "-q", "--prune=now"]);
        assert!(!has_commit(&repo, &head), "the commit is gone from here");

        let mut named = result("t-1", 1, "deepseek", 0);
        named.payload["worktree_head"] = json!(head);
        let scan = scan_order(&route, &named, &[], true);
        assert!(
            kinds(&scan).contains(&tamper::Kind::DeletedTest),
            "fetched and read: {:?}",
            scan.hits
        );
        assert!(!scan.unscanned());
    }

    fn run_origin(path: &Path) {
        let out = Command::new("git")
            .args(["init", "-q", "--bare"])
            .arg(path)
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    #[test]
    fn a_worktree_head_that_is_not_a_full_commit_id_never_reaches_git_and_is_a_concern() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        let repo = route.workspace.clone();
        let origin = dir.path().join("origin.git");
        run_origin(&origin);
        git(
            &repo,
            &["remote", "add", "origin", &origin.display().to_string()],
        );
        // The branch really does delete a test: only a read of it can say so.
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let marker = dir.path().join("pwned");
        let upload_pack = format!("--upload-pack=touch {}", marker.display());
        for head in [
            upload_pack.as_str(),
            "--output=pwned-file",
            "-h",
            "HEAD",
            "origin/main",
            "main",
            "refs/heads/main",
            "abc",
            "0123456789abcdef0123456789ABCDEF01234567",
            "0123456789abcdef0123456789abcdef01234567",
        ] {
            let mut named = result("t-1", 1, "deepseek", 0);
            named.payload["worktree_head"] = json!(head);
            assert!(order_diff(&route, &named).is_none(), "{head}: no diff");
            let scan = scan_order(&route, &named, &[], true);
            assert!(scan.diff.is_none(), "{head}");
            assert!(
                scan.unscanned() && !scan.tampered(),
                "{head}: it is a diff nobody read, not a clean one: {:?}",
                scan.hits
            );
            assert_eq!(scan.floor(), Verdict::Concern, "{head}");
        }
        assert!(!marker.exists(), "no command ran");
        assert!(!repo.join("pwned-file").exists());
        assert!(!fetch_from_origin(&repo, &upload_pack));
        assert!(!marker.exists());
        assert!(!has_commit(&repo, "HEAD") && !has_commit(&repo, "--help"));
    }

    #[test]
    fn a_commit_that_is_neither_the_order_branch_nor_a_descendant_of_its_base_is_not_read() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        let repo = route.workspace.clone();
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        // An unrelated history: a root commit that shares nothing with `main`.
        git(&repo, &["checkout", "-q", "--orphan", "stray"]);
        git(&repo, &["rm", "-rfq", "."]);
        fs::write(repo.join("other.txt"), "x").unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "stray"]);
        let stray = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["checkout", "-q", "-f", "main"]);
        let mut named = result("t-1", 1, "deepseek", 0);
        named.payload["worktree_head"] = json!(stray);
        let scan = scan_order(&route, &named, &[], true);
        assert!(scan.diff.is_none(), "{:?}", scan.hits);
        assert_eq!(scan.floor(), Verdict::Concern);
        assert!(
            scan.hits[0].detail.contains("not this order's work"),
            "{:?}",
            scan.hits
        );
        // The real tip is read, and its deleted test is found.
        let name = ferryman_channel::worktree::branch_name("t-1", "fang");
        named.payload["worktree_head"] = json!(git(&repo, &["rev-parse", &name]));
        let scan = scan_order(&route, &named, &[], true);
        assert!(kinds(&scan).contains(&tamper::Kind::DeletedTest));
    }

    #[test]
    fn a_gated_order_with_no_readable_commit_in_a_git_workspace_is_a_concern_not_a_pass() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        // No head named and no branch anywhere.
        let result = result("t-9", 1, "deepseek", 0);
        let scan = scan_order(&route, &result, &[], true);
        assert!(scan.unscanned(), "{:?}", scan.hits);
        assert_eq!(scan.floor(), Verdict::Concern);
        // An order that is not gated has nothing to scan, as before.
        let scan = scan_order(&route, &result, &[], false);
        assert!(scan.hits.is_empty());
        assert_eq!(scan.floor(), Verdict::Pass);
    }

    #[test]
    fn with_no_head_named_the_branch_is_fetched_before_a_stale_local_one_is_read() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, _config) = fixture(dir.path(), Vec::new());
        let repo = route.workspace.clone();
        let origin = dir.path().join("origin.git");
        run_origin(&origin);
        git(
            &repo,
            &["remote", "add", "origin", &origin.display().to_string()],
        );
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        let name = ferryman_channel::worktree::branch_name("t-1", "fang");
        git(&repo, &["push", "-q", "origin", &name]);
        // What is local is stale: the branch is back at `main`, and so is its tracking ref.
        git(&repo, &["branch", "-q", "-f", &name, "main"]);
        git(
            &repo,
            &["update-ref", &format!("refs/remotes/origin/{name}"), "main"],
        );
        let scan = scan_order(&route, &result("t-1", 1, "deepseek", 0), &[], true);
        assert!(
            kinds(&scan).contains(&tamper::Kind::DeletedTest),
            "the fetched tip was read, not the stale one: {:?}",
            scan.hits
        );
    }

    #[test]
    fn the_pre_done_pass_floors_a_high_tampering_hit_at_block_whatever_the_engine_says() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(
            dir.path(),
            vec![engine("qwen", "qwen-max", &says("pass", ""))],
        );
        branch(&route, "t-1", &[], &["tests/double.rs"]);
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
        assert_eq!(finding.verdict, Verdict::Block, "{finding:?}");
        assert_eq!(finding.engine, "qwen");
    }

    #[test]
    fn the_pre_done_pass_records_a_high_hit_with_no_engine_to_ask() {
        hermetic();
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(dir.path(), Vec::new());
        branch(&route, "t-1", &[], &["tests/double.rs"]);
        awaiting(&route, "t-1", "deepseek");
        let challenged = futures_lite_block(pass(
            &route,
            &config,
            &policy_of(&route),
            Utc::now(),
            &crate::Silent,
        ));
        assert_eq!(challenged, 1);
        let finding =
            data::read(&route, "t-1", 1, Trigger::PreDone, "wisp").expect("recorded by the scan");
        assert_eq!(finding.verdict, Verdict::Block);
        assert_eq!(finding.engine, "tamper-scan");
        assert_eq!(finding.trigger, Trigger::PreDone);
        assert!(finding.has_high());
        // And it counts: the floor is not a file nobody listens to. Under `blocking` it
        // holds the review engine's key until the master answers.
        let standing = data::standing(&route, "t-1", 1, Trigger::PreDone)
            .expect("the pre-done scan finding is eligible with no engine inventory for it");
        assert!(standing.unresolved_block());
        assert!(data::unresolved_block(&route, &policy_of(&route), "t-1", 1).is_some());

        // A clean branch with no engine records nothing, as before.
        let dir = tempfile::tempdir().unwrap();
        let (route, config) = fixture(dir.path(), Vec::new());
        awaiting(&route, "t-2", "deepseek");
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
        assert!(data::list(&route).is_empty());
    }
}

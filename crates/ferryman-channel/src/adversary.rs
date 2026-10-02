//! The adversary: a second model that challenges the work at three critical moments.
//!
//! ```text
//! <channel>/adversary/<subject>-r<revision>-<trigger>.<signer>.json            the finding, signed by <signer>
//! <channel>/adversary/<subject>-r<revision>-<trigger>.<signer>.override.json   the master's override of that finding
//! <channel>/adversary/<subject>-r<revision>-<trigger>.override.json            the master's waiver: go ahead with no finding
//! ```
//!
//! Builders (cheap and medium models) build. A separate engine, the *adversary*, reads
//! the work and tries to break it - but only when it matters, so it costs little:
//!
//! 1. [`Trigger::ContractLock`]: before an interface contract is locked - does what the
//!    provider returns match what the consumers expect?
//! 2. [`Trigger::RepeatFailure`]: when the same order has failed twice - is the next
//!    attempt fixing the cause or hiding the symptom?
//! 3. [`Trigger::PreDone`]: before an improvement is called done - what attack surface or
//!    edge case did everyone overlook?
//!
//! This module is the data: the signed finding, where it lives, who may override one, and
//! what each [`AdversaryMode`](crate::policy::AdversaryMode) makes of it. Asking an engine
//! is `ferryman-ops`' job; the deterministic parts - [`crate::tamper`] and
//! [`contract_context`] - live here so every machine reads the same facts.
//!
//! # Whose word counts
//!
//! A finding is honoured only when all of these hold; anything else is *ignored* (and
//! shown as "ignored: why" by `ferry adversary show`), exactly as a missing finding is:
//!
//! - its signature verifies against the channel's roster, its signer has not been revoked,
//!   and the file's name names that signer: one writer per path, so nobody can overwrite
//!   or pre-empt another adversary's word;
//! - its signer did not build the work it judges - the agent whose result it challenges
//!   (for a contract, any provider order's result agent);
//! - its signer published a valid signed engine inventory that lists the engine the
//!   finding names, so the engine named is one a machine of the fleet really has;
//! - the engine policy's `where` list, when it has one, allows the signer's machine;
//! - its revision is a real one: an order's existing result, a contract's existing provider
//!   result - or 0, "the shapes on their own", while no provider has a result.
//!
//! The deterministic tamper scan ([`TAMPER_SCAN`]) is the one exception to the builder and
//! engine rules, because it asks no model and can only block: a worker may record what the
//! scan found in the diff it is about to retry.
//!
//! # What the findings add up to
//!
//! For one (subject, revision, trigger) there may be several eligible findings, one per
//! adversary. [`Standing`] adds them up: any eligible Block blocks (Block dominates), and a
//! Block is answered only by an override of *each* Block. Gates read the revision under
//! decision - the provider result a lock is being decided on, the revision the review
//! engine is judging, the failed attempt the next one follows - never "the highest
//! revision there is", so a Pass at r999 cannot mask a Block at r1.
//!
//! A missing finding never blocks anything in `off` or `advisory` mode: the adversary is a
//! check on the work, not a gate that fails shut when the adversary is away. In `blocking`
//! mode it does fail shut: the lock, the engine key and auto-merge each wait for an
//! eligible finding on exactly the revision decided, or for the master's signed waiver
//! ([`waive`]). (The loop itself also holds the engine key in `blocking` mode until the
//! adversary has run; see `ferryman_ops::adversary`.)
//!
//! # Idempotence
//!
//! One run per (subject, revision, trigger, signer). [`record`] refuses to write a second
//! finding where the same signer's genuine one exists, so a loop that wakes every hour
//! pays once - while each eligible adversary still runs its own pass ([`done`]).
//!
//! # Override
//!
//! In `blocking` mode a Block stops the lock or the engine key. Only the master - or a
//! delegate holding the matching scope - may sign an [`Override`], which is recorded and
//! covers exactly the finding it names. The override does not edit the finding: the
//! record of what the adversary said, and that the master went ahead anyway, stays. It
//! names the finding the master looked at (`expected_finding`), so an override cannot be
//! applied to a finding that was replaced after they read it.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    AgentIdentity, ProjectRoute, SignatureCheck, Task, check_signature, delegation,
    interface::{self, InterfaceContract},
    is_safe_component,
    policy::{AdversaryMode, Builder, Policy},
};

const DIR: &str = "adversary";
/// Findings kept in one channel view before older ones are left out of a listing.
const MAX_LISTED: usize = 500;

/// The three moments the adversary is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trigger {
    /// Before an interface contract locks.
    ContractLock,
    /// When the same order has failed twice, before the next attempt.
    RepeatFailure,
    /// Before an improvement is called done.
    PreDone,
}

impl Trigger {
    pub const ALL: [Trigger; 3] = [Self::ContractLock, Self::RepeatFailure, Self::PreDone];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractLock => "contract-lock",
            Self::RepeatFailure => "repeat-failure",
            Self::PreDone => "pre-done",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "contract-lock" | "contract" | "lock" => Ok(Self::ContractLock),
            "repeat-failure" | "repeat" => Ok(Self::RepeatFailure),
            "pre-done" | "predone" | "done" => Ok(Self::PreDone),
            other => bail!("a trigger is contract-lock, repeat-failure or pre-done, not '{other}'"),
        }
    }

    /// As a person reads it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ContractLock => "before the contract locks",
            Self::RepeatFailure => "after the order failed twice",
            Self::PreDone => "before it is called done",
        }
    }

    /// The delegation scope that may override a Block at this moment: a contract is
    /// decided with `improve` (the scope that locks it), a result with `review` (the scope
    /// that approves it).
    #[must_use]
    pub fn override_scope(self) -> &'static str {
        match self {
            Self::ContractLock => delegation::IMPROVE,
            Self::RepeatFailure | Self::PreDone => delegation::REVIEW,
        }
    }
}

/// What the adversary concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Nothing worth stopping for.
    Pass,
    /// Something to read before going on.
    Concern,
    /// Do not go on: the work is wrong, or the symptom is being hidden.
    Block,
}

impl Verdict {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "pass" | "ok" | "approve" => Ok(Self::Pass),
            "concern" | "concerns" | "warn" | "warning" => Ok(Self::Concern),
            "block" | "blocked" | "reject" | "fail" => Ok(Self::Block),
            other => bail!("a verdict is pass, concern or block, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Concern => "concern",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" | "minor" | "info" => Ok(Self::Low),
            "medium" | "med" | "moderate" => Ok(Self::Medium),
            "high" | "critical" | "severe" => Ok(Self::High),
            other => bail!("a severity is low, medium or high, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One thing the adversary found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// A file, `file:line`, or contract path the issue is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// The adversary's signed record of one challenge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdversaryFinding {
    /// The order the challenge is about; for a contract lock, the first provider order,
    /// or empty when no order provides the contract yet.
    #[serde(default)]
    pub order_id: String,
    /// The revision challenged. For a contract lock: the newest provider result, or 0
    /// when the contract was reviewed on its own.
    pub revision: u32,
    pub trigger: Trigger,
    /// An order id, or `name@version` for a contract.
    pub subject: String,
    pub engine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub machine: String,
    /// The adversary was the engine that built the work: nothing else was allowed.
    #[serde(default)]
    pub same_engine: bool,
    pub verdict: Verdict,
    #[serde(default)]
    pub findings: Vec<Issue>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub signed_by: String,
    #[serde(default)]
    pub signature: String,
}

impl AdversaryFinding {
    fn payload(&self, project: &str) -> String {
        let bare = Self {
            signature: String::new(),
            ..self.clone()
        };
        format!(
            "ferryman-adversary-v1\n{project}\n{}",
            serde_jcs::to_string(&bare).unwrap_or_default()
        )
    }

    /// `block by deepseek: 2 finding(s), the worst "tests were deleted"`.
    #[must_use]
    pub fn describe(&self) -> String {
        let worst = self.top(1).into_iter().next();
        let mut line = format!(
            "{} by {}{}",
            self.verdict.as_str(),
            self.engine,
            if self.same_engine {
                " (the engine that built it)"
            } else {
                ""
            }
        );
        if self.findings.is_empty() {
            line.push_str(": nothing found");
        } else {
            line.push_str(&format!(": {} finding(s)", self.findings.len()));
            if let Some(worst) = worst {
                line.push_str(&format!(
                    ", the worst {} \"{}\"",
                    worst.severity.as_str(),
                    worst.title
                ));
            }
        }
        line
    }

    /// The `n` most severe issues, most severe first, in the order given among equals.
    #[must_use]
    pub fn top(&self, n: usize) -> Vec<&Issue> {
        let mut issues: Vec<&Issue> = self.findings.iter().collect();
        issues.sort_by_key(|issue| std::cmp::Reverse(issue.severity));
        issues.truncate(n);
        issues
    }

    /// The finding as lines a person reads: the headline, then the `n` worst issues.
    #[must_use]
    pub fn lines(&self, n: usize) -> Vec<String> {
        let mut lines = vec![format!(
            "adversary {} ({}): {}",
            self.verdict.as_str().to_ascii_uppercase(),
            self.trigger.label(),
            self.describe()
        )];
        for issue in self.top(n) {
            lines.push(format!(
                "  [{}] {}{}: {}",
                issue.severity.as_str(),
                issue.title,
                issue
                    .location
                    .as_deref()
                    .map(|place| format!(" ({place})"))
                    .unwrap_or_default(),
                issue.detail
            ));
        }
        lines
    }

    /// Whether the finding is one a human could mistake for a pass if only the verdict
    /// were looked at: a Pass with a High issue in it.
    #[must_use]
    pub fn has_high(&self) -> bool {
        self.findings
            .iter()
            .any(|issue| issue.severity == Severity::High)
    }

    /// `<subject>-r<revision>-<trigger>`, the stem of every file about this finding.
    #[must_use]
    pub fn stem(&self) -> String {
        stem(&self.subject, self.revision, self.trigger)
    }
}

fn stem(subject: &str, revision: u32, trigger: Trigger) -> String {
    format!("{subject}-r{revision}-{}", trigger.as_str())
}

/// `<stem>.<signer>.json`: the one path a signer writes a finding to.
fn finding_file(subject: &str, revision: u32, trigger: Trigger, signer: &str) -> String {
    format!("{}.{signer}.json", stem(subject, revision, trigger))
}

/// The engine name the deterministic diff scan records under when no model could be asked.
pub const TAMPER_SCAN: &str = "tamper-scan";

/// What `expected_finding` is when the master looked and no finding counted: the only
/// thing a [`waive`] covers.
pub const NO_FINDING: &str = "none";

/// Whether `subject` names an order or a `name@version` contract and nothing that could
/// climb out of the directory.
#[must_use]
pub fn subject_ok(subject: &str) -> bool {
    match subject.split_once('@') {
        Some((name, version)) => is_safe_component(name) && is_safe_component(version),
        None => is_safe_component(subject),
    }
}

fn dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join(DIR)
}

/// A signer that can be a part of a file name, and is not the word that names a waiver.
fn signer_ok(signer: &str) -> bool {
    is_safe_component(signer) && !signer.eq_ignore_ascii_case("override")
}

/// Where `signer`'s finding for a subject, revision and trigger is stored. Each signer has
/// a path of their own, so nobody can overwrite or pre-empt another adversary's word.
pub fn finding_path(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    signer: &str,
) -> Option<PathBuf> {
    (subject_ok(subject) && signer_ok(signer))
        .then(|| dir(route).join(finding_file(subject, revision, trigger, signer)))
}

fn override_path(route: &ProjectRoute, finding: &AdversaryFinding) -> Option<PathBuf> {
    (subject_ok(&finding.subject) && signer_ok(&finding.signed_by)).then(|| {
        dir(route).join(format!(
            "{}.{}.override.json",
            stem(&finding.subject, finding.revision, finding.trigger),
            finding.signed_by
        ))
    })
}

fn waiver_path(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<PathBuf> {
    subject_ok(subject).then(|| {
        dir(route).join(format!(
            "{}.override.json",
            stem(subject, revision, trigger)
        ))
    })
}

/// A finding read from disk is genuine only if its signature verifies as its signer's and
/// its signer is still on the channel. Whether it *counts* is [`eligibility`]'s question.
fn genuine(route: &ProjectRoute, finding: &AdversaryFinding) -> bool {
    subject_ok(&finding.subject)
        && signer_ok(&finding.signed_by)
        && check_signature(
            Some(&finding.signed_by),
            Some(&finding.signature),
            &finding.payload(&route.project_id),
            &crate::gate::roster(route),
        ) == SignatureCheck::Valid
        && !crate::master::is_revoked(route, &finding.signed_by).unwrap_or(true)
}

/// The genuine findings in files whose names start with `prefix`, read in one pass over
/// the directory. A finding counts only from the file its content names - its subject,
/// revision, trigger and signer - so a copy under another name is not read.
fn scan(route: &ProjectRoute, prefix: &str, subject: Option<&str>) -> Vec<AdversaryFinding> {
    let Ok(entries) = fs::read_dir(dir(route)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            if !name.starts_with(prefix)
                || !name.ends_with(".json")
                || name.ends_with(".override.json")
                || name.contains(".sync-conflict-")
            {
                return None;
            }
            let finding: AdversaryFinding =
                serde_json::from_slice(&fs::read(entry.path()).ok()?).ok()?;
            if subject.is_some_and(|subject| finding.subject != subject) {
                return None;
            }
            (name
                == finding_file(
                    &finding.subject,
                    finding.revision,
                    finding.trigger,
                    &finding.signed_by,
                )
                && genuine(route, &finding))
            .then_some(finding)
        })
        .collect()
}

/// `signer`'s genuine finding for exactly this (subject, revision, trigger), whether or
/// not it counts.
#[must_use]
pub fn read(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    signer: &str,
) -> Option<AdversaryFinding> {
    let path = finding_path(route, subject, revision, trigger, signer)?;
    let finding: AdversaryFinding = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (finding.subject == subject
        && finding.revision == revision
        && finding.trigger == trigger
        && finding.signed_by == signer
        && genuine(route, &finding))
    .then_some(finding)
}

/// Whether `signer` has already run for this (subject, revision, trigger). Per signer: each
/// eligible adversary runs its own pass.
#[must_use]
pub fn done(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    signer: &str,
) -> bool {
    read(route, subject, revision, trigger, signer).is_some()
}

/// Write the finding, signed by `identity`, the agent that ran the engine, at that agent's
/// own path. Returns whether anything was written: `false` when this agent's genuine
/// finding for the same (subject, revision, trigger) is already there, which is what makes
/// a run idempotent.
pub fn record(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    mut finding: AdversaryFinding,
) -> Result<bool> {
    if !subject_ok(&finding.subject) {
        bail!(
            "an adversary subject is an order id or name@version of path-safe parts, not '{}'",
            finding.subject
        );
    }
    if !signer_ok(identity.name()) {
        bail!("agent name must be a path-safe identifier");
    }
    if done(
        route,
        &finding.subject,
        finding.revision,
        finding.trigger,
        identity.name(),
    ) {
        return Ok(false);
    }
    finding.signed_by = identity.name().to_string();
    finding.signature = String::new();
    finding.signature = identity.sign_bytes(finding.payload(&route.project_id).as_bytes());
    let path = finding_path(
        route,
        &finding.subject,
        finding.revision,
        finding.trigger,
        identity.name(),
    )
    .context("a path-safe subject and signer have a path")?;
    crate::atomic_json(&path, &finding).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Every genuine finding, newest first (at most [`MAX_LISTED`]). For display only: a gate
/// decision reads exactly its subject's files ([`standing`], [`survey`]) and never this.
#[must_use]
pub fn list(route: &ProjectRoute) -> Vec<AdversaryFinding> {
    let mut found = scan(route, "", None);
    found.sort_by_key(|finding| std::cmp::Reverse(finding.created_at));
    found.truncate(MAX_LISTED);
    found
}

/// Every genuine finding about `subject`, newest first, however many there are.
#[must_use]
pub fn for_subject(route: &ProjectRoute, subject: &str) -> Vec<AdversaryFinding> {
    if !subject_ok(subject) {
        return Vec::new();
    }
    let mut found = scan(route, &format!("{subject}-r"), Some(subject));
    found.sort_by_key(|finding| std::cmp::Reverse(finding.created_at));
    found
}

// --- whose word counts -----------------------------------------------------------------------

/// A genuine finding that does not count, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Ignored {
    pub finding: AdversaryFinding,
    pub reason: String,
}

impl Ignored {
    /// `ignored: pre-done r2 by wisp (deepseek) - wisp built the work it judged`.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "ignored: {} r{} {} by {} ({}), {} - {}",
            self.finding.subject,
            self.finding.revision,
            self.finding.trigger.as_str(),
            self.finding.signed_by,
            self.finding.engine,
            self.finding.verdict.as_str(),
            self.reason
        )
    }

    /// For a screen or `--json`.
    #[must_use]
    pub fn view(&self) -> Value {
        json!({
            "ignored": true,
            "subject": self.finding.subject,
            "revision": self.finding.revision,
            "trigger": self.finding.trigger.as_str(),
            "verdict": self.finding.verdict.as_str(),
            "engine": self.finding.engine,
            "signed_by": self.finding.signed_by,
            "reason": self.reason,
        })
    }
}

/// What decides whether a finding counts, for one subject: who built it, which revisions
/// exist, what the fleet's signed inventories say each machine can run, and the policy's
/// `where`.
struct Facts {
    contract: bool,
    /// The revisions of verified results, with who built each: the agent a result names
    /// and the key that signed it.
    results: Vec<(u32, String)>,
    inventories: Vec<crate::receipts::EngineInventory>,
    policy: Policy,
}

impl Facts {
    fn load(route: &ProjectRoute, subject: &str) -> Self {
        let (contract, results) = subject_results(route, subject);
        let inventories = crate::receipts::list_engines(route)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, check)| *check == SignatureCheck::Valid)
            .map(|(inventory, _)| inventory)
            .collect();
        let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
        Self {
            contract,
            results,
            inventories,
            policy,
        }
    }

    /// Why `signer`'s word on this revision does not count, or `Ok`.
    fn check(
        &self,
        subject: &str,
        signer: &str,
        engine: Option<&str>,
        revision: u32,
        trigger: Trigger,
        verdict: Verdict,
    ) -> std::result::Result<(), String> {
        let real = self.results.iter().any(|(r, _)| *r == revision)
            || (self.contract && revision == 0 && self.results.is_empty());
        if !real {
            return Err(if self.contract {
                format!("{subject} has no provider result r{revision} to challenge")
            } else {
                format!("{subject} has no result r{revision} to challenge")
            });
        }
        // The scan asks no model and can only block, so the agent that is about to retry
        // may record what it found in its own failed diff.
        let scan = engine == Some(TAMPER_SCAN)
            && trigger == Trigger::RepeatFailure
            && verdict == Verdict::Block;
        let built = self
            .results
            .iter()
            .any(|(r, who)| who.eq_ignore_ascii_case(signer) && (self.contract || *r == revision));
        if built && !scan {
            return Err(format!("{signer} built the work it judged"));
        }
        let Some(inventory) = self
            .inventories
            .iter()
            .find(|inventory| inventory.agent.eq_ignore_ascii_case(signer))
        else {
            return Err(format!(
                "{signer} has published no valid signed engine inventory"
            ));
        };
        if let Some(engine) = engine
            && !scan
            && !inventory
                .engines
                .iter()
                .any(|listed| listed.name.eq_ignore_ascii_case(engine))
        {
            return Err(format!(
                "{signer}'s signed engine inventory does not list {engine}"
            ));
        }
        if !self.policy.allows_machine(signer, &inventory.machine) {
            return Err(format!(
                "{signer} on {} is not where the engine policy runs this project's work",
                inventory.machine
            ));
        }
        Ok(())
    }

    fn check_finding(&self, finding: &AdversaryFinding) -> std::result::Result<(), String> {
        self.check(
            &finding.subject,
            &finding.signed_by,
            Some(&finding.engine),
            finding.revision,
            finding.trigger,
            finding.verdict,
        )
    }
}

/// The verified results of `subject`'s orders - an order's own, or a contract's providers' -
/// as (revision, who built it). Whether `subject` is a contract comes first.
fn subject_results(route: &ProjectRoute, subject: &str) -> (bool, Vec<(u32, String)>) {
    let roster = crate::gate::roster(route);
    let built = |task: &Task| -> Vec<(u32, String)> {
        let mut out = Vec::new();
        for result in &task.results {
            if crate::verify_result(result, &roster) != SignatureCheck::Valid {
                continue;
            }
            out.push((result.revision, result.agent.clone()));
            if let Some(signer) = &result.signed_by
                && !signer.eq_ignore_ascii_case(&result.agent)
            {
                out.push((result.revision, signer.clone()));
            }
        }
        out
    };
    match subject.split_once('@') {
        Some((name, version)) => {
            let providers = interface::orders_for_interface(route, name, version)
                .map(|orders| orders.providers)
                .unwrap_or_default();
            let results = providers
                .iter()
                .filter_map(|order| crate::read_task(route, &order.id).ok())
                .flat_map(|task| built(&task))
                .collect();
            (true, results)
        }
        None => (
            false,
            crate::read_task(route, subject)
                .map(|task| built(&task))
                .unwrap_or_default(),
        ),
    }
}

/// Whether `signer`, asked to challenge `subject` at `revision` for `trigger` with `engine`
/// (when it is known), would be heard: it did not build the work, its signed inventory
/// lists the engine, the policy's `where` allows its machine, and the revision is real.
/// Asked before any engine is paid for, so no money goes on a finding that would be ignored.
pub fn eligibility(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    signer: &str,
    engine: Option<&str>,
) -> std::result::Result<(), String> {
    Facts::load(route, subject).check(subject, signer, engine, revision, trigger, Verdict::Pass)
}

// --- what the findings add up to -------------------------------------------------------------

/// One eligible finding, with the master's override of it when there is a genuine one.
#[derive(Debug, Clone, PartialEq)]
pub struct Voice {
    pub finding: AdversaryFinding,
    pub overridden: Option<Override>,
}

impl Voice {
    fn unresolved_block(&self) -> bool {
        self.finding.verdict == Verdict::Block && self.overridden.is_none()
    }

    fn rank(&self) -> u8 {
        match (self.finding.verdict, self.overridden.is_some()) {
            (Verdict::Block, false) => 3,
            (Verdict::Block, true) => 2,
            (Verdict::Concern, _) => 1,
            (Verdict::Pass, _) => 0,
        }
    }
}

/// What the eligible findings on one (subject, revision, trigger) add up to: any Block
/// blocks, and a Block is answered only by an override of each Block.
#[derive(Debug, Clone, PartialEq)]
pub struct Standing {
    /// The most telling finding: an unresolved Block first, then an overridden one, then a
    /// Concern, then a Pass; newest among equals.
    pub finding: AdversaryFinding,
    /// Its override, when it is a Block that was overridden - which, as an unresolved
    /// Block ranks first, means nothing is left unresolved.
    pub overridden: Option<Override>,
    /// Every finding that counts, the lead included.
    pub voices: Vec<Voice>,
}

impl Standing {
    fn of(voices: Vec<Voice>) -> Option<Self> {
        let lead = voices.iter().max_by_key(|voice| {
            (
                voice.rank(),
                voice
                    .finding
                    .findings
                    .iter()
                    .map(|issue| issue.severity)
                    .max(),
                voice.finding.created_at,
            )
        })?;
        Some(Self {
            finding: lead.finding.clone(),
            overridden: lead.overridden.clone(),
            voices,
        })
    }

    /// A Block nobody has overridden - from any adversary that counts.
    #[must_use]
    pub fn unresolved_block(&self) -> bool {
        self.voices.iter().any(Voice::unresolved_block)
    }

    /// The Blocks still standing.
    #[must_use]
    pub fn unresolved_blocks(&self) -> Vec<&Voice> {
        self.voices
            .iter()
            .filter(|voice| voice.unresolved_block())
            .collect()
    }

    /// The worst verdict among the findings that count.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.voices
            .iter()
            .map(|voice| voice.finding.verdict)
            .max()
            .unwrap_or(self.finding.verdict)
    }

    /// What an override covers, to be named by whoever signs it so it is applied to what
    /// they read: the digest of the Block still standing - of all of them, when several
    /// adversaries blocked - or of the lead finding when nothing stands.
    #[must_use]
    pub fn digest(&self) -> String {
        let standing = self.unresolved_blocks();
        let mut digests: Vec<String> = if standing.is_empty() {
            vec![finding_digest(&self.finding)]
        } else {
            standing
                .iter()
                .map(|voice| finding_digest(&voice.finding))
                .collect()
        };
        digests.sort();
        if digests.len() == 1 {
            return digests.remove(0);
        }
        hex::encode(Sha256::digest(digests.join(",").as_bytes()))
    }

    /// `block`, `block, overridden by josh`, `concern`, `pass`.
    #[must_use]
    pub fn status(&self) -> String {
        match &self.overridden {
            Some(over) => format!(
                "{}, overridden by {}",
                self.finding.verdict.as_str(),
                over.from()
            ),
            None => self.verdict().as_str().to_string(),
        }
    }

    /// The finding for a screen or `--json`.
    #[must_use]
    pub fn view(&self) -> Value {
        let finding = &self.finding;
        json!({
            "subject": finding.subject,
            "order_id": finding.order_id,
            "revision": finding.revision,
            "trigger": finding.trigger.as_str(),
            "trigger_label": finding.trigger.label(),
            "verdict": self.verdict().as_str(),
            "status": self.status(),
            "unresolved_block": self.unresolved_block(),
            "digest": self.digest(),
            "engine": finding.engine,
            "model": finding.model,
            "machine": finding.machine,
            "same_engine": finding.same_engine,
            "created_at": finding.created_at,
            "signed_by": finding.signed_by,
            "headline": finding.describe(),
            "findings": finding.findings,
            "override": self.overridden.as_ref().map(|over| json!({
                "by": over.from(),
                "at": over.at,
                "reason": over.reason,
            })),
            "voices": self.voices.iter().map(|voice| json!({
                "signed_by": voice.finding.signed_by,
                "engine": voice.finding.engine,
                "verdict": voice.finding.verdict.as_str(),
                "overridden": voice.overridden.is_some(),
            })).collect::<Vec<_>>(),
        })
    }
}

/// What one subject's findings come to: a [`Standing`] per (revision, trigger) that has an
/// eligible finding, and every genuine finding that was ignored, with why.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Survey {
    /// Oldest revision first, then in moment order.
    pub standings: Vec<Standing>,
    pub ignored: Vec<Ignored>,
}

/// Sort `findings` of `subject` into those that count and those that do not, and add the
/// ones that count up.
fn assemble(route: &ProjectRoute, subject: &str, findings: Vec<AdversaryFinding>) -> Survey {
    let mut survey = Survey::default();
    if findings.is_empty() {
        return survey;
    }
    let facts = Facts::load(route, subject);
    let mut groups: std::collections::BTreeMap<(u32, Trigger), Vec<Voice>> =
        std::collections::BTreeMap::new();
    for finding in findings {
        match facts.check_finding(&finding) {
            Ok(()) => groups
                .entry((finding.revision, finding.trigger))
                .or_default()
                .push(Voice {
                    overridden: read_override(route, &finding),
                    finding,
                }),
            Err(reason) => survey.ignored.push(Ignored { finding, reason }),
        }
    }
    survey.standings = groups.into_values().filter_map(Standing::of).collect();
    survey
        .ignored
        .sort_by_key(|ignored| std::cmp::Reverse(ignored.finding.created_at));
    survey
}

/// Everything the adversary said about `subject` that counts, and what was ignored. Reads
/// exactly this subject's files, however many findings there are in the channel.
#[must_use]
pub fn survey(route: &ProjectRoute, subject: &str) -> Survey {
    if !subject_ok(subject) {
        return Survey::default();
    }
    assemble(
        route,
        subject,
        scan(route, &format!("{subject}-r"), Some(subject)),
    )
}

/// What the eligible findings on exactly (subject, revision, trigger) add up to; `None`
/// when none counts. Reads only that one revision's files.
#[must_use]
pub fn standing(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<Standing> {
    if !subject_ok(subject) {
        return None;
    }
    let prefix = format!("{}.", stem(subject, revision, trigger));
    assemble(route, subject, scan(route, &prefix, Some(subject)))
        .standings
        .into_iter()
        .next()
}

/// [`survey`] over every subject in the channel's newest findings: for display only.
#[must_use]
pub fn list_standings(route: &ProjectRoute) -> Survey {
    let mut subjects: Vec<String> = list(route)
        .into_iter()
        .map(|finding| finding.subject)
        .collect();
    subjects.sort();
    subjects.dedup();
    let mut all = Survey::default();
    for subject in subjects {
        let one = survey(route, &subject);
        all.standings.extend(one.standings);
        all.ignored.extend(one.ignored);
    }
    all.standings
        .sort_by_key(|standing| std::cmp::Reverse(standing.finding.created_at));
    all.ignored
        .sort_by_key(|ignored| std::cmp::Reverse(ignored.finding.created_at));
    all
}

/// The revision a lock of `contract` is decided on: its newest provider result, or 0 while
/// no provider has one and the contract's shapes stand alone.
#[must_use]
pub fn contract_revision(route: &ProjectRoute, contract: &InterfaceContract) -> u32 {
    subject_results(route, &contract.reference())
        .1
        .iter()
        .map(|(revision, _)| *revision)
        .max()
        .unwrap_or(0)
}

/// [`standing`] at the revision a lock of `contract` is being decided on.
#[must_use]
pub fn lock_standing(route: &ProjectRoute, contract: &InterfaceContract) -> Option<Standing> {
    standing(
        route,
        &contract.reference(),
        contract_revision(route, contract),
        Trigger::ContractLock,
    )
}

/// [`standing`] for the failed attempt the next one follows: the newest revision of
/// `order_id` that failed, when it has failed twice.
#[must_use]
pub fn attempt_standing(route: &ProjectRoute, order_id: &str) -> Option<Standing> {
    let task = crate::read_task(route, order_id).ok()?;
    let repeat = repeat_failure(&task)?;
    standing(route, order_id, repeat.latest, Trigger::RepeatFailure)
}

/// The standing on `subject` at the revision under decision for `trigger`: a contract's
/// provider result for its lock, an order's newest result for its review, the failed
/// attempt for the repeat-failure moment. Never "the highest revision with a finding".
#[must_use]
pub fn decision_standing(
    route: &ProjectRoute,
    subject: &str,
    trigger: Trigger,
) -> Option<Standing> {
    standing(
        route,
        subject,
        decision_revision(route, subject, trigger)?,
        trigger,
    )
}

/// The revision a decision on `subject` at `trigger` is being made on: a contract's newest
/// provider result (or 0 while it has none), an order's newest result, the failed attempt
/// the next one follows. `None` when `subject` has no such moment.
#[must_use]
pub fn decision_revision(route: &ProjectRoute, subject: &str, trigger: Trigger) -> Option<u32> {
    match trigger {
        Trigger::ContractLock => {
            let (name, version) = subject.split_once('@')?;
            let contract = interface::read_contract(route, name, version)?;
            Some(contract_revision(route, &contract))
        }
        Trigger::RepeatFailure => {
            let task = crate::read_task(route, subject).ok()?;
            repeat_failure(&task).map(|repeat| repeat.latest)
        }
        Trigger::PreDone => crate::read_task(route, subject).ok()?.latest_revision(),
    }
}

/// Whether `expected`, as a master read it, names `seen`: the whole digest, or a prefix of
/// at least [`interface::DIGEST_MIN`] characters; [`NO_FINDING`] only names itself.
#[must_use]
pub fn finding_matches(seen: &str, expected: &str) -> bool {
    let expected = expected.trim().to_ascii_lowercase();
    if seen == NO_FINDING || expected == NO_FINDING {
        return seen == expected;
    }
    expected.len() >= interface::DIGEST_MIN && seen.to_ascii_lowercase().starts_with(&expected)
}

// --- overriding a Block ------------------------------------------------------------------

/// The master's signed decision to go ahead despite one Block finding - or, with
/// [`NO_FINDING`], with no finding at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Override {
    pub subject: String,
    pub revision: u32,
    pub trigger: Trigger,
    /// Which finding: a digest of its signature, so a re-run finding is not covered; or
    /// [`NO_FINDING`] for a waiver.
    pub finding: String,
    pub reason: String,
    /// The master, whose override it is.
    pub by: String,
    pub at: DateTime<Utc>,
    /// Who signed it: the master, or their delegate.
    #[serde(default)]
    pub signed_by: String,
    #[serde(default)]
    pub signature: String,
}

impl Override {
    fn payload(&self, project: &str) -> String {
        format!(
            "ferryman-adversary-override-v1\n{project}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.subject,
            self.revision,
            self.trigger.as_str(),
            self.finding,
            self.by,
            self.at.to_rfc3339(),
            hex::encode(Sha256::digest(self.reason.as_bytes()))
        )
    }

    /// `josh via telegram-grouchly`.
    #[must_use]
    pub fn from(&self) -> String {
        delegation::label(&self.by, &self.signed_by)
    }
}

/// A digest of one finding's signature: what an override names, and what the person who
/// signs it saw.
#[must_use]
pub fn finding_digest(finding: &AdversaryFinding) -> String {
    hex::encode(Sha256::digest(finding.signature.as_bytes()))
}

fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

/// The override record in `path`, when it is the master's (or a delegate's holding the
/// trigger's scope) over exactly `digest` for this subject, revision and trigger.
fn verified_override(
    route: &ProjectRoute,
    path: &std::path::Path,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    digest: &str,
) -> Option<Override> {
    let record: Override = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    let master = crate::master::read_master(route).ok()??;
    (record.subject == subject
        && record.revision == revision
        && record.trigger == trigger
        && record.finding == digest
        && record.by.eq_ignore_ascii_case(&master.master)
        && delegation::authority(
            &route.communications,
            &route.project_id,
            &record.by,
            &record.signed_by,
            trigger.override_scope(),
            Utc::now(),
        )
        .allowed()
        && check_signature(
            Some(&record.signed_by),
            Some(&record.signature),
            &record.payload(&route.project_id),
            &crate::gate::roster(route),
        ) == SignatureCheck::Valid)
        .then_some(record)
}

/// The override that covers `finding`, when a genuine one exists: signed by the master
/// (or a delegate holding the trigger's scope), over exactly this finding.
#[must_use]
pub fn read_override(route: &ProjectRoute, finding: &AdversaryFinding) -> Option<Override> {
    let path = override_path(route, finding)?;
    verified_override(
        route,
        &path,
        &finding.subject,
        finding.revision,
        finding.trigger,
        &finding_digest(finding),
    )
}

/// The master's waiver for (subject, revision, trigger), when a genuine one exists: their
/// signed word to go ahead although no eligible finding exists.
#[must_use]
pub fn read_waiver(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<Override> {
    let path = waiver_path(route, subject, revision, trigger)?;
    verified_override(route, &path, subject, revision, trigger, NO_FINDING)
}

/// Check that `by`, signed for by `signer`, may override at `trigger`, and return the master.
fn overriding_authority(
    route: &ProjectRoute,
    by: &str,
    trigger: Trigger,
    signer: &AgentIdentity,
) -> Result<String> {
    let Some(master) = crate::master::read_master(route)? else {
        bail!(
            "{} has no master, and only its master overrides the adversary",
            route.project_id
        );
    };
    if !by.eq_ignore_ascii_case(&master.master) {
        bail!(
            "only {}, the master, overrides the adversary",
            master.master
        );
    }
    if let delegation::Authority::Refused(why) = delegation::authority(
        &route.communications,
        &route.project_id,
        by,
        signer.name(),
        trigger.override_scope(),
        Utc::now(),
    ) {
        bail!("{} cannot override for {by}: {why}", signer.name());
    }
    Ok(master.master)
}

fn reason_or_default(reason: Option<&str>, by: &str, signer: &AgentIdentity) -> String {
    reason
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map_or_else(
            || format!("overridden by {}", delegation::label(by, signer.name())),
            str::to_string,
        )
}

fn sign_override(
    route: &ProjectRoute,
    path: &std::path::Path,
    mut record: Override,
    signer: &AgentIdentity,
) -> Result<()> {
    record.signature = signer.sign_bytes(record.payload(&route.project_id).as_bytes());
    crate::atomic_json(path, &record).with_context(|| format!("writing {}", path.display()))
}

/// Go ahead despite the Block finding(s) on (subject, revision, trigger): the master (`by`),
/// signed for by `signer` - themselves, or a delegate holding the scope for this moment
/// ([`Trigger::override_scope`]). `expected_finding` is [`Standing::digest`] as the master
/// read it: when the findings are not what they read, the override is refused, so a Block
/// replaced after they looked is not waved through. Each Block that counts is overridden;
/// refused when none stands. Idempotent: a genuine override already there is returned.
#[allow(clippy::too_many_arguments)]
pub fn override_block(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    expected_finding: &str,
    reason: Option<&str>,
    by: &str,
    signer: &AgentIdentity,
) -> Result<Override> {
    let master = overriding_authority(route, by, trigger, signer)?;
    let Some(standing) = standing(route, subject, revision, trigger) else {
        if expected_finding != NO_FINDING {
            bail!(
                "the finding on {subject} r{revision} changed since you looked: none counts now, \
                 and you read {}",
                short(expected_finding)
            );
        }
        bail!(
            "there is no {} finding for {subject} r{revision} that counts, so there is nothing \
             to override (see `ferry adversary show {subject}`)",
            trigger.as_str()
        );
    };
    let unresolved = standing.unresolved_blocks();
    if unresolved.is_empty() {
        if let Some(existing) = standing
            .voices
            .iter()
            .find_map(|voice| voice.overridden.clone())
        {
            return Ok(existing);
        }
        bail!(
            "the adversary's verdict on {subject} r{revision} is {}, not a Block; there is \
             nothing to override",
            standing.verdict().as_str()
        );
    }
    let seen = standing.digest();
    if !finding_matches(&seen, expected_finding) {
        bail!(
            "the finding on {subject} r{revision} changed since you looked (you read {}, it is \
             now {}); read it again before overriding",
            short(expected_finding),
            short(&seen)
        );
    }
    let reason = reason_or_default(reason, by, signer);
    for voice in unresolved {
        let path =
            override_path(route, &voice.finding).context("a path-safe subject has a path")?;
        sign_override(
            route,
            &path,
            Override {
                subject: subject.to_string(),
                revision,
                trigger,
                finding: finding_digest(&voice.finding),
                reason: reason.clone(),
                by: master.clone(),
                at: Utc::now(),
                signed_by: signer.name().to_string(),
                signature: String::new(),
            },
            signer,
        )?;
    }
    standing_after(route, subject, revision, trigger)
        .with_context(|| format!("the override for {subject} was written but does not verify"))
}

/// The override just written, read back through the standing so only a genuine one counts.
fn standing_after(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<Override> {
    let after = standing(route, subject, revision, trigger)?;
    if after.unresolved_block() {
        return None;
    }
    after
        .voices
        .iter()
        .find_map(|voice| voice.overridden.clone())
}

/// Go ahead although no eligible finding exists on (subject, revision, trigger): the
/// master's signed waiver, for `blocking` mode, where the adversary being away or ruled out
/// would otherwise hold the lock, the engine key and auto-merge for ever. It covers only
/// "no finding": an eligible Block that appears later is still a Block. `expected_finding`
/// must be [`NO_FINDING`] - what the master saw.
#[allow(clippy::too_many_arguments)]
pub fn waive(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    expected_finding: &str,
    reason: Option<&str>,
    by: &str,
    signer: &AgentIdentity,
) -> Result<Override> {
    let master = overriding_authority(route, by, trigger, signer)?;
    if let Some(standing) = standing(route, subject, revision, trigger) {
        bail!(
            "{subject} r{revision} has an adversary finding that counts ({}); a waiver is only \
             for when there is none - override a Block instead",
            standing.status()
        );
    }
    if expected_finding != NO_FINDING {
        bail!(
            "the finding on {subject} r{revision} changed since you looked: there is none now, \
             and you read {}",
            short(expected_finding)
        );
    }
    if let Some(existing) = read_waiver(route, subject, revision, trigger) {
        return Ok(existing);
    }
    let path =
        waiver_path(route, subject, revision, trigger).context("a path-safe subject has a path")?;
    sign_override(
        route,
        &path,
        Override {
            subject: subject.to_string(),
            revision,
            trigger,
            finding: NO_FINDING.to_string(),
            reason: reason_or_default(reason, by, signer),
            by: master,
            at: Utc::now(),
            signed_by: signer.name().to_string(),
            signature: String::new(),
        },
        signer,
    )?;
    read_waiver(route, subject, revision, trigger)
        .with_context(|| format!("the waiver for {subject} was written but does not verify"))
}

/// What an override or waiver of the decision on (subject, revision, trigger) must name to
/// be applied to what the master read: the digest of what the eligible findings come to, or
/// [`NO_FINDING`] when none counts.
#[must_use]
pub fn finding_seen(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> String {
    standing(route, subject, revision, trigger)
        .map_or_else(|| NO_FINDING.to_string(), |standing| standing.digest())
}

/// [`finding_seen`] at the revision a lock of `contract` is being decided on.
#[must_use]
pub fn lock_finding_seen(route: &ProjectRoute, contract: &InterfaceContract) -> String {
    finding_seen(
        route,
        &contract.reference(),
        contract_revision(route, contract),
        Trigger::ContractLock,
    )
}

/// The master's go-ahead for a decision the adversary holds: [`override_block`] of the
/// Block they read (`expected_finding` is its digest), or - when what they read was
/// [`NO_FINDING`] - [`waive`].
#[allow(clippy::too_many_arguments)]
pub fn override_or_waive(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    expected_finding: &str,
    reason: Option<&str>,
    by: &str,
    signer: &AgentIdentity,
) -> Result<Override> {
    if expected_finding == NO_FINDING {
        waive(
            route,
            subject,
            revision,
            trigger,
            expected_finding,
            reason,
            by,
            signer,
        )
    } else {
        override_block(
            route,
            subject,
            revision,
            trigger,
            expected_finding,
            reason,
            by,
            signer,
        )
    }
}

// --- what the modes make of a finding ------------------------------------------------------

/// Where one decision stands against the adversary in `blocking` mode.
enum Hold {
    /// An eligible finding exists and nothing it says stands, or the master waived.
    Clear,
    /// A Block that counts, not overridden.
    Blocked(Box<Standing>),
    /// No eligible finding, and no waiver.
    Missing,
}

fn hold(route: &ProjectRoute, subject: &str, revision: u32, trigger: Trigger) -> Hold {
    match standing(route, subject, revision, trigger) {
        Some(standing) if standing.unresolved_block() => Hold::Blocked(Box::new(standing)),
        Some(_) => Hold::Clear,
        None if read_waiver(route, subject, revision, trigger).is_some() => Hold::Clear,
        None => Hold::Missing,
    }
}

fn worst(standing: &Standing) -> String {
    standing
        .finding
        .top(1)
        .first()
        .map(|issue| format!(" - {}: {}", issue.title, issue.detail))
        .unwrap_or_default()
}

/// Why `contract` may not be locked, when it may not: the adversary's mode is `blocking`
/// and, at the provider result the lock is being decided on (or on the shapes alone, while
/// there is none), an eligible adversary has Blocked it and the master has not overridden
/// it - or no eligible adversary has read it at all and the master has not waived that.
#[must_use]
pub fn lock_refusal(
    route: &ProjectRoute,
    policy: &Policy,
    contract: &InterfaceContract,
) -> Option<String> {
    if policy.adversary != AdversaryMode::Blocking {
        return None;
    }
    let reference = contract.reference();
    let revision = contract_revision(route, contract);
    match hold(route, &reference, revision, Trigger::ContractLock) {
        Hold::Clear => None,
        Hold::Blocked(standing) => Some(format!(
            "the adversary ({}) blocks locking {reference}{}. The engine policy has \
             adversary = blocking, so locking needs an explicit master override: read it with \
             `ferry adversary show {reference}`, then lock with an override (ferry contract \
             lock {reference} --override \"why\", or the Override button)",
            standing.finding.engine,
            worst(&standing)
        )),
        Hold::Missing => Some(format!(
            "no adversary has read {reference} {}. The engine policy has adversary = blocking, \
             so locking waits for an adversary that did not build it to read exactly that - the \
             improve loop asks it, or `ferry adversary check` does - or for an explicit master \
             override with nothing found (ferry contract lock {reference} --override \"why\", \
             or the Override button)",
            if revision == 0 {
                "on its shapes".to_string()
            } else {
                format!("at the provider's result r{revision}")
            }
        )),
    }
}

/// Why the engine key may not be granted for `order_id` r`revision`, when it may not: the
/// adversary's mode is `blocking` and its pre-done finding on exactly this revision is a
/// Block the master has not overridden - or no eligible adversary has read exactly this
/// revision and the master has not waived that.
#[must_use]
pub fn engine_key_refusal(
    route: &ProjectRoute,
    policy: &Policy,
    order_id: &str,
    revision: u32,
) -> Option<String> {
    if policy.adversary != AdversaryMode::Blocking {
        return None;
    }
    match hold(route, order_id, revision, Trigger::PreDone) {
        Hold::Clear => None,
        Hold::Blocked(standing) => Some(format!(
            "the adversary ({}) blocks {order_id} r{revision}{}. adversary = blocking, so \
             the review engine's key waits for a master override (`ferry adversary override \
             {order_id}`, or the Override button)",
            standing.finding.engine,
            worst(&standing)
        )),
        Hold::Missing => Some(format!(
            "no adversary has read {order_id} r{revision}. adversary = blocking, so the review \
             engine's key waits for one that did not build it to read exactly this revision, \
             or for a master override with nothing found (`ferry adversary override \
             {order_id}`, or the Override button)"
        )),
    }
}

/// An unresolved Block on exactly this revision, at any moment, under any mode but `off`.
#[must_use]
pub fn unresolved_block(
    route: &ProjectRoute,
    policy: &Policy,
    order_id: &str,
    revision: u32,
) -> Option<Standing> {
    if policy.adversary == AdversaryMode::Off {
        return None;
    }
    Trigger::ALL
        .iter()
        .filter_map(|trigger| standing(route, order_id, revision, *trigger))
        .find(Standing::unresolved_block)
}

/// Why auto-merge must not carry `order_id` r`revision`, when it must not: a merge nobody is
/// watching never carries a Block nobody answered (any mode but `off`), and in `blocking`
/// mode never goes past a revision no eligible adversary has read, unless the master waived.
#[must_use]
pub fn merge_refusal(
    route: &ProjectRoute,
    policy: &Policy,
    order_id: &str,
    revision: u32,
) -> Option<String> {
    if let Some(block) = unresolved_block(route, policy, order_id, revision) {
        return Some(format!(
            "{order_id} r{revision} has an unresolved adversary Block ({}); it is not merged on \
             its own - the master overrides it or sends the work back",
            block.finding.describe()
        ));
    }
    engine_key_refusal(route, policy, order_id, revision)
        .map(|why| format!("{why}; nothing is merged on its own until then"))
}

// --- the contract moment ---------------------------------------------------------------------

/// Everything the adversary is shown about a contract waiting for its lock, and the part
/// of it no model is needed for.
#[derive(Debug, Clone)]
pub struct ContractContext {
    pub contract: InterfaceContract,
    /// The first provider order, or empty.
    pub order_id: String,
    /// The newest provider result's revision, or 0 when none has a result.
    pub revision: u32,
    /// The provider's result payload, when one has a result.
    pub provider_result: Option<Value>,
    /// What built the provider's result.
    pub builders: Vec<Builder>,
    /// What the consumer orders ask for, in their own words.
    pub consumers: Vec<(String, String)>,
    /// The provider's `response` held to the proposed response shape - deterministic.
    pub precheck: Vec<String>,
}

/// Gather the context for reviewing `contract`: its providers' and consumers' orders, the
/// newest provider result, and the deterministic check of that result's `response`
/// against the proposed response shape.
pub fn contract_context(
    route: &ProjectRoute,
    contract: &InterfaceContract,
) -> Result<ContractContext> {
    let orders = interface::orders_for_interface(route, &contract.name, &contract.version)?;
    let mut context = ContractContext {
        contract: contract.clone(),
        order_id: orders
            .providers
            .first()
            .map(|order| order.id.clone())
            .unwrap_or_default(),
        revision: 0,
        provider_result: None,
        builders: Vec::new(),
        consumers: Vec::new(),
        precheck: Vec::new(),
    };
    let roster = crate::gate::roster(route);
    let mut newest: Option<(u32, String, Value)> = None;
    for order in &orders.providers {
        let Ok(task) = crate::read_task(route, &order.id) else {
            continue;
        };
        for result in &task.results {
            // Only a result that verifies is a provider's word about its own work.
            if crate::verify_result(result, &roster) != SignatureCheck::Valid {
                continue;
            }
            if let Some(builder) = Builder::from_payload(&result.payload)
                && !context.builders.contains(&builder)
            {
                context.builders.push(builder);
            }
            if newest
                .as_ref()
                .is_none_or(|(revision, _, _)| result.revision > *revision)
            {
                newest = Some((result.revision, order.id.clone(), result.payload.clone()));
            }
        }
    }
    if let Some((revision, order_id, payload)) = newest {
        context.revision = revision;
        context.order_id = order_id;
        context.precheck = match payload.get("response") {
            None | Some(Value::Null) => vec![
                "result.response: missing; the provider's result carries no response to hold to \
                 the proposed shape"
                    .to_string(),
            ],
            Some(response) => contract.response.check_at(response, "result.response"),
        };
        context.provider_result = Some(payload);
    }
    for order in &orders.consumers {
        let text = order
            .payload
            .get("task")
            .and_then(Value::as_str)
            .map_or_else(|| order.payload.to_string(), str::to_string);
        context.consumers.push((order.id.clone(), text));
    }
    Ok(context)
}

// --- the repeat-failure moment -----------------------------------------------------------------

/// One revision that did not hold.
#[derive(Debug, Clone, PartialEq)]
pub struct FailedRevision {
    pub revision: u32,
    pub builder: Option<Builder>,
    /// Why it counts as a failure: sent back with these notes, refuted by this evidence,
    /// a required check that exited non-zero.
    pub reasons: Vec<String>,
    /// The required checks as run, with the end of what they printed.
    pub checks: Vec<(String, Option<i32>, String)>,
}

/// The revisions of an order that failed, and the newest of them.
#[derive(Debug, Clone, PartialEq)]
pub struct RepeatFailure {
    pub failures: Vec<FailedRevision>,
    pub latest: u32,
}

/// The revisions of `task` that failed: sent back by a reviewer (`ChangesRequested`),
/// refuted by their own evidence, or with a required check that did not exit zero.
/// A revision counts once however many of those hold.
#[must_use]
pub fn failed_revisions(task: &Task) -> Vec<FailedRevision> {
    let mut found = Vec::new();
    for result in &task.results {
        let mut reasons = Vec::new();
        if let Some(review) = task
            .reviews
            .iter()
            .find(|review| review.revision == result.revision && !review.accepted)
        {
            reasons.push(format!(
                "sent back by {}: {}",
                review.reviewer,
                review.notes.as_deref().unwrap_or("no notes")
            ));
        }
        let evidence = crate::evidence::of(&task.order.payload, result);
        let classified = crate::evidence::classify(&task.order.payload, result);
        if classified.status == crate::evidence::Status::Refuted {
            reasons.push(format!(
                "refuted by its evidence: {}",
                classified.reasons.join("; ")
            ));
        }
        let mut checks = Vec::new();
        if let Some(evidence) = &evidence {
            for check in &evidence.checks {
                checks.push((check.command.clone(), check.exit_code, check.tail.clone()));
                if check.exit_code != Some(0) {
                    reasons.push(match check.exit_code {
                        Some(code) => format!("required check `{}` exited {code}", check.command),
                        None => format!("required check `{}` did not finish", check.command),
                    });
                }
            }
        }
        // A revision that was accepted did not fail, whatever an earlier check said.
        let accepted = task
            .reviews
            .iter()
            .any(|review| review.revision == result.revision && review.accepted);
        if !reasons.is_empty() && !accepted {
            found.push(FailedRevision {
                revision: result.revision,
                builder: Builder::from_payload(&result.payload),
                reasons,
                checks,
            });
        }
    }
    found.sort_by_key(|failed| failed.revision);
    found.dedup_by_key(|failed| failed.revision);
    found
}

/// Whether `task` has failed twice - two revisions that did not hold - and what it has
/// failed with so far. `None` for fewer.
#[must_use]
pub fn repeat_failure(task: &Task) -> Option<RepeatFailure> {
    let failures = failed_revisions(task);
    let latest = failures.last()?.revision;
    (failures.len() >= 2).then_some(RepeatFailure { failures, latest })
}

/// What the next attempt at `order_id` is told, when an eligible adversary blocked it or the
/// scan found tampering: the finding's words, ready for an engine prompt. `None` when the
/// failed attempt the next one follows has no Block that counts.
#[must_use]
pub fn attempt_notice(route: &ProjectRoute, order_id: &str) -> Option<String> {
    let standing = attempt_standing(route, order_id)?;
    if standing.verdict() != Verdict::Block {
        return None;
    }
    let mut text = format!(
        "An independent adversary ({}) reviewed the failed attempts at this order, which has \
         now failed at least twice, and BLOCKED the next attempt as it stood. Its findings:\n",
        standing.finding.engine
    );
    for issue in &standing.finding.findings {
        text.push_str(&format!(
            "- [{}] {}{}: {}\n",
            issue.severity.as_str(),
            issue.title,
            issue
                .location
                .as_deref()
                .map(|place| format!(" ({place})"))
                .unwrap_or_default(),
            issue.detail
        ));
    }
    text.push_str(
        "\nFix the cause of the failure. Do not delete, skip, ignore or loosen tests or \
         checks, do not add `|| true` or `exit 0` to a command, and do not move tests out of \
         the paths that are checked: the checks the order names are run again by the worker \
         and any such change is detected and sent back.\n",
    );
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRoute, Order, Review, TaskResult, receipts::EngineReport};
    use std::path::Path;

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    /// A channel whose master is `members[0]`, every member on its roster.
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

    fn publish_engines(route: &ProjectRoute, who: &AgentIdentity, machine: &str, names: &[&str]) {
        let reports = names
            .iter()
            .map(|name| EngineReport {
                name: (*name).into(),
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
        crate::receipts::refresh_engines(route, who, machine, "0.0.0", reports, Utc::now())
            .unwrap();
    }

    /// A channel with a master (`boss`), a builder (`fang`) and three agents on the roster:
    /// `wisp` and `bridge`, who publish signed inventories listing deepseek, and `scribe`,
    /// who publishes none.
    struct Fleet {
        _dir: tempfile::TempDir,
        route: ProjectRoute,
        boss: AgentIdentity,
        fang: AgentIdentity,
        wisp: AgentIdentity,
        bridge: AgentIdentity,
        scribe: AgentIdentity,
    }

    impl Fleet {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (boss, fang, wisp, bridge, scribe) = (
                person("boss", 1),
                person("fang", 2),
                person("wisp", 3),
                person("bridge", 4),
                person("scribe", 5),
            );
            let route = route(dir.path(), &[&boss, &fang, &wisp, &bridge, &scribe]);
            publish_engines(&route, &fang, "nebra", &["qwen"]);
            publish_engines(&route, &wisp, "grouchly", &["deepseek"]);
            publish_engines(&route, &bridge, "beastly", &["deepseek", "glm"]);
            Self {
                _dir: dir,
                route,
                boss,
                fang,
                wisp,
                bridge,
                scribe,
            }
        }

        fn issue(&self, id: &str, interface: Option<interface::Side>) {
            let mut order = Order {
                id: id.into(),
                project_id: "demo".into(),
                issued_by: "boss".into(),
                assigned_to: None,
                created_at: Utc::now(),
                payload: json!({
                    "task": format!("{id} work"),
                    "tags": ["improvement"],
                    "improvement": { "acceptance": ["`cargo test` passes"] }
                }),
                requires_review: true,
                requires_approval: false,
                depends_on: Vec::new(),
                signed_by: None,
                signature: None,
                result_contract: None,
                interface: interface.map(|side| interface::InterfaceRef {
                    name: "user-api".into(),
                    version: "1".into(),
                    side,
                }),
                touches: Vec::new(),
                allow_overlap: false,
            };
            self.boss.sign_order(&mut order);
            crate::issue_order(&self.route, &order).unwrap();
        }

        /// `fang` submits a signed result for `id` at `revision`.
        fn built(&self, id: &str, revision: u32, payload: Value) {
            let mut result = TaskResult {
                order_id: id.into(),
                agent: "fang".into(),
                revision,
                submitted_at: Utc::now(),
                payload,
                signed_by: None,
                signature: None,
            };
            self.fang.sign_result(&mut result);
            crate::submit_result(&self.route, &result).unwrap();
        }

        /// An order `id` with `fang`'s signed results at revisions 1..=`revisions`.
        fn work(&self, id: &str, revisions: u32) {
            self.issue(id, None);
            for revision in 1..=revisions {
                self.built(id, revision, passing("qwen"));
            }
        }
    }

    fn finding(
        subject: &str,
        revision: u32,
        trigger: Trigger,
        verdict: Verdict,
    ) -> AdversaryFinding {
        AdversaryFinding {
            order_id: subject.split('@').next().unwrap_or_default().to_string(),
            revision,
            trigger,
            subject: subject.to_string(),
            engine: "deepseek".into(),
            model: Some("deepseek-chat".into()),
            machine: "grouchly".into(),
            same_engine: false,
            verdict,
            findings: vec![
                Issue {
                    severity: Severity::Low,
                    title: "naming".into(),
                    detail: "a nit".into(),
                    location: None,
                },
                Issue {
                    severity: Severity::High,
                    title: "tests were deleted".into(),
                    detail: "two tests are gone".into(),
                    location: Some("tests/api.rs".into()),
                },
            ],
            created_at: Utc::now(),
            signed_by: String::new(),
            signature: String::new(),
        }
    }

    fn policy(mode: AdversaryMode) -> Policy {
        Policy {
            adversary: mode,
            ..Policy::default()
        }
    }

    fn digest_of(route: &ProjectRoute, subject: &str, revision: u32, trigger: Trigger) -> String {
        standing(route, subject, revision, trigger)
            .expect("an eligible finding")
            .digest()
    }

    #[test]
    fn a_finding_is_signed_stored_at_its_signers_path_and_read_back() {
        let f = Fleet::new();
        f.work("t-1", 2);
        assert!(
            record(
                &f.route,
                &f.wisp,
                finding("t-1", 2, Trigger::PreDone, Verdict::Block)
            )
            .unwrap()
        );
        let path = finding_path(&f.route, "t-1", 2, Trigger::PreDone, "wisp").unwrap();
        assert!(path.ends_with("t-1-r2-pre-done.wisp.json"), "{path:?}");
        let read = read(&f.route, "t-1", 2, Trigger::PreDone, "wisp").expect("a genuine finding");
        assert_eq!(read.signed_by, "wisp");
        assert_eq!(read.verdict, Verdict::Block);
        assert_eq!(read.top(1)[0].title, "tests were deleted");
        assert!(read.describe().contains("block by deepseek"));
        assert!(read.has_high());
        assert_eq!(list(&f.route).len(), 1);
        assert_eq!(for_subject(&f.route, "t-1").len(), 1);
        let standing = standing(&f.route, "t-1", 2, Trigger::PreDone).unwrap();
        assert_eq!(standing.verdict(), Verdict::Block);
        assert!(standing.unresolved_block());
        assert!(self::standing(&f.route, "t-1", 2, Trigger::ContractLock).is_none());
    }

    #[test]
    fn a_second_run_by_the_same_signer_writes_nothing_while_another_signer_runs_its_own() {
        let f = Fleet::new();
        f.work("t-1", 2);
        assert!(
            record(
                &f.route,
                &f.wisp,
                finding("t-1", 1, Trigger::PreDone, Verdict::Pass)
            )
            .unwrap()
        );
        let path = finding_path(&f.route, "t-1", 1, Trigger::PreDone, "wisp").unwrap();
        let before = fs::read(&path).unwrap();
        assert!(
            !record(
                &f.route,
                &f.wisp,
                finding("t-1", 1, Trigger::PreDone, Verdict::Block)
            )
            .unwrap(),
            "wisp's genuine finding is already there"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "the file is untouched");
        assert!(done(&f.route, "t-1", 1, Trigger::PreDone, "wisp"));
        // Done is per signer: bridge has not run, and runs at a path of its own.
        assert!(!done(&f.route, "t-1", 1, Trigger::PreDone, "bridge"));
        assert!(
            record(
                &f.route,
                &f.bridge,
                finding("t-1", 1, Trigger::PreDone, Verdict::Block)
            )
            .unwrap()
        );
        assert!(done(&f.route, "t-1", 1, Trigger::PreDone, "bridge"));
        assert_eq!(fs::read(&path).unwrap(), before, "wisp's file is untouched");
        // Another revision, or another trigger, is another run.
        assert!(
            record(
                &f.route,
                &f.wisp,
                finding("t-1", 2, Trigger::PreDone, Verdict::Pass)
            )
            .unwrap()
        );
        assert!(
            record(
                &f.route,
                &f.wisp,
                finding("t-1", 1, Trigger::RepeatFailure, Verdict::Pass)
            )
            .unwrap()
        );
    }

    #[test]
    fn forged_edited_unsigned_and_misfiled_findings_are_ignored() {
        let f = Fleet::new();
        f.work("t-1", 1);
        f.work("t-2", 1);
        let mallory = person("mallory", 9);
        let route = &f.route;
        record(
            route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        let path = finding_path(route, "t-1", 1, Trigger::PreDone, "wisp").unwrap();

        // Edited after signing: the verdict was flipped to a Block.
        let mut edited: AdversaryFinding =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edited.verdict = Verdict::Block;
        crate::atomic_json(&path, &edited).unwrap();
        assert!(read(route, "t-1", 1, Trigger::PreDone, "wisp").is_none());
        assert!(list(route).is_empty());

        // Signed by a key that is not on the roster.
        let mut forged = finding("t-1", 1, Trigger::PreDone, Verdict::Block);
        forged.signed_by = "mallory".into();
        forged.signature = mallory.sign_bytes(forged.payload("demo").as_bytes());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(read(route, "t-1", 1, Trigger::PreDone, "wisp").is_none());

        // Signed as wisp by someone who is not wisp.
        let mut lie = finding("t-1", 1, Trigger::PreDone, Verdict::Block);
        lie.signed_by = "wisp".into();
        lie.signature = mallory.sign_bytes(lie.payload("demo").as_bytes());
        crate::atomic_json(&path, &lie).unwrap();
        assert!(read(route, "t-1", 1, Trigger::PreDone, "wisp").is_none());

        // Unsigned.
        crate::atomic_json(&path, &finding("t-1", 1, Trigger::PreDone, Verdict::Block)).unwrap();
        assert!(read(route, "t-1", 1, Trigger::PreDone, "wisp").is_none());

        // A genuine finding copied to another subject's file name is not that subject's.
        record(
            route,
            &f.wisp,
            finding("t-2", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        fs::copy(
            finding_path(route, "t-2", 1, Trigger::PreDone, "wisp").unwrap(),
            finding_path(route, "t-3", 1, Trigger::PreDone, "wisp").unwrap(),
        )
        .unwrap();
        assert!(read(route, "t-3", 1, Trigger::PreDone, "wisp").is_none());

        // A forged file does not stop the genuine run: nothing genuine was there.
        assert!(
            record(
                route,
                &f.wisp,
                finding("t-1", 1, Trigger::PreDone, Verdict::Pass)
            )
            .unwrap()
        );
        assert!(read(route, "t-1", 1, Trigger::PreDone, "wisp").is_some());
    }

    #[test]
    fn one_writer_per_path_a_finding_signed_by_someone_else_is_not_the_signers() {
        let f = Fleet::new();
        f.work("t-1", 1);
        // bridge, genuinely signed as bridge, writes into wisp's path to pre-empt it.
        let mut squat = finding("t-1", 1, Trigger::PreDone, Verdict::Pass);
        squat.signed_by = "bridge".into();
        squat.signature = f.bridge.sign_bytes(squat.payload("demo").as_bytes());
        let wisps = finding_path(&f.route, "t-1", 1, Trigger::PreDone, "wisp").unwrap();
        crate::atomic_json(&wisps, &squat).unwrap();
        assert!(read(&f.route, "t-1", 1, Trigger::PreDone, "wisp").is_none());
        assert!(!done(&f.route, "t-1", 1, Trigger::PreDone, "wisp"));
        assert!(
            survey(&f.route, "t-1").standings.is_empty(),
            "the squatted file counts for nobody"
        );
        // So wisp's own word still lands, and counts.
        assert!(
            record(
                &f.route,
                &f.wisp,
                finding("t-1", 1, Trigger::PreDone, Verdict::Block)
            )
            .unwrap()
        );
        assert!(
            standing(&f.route, "t-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );
        // The word "override" names a waiver, not a signer.
        let sneaky = person("override", 7);
        assert!(
            record(
                &f.route,
                &sneaky,
                finding("t-1", 1, Trigger::PreDone, Verdict::Pass)
            )
            .is_err()
        );
        assert!(finding_path(&f.route, "t-1", 1, Trigger::PreDone, "Override").is_none());
    }

    #[test]
    fn a_finding_cannot_be_lifted_into_another_project() {
        let f = Fleet::new();
        f.work("t-1", 1);
        let other = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 3));
        let mut elsewhere = route(other.path(), &[&boss, &wisp]);
        elsewhere.project_id = "other".into();
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        fs::create_dir_all(dir(&elsewhere)).unwrap();
        fs::copy(
            finding_path(&f.route, "t-1", 1, Trigger::PreDone, "wisp").unwrap(),
            finding_path(&elsewhere, "t-1", 1, Trigger::PreDone, "wisp").unwrap(),
        )
        .unwrap();
        assert!(read(&elsewhere, "t-1", 1, Trigger::PreDone, "wisp").is_none());
    }

    #[test]
    fn subjects_that_could_climb_out_of_the_directory_are_refused() {
        assert!(subject_ok("t-1"));
        assert!(subject_ok("user-api@1"));
        assert!(!subject_ok("../x"));
        assert!(!subject_ok("a@../b"));
        assert!(!subject_ok("a/b"));
        assert!(!subject_ok(""));
        assert!(!subject_ok("@1"));
        let f = Fleet::new();
        assert!(
            record(
                &f.route,
                &f.wisp,
                finding("../x", 1, Trigger::PreDone, Verdict::Pass)
            )
            .is_err()
        );
        assert!(finding_path(&f.route, "../x", 1, Trigger::PreDone, "wisp").is_none());
        assert!(finding_path(&f.route, "t-1", 1, Trigger::PreDone, "../wisp").is_none());
    }

    // --- whose word counts ---------------------------------------------------------------

    #[test]
    fn the_builder_cannot_vouch_for_its_own_work() {
        let f = Fleet::new();
        f.work("t-1", 1);
        // fang built r1 and has a valid inventory listing qwen: its Pass is still ignored.
        let mut own = finding("t-1", 1, Trigger::PreDone, Verdict::Pass);
        own.engine = "qwen".into();
        record(&f.route, &f.fang, own).unwrap();
        assert!(standing(&f.route, "t-1", 1, Trigger::PreDone).is_none());
        let survey = survey(&f.route, "t-1");
        assert!(survey.standings.is_empty());
        assert_eq!(survey.ignored.len(), 1);
        let line = survey.ignored[0].line();
        assert!(
            line.starts_with("ignored: t-1 r1 pre-done by fang"),
            "{line}"
        );
        assert!(line.contains("built the work it judged"), "{line}");
        assert_eq!(survey.ignored[0].view()["reason"], survey.ignored[0].reason);
        assert!(
            eligibility(&f.route, "t-1", 1, Trigger::PreDone, "fang", Some("qwen"))
                .unwrap_err()
                .contains("built the work")
        );
        assert!(
            eligibility(
                &f.route,
                "t-1",
                1,
                Trigger::PreDone,
                "wisp",
                Some("deepseek")
            )
            .is_ok()
        );
    }

    #[test]
    fn a_signer_with_no_valid_signed_inventory_listing_the_engine_is_ignored() {
        let f = Fleet::new();
        f.work("t-1", 1);
        // scribe is on the roster and publishes no inventory.
        record(
            &f.route,
            &f.scribe,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        // wisp names an engine its inventory does not list.
        let mut wrong = finding("t-1", 1, Trigger::PreDone, Verdict::Pass);
        wrong.engine = "gpt".into();
        record(&f.route, &f.wisp, wrong).unwrap();
        let survey = survey(&f.route, "t-1");
        assert!(survey.standings.is_empty());
        assert_eq!(survey.ignored.len(), 2);
        let reasons: Vec<&str> = survey.ignored.iter().map(|i| i.reason.as_str()).collect();
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("scribe has published no valid signed engine inventory")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wisp's signed engine inventory does not list gpt")),
            "{reasons:?}"
        );
        // A tampered inventory is no inventory.
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        assert_eq!(self::survey(&f.route, "t-1").standings.len(), 1);
        let path = f.route.communications.join("engines").join("bridge.json");
        let mut inventory: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        inventory["machine"] = json!("somewhere-else");
        crate::atomic_json(&path, &inventory).unwrap();
        let after = self::survey(&f.route, "t-1");
        assert!(after.standings.is_empty(), "{:?}", after.standings);
        assert!(after.ignored.iter().any(|i| {
            i.reason
                .contains("bridge has published no valid signed engine")
        }));
    }

    #[test]
    fn the_policys_where_list_rules_out_a_signer_on_another_machine() {
        let f = Fleet::new();
        f.work("t-1", 1);
        let mut allowed = policy(AdversaryMode::Blocking);
        allowed.machines = vec!["beastly".into()];
        crate::policy::set_policy(&f.route.communications, "demo", Some(allowed), &f.boss).unwrap();
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        let survey = survey(&f.route, "t-1");
        assert!(survey.standings.is_empty(), "wisp runs on grouchly");
        assert!(
            survey.ignored[0]
                .reason
                .contains("is not where the engine policy runs"),
            "{:?}",
            survey.ignored
        );
        // bridge is on beastly.
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        assert_eq!(self::survey(&f.route, "t-1").standings.len(), 1);
    }

    #[test]
    fn only_real_revisions_count_so_a_pass_at_a_made_up_revision_masks_nothing() {
        let f = Fleet::new();
        f.work("t-1", 1);
        let blocking = policy(AdversaryMode::Blocking);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 999, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        assert!(
            engine_key_refusal(&f.route, &blocking, "t-1", 1)
                .unwrap()
                .contains("blocks t-1 r1")
        );
        let survey = survey(&f.route, "t-1");
        assert_eq!(survey.standings.len(), 1);
        assert_eq!(survey.standings[0].finding.revision, 1);
        assert!(
            survey.ignored[0].reason.contains("no result r999"),
            "{:?}",
            survey.ignored
        );
        // And a Block at r999 holds nothing either: nobody reads it as the order's.
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 998, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        assert!(standing(&f.route, "t-1", 998, Trigger::PreDone).is_none());
    }

    #[test]
    fn block_dominates_and_an_override_must_answer_every_block() {
        let f = Fleet::new();
        f.work("t-1", 1);
        let blocking = policy(AdversaryMode::Blocking);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_none());
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let standing = standing(&f.route, "t-1", 1, Trigger::PreDone).unwrap();
        assert_eq!(standing.voices.len(), 2);
        assert_eq!(standing.verdict(), Verdict::Block);
        assert!(standing.unresolved_block());
        assert_eq!(standing.finding.signed_by, "bridge", "the Block leads");
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_some());
        let digest = standing.digest();
        override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &digest,
            Some("accepted"),
            "boss",
            &f.boss,
        )
        .unwrap();
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_none());
    }

    #[test]
    fn a_missing_finding_holds_nothing_unless_the_mode_is_blocking_and_then_only_a_waiver_or_a_finding_frees_it()
     {
        let f = Fleet::new();
        f.work("t-1", 1);
        let blocking = policy(AdversaryMode::Blocking);
        for mode in [AdversaryMode::Off, AdversaryMode::Advisory] {
            assert!(engine_key_refusal(&f.route, &policy(mode), "t-1", 1).is_none());
            assert!(merge_refusal(&f.route, &policy(mode), "t-1", 1).is_none());
        }
        let why = engine_key_refusal(&f.route, &blocking, "t-1", 1).unwrap();
        assert!(why.contains("no adversary has read t-1 r1"), "{why}");
        assert!(merge_refusal(&f.route, &blocking, "t-1", 1).is_some());

        // The builder's Pass is not an adversary's: it does not open the gate.
        let mut own = finding("t-1", 1, Trigger::PreDone, Verdict::Pass);
        own.engine = "qwen".into();
        record(&f.route, &f.fang, own).unwrap();
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_some());
        // A signer with no inventory does not either.
        record(
            &f.route,
            &f.scribe,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_some());

        // Only the master waives, and only by what they saw.
        let error = waive(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            NO_FINDING,
            None,
            "wisp",
            &f.wisp,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("only boss, the master"), "{error}");
        let error = waive(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            "abc123",
            None,
            "boss",
            &f.boss,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("changed since you looked"), "{error}");
        let waiver = waive(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            NO_FINDING,
            Some("the adversary is away"),
            "boss",
            &f.boss,
        )
        .unwrap();
        assert_eq!(waiver.finding, NO_FINDING);
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_none());
        assert!(merge_refusal(&f.route, &blocking, "t-1", 1).is_none());
        // It covers "no finding" only: a Block that arrives afterwards still blocks.
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_some());
        assert!(merge_refusal(&f.route, &blocking, "t-1", 1).is_some());
        // And now that a finding counts, a waiver is the wrong tool.
        assert!(
            waive(
                &f.route,
                "t-1",
                1,
                Trigger::PreDone,
                NO_FINDING,
                None,
                "boss",
                &f.boss
            )
            .is_err()
        );
    }

    #[test]
    fn a_forged_waiver_is_not_one() {
        let f = Fleet::new();
        f.work("t-1", 1);
        let blocking = policy(AdversaryMode::Blocking);
        let path = waiver_path(&f.route, "t-1", 1, Trigger::PreDone).unwrap();
        let mut forged = Override {
            subject: "t-1".into(),
            revision: 1,
            trigger: Trigger::PreDone,
            finding: NO_FINDING.into(),
            reason: "trust me".into(),
            by: "boss".into(),
            at: Utc::now(),
            signed_by: "scribe".into(),
            signature: String::new(),
        };
        forged.signature = f.scribe.sign_bytes(forged.payload("demo").as_bytes());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(read_waiver(&f.route, "t-1", 1, Trigger::PreDone).is_none());
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_some());
    }

    #[test]
    fn the_deterministic_scan_is_the_one_finding_the_builder_may_record_about_itself() {
        let f = Fleet::new();
        f.work("t-1", 2);
        let mut scan = finding("t-1", 2, Trigger::RepeatFailure, Verdict::Block);
        scan.engine = TAMPER_SCAN.into();
        record(&f.route, &f.fang, scan).unwrap();
        let standing = standing(&f.route, "t-1", 2, Trigger::RepeatFailure)
            .expect("the scan of the diff about to be retried counts");
        assert!(standing.unresolved_block());
        // A model's finding by the builder, or a scan that only passes, does not.
        let mut model = finding("t-1", 1, Trigger::RepeatFailure, Verdict::Block);
        model.engine = "qwen".into();
        record(&f.route, &f.fang, model).unwrap();
        assert!(self::standing(&f.route, "t-1", 1, Trigger::RepeatFailure).is_none());
        let mut passing_scan = finding("t-1", 1, Trigger::PreDone, Verdict::Pass);
        passing_scan.engine = TAMPER_SCAN.into();
        record(&f.route, &f.fang, passing_scan).unwrap();
        assert!(self::standing(&f.route, "t-1", 1, Trigger::PreDone).is_none());
    }

    #[test]
    fn gate_decisions_read_the_subjects_files_however_many_findings_the_channel_holds() {
        let f = Fleet::new();
        f.work("t-1", 1);
        f.issue("t-9", None);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        // More newer findings about another subject than a listing keeps.
        for revision in 1..=(MAX_LISTED as u32 + 5) {
            record(
                &f.route,
                &f.wisp,
                finding("t-9", revision, Trigger::PreDone, Verdict::Pass),
            )
            .unwrap();
        }
        assert_eq!(list(&f.route).len(), MAX_LISTED, "the listing is truncated");
        assert!(
            !list(&f.route)
                .iter()
                .any(|finding| finding.subject == "t-1"),
            "t-1's finding fell off the display"
        );
        // The gate still sees it.
        let blocking = policy(AdversaryMode::Blocking);
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 1).is_some());
        assert!(
            standing(&f.route, "t-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );
        assert_eq!(for_subject(&f.route, "t-9").len(), MAX_LISTED + 5);
    }

    // --- override --------------------------------------------------------------------

    #[test]
    fn only_the_master_or_a_delegate_with_the_scope_overrides_and_only_a_block() {
        let f = Fleet::new();
        f.work("t-1", 1);
        f.work("t-2", 1);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        record(
            &f.route,
            &f.wisp,
            finding("t-2", 1, Trigger::PreDone, Verdict::Concern),
        )
        .unwrap();
        let d1 = digest_of(&f.route, "t-1", 1, Trigger::PreDone);
        let d2 = digest_of(&f.route, "t-2", 1, Trigger::PreDone);

        // A teammate is not the master.
        let error = override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &d1,
            None,
            "wisp",
            &f.wisp,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("only boss, the master"), "{error}");
        // The master, signing as someone who holds nothing for them, is refused too.
        let error = override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &d1,
            None,
            "boss",
            &f.scribe,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("cannot override"), "{error}");
        // A concern is not a block.
        let error = override_block(
            &f.route,
            "t-2",
            1,
            Trigger::PreDone,
            &d2,
            None,
            "boss",
            &f.boss,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a Block"), "{error}");
        // No finding at all.
        assert!(
            override_block(
                &f.route,
                "t-9",
                1,
                Trigger::PreDone,
                &d1,
                None,
                "boss",
                &f.boss
            )
            .is_err()
        );

        let given = override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &d1,
            Some("risk accepted"),
            "boss",
            &f.boss,
        )
        .unwrap();
        assert_eq!(given.reason, "risk accepted");
        assert_eq!(given.from(), "boss");
        let standing = standing(&f.route, "t-1", 1, Trigger::PreDone).unwrap();
        assert!(!standing.unresolved_block());
        assert!(standing.status().contains("overridden by boss"));
        // Idempotent.
        let again = override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &d1,
            None,
            "boss",
            &f.boss,
        )
        .unwrap();
        assert_eq!(again, given);
    }

    #[test]
    fn an_override_is_refused_when_the_finding_changed_since_the_master_looked() {
        let f = Fleet::new();
        f.work("t-1", 1);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let looked_at = digest_of(&f.route, "t-1", 1, Trigger::PreDone);
        // A second adversary's Block arrives before the master presses the button.
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let error = override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &looked_at,
            None,
            "boss",
            &f.boss,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("changed since you looked"), "{error}");
        assert!(
            standing(&f.route, "t-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block(),
            "nothing was overridden"
        );
        // Reading it again and overriding what they read works.
        let now = digest_of(&f.route, "t-1", 1, Trigger::PreDone);
        assert_ne!(now, looked_at);
        override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &now,
            None,
            "boss",
            &f.boss,
        )
        .unwrap();
        assert!(
            !standing(&f.route, "t-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );
        // A made-up digest never overrides.
        f.work("t-2", 1);
        record(
            &f.route,
            &f.wisp,
            finding("t-2", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        assert!(
            override_block(
                &f.route,
                "t-2",
                1,
                Trigger::PreDone,
                &"0".repeat(64),
                None,
                "boss",
                &f.boss
            )
            .is_err()
        );
    }

    #[test]
    fn a_delegate_overrides_only_with_the_scope_for_that_moment() {
        let f = Fleet::new();
        f.work("t-1", 1);
        let proposed = contract(&f);
        delegation::grant(
            &f.route.communications,
            "demo",
            &f.boss,
            "scribe",
            &[delegation::REVIEW.to_string()],
            None,
        )
        .unwrap();
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        record(
            &f.route,
            &f.wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        )
        .unwrap();
        let d1 = digest_of(&f.route, "t-1", 1, Trigger::PreDone);
        let d2 = digest_of(&f.route, "user-api@1", 0, Trigger::ContractLock);
        let by_scribe = override_block(
            &f.route,
            "t-1",
            1,
            Trigger::PreDone,
            &d1,
            None,
            "boss",
            &f.scribe,
        )
        .unwrap();
        assert_eq!(by_scribe.from(), "boss via scribe");
        // `review` is not what locks a contract.
        let error = override_block(
            &f.route,
            "user-api@1",
            0,
            Trigger::ContractLock,
            &d2,
            None,
            "boss",
            &f.scribe,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("improve"), "{error}");
        assert_eq!(proposed.reference(), "user-api@1");
    }

    #[test]
    fn an_override_covers_exactly_the_finding_it_names_and_cannot_be_forged() {
        let f = Fleet::new();
        f.work("t-1", 1);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let finding_now = read(&f.route, "t-1", 1, Trigger::PreDone, "wisp").unwrap();
        let path = override_path(&f.route, &finding_now).unwrap();
        assert!(
            path.ends_with("t-1-r1-pre-done.wisp.override.json"),
            "{path:?}"
        );

        // scribe is on the roster and signs an override in the master's name.
        let mut forged = Override {
            subject: "t-1".into(),
            revision: 1,
            trigger: Trigger::PreDone,
            finding: finding_digest(&finding_now),
            reason: "trust me".into(),
            by: "boss".into(),
            at: Utc::now(),
            signed_by: "scribe".into(),
            signature: String::new(),
        };
        forged.signature = f.scribe.sign_bytes(forged.payload("demo").as_bytes());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(
            read_override(&f.route, &finding_now).is_none(),
            "not the master's"
        );
        assert!(
            standing(&f.route, "t-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );

        // A real override of a different finding does not cover this one.
        let mut other = forged.clone();
        other.signed_by = "boss".into();
        other.finding = "0".repeat(64);
        other.signature = f.boss.sign_bytes(other.payload("demo").as_bytes());
        crate::atomic_json(&path, &other).unwrap();
        assert!(
            read_override(&f.route, &finding_now).is_none(),
            "another finding"
        );
    }

    // --- the three gates -----------------------------------------------------------------

    fn contract(f: &Fleet) -> InterfaceContract {
        let shape = crate::contract::Shape::parse(&json!({
            "type": "object",
            "required": ["id", "name"],
            "properties": { "id": { "type": "integer" }, "name": { "type": "string" } }
        }))
        .unwrap();
        interface::propose(&f.route, &f.boss, "user-api", "1", "users", None, shape).unwrap()
    }

    #[test]
    fn blocking_mode_refuses_the_lock_until_the_master_overrides_and_advisory_never_does() {
        let f = Fleet::new();
        let proposed = contract(&f);
        record(
            &f.route,
            &f.wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        )
        .unwrap();

        assert!(lock_refusal(&f.route, &policy(AdversaryMode::Advisory), &proposed).is_none());
        assert!(lock_refusal(&f.route, &policy(AdversaryMode::Off), &proposed).is_none());
        let why = lock_refusal(&f.route, &policy(AdversaryMode::Blocking), &proposed).unwrap();
        assert!(why.contains("blocks locking user-api@1"), "{why}");
        assert!(why.contains("--override"), "{why}");

        let digest = digest_of(&f.route, "user-api@1", 0, Trigger::ContractLock);
        override_block(
            &f.route,
            "user-api@1",
            0,
            Trigger::ContractLock,
            &digest,
            None,
            "boss",
            &f.boss,
        )
        .unwrap();
        assert!(lock_refusal(&f.route, &policy(AdversaryMode::Blocking), &proposed).is_none());
    }

    #[test]
    fn a_contract_with_no_eligible_finding_waits_in_blocking_mode_for_a_finding_or_a_waiver() {
        let f = Fleet::new();
        let proposed = contract(&f);
        let blocking = policy(AdversaryMode::Blocking);
        let why = lock_refusal(&f.route, &blocking, &proposed).unwrap();
        assert!(why.contains("no adversary has read user-api@1"), "{why}");
        assert!(lock_refusal(&f.route, &policy(AdversaryMode::Advisory), &proposed).is_none());
        record(
            &f.route,
            &f.wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Pass),
        )
        .unwrap();
        assert!(lock_refusal(&f.route, &blocking, &proposed).is_none());
    }

    #[test]
    fn a_contracts_findings_are_for_the_provider_result_it_is_decided_on() {
        let f = Fleet::new();
        let proposed = contract(&f);
        let blocking = policy(AdversaryMode::Blocking);
        record(
            &f.route,
            &f.wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        )
        .unwrap();
        assert!(lock_refusal(&f.route, &blocking, &proposed).is_some());

        // A provider builds it: the shapes-alone Block no longer describes what is decided.
        f.issue("back", Some(interface::Side::Provides));
        f.built(
            "back",
            1,
            json!({ "engine": "qwen", "response": { "id": 7, "name": "a" } }),
        );
        assert_eq!(contract_revision(&f.route, &proposed), 1);
        let why = lock_refusal(&f.route, &blocking, &proposed).unwrap();
        assert!(why.contains("at the provider's result r1"), "{why}");
        // The provider cannot vouch for its own work.
        let mut own = finding("user-api@1", 1, Trigger::ContractLock, Verdict::Pass);
        own.engine = "qwen".into();
        record(&f.route, &f.fang, own).unwrap();
        assert!(lock_refusal(&f.route, &blocking, &proposed).is_some());
        // An adversary that did not build it reads exactly that revision.
        record(
            &f.route,
            &f.bridge,
            finding("user-api@1", 1, Trigger::ContractLock, Verdict::Pass),
        )
        .unwrap();
        assert!(lock_refusal(&f.route, &blocking, &proposed).is_none());
        let survey = survey(&f.route, "user-api@1");
        assert!(
            survey
                .ignored
                .iter()
                .any(|ignored| ignored.reason.contains("no provider result r0")),
            "{:?}",
            survey.ignored
        );
        assert!(
            survey
                .ignored
                .iter()
                .any(|ignored| ignored.reason.contains("built the work it judged")),
            "{:?}",
            survey.ignored
        );
    }

    #[test]
    fn blocking_mode_withholds_the_engine_key_only_on_the_revision_that_was_blocked() {
        let f = Fleet::new();
        f.work("t-1", 3);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 2, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let blocking = policy(AdversaryMode::Blocking);
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 2).is_some());
        // Another revision has no finding of its own: in blocking mode it waits for one.
        let other = engine_key_refusal(&f.route, &blocking, "t-1", 3).unwrap();
        assert!(other.contains("no adversary has read t-1 r3"), "{other}");
        assert!(engine_key_refusal(&f.route, &policy(AdversaryMode::Advisory), "t-1", 2).is_none());
        // Auto-merge looks at every mode but off.
        assert!(unresolved_block(&f.route, &policy(AdversaryMode::Advisory), "t-1", 2).is_some());
        assert!(unresolved_block(&f.route, &policy(AdversaryMode::Off), "t-1", 2).is_none());
        assert!(
            merge_refusal(&f.route, &policy(AdversaryMode::Advisory), "t-1", 2)
                .unwrap()
                .contains("unresolved adversary Block")
        );
        let digest = digest_of(&f.route, "t-1", 2, Trigger::PreDone);
        override_block(
            &f.route,
            "t-1",
            2,
            Trigger::PreDone,
            &digest,
            None,
            "boss",
            &f.boss,
        )
        .unwrap();
        assert!(engine_key_refusal(&f.route, &blocking, "t-1", 2).is_none());
        assert!(unresolved_block(&f.route, &blocking, "t-1", 2).is_none());
        assert!(merge_refusal(&f.route, &blocking, "t-1", 2).is_none());
    }

    fn task_with(results: &[(u32, Value)], reviews: &[(u32, bool, &str)]) -> Task {
        let order = Order {
            id: "t-1".into(),
            project_id: "demo".into(),
            issued_by: "boss".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({
                "task": "do it",
                "tags": ["improvement"],
                "improvement": { "acceptance": ["`cargo test` passes"] }
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
        Task {
            order,
            claims: Vec::new(),
            results: results
                .iter()
                .map(|(revision, payload)| TaskResult {
                    order_id: "t-1".into(),
                    agent: "fang".into(),
                    revision: *revision,
                    submitted_at: Utc::now(),
                    payload: payload.clone(),
                    signed_by: None,
                    signature: None,
                })
                .collect(),
            reviews: reviews
                .iter()
                .map(|(revision, accepted, notes)| Review {
                    order_id: "t-1".into(),
                    revision: *revision,
                    reviewer: "boss".into(),
                    reviewed_at: Utc::now(),
                    accepted: *accepted,
                    notes: Some((*notes).to_string()),
                    signed_by: None,
                    signature: None,
                })
                .collect(),
            recommendations: Vec::new(),
            heartbeats: Vec::new(),
            releases: Vec::new(),
            kills: Vec::new(),
        }
    }

    fn passing(engine: &str) -> Value {
        json!({
            "output": "implemented the change and the tests pass",
            "engine": engine,
            "model": "m",
            "evidence": {
                "recorded_by": "worker", "git": true, "commits": ["abc1234 change"],
                "checks": [{ "command": "cargo test", "exit_code": 0, "seconds": 3,
                             "tail": "test result: ok" }]
            }
        })
    }

    fn failing_check(engine: &str) -> Value {
        json!({
            "output": "I could not make the tests pass",
            "engine": engine,
            "evidence": {
                "recorded_by": "worker", "git": true, "commits": ["abc1234 change"],
                "checks": [{ "command": "cargo test", "exit_code": 101, "seconds": 3,
                             "tail": "test result: FAILED. 1 failed" }]
            }
        })
    }

    #[test]
    fn two_failed_revisions_are_a_repeat_failure_by_any_of_the_three_signals() {
        // Sent back twice.
        let sent_back = task_with(
            &[(1, passing("a")), (2, passing("a"))],
            &[(1, false, "wrong approach"), (2, false, "still wrong")],
        );
        let repeat = repeat_failure(&sent_back).expect("two sent back");
        assert_eq!(repeat.latest, 2);
        assert!(repeat.failures[0].reasons[0].contains("wrong approach"));

        // A required check that exits non-zero, twice, with no review at all.
        let failing = task_with(&[(1, failing_check("a")), (2, failing_check("b"))], &[]);
        let repeat = repeat_failure(&failing).expect("two failed checks");
        assert_eq!(repeat.failures.len(), 2);
        assert!(
            repeat.failures[1]
                .reasons
                .iter()
                .any(|r| r.contains("exited 101"))
        );
        assert_eq!(repeat.failures[1].builder.as_ref().unwrap().engine, "b");
        assert_eq!(repeat.failures[0].checks[0].0, "cargo test");
        assert!(repeat.failures[0].checks[0].2.contains("FAILED"));

        // Refuted by its own evidence: claims success with no commit and no diff.
        let hollow = json!({
            "output": "done, all committed",
            "engine": "a",
            "evidence": { "recorded_by": "worker", "git": true,
                          "checks": [{ "command": "cargo test", "exit_code": 0, "seconds": 1 }] }
        });
        let refuted = task_with(&[(1, hollow.clone()), (2, hollow)], &[]);
        assert!(repeat_failure(&refuted).is_some());
    }

    #[test]
    fn one_failure_or_a_failure_that_was_later_accepted_is_not_a_repeat() {
        let once = task_with(&[(1, failing_check("a")), (2, passing("a"))], &[]);
        assert!(repeat_failure(&once).is_none(), "one failure");
        let mixed = task_with(
            &[(1, failing_check("a")), (2, passing("a"))],
            &[(1, false, "no"), (2, true, "yes")],
        );
        assert!(
            repeat_failure(&mixed).is_none(),
            "sent back once, then accepted"
        );
        let accepted_anyway = task_with(
            &[(1, failing_check("a")), (2, failing_check("a"))],
            &[(1, false, "no"), (2, true, "ok")],
        );
        assert_eq!(
            failed_revisions(&accepted_anyway).len(),
            1,
            "an accepted revision did not fail"
        );
        assert!(repeat_failure(&task_with(&[], &[])).is_none());
    }

    #[test]
    fn the_next_attempt_is_told_only_what_an_eligible_block_found() {
        let f = Fleet::new();
        f.issue("t-1", None);
        f.built("t-1", 1, failing_check("qwen"));
        assert!(attempt_notice(&f.route, "t-1").is_none(), "failed once");
        f.built("t-1", 2, failing_check("qwen"));
        assert!(attempt_notice(&f.route, "t-1").is_none(), "no finding yet");
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 2, Trigger::RepeatFailure, Verdict::Concern),
        )
        .unwrap();
        assert!(
            attempt_notice(&f.route, "t-1").is_none(),
            "a concern is not carried"
        );
        // A Block at a revision that is not the failed attempt the next one follows is not it.
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 3, Trigger::RepeatFailure, Verdict::Block),
        )
        .unwrap();
        assert!(attempt_notice(&f.route, "t-1").is_none());
        record(
            &f.route,
            &f.bridge,
            finding("t-1", 2, Trigger::RepeatFailure, Verdict::Block),
        )
        .unwrap();
        let notice = attempt_notice(&f.route, "t-1").expect("a block is carried");
        assert!(notice.contains("tests were deleted"), "{notice}");
        assert!(notice.contains("Do not delete"), "{notice}");
        let standing = attempt_standing(&f.route, "t-1").unwrap();
        assert_eq!(standing.finding.revision, 2);
        assert_eq!(
            decision_standing(&f.route, "t-1", Trigger::RepeatFailure)
                .unwrap()
                .digest(),
            standing.digest()
        );
    }

    #[test]
    fn the_decision_standing_is_the_revision_under_decision_not_the_highest_with_a_finding() {
        let f = Fleet::new();
        f.work("t-1", 2);
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        // The order's newest result is r2, which no one has read.
        assert!(decision_standing(&f.route, "t-1", Trigger::PreDone).is_none());
        record(
            &f.route,
            &f.wisp,
            finding("t-1", 2, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        assert_eq!(
            decision_standing(&f.route, "t-1", Trigger::PreDone)
                .unwrap()
                .finding
                .revision,
            2
        );
    }

    #[test]
    fn the_context_for_a_contract_checks_the_providers_response_against_the_proposed_shape() {
        let f = Fleet::new();
        let proposed = contract(&f);

        // No provider yet: the contract is reviewed alone.
        let alone = contract_context(&f.route, &proposed).unwrap();
        assert_eq!(alone.revision, 0);
        assert!(alone.provider_result.is_none());
        assert!(alone.precheck.is_empty());

        // A consumer and a provider with a result whose response is wrong.
        f.issue("front", Some(interface::Side::Consumes));
        f.issue("back", Some(interface::Side::Provides));
        f.built(
            "back",
            1,
            json!({ "engine": "qwen", "model": "qwen-coder", "response": { "id": "seven" } }),
        );
        // A result nobody signed is nobody's word, and is not the provider's newest.
        let mut unsigned = TaskResult {
            order_id: "back".into(),
            agent: "fang".into(),
            revision: 2,
            submitted_at: Utc::now(),
            payload: json!({ "engine": "glm", "response": { "id": 7, "name": "a" } }),
            signed_by: None,
            signature: None,
        };
        crate::submit_result(&f.route, &unsigned).unwrap();
        unsigned.revision = 3;
        unsigned.signature = Some("00".repeat(64));
        unsigned.signed_by = Some("fang".into());
        crate::submit_result(&f.route, &unsigned).unwrap();

        let context = contract_context(&f.route, &proposed).unwrap();
        assert_eq!(context.revision, 1);
        assert_eq!(contract_revision(&f.route, &proposed), 1);
        assert_eq!(context.order_id, "back");
        assert_eq!(
            context.builders,
            [Builder {
                engine: "qwen".into(),
                model: Some("qwen-coder".into())
            }]
        );
        assert_eq!(
            context.consumers,
            [("front".to_string(), "front work".to_string())]
        );
        assert!(
            context
                .precheck
                .iter()
                .any(|line| line.contains("result.response.id")),
            "the integer is a string: {:?}",
            context.precheck
        );
        assert!(
            context.precheck.iter().any(|line| line.contains("name")),
            "name is missing: {:?}",
            context.precheck
        );
    }
}

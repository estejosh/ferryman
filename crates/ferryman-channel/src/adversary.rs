//! The adversary: a second model that challenges the work at three critical moments.
//!
//! ```text
//! <channel>/adversary/<subject>-r<revision>-<trigger>.json            the finding, signed
//! <channel>/adversary/<subject>-r<revision>-<trigger>.override.json   the master's override
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
//! # Trust
//!
//! A finding is honoured only when its signature verifies against the channel's roster
//! and its signer has not been revoked. Anything else - unsigned, edited, forged, copied
//! from another project - is ignored, exactly as a missing finding is. A missing finding
//! never blocks anything: the adversary is a check on the work, not a gate that fails
//! shut when the adversary is away. (The loop itself does hold the engine key in
//! `blocking` mode until the adversary has run; see `ferryman_ops::adversary`.)
//!
//! # Idempotence
//!
//! One run per (subject, revision, trigger). [`record`] refuses to write a second
//! finding where a genuine one exists, so a loop that wakes every hour pays once.
//!
//! # Override
//!
//! In `blocking` mode a Block stops the lock or the engine key. Only the master - or a
//! delegate holding the matching scope - may sign an [`Override`], which is recorded and
//! covers exactly the finding it names. The override does not edit the finding: the
//! record of what the adversary said, and that the master went ahead anyway, stays.

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

/// Where the finding for a subject, revision and trigger is stored.
pub fn finding_path(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<PathBuf> {
    subject_ok(subject)
        .then(|| dir(route).join(format!("{}.json", stem(subject, revision, trigger))))
}

fn override_path(
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

/// A finding read from disk is genuine only if it says what its file name says, its
/// signature verifies, and its signer is still on the channel.
fn genuine(route: &ProjectRoute, finding: &AdversaryFinding) -> bool {
    if !subject_ok(&finding.subject) || finding.signed_by.is_empty() {
        return false;
    }
    check_signature(
        Some(&finding.signed_by),
        Some(&finding.signature),
        &finding.payload(&route.project_id),
        &crate::gate::roster(route),
    ) == SignatureCheck::Valid
        && !crate::master::is_revoked(route, &finding.signed_by).unwrap_or(true)
}

/// The finding for exactly this (subject, revision, trigger), when a genuine one exists.
#[must_use]
pub fn read(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<AdversaryFinding> {
    let path = finding_path(route, subject, revision, trigger)?;
    let finding: AdversaryFinding = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (finding.subject == subject
        && finding.revision == revision
        && finding.trigger == trigger
        && genuine(route, &finding))
    .then_some(finding)
}

/// Whether the adversary has already run for this (subject, revision, trigger).
#[must_use]
pub fn done(route: &ProjectRoute, subject: &str, revision: u32, trigger: Trigger) -> bool {
    read(route, subject, revision, trigger).is_some()
}

/// Write the finding, signed by `identity`, the agent that ran the engine. Returns whether
/// anything was written: `false` when a genuine finding for the same (subject, revision,
/// trigger) is already there, which is what makes a run idempotent.
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
    if !is_safe_component(identity.name()) {
        bail!("agent name must be a path-safe identifier");
    }
    if done(route, &finding.subject, finding.revision, finding.trigger) {
        return Ok(false);
    }
    finding.signed_by = identity.name().to_string();
    finding.signature = String::new();
    finding.signature = identity.sign_bytes(finding.payload(&route.project_id).as_bytes());
    let path = finding_path(route, &finding.subject, finding.revision, finding.trigger)
        .context("a path-safe subject has a path")?;
    crate::atomic_json(&path, &finding).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Every genuine finding, newest first (at most [`MAX_LISTED`]).
#[must_use]
pub fn list(route: &ProjectRoute) -> Vec<AdversaryFinding> {
    let Ok(entries) = fs::read_dir(dir(route)) else {
        return Vec::new();
    };
    let mut found: Vec<AdversaryFinding> = entries
        .flatten()
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.ends_with(".json")
                    && !name.ends_with(".override.json")
                    && !name.contains(".sync-conflict-")
            })
        })
        .filter_map(|entry| {
            serde_json::from_slice::<AdversaryFinding>(&fs::read(entry.path()).ok()?).ok()
        })
        .filter(|finding| {
            // The file must be the one its content names: a finding copied to another
            // file name is not read as the finding for that name.
            read(route, &finding.subject, finding.revision, finding.trigger)
                .is_some_and(|genuine| genuine == *finding)
        })
        .collect();
    found.sort_by_key(|finding| std::cmp::Reverse(finding.created_at));
    found.truncate(MAX_LISTED);
    found
}

/// Every genuine finding about `subject`, newest first.
#[must_use]
pub fn for_subject(route: &ProjectRoute, subject: &str) -> Vec<AdversaryFinding> {
    list(route)
        .into_iter()
        .filter(|finding| finding.subject == subject)
        .collect()
}

/// The finding about `subject` at the highest revision for `trigger`.
#[must_use]
pub fn latest(route: &ProjectRoute, subject: &str, trigger: Trigger) -> Option<AdversaryFinding> {
    for_subject(route, subject)
        .into_iter()
        .filter(|finding| finding.trigger == trigger)
        .max_by_key(|finding| (finding.revision, finding.created_at))
}

// --- overriding a Block ------------------------------------------------------------------

/// The master's signed decision to go ahead despite one Block finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Override {
    pub subject: String,
    pub revision: u32,
    pub trigger: Trigger,
    /// Which finding: a digest of its signature, so a re-run finding is not covered.
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

fn finding_digest(finding: &AdversaryFinding) -> String {
    hex::encode(Sha256::digest(finding.signature.as_bytes()))
}

/// The override that covers `finding`, when a genuine one exists: signed by the master
/// (or a delegate holding the trigger's scope), over exactly this finding.
#[must_use]
pub fn read_override(route: &ProjectRoute, finding: &AdversaryFinding) -> Option<Override> {
    let path = override_path(route, &finding.subject, finding.revision, finding.trigger)?;
    let record: Override = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    let master = crate::master::read_master(route).ok()??;
    (record.subject == finding.subject
        && record.revision == finding.revision
        && record.trigger == finding.trigger
        && record.finding == finding_digest(finding)
        && record.by.eq_ignore_ascii_case(&master.master)
        && delegation::authority(
            &route.communications,
            &route.project_id,
            &record.by,
            &record.signed_by,
            finding.trigger.override_scope(),
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

/// Go ahead despite the Block finding for (subject, revision, trigger): the master (`by`),
/// signed for by `signer` - themselves, or a delegate holding the scope for this moment
/// ([`Trigger::override_scope`]). Refused when there is no genuine Block to override.
/// Idempotent: a genuine override already there is returned as it is.
pub fn override_block(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
    reason: Option<&str>,
    by: &str,
    signer: &AgentIdentity,
) -> Result<Override> {
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
    let Some(finding) = read(route, subject, revision, trigger) else {
        bail!(
            "there is no genuine {} finding for {subject} r{revision} to override",
            trigger.as_str()
        );
    };
    if finding.verdict != Verdict::Block {
        bail!(
            "the adversary's verdict on {subject} r{revision} is {}, not a Block; there is \
             nothing to override",
            finding.verdict.as_str()
        );
    }
    if let Some(existing) = read_override(route, &finding) {
        return Ok(existing);
    }
    let reason = reason
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map_or_else(
            || format!("overridden by {}", delegation::label(by, signer.name())),
            str::to_string,
        );
    let mut record = Override {
        subject: subject.to_string(),
        revision,
        trigger,
        finding: finding_digest(&finding),
        reason,
        by: master.master,
        at: Utc::now(),
        signed_by: signer.name().to_string(),
        signature: String::new(),
    };
    record.signature = signer.sign_bytes(record.payload(&route.project_id).as_bytes());
    let path = override_path(route, subject, revision, trigger)
        .context("a path-safe subject has a path")?;
    crate::atomic_json(&path, &record).with_context(|| format!("writing {}", path.display()))?;
    read_override(route, &finding)
        .with_context(|| format!("the override for {subject} was written but does not verify"))
}

/// A finding with what became of it.
#[derive(Debug, Clone, PartialEq)]
pub struct Standing {
    pub finding: AdversaryFinding,
    pub overridden: Option<Override>,
}

impl Standing {
    /// A Block nobody has overridden.
    #[must_use]
    pub fn unresolved_block(&self) -> bool {
        self.finding.verdict == Verdict::Block && self.overridden.is_none()
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
            None => self.finding.verdict.as_str().to_string(),
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
            "verdict": finding.verdict.as_str(),
            "status": self.status(),
            "unresolved_block": self.unresolved_block(),
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
        })
    }
}

/// [`Standing`] for the finding at exactly (subject, revision, trigger).
#[must_use]
pub fn standing(
    route: &ProjectRoute,
    subject: &str,
    revision: u32,
    trigger: Trigger,
) -> Option<Standing> {
    let finding = read(route, subject, revision, trigger)?;
    let overridden = read_override(route, &finding);
    Some(Standing {
        finding,
        overridden,
    })
}

/// [`Standing`] for the newest finding about `subject` at `trigger`.
#[must_use]
pub fn latest_standing(route: &ProjectRoute, subject: &str, trigger: Trigger) -> Option<Standing> {
    let finding = latest(route, subject, trigger)?;
    let overridden = read_override(route, &finding);
    Some(Standing {
        finding,
        overridden,
    })
}

// --- what the modes make of a finding ------------------------------------------------------

/// Why `contract` may not be locked, when it may not: the adversary's mode is `blocking`,
/// its newest word on the contract is a Block, and the master has not overridden it.
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
    let standing = latest_standing(route, &reference, Trigger::ContractLock)?;
    standing.unresolved_block().then(|| {
        let worst = standing
            .finding
            .top(1)
            .first()
            .map(|issue| format!(" - {}: {}", issue.title, issue.detail))
            .unwrap_or_default();
        format!(
            "the adversary ({}) blocks locking {reference}{worst}. The engine policy has \
             adversary = blocking, so locking needs an explicit master override: read it with \
             `ferry adversary show {reference}`, then lock with an override (ferry contract \
             lock {reference} --override \"why\", or the Override button)",
            standing.finding.engine
        )
    })
}

/// Why the engine key may not be granted for `order_id` r`revision`, when it may not: the
/// adversary's mode is `blocking`, its pre-done finding on exactly this revision is a
/// Block, and the master has not overridden it.
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
    let standing = self::standing(route, order_id, revision, Trigger::PreDone)?;
    standing.unresolved_block().then(|| {
        let worst = standing
            .finding
            .top(1)
            .first()
            .map(|issue| format!(" - {}: {}", issue.title, issue.detail))
            .unwrap_or_default();
        format!(
            "the adversary ({}) blocks {order_id} r{revision}{worst}. adversary = blocking, so \
             the review engine's key waits for a master override (`ferry adversary override \
             {order_id}`, or the Override button)",
            standing.finding.engine
        )
    })
}

/// An unresolved Block on exactly this revision, under any mode but `off`: what auto-merge
/// checks, because a merge nobody is watching must never carry a Block nobody answered.
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

// --- the contract moment ---------------------------------------------------------------------

/// Everything the adversary is shown about a contract waiting for its lock, and the part
/// of it no model is needed for.
#[derive(Debug, Clone)]
pub struct ContractContext {
    pub contract: InterfaceContract,
    /// The first provider order, or empty.
    pub order_id: String,
    /// How many provider results there are across every provider order (0 when none has a
    /// result): the round the contract is reviewed at. It grows whenever any provider
    /// submits, so each (provider order, revision) is read once.
    pub revision: u32,
    /// The newest provider result's payload, when one has a result.
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
    // Revisions count per order, so two providers' revision 1s are two different results and
    // a bigger number is not a newer one. The newest result is the latest submitted (ties
    // broken the same way on every machine), and the contract's `revision` is how many
    // provider results there are in all: it grows whenever any provider submits, so every
    // (provider order, revision) is reviewed once and the lock gate always reads the newest
    // review.
    let mut newest: Option<(chrono::DateTime<chrono::Utc>, String, u32, Value)> = None;
    let mut round = 0_u32;
    for order in &orders.providers {
        let Ok(task) = crate::read_task(route, &order.id) else {
            continue;
        };
        for result in &task.results {
            round += 1;
            if let Some(builder) = Builder::from_payload(&result.payload)
                && !context.builders.contains(&builder)
            {
                context.builders.push(builder);
            }
            let key = (result.submitted_at, order.id.clone(), result.revision);
            if newest
                .as_ref()
                .is_none_or(|(at, id, revision, _)| key > (*at, id.clone(), *revision))
            {
                newest = Some((key.0, key.1, key.2, result.payload.clone()));
            }
        }
    }
    if let Some((_, order_id, _, payload)) = newest {
        context.revision = round;
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

/// What the next attempt at `order_id` is told, when the adversary blocked it or the scan
/// found tampering: the finding's words, ready for an engine prompt. Empty when the
/// newest repeat-failure finding is not a Block.
#[must_use]
pub fn attempt_notice(route: &ProjectRoute, order_id: &str) -> Option<String> {
    let standing = latest_standing(route, order_id, Trigger::RepeatFailure)?;
    if standing.finding.verdict != Verdict::Block {
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
    use crate::{AgentRoute, Order, Review, TaskResult};
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

    #[test]
    fn a_finding_is_signed_stored_and_read_back_and_ranks_its_worst_first() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        let made = finding("t-1", 2, Trigger::PreDone, Verdict::Block);
        assert!(record(&route, &wisp, made).unwrap());
        let read = read(&route, "t-1", 2, Trigger::PreDone).expect("a genuine finding reads");
        assert_eq!(read.signed_by, "wisp");
        assert_eq!(read.verdict, Verdict::Block);
        assert_eq!(read.top(1)[0].title, "tests were deleted");
        assert!(read.describe().contains("block by deepseek"));
        assert!(read.has_high());
        assert_eq!(list(&route).len(), 1);
        assert_eq!(for_subject(&route, "t-1").len(), 1);
        assert!(latest(&route, "t-1", Trigger::PreDone).is_some());
        assert!(latest(&route, "t-1", Trigger::ContractLock).is_none());
    }

    #[test]
    fn a_second_run_for_the_same_subject_revision_and_trigger_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        assert!(
            record(
                &route,
                &wisp,
                finding("t-1", 1, Trigger::PreDone, Verdict::Pass)
            )
            .unwrap()
        );
        let path = finding_path(&route, "t-1", 1, Trigger::PreDone).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(
            !record(
                &route,
                &boss,
                finding("t-1", 1, Trigger::PreDone, Verdict::Block)
            )
            .unwrap(),
            "a genuine finding is already there"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "the file is untouched");
        assert!(done(&route, "t-1", 1, Trigger::PreDone));
        // Another revision, or another trigger, is another run.
        assert!(
            record(
                &route,
                &wisp,
                finding("t-1", 2, Trigger::PreDone, Verdict::Pass)
            )
            .unwrap()
        );
        assert!(
            record(
                &route,
                &wisp,
                finding("t-1", 1, Trigger::RepeatFailure, Verdict::Pass)
            )
            .unwrap()
        );
    }

    #[test]
    fn forged_edited_unsigned_and_misfiled_findings_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp, mallory) = (person("boss", 1), person("wisp", 2), person("mallory", 9));
        let route = route(dir.path(), &[&boss, &wisp]);
        record(
            &route,
            &wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Pass),
        )
        .unwrap();
        let path = finding_path(&route, "t-1", 1, Trigger::PreDone).unwrap();

        // Edited after signing: the verdict was flipped to a Block.
        let mut edited: AdversaryFinding =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edited.verdict = Verdict::Block;
        crate::atomic_json(&path, &edited).unwrap();
        assert!(read(&route, "t-1", 1, Trigger::PreDone).is_none(), "edited");
        assert!(list(&route).is_empty());

        // Signed by a key that is not on the roster.
        let mut forged = finding("t-1", 1, Trigger::PreDone, Verdict::Block);
        forged.signed_by = "mallory".into();
        forged.signature = mallory.sign_bytes(forged.payload("demo").as_bytes());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(read(&route, "t-1", 1, Trigger::PreDone).is_none(), "forged");

        // Signed as wisp by someone who is not wisp.
        let mut lie = finding("t-1", 1, Trigger::PreDone, Verdict::Block);
        lie.signed_by = "wisp".into();
        lie.signature = mallory.sign_bytes(lie.payload("demo").as_bytes());
        crate::atomic_json(&path, &lie).unwrap();
        assert!(
            read(&route, "t-1", 1, Trigger::PreDone).is_none(),
            "impersonated"
        );

        // Unsigned.
        let unsigned = finding("t-1", 1, Trigger::PreDone, Verdict::Block);
        crate::atomic_json(&path, &unsigned).unwrap();
        assert!(
            read(&route, "t-1", 1, Trigger::PreDone).is_none(),
            "unsigned"
        );

        // A genuine finding copied to another file name is not the finding for that name.
        record(
            &route,
            &wisp,
            finding("t-2", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        fs::copy(
            finding_path(&route, "t-2", 1, Trigger::PreDone).unwrap(),
            finding_path(&route, "t-3", 1, Trigger::PreDone).unwrap(),
        )
        .unwrap();
        assert!(
            read(&route, "t-3", 1, Trigger::PreDone).is_none(),
            "misfiled"
        );

        // A forged file does not stop the genuine run: nothing genuine was there.
        assert!(
            record(
                &route,
                &wisp,
                finding("t-1", 1, Trigger::PreDone, Verdict::Pass)
            )
            .unwrap()
        );
        assert!(read(&route, "t-1", 1, Trigger::PreDone).is_some());
    }

    #[test]
    fn a_finding_cannot_be_lifted_into_another_project() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        let mut elsewhere = self::route(other.path(), &[&boss, &wisp]);
        elsewhere.project_id = "other".into();
        record(
            &route,
            &wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        fs::create_dir_all(dir_of(&elsewhere)).unwrap();
        fs::copy(
            finding_path(&route, "t-1", 1, Trigger::PreDone).unwrap(),
            finding_path(&elsewhere, "t-1", 1, Trigger::PreDone).unwrap(),
        )
        .unwrap();
        assert!(read(&elsewhere, "t-1", 1, Trigger::PreDone).is_none());
    }

    fn dir_of(route: &ProjectRoute) -> PathBuf {
        dir(route)
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
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        assert!(
            record(
                &route,
                &wisp,
                finding("../x", 1, Trigger::PreDone, Verdict::Pass)
            )
            .is_err()
        );
    }

    #[test]
    fn only_the_master_or_a_delegate_with_the_scope_overrides_and_only_a_block() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp, bridge) = (person("boss", 1), person("wisp", 2), person("bridge", 3));
        let route = route(dir.path(), &[&boss, &wisp, &bridge]);
        record(
            &route,
            &wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        record(
            &route,
            &wisp,
            finding("t-2", 1, Trigger::PreDone, Verdict::Concern),
        )
        .unwrap();

        // A teammate is not the master.
        let error = override_block(&route, "t-1", 1, Trigger::PreDone, None, "wisp", &wisp)
            .unwrap_err()
            .to_string();
        assert!(error.contains("only boss, the master"), "{error}");
        // The master, signing as someone who holds nothing for them, is refused too.
        let error = override_block(&route, "t-1", 1, Trigger::PreDone, None, "boss", &bridge)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot override"), "{error}");
        // A concern is not a block.
        let error = override_block(&route, "t-2", 1, Trigger::PreDone, None, "boss", &boss)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a Block"), "{error}");
        // No finding at all.
        assert!(override_block(&route, "t-9", 1, Trigger::PreDone, None, "boss", &boss).is_err());

        let standing = standing(&route, "t-1", 1, Trigger::PreDone).unwrap();
        assert!(standing.unresolved_block());
        let given = override_block(
            &route,
            "t-1",
            1,
            Trigger::PreDone,
            Some("risk accepted"),
            "boss",
            &boss,
        )
        .unwrap();
        assert_eq!(given.reason, "risk accepted");
        assert_eq!(given.from(), "boss");
        let standing = self::standing(&route, "t-1", 1, Trigger::PreDone).unwrap();
        assert!(!standing.unresolved_block());
        assert!(standing.status().contains("overridden by boss"));
        // Idempotent.
        let again =
            override_block(&route, "t-1", 1, Trigger::PreDone, None, "boss", &boss).unwrap();
        assert_eq!(again, given);
    }

    #[test]
    fn a_delegate_overrides_only_with_the_scope_for_that_moment() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp, bridge) = (person("boss", 1), person("wisp", 2), person("bridge", 3));
        let route = route(dir.path(), &[&boss, &wisp, &bridge]);
        delegation::grant(
            &route.communications,
            "demo",
            &boss,
            "bridge",
            &[delegation::REVIEW.to_string()],
            None,
        )
        .unwrap();
        record(
            &route,
            &wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        record(
            &route,
            &wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        )
        .unwrap();
        let by_bridge =
            override_block(&route, "t-1", 1, Trigger::PreDone, None, "boss", &bridge).unwrap();
        assert_eq!(by_bridge.from(), "boss via bridge");
        // `review` is not what locks a contract.
        let error = override_block(
            &route,
            "user-api@1",
            0,
            Trigger::ContractLock,
            None,
            "boss",
            &bridge,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("improve"), "{error}");
    }

    #[test]
    fn an_override_covers_exactly_the_finding_it_names_and_cannot_be_forged() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp, mallory) = (person("boss", 1), person("wisp", 2), person("mallory", 9));
        let route = route(dir.path(), &[&boss, &wisp, &mallory]);
        record(
            &route,
            &wisp,
            finding("t-1", 1, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let path = override_path(&route, "t-1", 1, Trigger::PreDone).unwrap();

        // mallory is on the roster and signs an override in the master's name.
        let finding_now = read(&route, "t-1", 1, Trigger::PreDone).unwrap();
        let mut forged = Override {
            subject: "t-1".into(),
            revision: 1,
            trigger: Trigger::PreDone,
            finding: finding_digest(&finding_now),
            reason: "trust me".into(),
            by: "boss".into(),
            at: Utc::now(),
            signed_by: "mallory".into(),
            signature: String::new(),
        };
        forged.signature = mallory.sign_bytes(forged.payload("demo").as_bytes());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(
            read_override(&route, &finding_now).is_none(),
            "not the master's"
        );
        assert!(
            standing(&route, "t-1", 1, Trigger::PreDone)
                .unwrap()
                .unresolved_block()
        );

        // A real override of a different finding does not cover this one.
        let mut other = forged.clone();
        other.signed_by = "boss".into();
        other.finding = "0".repeat(64);
        other.signature = boss.sign_bytes(other.payload("demo").as_bytes());
        crate::atomic_json(&path, &other).unwrap();
        assert!(
            read_override(&route, &finding_now).is_none(),
            "another finding"
        );
    }

    fn contract(route: &ProjectRoute, who: &AgentIdentity) -> InterfaceContract {
        let shape = crate::contract::Shape::parse(&json!({
            "type": "object",
            "required": ["id", "name"],
            "properties": { "id": { "type": "integer" }, "name": { "type": "string" } }
        }))
        .unwrap();
        interface::propose(route, who, "user-api", "1", "users", None, shape).unwrap()
    }

    fn policy(mode: AdversaryMode) -> Policy {
        Policy {
            adversary: mode,
            ..Policy::default()
        }
    }

    #[test]
    fn blocking_mode_refuses_the_lock_until_the_master_overrides_and_advisory_never_does() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        let proposed = contract(&route, &wisp);
        record(
            &route,
            &wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        )
        .unwrap();

        assert!(lock_refusal(&route, &policy(AdversaryMode::Advisory), &proposed).is_none());
        assert!(lock_refusal(&route, &policy(AdversaryMode::Off), &proposed).is_none());
        let why = lock_refusal(&route, &policy(AdversaryMode::Blocking), &proposed).unwrap();
        assert!(why.contains("blocks locking user-api@1"), "{why}");
        assert!(why.contains("--override"), "{why}");

        override_block(
            &route,
            "user-api@1",
            0,
            Trigger::ContractLock,
            None,
            "boss",
            &boss,
        )
        .unwrap();
        assert!(lock_refusal(&route, &policy(AdversaryMode::Blocking), &proposed).is_none());
    }

    #[test]
    fn an_older_block_does_not_hold_a_contract_a_newer_pass_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        let proposed = contract(&route, &wisp);
        record(
            &route,
            &wisp,
            finding("user-api@1", 0, Trigger::ContractLock, Verdict::Block),
        )
        .unwrap();
        record(
            &route,
            &wisp,
            finding("user-api@1", 1, Trigger::ContractLock, Verdict::Pass),
        )
        .unwrap();
        assert!(lock_refusal(&route, &policy(AdversaryMode::Blocking), &proposed).is_none());
    }

    #[test]
    fn blocking_mode_withholds_the_engine_key_only_on_the_revision_that_was_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        record(
            &route,
            &wisp,
            finding("t-1", 2, Trigger::PreDone, Verdict::Block),
        )
        .unwrap();
        let blocking = policy(AdversaryMode::Blocking);
        assert!(engine_key_refusal(&route, &blocking, "t-1", 2).is_some());
        assert!(
            engine_key_refusal(&route, &blocking, "t-1", 3).is_none(),
            "another revision"
        );
        assert!(engine_key_refusal(&route, &policy(AdversaryMode::Advisory), "t-1", 2).is_none());
        // Auto-merge looks at every mode but off.
        assert!(unresolved_block(&route, &policy(AdversaryMode::Advisory), "t-1", 2).is_some());
        assert!(unresolved_block(&route, &policy(AdversaryMode::Off), "t-1", 2).is_none());
        override_block(&route, "t-1", 2, Trigger::PreDone, None, "boss", &boss).unwrap();
        assert!(engine_key_refusal(&route, &blocking, "t-1", 2).is_none());
        assert!(unresolved_block(&route, &blocking, "t-1", 2).is_none());
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
    fn the_next_attempt_is_told_only_what_a_block_found() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        assert!(attempt_notice(&route, "t-1").is_none());
        record(
            &route,
            &wisp,
            finding("t-1", 2, Trigger::RepeatFailure, Verdict::Concern),
        )
        .unwrap();
        assert!(
            attempt_notice(&route, "t-1").is_none(),
            "a concern is not carried"
        );
        record(
            &route,
            &wisp,
            finding("t-1", 3, Trigger::RepeatFailure, Verdict::Block),
        )
        .unwrap();
        let notice = attempt_notice(&route, "t-1").expect("a block is carried");
        assert!(notice.contains("tests were deleted"), "{notice}");
        assert!(notice.contains("Do not delete"), "{notice}");
    }

    #[test]
    fn the_context_for_a_contract_checks_the_providers_response_against_the_proposed_shape() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        let proposed = contract(&route, &wisp);

        // No provider yet: the contract is reviewed alone.
        let alone = contract_context(&route, &proposed).unwrap();
        assert_eq!(alone.revision, 0);
        assert!(alone.provider_result.is_none());
        assert!(alone.precheck.is_empty());

        // A consumer and a provider with a result whose response is wrong.
        for (id, side) in [
            ("front", interface::Side::Consumes),
            ("back", interface::Side::Provides),
        ] {
            let mut order = Order {
                id: id.into(),
                project_id: "demo".into(),
                issued_by: "boss".into(),
                assigned_to: None,
                created_at: Utc::now(),
                payload: json!({ "task": format!("{id} work") }),
                requires_review: false,
                requires_approval: false,
                depends_on: Vec::new(),
                signed_by: None,
                signature: None,
                result_contract: None,
                interface: Some(interface::InterfaceRef {
                    name: "user-api".into(),
                    version: "1".into(),
                    side,
                }),
                touches: Vec::new(),
                allow_overlap: false,
            };
            boss.sign_order(&mut order);
            crate::issue_order(&route, &order).unwrap();
        }
        let mut result = TaskResult {
            order_id: "back".into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "engine": "qwen", "model": "qwen-coder",
                              "response": { "id": "seven" } }),
            signed_by: None,
            signature: None,
        };
        wisp.sign_result(&mut result);
        crate::submit_result(&route, &result).unwrap();

        let context = contract_context(&route, &proposed).unwrap();
        assert_eq!(context.revision, 1);
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

    #[test]
    fn a_second_providers_revision_one_is_a_new_round_and_the_newest_result_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let (boss, wisp) = (person("boss", 1), person("wisp", 2));
        let route = route(dir.path(), &[&boss, &wisp]);
        let proposed = contract(&route, &wisp);
        for id in ["back", "back2"] {
            let mut order = Order {
                id: id.into(),
                project_id: "demo".into(),
                issued_by: "boss".into(),
                assigned_to: None,
                created_at: Utc::now(),
                payload: json!({ "task": format!("{id} work") }),
                requires_review: false,
                requires_approval: false,
                depends_on: Vec::new(),
                signed_by: None,
                signature: None,
                result_contract: None,
                interface: Some(interface::InterfaceRef {
                    name: "user-api".into(),
                    version: "1".into(),
                    side: interface::Side::Provides,
                }),
                touches: Vec::new(),
                allow_overlap: false,
            };
            boss.sign_order(&mut order);
            crate::issue_order(&route, &order).unwrap();
        }
        let start = Utc::now();
        let submit = |id: &str, revision: u32, engine: &str, seconds: i64| {
            let mut result = TaskResult {
                order_id: id.into(),
                agent: "wisp".into(),
                revision,
                submitted_at: start + chrono::Duration::seconds(seconds),
                payload: json!({ "engine": engine, "response": { "id": 1 } }),
                signed_by: None,
                signature: None,
            };
            wisp.sign_result(&mut result);
            crate::submit_result(&route, &result).unwrap();
        };

        submit("back", 1, "first", 1);
        let one = contract_context(&route, &proposed).unwrap();
        assert_eq!((one.order_id.as_str(), one.revision), ("back", 1));

        // Another provider's revision 1, later: not a repeat of the number 1, and the one
        // the adversary must now read.
        submit("back2", 1, "second", 2);
        let two = contract_context(&route, &proposed).unwrap();
        assert_eq!(two.order_id, "back2");
        assert_eq!(two.revision, 2, "a new round, so it is reviewed again");
        assert_eq!(two.provider_result.as_ref().unwrap()["engine"], "second");

        // The first provider's next revision is newer still.
        submit("back", 2, "third", 3);
        let three = contract_context(&route, &proposed).unwrap();
        assert_eq!((three.order_id.as_str(), three.revision), ("back", 3));
        assert_eq!(three.provider_result.as_ref().unwrap()["engine"], "third");
    }
}

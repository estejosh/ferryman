//! The engine policy: which AI engines, on which machines, may do a project's background
//! work, and in what order.
//!
//! ```text
//! <channel>/ENGINE_POLICY                      the master's signed policy, or their signed "auto"
//! <channel>/ADVERSARY_POLICY                   the master's own signed adversary policy
//! <channel>/improve/<week>/steps/<agent>.json  which engine on which machine did each improve
//!                                              step, signed by the agent that did it
//! ```
//!
//! # Why
//!
//! The improve loop and its orders run with nobody watching. Left to the operator's
//! engine order, a background loop happily spends someone's Claude or Codex subscription
//! limits - the ones they need on Thursday. The policy says, per project, which engines
//! each role of background work prefers, which it must never use, and which machines may
//! run it. With no policy set the fleet chooses for itself ("auto"): local and free
//! engines first, subscriptions never.
//!
//! # Background and direct work
//!
//! Background work is improvement orders (and their audit verifications) and the improve
//! loop's own planning and review. An order a person gives directly is theirs to spend
//! on: `protect_subscriptions` never touches it, and `never` does only when the policy
//! says `never_applies_to = "all"`.
//!
//! # No fallback
//!
//! When nothing the policy allows can do the work, the work waits. It never falls back to
//! a blocked engine. The loop records why, and asks the master once a week per role
//! (a signed question, with buttons on the phone).
//!
//! # Trust
//!
//! Exactly [`crate::ferry::SELF_IMPROVE`]'s: the file is honoured only when the project's
//! master signed it, by the key the channel knows them by, or their delegate did under an
//! `improve` delegation. Anything else - unsigned, edited, forged, lifted from another
//! project - is ignored, and the project runs on auto.
//!
//! # Rollback and deletion
//!
//! A signed file stays valid for ever, so an old one put back (or the file deleted, or
//! replaced with garbage) would quietly undo what the master chose since. Each signing
//! therefore carries a `seq` that is one more than the highest the signer could see, and
//! each machine keeps, outside the synced channel (in its own state directory), the
//! highest `seq` it has seen and the last good setting with its signature. A channel file
//! with a lower `seq`, or no verifying file at all, does not change what this machine
//! runs: it keeps using the last known good setting (re-verified every time) and raises
//! one question to the master ([`ask_rollback`]). Signing the policy again - from a
//! machine that has seen the newest - supersedes everything.
//!
//! A delegate's setting lasts as long as its delegation: when the delegation is revoked
//! or lapses, the setting stops verifying like any other unauthorised file. Delegation is
//! judged when the file is read, not when it was signed, because a signature-time check
//! would let a revoked delegate backdate a setting.
//!
//! # The adversary's policy is the master's alone
//!
//! The adversary is the check on the work, so nobody who could be checked - and a delegate
//! signing the engine policy can be - gets to choose, starve or switch it off. Everything
//! about it lives in its own file, `ADVERSARY_POLICY`: its mode, its engine preferences,
//! its own `never`, the agents allowed to judge, and its weekly cap
//! ([`AdversaryTerms`]). That file is honoured only when the master signed it with their
//! own key - no delegation - and is protected against rollback exactly like the engine
//! policy (its own `seq`, high-water mark and last known good, per machine).
//!
//! [`effective`] lays the adversary's terms over the engine policy, so the rest of the
//! code reads one [`Policy`]; but whatever an `ENGINE_POLICY` file says about the adversary
//! is dropped on the way in, the engine policy's `never`, `where` and caps do not apply to
//! the adversary ([`rank`] ranks it under its own `never` and no `where`), and
//! [`set_policy_as`] refuses a delegate any change to the adversary part.
//! A machine that does not know `ADVERSARY_POLICY` (v0.5.17) simply never runs the adversary.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AgentIdentity, ProjectRoute, SignatureCheck,
    receipts::{EngineReport, PRESENCE_ABSENT_AFTER_SECS},
};

/// The file, inside a channel, that holds the master's signed engine policy.
pub const ENGINE_POLICY: &str = "ENGINE_POLICY";

/// The file, inside a channel, that holds the master's signed adversary policy: the
/// adversary's mode, preferences, `never`, allowed agents and weekly cap. Only the master
/// signs it.
pub const ADVERSARY_POLICY: &str = "ADVERSARY_POLICY";
/// How long a free-tier engine that asked for money stays ranked down in auto mode.
pub const FLAG_DAYS: i64 = 7;
/// Engine inventories older than this are not counted as the fleet.
pub const INVENTORY_FRESH_HOURS: i64 = 24;
/// The answer that accepts the recommended policy.
pub const ACCEPT_RECOMMENDED: &str = "Accept recommended";
/// The answer that leaves held work waiting.
pub const KEEP_HOLDING: &str = "Keep holding";
/// Step records kept per agent per week.
const KEEP_STEPS: usize = 200;
/// Longest selector accepted.
const SELECTOR_CHARS: usize = 120;

/// A kind of background work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The improve loop turning evidence into a plan.
    Plan,
    /// Improvement orders at build tier, and audit verifications.
    Build,
    /// The improve loop judging a plan or a result.
    Review,
    /// Improvement orders at chore tier.
    Chore,
    /// The challenger: a judge-tier engine, never the one that built the work, that is
    /// asked to break it at three critical moments. See [`crate::adversary`].
    Adversary,
}

impl Role {
    pub const ALL: [Role; 5] = [
        Role::Plan,
        Role::Build,
        Role::Review,
        Role::Chore,
        Role::Adversary,
    ];

    /// The four roles that plan, build and judge. The adversary is deliberately left out
    /// wherever one preference is applied to "every role": the engine that builds is
    /// exactly the one that must not also be asked to challenge the build.
    pub const BUILDING: [Role; 4] = [Role::Plan, Role::Build, Role::Review, Role::Chore];

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plan" => Ok(Self::Plan),
            "build" => Ok(Self::Build),
            "review" => Ok(Self::Review),
            "chore" => Ok(Self::Chore),
            "adversary" => Ok(Self::Adversary),
            other => bail!("a role is plan, build, review, chore or adversary, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Build => "build",
            Self::Review => "review",
            Self::Chore => "chore",
            Self::Adversary => "adversary",
        }
    }

    /// The tier the role's work asks for.
    #[must_use]
    pub fn tier(self) -> &'static str {
        match self {
            Self::Plan | Self::Review | Self::Adversary => "judge",
            Self::Build => "build",
            Self::Chore => "chore",
        }
    }

    /// The role an order of this tier plays.
    #[must_use]
    pub fn for_order_tier(tier: &str) -> Self {
        if tier.eq_ignore_ascii_case("chore") {
            Self::Chore
        } else {
            Self::Build
        }
    }
}

/// Which work `never` applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NeverScope {
    /// Only background work: a person's own orders may still use any engine.
    #[default]
    Background,
    /// Every order, a person's own included.
    All,
}

/// What fm may merge on its own once an improvement holds both keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoMerge {
    /// Nothing: every approved improvement waits for the master to merge it.
    #[default]
    None,
    /// Docs, tests and dependency bumps only; anything touching code or config waits.
    LowRisk,
}

impl AutoMerge {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "none" | "off" | "no" | "false" => Ok(Self::None),
            "low-risk" | "lowrisk" | "on" | "yes" | "true" => Ok(Self::LowRisk),
            other => bail!("auto_merge is none or low-risk, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LowRisk => "low-risk",
        }
    }

    fn is_none(&self) -> bool {
        *self == Self::None
    }
}

/// What the adversary's findings do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdversaryMode {
    /// The adversary never runs.
    Off,
    /// It runs at its three moments and its findings are shown beside the decision they
    /// bear on; nothing waits for it, and a Block is a warning.
    #[default]
    Advisory,
    /// A Block stops the thing it challenges: the contract is not locked, the engine
    /// key is not granted, until the master signs an override.
    Blocking,
}

impl AdversaryMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "no" | "false" => Ok(Self::Off),
            "advisory" | "on" | "yes" | "true" => Ok(Self::Advisory),
            "blocking" | "block" => Ok(Self::Blocking),
            other => bail!("adversary is off, advisory or blocking, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Advisory => "advisory",
            Self::Blocking => "blocking",
        }
    }

    /// The default mode is left out of the signed JSON, so a policy signed before the
    /// adversary existed still verifies.
    fn is_advisory(&self) -> bool {
        *self == Self::Advisory
    }
}

/// Whether work is the fleet's own or a person's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Background,
    Direct,
}

fn yes() -> bool {
    true
}

/// How hard an engine is asked to think: the `{effort}` an engine's arguments may use,
/// the extra arguments it may declare per level, and the reasoning-effort field an HTTP
/// engine that supports one is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Low,
    Medium,
    High,
}

impl Effort {
    pub const ALL: [Effort; 3] = [Effort::Low, Effort::Medium, Effort::High];

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => bail!("effort is low, medium or high, not '{other}'"),
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

impl Role {
    /// The effort a role runs at when the policy names none: plan on high, build on
    /// medium, chores on low, and the judges - review and the adversary - on high.
    #[must_use]
    pub fn default_effort(self) -> Effort {
        match self {
            Self::Plan | Self::Review | Self::Adversary => Effort::High,
            Self::Build => Effort::Medium,
            Self::Chore => Effort::Low,
        }
    }
}

/// How big a model is, which is what decides what work it is worth spending on: a swarm
/// of small ones for chores, mid-size ones to build, a large one to plan and judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelClass {
    Small,
    Medium,
    Large,
}

impl ModelClass {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "small" => Ok(Self::Small),
            "medium" | "mid" => Ok(Self::Medium),
            "large" => Ok(Self::Large),
            other => bail!("class is small, medium or large, not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }
}

/// A model's size class, guessed from its name when nobody declared one.
///
/// A parameter count in the name decides first - `llama-3.1-8b` is small, `70b` and up is
/// large, in between is medium - and for a mixture-of-experts name that also gives the
/// active count (`...-120b-a12b`) the active count is the one used, since that is what
/// it costs to run. Without a size, a word decides: small for `haiku`, `mini`, `nano`,
/// `flash-lite` and `small`; large for `opus`, `pro`, `ultra`, `large`, `reasoner` and
/// `r1`; medium for everything else (`sonnet`, `flash`, `deepseek-chat`, `nemotron
/// super`). Whoever runs the engine can always say better: `engine.<name>.class`.
#[must_use]
pub fn guess_class(model: &str) -> ModelClass {
    let lower = model.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(['-', '_', '/', ':', ' ', '@'])
        .filter(|token| !token.is_empty())
        .collect();
    // `70b`, `1.5b`; and `a12b`, the active parameters of a mixture of experts.
    let billions = |token: &str, active: bool| -> Option<f64> {
        let digits = if active {
            token.strip_prefix('a')?
        } else {
            token
        };
        let digits = digits.strip_suffix('b')?;
        (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit() || c == '.'))
            .then(|| digits.parse::<f64>().ok())
            .flatten()
    };
    let size = tokens
        .iter()
        .find_map(|token| billions(token, true))
        .or_else(|| tokens.iter().find_map(|token| billions(token, false)));
    if let Some(size) = size {
        return if size < 10.0 {
            ModelClass::Small
        } else if size < 70.0 {
            ModelClass::Medium
        } else {
            ModelClass::Large
        };
    }
    let has = |word: &str| tokens.contains(&word);
    if has("haiku")
        || has("mini")
        || has("nano")
        || has("small")
        || lower.contains("flash-lite")
        || lower.contains("flash_lite")
    {
        ModelClass::Small
    } else if has("opus")
        || has("pro")
        || has("ultra")
        || has("large")
        || has("reasoner")
        || has("r1")
    {
        ModelClass::Large
    } else {
        ModelClass::Medium
    }
}

/// One project's engine policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Per role (`plan`, `build`, `review`, `chore`): selectors, most preferred first.
    /// Engines no selector matches come after, in auto order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub prefer: BTreeMap<String, Vec<String>>,
    /// Selectors that must never be used for background work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never: Vec<String>,
    /// Agents or machines allowed to run this project's self-improve work. Empty is any.
    #[serde(default, rename = "where", skip_serializing_if = "Vec::is_empty")]
    pub machines: Vec<String>,
    /// Per role: dollars the fleet may spend on it in one ISO week.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps_usd: BTreeMap<String, f64>,
    /// Never spend a subscription on background work.
    #[serde(default = "yes")]
    pub protect_subscriptions: bool,
    #[serde(default)]
    pub never_applies_to: NeverScope,
    /// What fm merges on its own after both keys: `none` (the default) or `low-risk`
    /// (docs, tests, dependency bumps). Left out of the signed JSON when `none`, so a
    /// policy signed before this existed still verifies.
    #[serde(default, skip_serializing_if = "AutoMerge::is_none")]
    pub auto_merge: AutoMerge,
    /// What the adversary's findings do: `off`, `advisory` (the default) or `blocking`.
    /// Left out of the signed JSON when advisory, like `auto_merge` when none.
    #[serde(default, skip_serializing_if = "AdversaryMode::is_advisory")]
    pub adversary: AdversaryMode,
    /// Selectors the adversary never uses, from the master's [`ADVERSARY_POLICY`]. Part of
    /// the policy as a screen or a command line edits it, never of the `ENGINE_POLICY`
    /// file: [`set_policy_as`] writes it to the master's own file, and anything the
    /// engine policy file carries here is dropped on reading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adversary_never: Vec<String>,
    /// The agents the master allows to judge, from the same file (see
    /// [`AdversaryTerms::agents`]); empty is any. Kept out of `ENGINE_POLICY` like
    /// [`Self::adversary_never`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adversary_agents: Vec<String>,
    /// Per role: how hard its engine is asked to think. A role left out runs at
    /// [`Role::default_effort`]. Left out of the signed JSON when empty, so a policy
    /// signed before this existed still verifies.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub effort: BTreeMap<Role, Effort>,
    /// Per role: the most improvement orders of that role the fleet has claimed at once
    /// (build and chore are the roles that claim orders). A role left out is not
    /// capped. Left out of the signed JSON when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub width: BTreeMap<Role, u8>,
    /// Roles whose background work may use a subscription despite
    /// `protect_subscriptions` - and only an engine that has a `weekly_requests` cap, so
    /// a swarm cannot drain it. Left out of the signed JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscription_roles: Vec<Role>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            prefer: BTreeMap::new(),
            never: Vec::new(),
            machines: Vec::new(),
            caps_usd: BTreeMap::new(),
            protect_subscriptions: true,
            never_applies_to: NeverScope::Background,
            auto_merge: AutoMerge::None,
            adversary: AdversaryMode::Advisory,
            adversary_never: Vec::new(),
            adversary_agents: Vec::new(),
            effort: BTreeMap::new(),
            width: BTreeMap::new(),
            subscription_roles: Vec::new(),
        }
    }
}

impl Policy {
    /// Refuse a policy with a role, selector or cap that means nothing.
    pub fn check(&self) -> Result<()> {
        for (role, list) in &self.prefer {
            Role::parse(role)?;
            for selector in list {
                check_selector(selector)?;
            }
        }
        for selector in self
            .never
            .iter()
            .chain(&self.machines)
            .chain(&self.adversary_never)
        {
            check_selector(selector)?;
        }
        self.adversary_terms().check()?;
        for (role, cap) in &self.caps_usd {
            Role::parse(role)?;
            if !cap.is_finite() || *cap < 0.0 {
                bail!("the {role} cap must be a dollar amount of zero or more");
            }
        }
        for (role, width) in &self.width {
            if *width == 0 {
                bail!(
                    "the {} width must be 1 or more; to stop a role, leave it no engine",
                    role.as_str()
                );
            }
        }
        Ok(())
    }

    /// How hard `role`'s engine is asked to think: the policy's word, else the default.
    #[must_use]
    pub fn effort_for(&self, role: Role) -> Effort {
        self.effort
            .get(&role)
            .copied()
            .unwrap_or_else(|| role.default_effort())
    }

    /// The most orders of `role` the fleet may have claimed at once, when capped.
    #[must_use]
    pub fn width_for(&self, role: Role) -> Option<u8> {
        self.width.get(&role).copied()
    }

    /// Whether the policy lets `role` use a subscription that is capped.
    #[must_use]
    pub fn subscriptions_for(&self, role: Role) -> bool {
        self.subscription_roles.contains(&role)
    }

    /// The role's preference list, empty when it has none.
    #[must_use]
    pub fn preferences(&self, role: Role) -> &[String] {
        self.prefer.get(role.as_str()).map_or(&[], Vec::as_slice)
    }

    /// Where the engine stands in the role's list: the first selector it matches.
    #[must_use]
    pub fn preference(&self, role: Role, engine: &Candidate) -> Option<usize> {
        self.preferences(role)
            .iter()
            .position(|selector| matches(selector, engine))
    }

    /// Why this engine may not do this work, or `None` when it may.
    #[must_use]
    pub fn blocked(&self, engine: &Candidate, work: Work) -> Option<String> {
        self.blocked_for(engine, work, None)
    }

    /// [`Self::blocked`] for work in `role`: `subscription_roles` lets a role use a
    /// subscription, but only one with a `weekly_requests` cap.
    #[must_use]
    pub fn blocked_for(
        &self,
        engine: &Candidate,
        work: Work,
        role: Option<Role>,
    ) -> Option<String> {
        if (work == Work::Background || self.never_applies_to == NeverScope::All)
            && let Some(selector) = self.never.iter().find(|s| matches(s, engine))
        {
            return Some(format!("never: matches '{selector}'"));
        }
        if work == Work::Background
            && self.protect_subscriptions
            && engine.paid_class() == "subscription"
        {
            if let Some(role) = role
                && self.subscriptions_for(role)
            {
                if engine.weekly_requests.is_some() {
                    return None;
                }
                return Some(format!(
                    "a subscription with no weekly_requests cap: subscription_roles lists {} \
                     but only an engine with a weekly cap may be used, so a swarm cannot \
                     drain it",
                    role.as_str()
                ));
            }
            return Some(if engine.paid == "subscription" {
                "a subscription, and protect_subscriptions is on".to_string()
            } else {
                format!(
                    "taken for a subscription ({} CLI with no paid= set), and \
                     protect_subscriptions is on",
                    engine.name
                )
            });
        }
        None
    }

    /// Whether this agent, on this machine, may run the project's self-improve work.
    #[must_use]
    pub fn allows_machine(&self, agent: &str, machine: &str) -> bool {
        self.machines.is_empty()
            || self
                .machines
                .iter()
                .any(|m| m.eq_ignore_ascii_case(agent) || m.eq_ignore_ascii_case(machine))
    }

    #[must_use]
    pub fn cap(&self, role: Role) -> Option<f64> {
        self.caps_usd.get(role.as_str()).copied()
    }

    /// Never use `engine` for background work. Returns whether anything changed.
    pub fn block(&mut self, engine: &str) -> bool {
        let selector = format!("name:{}", engine.trim().to_ascii_lowercase());
        for list in self.prefer.values_mut() {
            list.retain(|s| !s.eq_ignore_ascii_case(&selector));
        }
        if self.never.iter().any(|s| s.eq_ignore_ascii_case(&selector)) {
            return false;
        }
        self.never.push(selector);
        true
    }

    /// Put `engine` first for every role, and lift any `never` naming it exactly.
    pub fn move_to_top(&mut self, engine: &str) {
        let selector = format!("name:{}", engine.trim().to_ascii_lowercase());
        self.never.retain(|s| !s.eq_ignore_ascii_case(&selector));
        for role in Role::BUILDING {
            let list = self.prefer.entry(role.as_str().to_string()).or_default();
            list.retain(|s| !s.eq_ignore_ascii_case(&selector));
            list.insert(0, selector.clone());
        }
    }

    /// The simple choice: `selector` first for improvement work - planning and building.
    pub fn set_improvement_engine(&mut self, selector: &str) {
        for role in [Role::Plan, Role::Build] {
            self.prefer
                .insert(role.as_str().to_string(), vec![selector.trim().to_string()]);
        }
    }

    /// The simple choice: `selector` first for review.
    pub fn set_review_engine(&mut self, selector: &str) {
        self.prefer.insert(
            Role::Review.as_str().to_string(),
            vec![selector.trim().to_string()],
        );
    }

    /// What does improvement work first, when the policy says.
    #[must_use]
    pub fn improvement_engine(&self) -> Option<&str> {
        self.preferences(Role::Build).first().map(String::as_str)
    }

    /// What reviews first, when the policy says.
    #[must_use]
    pub fn review_engine(&self) -> Option<&str> {
        self.preferences(Role::Review).first().map(String::as_str)
    }

    /// The simple choice: `selector` first for the adversary.
    pub fn set_adversary_engine(&mut self, selector: &str) {
        self.prefer.insert(
            Role::Adversary.as_str().to_string(),
            vec![selector.trim().to_string()],
        );
    }

    /// What challenges first, when the policy says.
    #[must_use]
    pub fn adversary_engine(&self) -> Option<&str> {
        self.preferences(Role::Adversary)
            .first()
            .map(String::as_str)
    }

    /// One line per part, as a person reads it.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for role in Role::ALL {
            let list = self.preferences(role);
            if !list.is_empty() {
                lines.push(format!(
                    "prefer for {}: {}",
                    role.as_str(),
                    list.join(" > ")
                ));
            }
        }
        if !self.never.is_empty() {
            lines.push(format!("never: {}", self.never.join(", ")));
        }
        lines.push(format!(
            "where: {}",
            if self.machines.is_empty() {
                "any worker".to_string()
            } else {
                self.machines.join(", ")
            }
        ));
        for (role, cap) in &self.caps_usd {
            lines.push(format!("{role} capped at ${cap:.2} a week"));
        }
        lines.push(format!(
            "subscriptions {} for background work",
            if self.protect_subscriptions {
                "protected"
            } else {
                "allowed"
            }
        ));
        if !self.subscription_roles.is_empty() {
            lines.push(format!(
                "subscriptions allowed for {} - only an engine with a weekly_requests cap",
                self.subscription_roles
                    .iter()
                    .map(|role| role.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for role in Role::ALL {
            let effort = self.effort.get(&role);
            let width = self.width.get(&role);
            if effort.is_some() || width.is_some() {
                lines.push(format!(
                    "{}: effort {}{}",
                    role.as_str(),
                    self.effort_for(role).as_str(),
                    width.map_or(String::new(), |width| format!(", width {width}"))
                ));
            }
        }
        if self.never_applies_to == NeverScope::All {
            lines.push("never applies to people's own orders too".to_string());
        }
        lines.push(
            match self.auto_merge {
                AutoMerge::None => "auto-merge: none - you merge every approved improvement",
                AutoMerge::LowRisk => {
                    "auto-merge: docs, tests and dependency bumps after both approvals"
                }
            }
            .to_string(),
        );
        lines.push(
            match self.adversary {
                AdversaryMode::Off => "adversary: off - nothing challenges the work",
                AdversaryMode::Advisory => {
                    "adversary: advisory - a second model challenges the work at three moments; \
                     its findings are shown, nothing waits for it"
                }
                AdversaryMode::Blocking => {
                    "adversary: blocking - a Block finding stops a contract lock or the engine \
                     key until you override it"
                }
            }
            .to_string(),
        );
        if self.adversary != AdversaryMode::Off {
            lines.push(if self.adversary_agents.is_empty() {
                "adversary agents: any member whose signed inventory lists an engine the \
                 adversary may use (no allowlist)"
                    .to_string()
            } else {
                format!(
                    "adversary agents: {} only",
                    self.adversary_agents.join(", ")
                )
            });
        }
        if !self.adversary_never.is_empty() {
            lines.push(format!(
                "adversary never: {}",
                self.adversary_never.join(", ")
            ));
        }
        lines
    }
}

fn check_selector(selector: &str) -> Result<()> {
    let trimmed = selector.trim();
    if trimmed.is_empty() || trimmed.chars().count() > SELECTOR_CHARS {
        bail!("a selector must be 1 to {SELECTOR_CHARS} characters");
    }
    if let Some(class) = trimmed.strip_prefix("paid:")
        && !matches!(
            normal_paid(class).as_str(),
            "subscription" | "prepaid" | "free-tier" | "local" | "unknown"
        )
    {
        bail!("paid:{class} names no paid class (subscription, prepaid, free-tier, local)");
    }
    if let Some(class) = trimmed.strip_prefix("class:") {
        ModelClass::parse(class)?;
    }
    Ok(())
}

fn normal_paid(class: &str) -> String {
    match class.trim().to_ascii_lowercase().as_str() {
        "free" | "freetier" | "free_tier" => "free-tier".to_string(),
        other => other.to_string(),
    }
}

// --- engines, as the policy sees them --------------------------------------------------

/// One engine on one worker, as the policy matches and ranks it. Built from a worker's
/// signed inventory line, so every machine ranks the fleet the same way.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Candidate {
    pub agent: String,
    pub machine: String,
    /// Its place in the operator's list on that worker.
    pub order: usize,
    pub name: String,
    pub model: Option<String>,
    /// `judge`, `build` or `chore`, as configured.
    pub tier: String,
    /// `subscription`, `prepaid`, `free-tier`, `local` or `unknown`, as configured.
    pub paid: String,
    pub host: Option<String>,
    /// A weekly cap bounds it.
    pub capped: bool,
    /// Its weekly request cap, when one is set: the cap `subscription_roles` needs.
    pub weekly_requests: Option<u64>,
    /// The size class its worker published; `None` from a worker older than classes.
    pub class: Option<ModelClass>,
    /// `up`, `down`, `exhausted` or `unknown`.
    pub state: String,
    /// When an exhausted engine is expected back.
    pub until: Option<DateTime<Utc>>,
    pub verified: u64,
    pub refuted: u64,
    pub demoted: bool,
    /// Dollars spent this week.
    pub spend_usd: f64,
    /// Why a free tier is flagged, while it is.
    pub flag: Option<String>,
    /// For a gateway engine (OmniRoute): the provider/models its route ends at. A
    /// selector that names any of them matches, so `never claude` holds through it.
    pub route: Vec<String>,
    /// What it can do: what its worker published, else guessed from its name, kind and
    /// how it is paid (see [`crate::capability`]). Empty for a hand-built candidate.
    pub capabilities: crate::capability::Capabilities,
}

impl Candidate {
    #[must_use]
    pub fn from_report(agent: &str, machine: &str, order: usize, report: &EngineReport) -> Self {
        let trust = report.trust.clone().unwrap_or_default();
        let billing = report.billing.clone().unwrap_or_default();
        Self {
            capabilities: crate::capability::Capabilities::for_report(report).0,
            agent: agent.to_string(),
            machine: machine.to_string(),
            order,
            name: report.name.clone(),
            model: report.model.clone(),
            tier: report.tier.clone(),
            paid: report.paid.clone(),
            host: billing.host,
            capped: billing.capped,
            weekly_requests: billing.weekly_requests,
            class: report
                .class
                .as_deref()
                .and_then(|class| ModelClass::parse(class).ok()),
            state: report.state.clone(),
            until: report.until,
            verified: trust.verified,
            refuted: trust.refuted,
            demoted: trust.demoted,
            spend_usd: billing.spend_usd,
            flag: billing.flag,
            route: billing.route,
        }
    }

    /// How it is paid for, as the policy counts it: as configured - except that a
    /// `claude` or `codex` CLI with nothing configured is taken for the subscription it
    /// almost always is, so an unmarked Claude Code never quietly spends its limits in
    /// the background. Setting `paid` in agent.toml overrides this.
    #[must_use]
    pub fn paid_class(&self) -> &str {
        let unmarked_cli = self.paid == "unknown" && self.host.is_none();
        let name = self.name.to_ascii_lowercase();
        let model = self.model.as_deref().unwrap_or("").to_ascii_lowercase();
        if unmarked_cli
            && (name.starts_with("claude")
                || name.starts_with("codex")
                || model.starts_with("claude")
                || model.starts_with("anthropic/"))
        {
            return "subscription";
        }
        &self.paid
    }

    /// Its size class: the one its worker published (declared or guessed there), else
    /// guessed here from its model - or its name, with no model.
    #[must_use]
    pub fn class(&self) -> ModelClass {
        self.class
            .unwrap_or_else(|| guess_class(self.model.as_deref().unwrap_or(&self.name)))
    }

    /// The tier it may work at now: chore while demoted.
    fn level(&self) -> u8 {
        if self.demoted {
            0
        } else {
            tier_level(&self.tier)
        }
    }

    fn usable(&self) -> bool {
        self.state != "exhausted"
    }

    fn trust_score(&self) -> Option<u64> {
        let decided = self.verified + self.refuted;
        (decided > 0).then(|| self.verified * 100 / decided)
    }

    fn cost_per_verified(&self) -> Option<f64> {
        (self.verified > 0 && self.spend_usd > 0.0).then(|| self.spend_usd / self.verified as f64)
    }

    /// `nemotron on grouchly`
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} on {}", self.name, self.machine)
    }

    /// `free-tier, 12 verified, 0 refuted`
    #[must_use]
    pub fn facts(&self) -> String {
        let mut text = self.paid_class().to_string();
        if self.paid_class() == "prepaid" {
            text.push_str(if self.capped {
                " with a cap"
            } else {
                " with no cap"
            });
        }
        if self.paid_class() == "subscription" {
            match self.weekly_requests {
                Some(cap) => text.push_str(&format!(" with a weekly cap of {cap} requests")),
                None => text.push_str(" with no weekly request cap"),
            }
        }
        text.push_str(&format!(
            ", {} verified, {} refuted",
            self.verified, self.refuted
        ));
        if let Some(cost) = self.cost_per_verified() {
            text.push_str(&format!(", ${cost:.2} per verified result"));
        }
        if self.demoted {
            text.push_str(", demoted");
        }
        if let Some(flag) = &self.flag {
            text.push_str(&format!(", flagged: {flag}"));
        }
        text
    }
}

fn tier_level(tier: &str) -> u8 {
    match tier.trim().to_ascii_lowercase().as_str() {
        "chore" => 0,
        "judge" => 2,
        _ => 1,
    }
}

/// How auto mode ranks the way an engine is paid for, lowest first: local, free tier,
/// prepaid with a cap, unknown (and a free tier that asked for money), prepaid with no
/// cap, subscription.
#[must_use]
pub fn auto_rank(engine: &Candidate) -> u8 {
    match engine.paid_class() {
        "local" => 0,
        "free-tier" if engine.flag.is_none() => 1,
        "prepaid" if engine.capped => 2,
        "free-tier" | "unknown" => 3,
        "prepaid" => 4,
        _ => 5,
    }
}

// --- selectors ---------------------------------------------------------------------------

/// Whether a selector picks out this engine. Case never matters.
///
/// - `paid:free-tier` (also `paid:subscription`, `paid:prepaid`, `paid:local`,
///   `paid:unknown`): how it is paid for;
/// - `class:small` (also `class:medium`, `class:large`): its size class;
/// - `model:nvidia/nemotron*`: a model glob; `name:nemotron` (or `engine:`): the engine's
///   name in agent.toml, glob allowed; `host:deepseek.com` (or `provider:`): the endpoint
///   host or any subdomain of it;
/// - anything with `*`, `?` or `/` is a glob over the engine name and the model;
/// - a bare word matches an engine of that name, or one whose model or host contains it:
///   `claude` matches the `claude` engine and every `claude-*` model, `deepseek` matches
///   `api.deepseek.com`.
#[must_use]
pub fn matches(selector: &str, engine: &Candidate) -> bool {
    let selector = selector.trim().to_ascii_lowercase();
    let name = engine.name.to_ascii_lowercase();
    let model = engine.model.as_deref().unwrap_or("").to_ascii_lowercase();
    let host = engine.host.as_deref().unwrap_or("").to_ascii_lowercase();
    let (kind, pattern) = match selector.split_once(':') {
        Some((kind, rest))
            if matches!(
                kind,
                "paid" | "model" | "name" | "engine" | "host" | "provider" | "class"
            ) =>
        {
            (kind, rest.trim())
        }
        _ => ("", selector.as_str()),
    };
    if pattern.is_empty() {
        return false;
    }
    // A gateway's route: `cc/claude-sonnet-4-6`, `nvidia/nemotron-70b:free`.
    let route: Vec<String> = engine
        .route
        .iter()
        .map(|step| step.to_ascii_lowercase())
        .collect();
    let provider_of = |step: &String| step.split('/').next().unwrap_or_default().to_string();
    match kind {
        "paid" => normal_paid(pattern) == engine.paid_class(),
        "class" => ModelClass::parse(pattern).is_ok_and(|class| class == engine.class()),
        "model" => {
            (!model.is_empty() && glob(pattern, &model))
                || route.iter().any(|step| glob(pattern, step))
        }
        "name" | "engine" => glob(pattern, &name),
        "host" | "provider" => {
            (!host.is_empty() && (glob(pattern, &host) || host.ends_with(&format!(".{pattern}"))))
                || route.iter().any(|step| provider_of(step) == pattern)
        }
        _ if pattern.contains(['*', '?', '/']) => {
            glob(pattern, &name)
                || (!model.is_empty() && glob(pattern, &model))
                || route.iter().any(|step| glob(pattern, step))
        }
        _ => {
            name == pattern
                || model.contains(pattern)
                || host.contains(pattern)
                || route.iter().any(|step| step.contains(pattern))
        }
    }
}

/// `*` any run of characters, `?` any one; everything else literal.
#[must_use]
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((star_p, star_t)) = star {
            pi = star_p + 1;
            ti = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

// --- ranking -----------------------------------------------------------------------------

/// Every engine, sorted for one role: the ones that may do it now, the ones that may but
/// are out of credit, and the ones the policy blocks.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ranking {
    /// Indexes into the engines given, best first: allowed, able to do the role, usable.
    pub order: Vec<usize>,
    /// Allowed and able, but exhausted until a reset, with the reason.
    pub out: Vec<(usize, String)>,
    /// Blocked by the policy, with the reason.
    pub blocked: Vec<(usize, String)>,
}

impl Ranking {
    /// Why nothing can do the work, for a hold.
    #[must_use]
    pub fn why_none(&self, role: Role, engines: &[Candidate]) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (index, why) in self.out.iter().chain(&self.blocked) {
            parts.push(format!("{} {why}", engines[*index].label()));
        }
        if parts.is_empty() {
            format!("no engine able to do {} work is known", role.as_str())
        } else {
            format!(
                "no allowed engine can do {} work now - {}",
                role.as_str(),
                parts.join("; ")
            )
        }
    }
}

/// How far an engine at `level` is from the work, `None` when it cannot do it.
fn fit(role: Role, wanted: u8, level: u8) -> Option<u8> {
    match role {
        // Review is a judge's work, and only a judge's. So is challenging it.
        Role::Review | Role::Adversary => (level == 2).then_some(0),
        // A judge plans; a builder plans only when no judge can, marked unreviewed.
        Role::Plan => (level >= 1).then(|| 2 - level),
        // Never below the tier; the nearest tier first, so a judge builds last.
        Role::Build | Role::Chore => (level >= wanted).then(|| level - wanted),
    }
}

/// Rank `engines` for `role` at the order's `tier` under `policy`.
///
/// Blocked engines (`never`, subscriptions while protected, a machine outside `where`)
/// are set aside. The rest are grouped by the role's preference list - listed engines in
/// the listed order, then the unlisted in auto order - and within a group by the rules
/// engines always followed: the nearest tier, an engine that answered its probe before
/// one that did not, better trust, cheaper per verified result, then the operator's
/// order.
#[must_use]
pub fn rank(policy: &Policy, role: Role, tier: &str, work: Work, engines: &[Candidate]) -> Ranking {
    if role == Role::Adversary {
        // The adversary is ranked under its own `never` and no `where`: the engine
        // policy's cannot starve it.
        return rank_in(&policy.adversary_view(), role, tier, work, engines);
    }
    rank_in(policy, role, tier, work, engines)
}

fn rank_in(policy: &Policy, role: Role, tier: &str, work: Work, engines: &[Candidate]) -> Ranking {
    let wanted = tier_level(tier);
    let listed = policy.preferences(role).len();
    let mut ranking = Ranking::default();
    let mut keyed = Vec::new();
    for (index, engine) in engines.iter().enumerate() {
        let Some(distance) = fit(role, wanted, engine.level()) else {
            continue;
        };
        if work == Work::Background && !policy.allows_machine(&engine.agent, &engine.machine) {
            ranking.blocked.push((
                index,
                format!("is not in where ({})", policy.machines.join(", ")),
            ));
            continue;
        }
        if let Some(why) = policy.blocked_for(engine, work, Some(role)) {
            ranking.blocked.push((index, why));
            continue;
        }
        if !engine.usable() {
            ranking.out.push((
                index,
                match engine.until {
                    Some(until) => format!("is out until {}", until.format("%a %H:%M UTC")),
                    None => "is out of credit".to_string(),
                },
            ));
            continue;
        }
        // A plan a judge wrote needs no second reading, so among engines the operator
        // ranked alike a judge plans first, whatever it costs.
        let group = if work == Work::Background {
            (
                policy.preference(role, engine).unwrap_or(listed),
                if role == Role::Plan { distance } else { 0 },
                auto_rank(engine),
            )
        } else {
            (0, 0, 0)
        };
        let key = (
            group,
            distance,
            engine.state == "down",
            std::cmp::Reverse(engine.trust_score().unwrap_or(50)),
            // Cents per verified result; unknown sorts after known.
            engine
                .cost_per_verified()
                .map_or(u64::MAX, |cost| (cost * 100.0) as u64),
            engine.order,
        );
        keyed.push((key, index));
    }
    keyed.sort();
    ranking.order = keyed.into_iter().map(|(_, index)| index).collect();
    ranking
}

// --- the adversary: someone other than the builder --------------------------------------

/// The model families the adversary's diversity rule tells apart: keywords looked for in
/// an engine's model, its gateway route, its name, then its endpoint host - in that
/// order, because the model says whose weights answer and the host only who serves them.
const FAMILIES: &[(&str, &[&str])] = &[
    ("anthropic", &["claude", "anthropic"]),
    ("openai", &["gpt", "openai", "codex", "chatgpt"]),
    ("google", &["gemini", "gemma", "google"]),
    ("deepseek", &["deepseek"]),
    ("meta", &["llama"]),
    ("qwen", &["qwen", "alibaba", "dashscope"]),
    ("mistral", &["mistral", "mixtral", "codestral"]),
    ("nvidia", &["nemotron", "nvidia"]),
    ("xai", &["grok", "x.ai"]),
    ("zhipu", &["glm", "zhipu"]),
    ("moonshot", &["kimi", "moonshot"]),
];

/// The model family an engine belongs to: `anthropic`, `openai`, `deepseek`, ... or, for
/// one nothing recognises, its own name - so two unknown engines count as two families
/// and one engine is always its own.
#[must_use]
pub fn family_of(engine: &Candidate) -> String {
    let model = engine.model.as_deref().unwrap_or("").to_ascii_lowercase();
    let route = engine.route.join(" ").to_ascii_lowercase();
    let name = engine.name.to_ascii_lowercase();
    let host = engine.host.as_deref().unwrap_or("").to_ascii_lowercase();
    for source in [&model, &route, &name, &host] {
        if source.is_empty() {
            continue;
        }
        for (family, words) in FAMILIES {
            if words.iter().any(|word| source.contains(word)) {
                return (*family).to_string();
            }
        }
    }
    name
}

/// Which engine built the work under challenge, as its result's payload names it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Builder {
    pub engine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl Builder {
    /// The builder a result payload names (`engine`, and `model` when it recorded one).
    #[must_use]
    pub fn from_payload(payload: &serde_json::Value) -> Option<Self> {
        let engine = payload.get("engine")?.as_str()?.trim();
        (!engine.is_empty()).then(|| Self {
            engine: engine.to_string(),
            model: payload
                .get("model")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }

    /// The builder as a candidate, taking what the fleet knows of an engine by that name
    /// (its host, its route) so its family reads the way the adversary's does.
    #[must_use]
    pub fn candidate(&self, engines: &[Candidate]) -> Candidate {
        let mut found = engines
            .iter()
            .find(|engine| engine.name.eq_ignore_ascii_case(&self.engine))
            .cloned()
            .unwrap_or_default();
        found.name.clone_from(&self.engine);
        if self.model.is_some() {
            found.model.clone_from(&self.model);
        }
        found
    }

    /// Whether `engine` is the engine that built it: the same name, and the same model
    /// unless either side did not record one.
    #[must_use]
    pub fn is(&self, engine: &Candidate) -> bool {
        self.engine.eq_ignore_ascii_case(&engine.name)
            && match (&self.model, &engine.model) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => true,
            }
    }
}

/// The allowed adversaries for one piece of work, best first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Challengers {
    pub ranking: Ranking,
    /// Parallel to `ranking.order`: whether that engine is one that built the work. Only
    /// ever true for the last entries - an engine is used against its own work only when
    /// nothing else is allowed.
    pub same_engine: Vec<bool>,
    /// Parallel to `ranking.order`: whether that engine is of a builder's family.
    pub same_family: Vec<bool>,
}

/// Put the engines that did not build the work first, and among those the ones of a
/// different model family from every builder. Stable: within each group the policy's own
/// order stands. An engine that built the work is kept, last, rather than dropped, so a
/// fleet with exactly one allowed judge still gets its challenge - marked as the
/// builder's own.
#[must_use]
pub fn diversify(ranking: Ranking, built_by: &[Builder], engines: &[Candidate]) -> Challengers {
    let families: Vec<String> = built_by
        .iter()
        .map(|builder| family_of(&builder.candidate(engines)))
        .collect();
    let mut keyed: Vec<(bool, bool, usize)> = ranking
        .order
        .iter()
        .map(|index| {
            let engine = &engines[*index];
            let same_engine = built_by.iter().any(|builder| builder.is(engine));
            let same_family = families.contains(&family_of(engine));
            (same_engine, same_family, *index)
        })
        .collect();
    keyed.sort_by_key(|(same_engine, same_family, _)| (*same_engine, *same_family));
    Challengers {
        same_engine: keyed.iter().map(|k| k.0).collect(),
        same_family: keyed.iter().map(|k| k.1).collect(),
        ranking: Ranking {
            order: keyed.into_iter().map(|k| k.2).collect(),
            ..ranking
        },
    }
}

/// Rank `engines` for the adversary's work on something `built_by` built: the same rules
/// as any background work (`never`, protected subscriptions, `where`, the role's
/// preference list and caps) - then the diversity rule of [`diversify`].
#[must_use]
pub fn rank_adversary(policy: &Policy, built_by: &[Builder], engines: &[Candidate]) -> Challengers {
    diversify(
        rank(
            policy,
            Role::Adversary,
            Role::Adversary.tier(),
            Work::Background,
            engines,
        ),
        built_by,
        engines,
    )
}

/// The policy as it falls on the fleet: per role, who does the work in which order and
/// who is out of credit; and every engine the policy blocks, with why. For the
/// dashboard and `--json`.
#[must_use]
pub fn view(policy: &Policy, engines: &[Candidate]) -> serde_json::Value {
    let describe = |engine: &Candidate| {
        serde_json::json!({
            "engine": engine.name,
            "agent": engine.agent,
            "machine": engine.machine,
            "model": engine.model,
            "paid": engine.paid_class(),
            "class": engine.class().as_str(),
            "weekly_requests": engine.weekly_requests,
            "facts": engine.facts(),
        })
    };
    let mut roles = serde_json::Map::new();
    let mut blocked: Vec<serde_json::Value> = Vec::new();
    let mut seen = BTreeSet::new();
    for role in Role::ALL {
        let ranking = rank(policy, role, role.tier(), Work::Background, engines);
        roles.insert(
            role.as_str().to_string(),
            serde_json::json!({
                "effort": policy.effort_for(role).as_str(),
                "effort_set": policy.effort.contains_key(&role),
                "width": policy.width_for(role),
                "subscriptions": policy.subscriptions_for(role),
                "order": ranking.order.iter().map(|i| describe(&engines[*i])).collect::<Vec<_>>(),
                "out": ranking.out.iter().map(|(i, why)| {
                    let mut line = describe(&engines[*i]);
                    line["why"] = serde_json::json!(why);
                    line
                }).collect::<Vec<_>>(),
            }),
        );
        for (index, why) in ranking.blocked {
            if seen.insert(engines[index].label()) {
                let mut line = describe(&engines[index]);
                line["why"] = serde_json::json!(why);
                blocked.push(line);
            }
        }
    }
    serde_json::json!({ "roles": roles, "blocked": blocked })
}

/// What a person picks from: every engine the fleet published that can improve (plan
/// and build) or review, once each by name, with how it is paid for, the machines it is
/// on, whether the policy blocks it, and whether it is what auto recommends. The value
/// to set is the selector `name:<engine>`.
#[must_use]
pub fn choices(policy: &Policy, engines: &[Candidate], recommended: &Policy) -> serde_json::Value {
    let option = |engine: &Candidate, recommend: Option<&str>| {
        let selector = format!("name:{}", engine.name.to_ascii_lowercase());
        let machines: Vec<String> = engines
            .iter()
            .filter(|other| other.name.eq_ignore_ascii_case(&engine.name))
            .map(|other| other.machine.clone())
            .collect();
        serde_json::json!({
            "selector": selector,
            "label": label(engine),
            "paid": engine.paid_class(),
            "class": engine.class().as_str(),
            "weekly_requests": engine.weekly_requests,
            "machines": machines,
            "blocked": policy.blocked(engine, Work::Background),
            "recommended": recommend.is_some_and(|chosen| chosen.eq_ignore_ascii_case(&selector)),
        })
    };
    let mut improve = Vec::new();
    let mut review = Vec::new();
    let mut adversary = Vec::new();
    let mut seen = BTreeSet::new();
    for engine in engines {
        if !seen.insert(engine.name.to_ascii_lowercase()) {
            continue;
        }
        if engine.level() >= 1 {
            improve.push(option(engine, recommended.improvement_engine()));
        }
        if engine.level() == 2 {
            review.push(option(engine, recommended.review_engine()));
            adversary.push(option(engine, recommended.adversary_engine()));
        }
    }
    serde_json::json!({
        "improve": improve,
        "review": review,
        "adversary": adversary,
        "current": {
            "improve": policy.improvement_engine(),
            "review": policy.review_engine(),
            "adversary": policy.adversary_engine(),
            "adversary_mode": policy.adversary.as_str(),
        },
        "recommended": {
            "improve": recommended.improvement_engine(),
            "review": recommended.review_engine(),
            "adversary": recommended.adversary_engine(),
        },
    })
}

/// How a person reads an engine: `nemotron (nvidia/nemotron-70b)`, or for a gateway
/// route `OmniRoute: free-stack`.
#[must_use]
pub fn label(engine: &Candidate) -> String {
    match (&engine.model, engine.route.is_empty()) {
        (Some(model), false) => format!("OmniRoute: {model}"),
        (Some(model), true) => format!("{} ({model})", engine.name),
        (None, _) => engine.name.clone(),
    }
}

/// [`view`] as lines a person reads: one per role, one per blocked engine.
#[must_use]
pub fn summary(policy: &Policy, engines: &[Candidate]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut blocked: Vec<String> = Vec::new();
    for role in Role::ALL {
        let ranking = rank(policy, role, role.tier(), Work::Background, engines);
        let order: Vec<String> = ranking
            .order
            .iter()
            .map(|index| engines[*index].label())
            .collect();
        let mut line = format!(
            "{:<7}{}",
            role.as_str(),
            if order.is_empty() {
                "nothing allowed can do it now - it waits".to_string()
            } else {
                order.join(" > ")
            }
        );
        if !ranking.out.is_empty() {
            let out: Vec<String> = ranking
                .out
                .iter()
                .map(|(index, why)| format!("{} {why}", engines[*index].label()))
                .collect();
            line.push_str(&format!(" (also allowed: {})", out.join(", ")));
        }
        lines.push(line);
        for (index, why) in ranking.blocked {
            let text = format!("blocked {}: {why}", engines[index].label());
            if !blocked.contains(&text) {
                blocked.push(text);
            }
        }
    }
    lines.extend(blocked);
    lines
}

// --- auto: the policy the fleet would choose ---------------------------------------------

/// A proposed policy, with one line of reason per choice.
#[derive(Debug, Clone, PartialEq)]
pub struct Recommendation {
    pub policy: Policy,
    pub reasons: Vec<String>,
}

fn ordinal(rank: usize) -> String {
    match rank {
        0 => "first".to_string(),
        1 => "second".to_string(),
        2 => "third".to_string(),
        n => format!("#{}", n + 1),
    }
}

/// What auto mode would choose, from the engines the fleet published and the workers
/// that are online now.
///
/// For each role the allowed engines in auto order - local, free tier, capped prepaid,
/// unknown, uncapped prepaid; subscriptions never while protected - with ties broken by
/// trust, then cost per verified result, then the operator's order; plan and review
/// prefer a judge-tier engine. An engine that is out of credit today still has its
/// place: the recommendation is a standing order, not today's weather. `where` is the
/// workers online now and not paused.
#[must_use]
pub fn recommend(engines: &[Candidate], online: &[String]) -> Recommendation {
    let merged = merge_engines(engines);
    let base = Policy::default();
    let mut policy = Policy::default();
    let mut reasons = Vec::new();
    for role in Role::BUILDING {
        let ranking = rank(&base, role, role.tier(), Work::Background, &merged);
        let list: Vec<String> = ranking
            .order
            .iter()
            .map(|index| format!("name:{}", merged[*index].name.to_ascii_lowercase()))
            .collect();
        for (place, index) in ranking.order.iter().enumerate() {
            let engine = &merged[*index];
            let judge = if matches!(role, Role::Plan | Role::Review) && engine.tier == "judge" {
                "judge tier, "
            } else {
                ""
            };
            reasons.push(format!(
                "{} {} for {}: {judge}{}",
                engine.name,
                ordinal(place),
                role.as_str(),
                engine.facts()
            ));
        }
        if list.is_empty() {
            reasons.push(format!(
                "nothing for {}: no allowed engine can do it, so it would wait",
                role.as_str()
            ));
        } else {
            policy.prefer.insert(role.as_str().to_string(), list);
        }
    }
    // The adversary: judge tier, the best record, and - the point of it - not the family
    // of the engine that builds first, so the challenger does not share the builder's
    // blind spots.
    let top_build: Vec<Builder> = rank(
        &base,
        Role::Build,
        Role::Build.tier(),
        Work::Background,
        &merged,
    )
    .order
    .first()
    .map(|index| Builder {
        engine: merged[*index].name.clone(),
        model: merged[*index].model.clone(),
    })
    .into_iter()
    .collect();
    let challengers = diversify(
        rank(
            &base,
            Role::Adversary,
            Role::Adversary.tier(),
            Work::Background,
            &merged,
        ),
        &top_build,
        &merged,
    );
    let mut adversaries = Vec::new();
    for (place, index) in challengers.ranking.order.iter().enumerate() {
        let engine = &merged[*index];
        adversaries.push(format!("name:{}", engine.name.to_ascii_lowercase()));
        let versus = match top_build.first() {
            None => String::new(),
            Some(builder) if challengers.same_engine[place] => {
                format!(
                    "the same engine as {}, the top build engine - used only when nothing \
                     else is allowed, ",
                    builder.engine
                )
            }
            Some(builder) if challengers.same_family[place] => format!(
                "the same family ({}) as {}, the top build engine, ",
                family_of(engine),
                builder.engine
            ),
            Some(builder) => format!(
                "a different family ({}) from {}, the top build engine, ",
                family_of(engine),
                builder.engine
            ),
        };
        reasons.push(format!(
            "{} {} for adversary: judge tier, {versus}{}",
            engine.name,
            ordinal(place),
            engine.facts()
        ));
    }
    if adversaries.is_empty() {
        reasons.push(
            "nothing for adversary: no allowed judge-tier engine, so nothing would challenge \
             the work"
                .to_string(),
        );
    } else {
        policy
            .prefer
            .insert(Role::Adversary.as_str().to_string(), adversaries);
    }
    let mut blocked = BTreeSet::new();
    for engine in &merged {
        if let Some(why) = base.blocked(engine, Work::Background)
            && blocked.insert(engine.name.to_ascii_lowercase())
        {
            reasons.push(format!("{} never for background work: {why}", engine.name));
        }
    }
    policy.machines = online_machines(online, &mut reasons);
    Recommendation { policy, reasons }
}

/// One entry per engine name: the same engine on two machines is one choice, and its
/// record is the two machines' together. A subscription is capped only when it is on
/// every machine that has it.
fn merge_engines(engines: &[Candidate]) -> Vec<Candidate> {
    let mut merged: Vec<Candidate> = Vec::new();
    for engine in engines {
        match merged
            .iter_mut()
            .find(|seen| seen.name.eq_ignore_ascii_case(&engine.name))
        {
            Some(seen) => {
                seen.verified += engine.verified;
                seen.refuted += engine.refuted;
                seen.spend_usd += engine.spend_usd;
                seen.demoted &= engine.demoted;
                seen.flag = seen.flag.take().or_else(|| engine.flag.clone());
                seen.capped &= engine.capped;
                seen.weekly_requests = seen
                    .weekly_requests
                    .zip(engine.weekly_requests)
                    .map(|(a, b)| a.min(b));
            }
            None => {
                let mut first = engine.clone();
                first.state = "up".to_string();
                first.until = None;
                merged.push(first);
            }
        }
    }
    merged
}

/// The workers online now, once each, with the line that says so.
fn online_machines(online: &[String], reasons: &mut Vec<String>) -> Vec<String> {
    let mut machines: Vec<String> = Vec::new();
    for agent in online {
        if !machines.iter().any(|m| m.eq_ignore_ascii_case(agent)) {
            machines.push(agent.clone());
        }
    }
    if machines.is_empty() {
        reasons.push("where: any worker (none is online now to choose from)".to_string());
    } else {
        reasons.push(format!(
            "where: {} - online now and not paused",
            machines.join(", ")
        ));
    }
    machines
}

// --- the team preset ----------------------------------------------------------------------

/// What a person asks of the team preset beyond its defaults.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TeamOptions {
    /// Roles whose background work may use a capped subscription.
    pub subscription_roles: Vec<Role>,
    /// Widths that replace the preset's (plan 1, build 3, chore 4).
    pub width: BTreeMap<Role, u8>,
    /// Efforts that replace the preset's (plan, review and adversary high, build medium,
    /// chore low).
    pub effort: BTreeMap<Role, Effort>,
}

/// The size classes a role looks for, best fit first: a large model plans, judges and
/// challenges; a mid-size one builds; a small one does chores. Whatever is left after the
/// fit follows, so a fleet without the ideal engine still has someone to ask.
fn class_order(role: Role) -> [ModelClass; 3] {
    match role {
        Role::Plan | Role::Review | Role::Adversary => {
            [ModelClass::Large, ModelClass::Medium, ModelClass::Small]
        }
        Role::Build => [ModelClass::Medium, ModelClass::Large, ModelClass::Small],
        Role::Chore => [ModelClass::Small, ModelClass::Medium, ModelClass::Large],
    }
}

fn class_place(role: Role, engine: &Candidate) -> usize {
    class_order(role)
        .iter()
        .position(|class| *class == engine.class())
        .unwrap_or(2)
}

/// "Plan on high, build on medium, swarm the cheap work": a recommended policy built from
/// the engines the fleet published.
///
/// - plan: a large judge-tier engine, high effort, one at a time;
/// - build: mid-size engines, medium effort, three orders at once;
/// - chore: the smallest engines, low effort, four at once;
/// - review: a large judge, high effort;
/// - adversary: a large judge of a different model family from the engine that builds
///   first, high effort, advisory.
///
/// Within a size class the order is [`recommend`]'s: local, free, capped prepaid, then
/// the rest, with trust and cost per verified result breaking ties, and subscriptions
/// never while `protect_subscriptions` holds - except for the roles in
/// `options.subscription_roles`, and then only an engine with a `weekly_requests` cap. An
/// engine of the wrong size is kept after the right ones, as the fallback.
#[must_use]
pub fn team(engines: &[Candidate], online: &[String], options: &TeamOptions) -> Recommendation {
    let merged = merge_engines(engines);
    let mut policy = Policy::default();
    for role in &options.subscription_roles {
        if !policy.subscription_roles.contains(role) {
            policy.subscription_roles.push(*role);
        }
    }
    policy.subscription_roles.sort();
    for role in Role::ALL {
        policy.effort.insert(
            role,
            options
                .effort
                .get(&role)
                .copied()
                .unwrap_or_else(|| role.default_effort()),
        );
    }
    for (role, width) in [(Role::Plan, 1), (Role::Build, 3), (Role::Chore, 4)] {
        policy.width.insert(role, width);
    }
    for (role, width) in &options.width {
        policy.width.insert(*role, *width);
    }
    let mut reasons = Vec::new();
    let mut build_first: Option<Builder> = None;
    for role in [Role::Plan, Role::Build, Role::Review, Role::Chore] {
        let ranking = rank(&policy, role, role.tier(), Work::Background, &merged);
        let mut order: Vec<usize> = ranking.order.clone();
        // A judge plans before anything else does, whatever its size; then the size that
        // fits, then the ranking the engines always followed.
        order.sort_by_key(|index| {
            let engine = &merged[*index];
            (
                matches!(role, Role::Plan | Role::Review) && engine.level() < 2,
                class_place(role, engine),
            )
        });
        let list: Vec<String> = order
            .iter()
            .map(|index| format!("name:{}", merged[*index].name.to_ascii_lowercase()))
            .collect();
        let effort = policy.effort_for(role);
        for (place, index) in order.iter().enumerate() {
            let engine = &merged[*index];
            let fits = class_place(role, engine) == 0;
            let judge = if matches!(role, Role::Plan | Role::Review) && engine.level() == 2 {
                ", judge tier"
            } else {
                ""
            };
            reasons.push(format!(
                "{} {} for {}: {} class{judge}{}, {} effort, {}",
                engine.name,
                ordinal(place),
                role.as_str(),
                engine.class().as_str(),
                if fits {
                    String::new()
                } else {
                    format!(" (not {}: the fallback)", class_order(role)[0].as_str())
                },
                effort.as_str(),
                engine.facts()
            ));
        }
        if role == Role::Build {
            build_first = order.first().map(|index| Builder {
                engine: merged[*index].name.clone(),
                model: merged[*index].model.clone(),
            });
        }
        if list.is_empty() {
            reasons.push(format!(
                "nothing for {}: no allowed engine can do it, so it would wait",
                role.as_str()
            ));
        } else {
            policy.prefer.insert(role.as_str().to_string(), list);
        }
    }
    // The adversary: a large judge, and - the point of it - not the family of the engine
    // that builds first.
    let top_build: Vec<Builder> = build_first.into_iter().collect();
    let challengers = diversify(
        rank(
            &policy,
            Role::Adversary,
            Role::Adversary.tier(),
            Work::Background,
            &merged,
        ),
        &top_build,
        &merged,
    );
    let mut keyed: Vec<(bool, bool, usize, usize)> = challengers
        .ranking
        .order
        .iter()
        .enumerate()
        .map(|(place, index)| {
            (
                challengers.same_engine[place],
                challengers.same_family[place],
                class_place(Role::Adversary, &merged[*index]),
                *index,
            )
        })
        .collect();
    keyed.sort_by_key(|(same_engine, same_family, class, _)| (*same_engine, *same_family, *class));
    let mut adversaries = Vec::new();
    for (place, (same_engine, same_family, _, index)) in keyed.iter().enumerate() {
        let engine = &merged[*index];
        adversaries.push(format!("name:{}", engine.name.to_ascii_lowercase()));
        let versus = match top_build.first() {
            None => String::new(),
            Some(builder) if *same_engine => format!(
                "the same engine as {}, the top build engine - used only when nothing else \
                 is allowed, ",
                builder.engine
            ),
            Some(builder) if *same_family => format!(
                "the same family ({}) as {}, the top build engine, ",
                family_of(engine),
                builder.engine
            ),
            Some(builder) => format!(
                "a different family ({}) from {}, the top build engine, ",
                family_of(engine),
                builder.engine
            ),
        };
        reasons.push(format!(
            "{} {} for adversary: {} class, judge tier, {versus}{} effort, {}",
            engine.name,
            ordinal(place),
            engine.class().as_str(),
            policy.effort_for(Role::Adversary).as_str(),
            engine.facts()
        ));
    }
    if adversaries.is_empty() {
        reasons.push(
            "nothing for adversary: no allowed judge-tier engine, so nothing would challenge \
             the work"
                .to_string(),
        );
    } else {
        policy
            .prefer
            .insert(Role::Adversary.as_str().to_string(), adversaries);
    }
    for role in [Role::Plan, Role::Build, Role::Chore] {
        if let Some(width) = policy.width_for(role) {
            reasons.push(format!(
                "{}: up to {width} at once across the fleet",
                role.as_str()
            ));
        }
    }
    // What the subscription opt-in did and did not reach.
    let mut named = BTreeSet::new();
    for engine in &merged {
        if engine.paid_class() != "subscription" {
            continue;
        }
        for role in &policy.subscription_roles {
            if let Some(why) = policy.blocked_for(engine, Work::Background, Some(*role))
                && named.insert((engine.name.to_ascii_lowercase(), *role))
            {
                reasons.push(format!(
                    "{} not used for {}: {why}",
                    engine.name,
                    role.as_str()
                ));
            }
        }
    }
    let mut blocked = BTreeSet::new();
    for engine in &merged {
        let used = policy
            .prefer
            .values()
            .any(|list| list.contains(&format!("name:{}", engine.name.to_ascii_lowercase())));
        if !used
            && let Some(why) = policy.blocked(engine, Work::Background)
            && blocked.insert(engine.name.to_ascii_lowercase())
        {
            reasons.push(format!("{} never for background work: {why}", engine.name));
        }
    }
    policy.machines = online_machines(online, &mut reasons);
    Recommendation { policy, reasons }
}

/// The team preset for one project, from its channel.
#[must_use]
pub fn team_for(route: &ProjectRoute, now: DateTime<Utc>, options: &TeamOptions) -> Recommendation {
    team(&fleet(route, now), &online(route, now), options)
}

/// Warnings for the roles `policy.subscription_roles` opens to subscriptions: a
/// subscription engine with no `weekly_requests` cap stays blocked (a swarm could drain
/// it), and a role that lists the opt-in while the fleet has no capped subscription gets
/// nothing from it. One line each, for the CLI, the dashboard and the phone.
#[must_use]
pub fn subscription_warnings(policy: &Policy, engines: &[Candidate]) -> Vec<String> {
    if policy.subscription_roles.is_empty() {
        return Vec::new();
    }
    let merged = merge_engines(engines);
    let roles: Vec<&str> = policy
        .subscription_roles
        .iter()
        .map(|role| role.as_str())
        .collect();
    let roles = roles.join(", ");
    let mut lines = Vec::new();
    let mut capped = false;
    for engine in &merged {
        if engine.paid_class() != "subscription" {
            continue;
        }
        if engine.weekly_requests.is_some() {
            capped = true;
        } else {
            lines.push(format!(
                "{} is a subscription with no weekly_requests cap, so it stays out of {roles}: \
                 set weekly_requests on its engine in agent.toml to let a swarm use it",
                engine.name
            ));
        }
    }
    if !capped {
        lines.push(format!(
            "subscription_roles lists {roles}, but no subscription engine with a weekly_requests \
             cap is published, so it changes nothing yet"
        ));
    }
    lines
}

// --- width: how many orders at once -------------------------------------------------------

/// The tag every improvement order carries.
pub const IMPROVEMENT_TAG: &str = "improvement";

fn is_improvement_order(order: &crate::Order) -> bool {
    order
        .payload
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(IMPROVEMENT_TAG)))
}

/// The role an improvement order's work is done in: chore for a chore-tier order,
/// otherwise build.
#[must_use]
pub fn order_role(order: &crate::Order) -> Role {
    Role::for_order_tier(
        order
            .payload
            .get("tier")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("build"),
    )
}

/// How many improvement orders are claimed right now, per role, by anyone: a claim whose
/// holder's heartbeat has lapsed (stale) is not being worked on, so it is not counted.
/// Only orders whose signature and authority verify count, as for file overlap: a forged
/// or unsigned order must not be able to use up the width and keep real work waiting.
#[must_use]
pub fn claimed_per_role(route: &ProjectRoute, tasks: &[crate::Task]) -> BTreeMap<Role, usize> {
    let mut counts = BTreeMap::new();
    for task in tasks {
        if is_improvement_order(&task.order)
            && matches!(task.state(), crate::TaskState::Claimed { .. })
            && crate::verify_order_in(route, &task.order) == SignatureCheck::Valid
        {
            *counts.entry(order_role(&task.order)).or_insert(0) += 1;
        }
    }
    counts
}

/// Why a worker should not claim `order` yet: it is an improvement order, and the fleet
/// already has the policy's `width` for its role claimed. `None` when it may be claimed,
/// including whenever the role has no width.
///
/// Counted from `tasks` as read now, so an order this same worker claimed a moment ago
/// in the same pass counts. Like the file-overlap check it is a soft cap: two machines
/// claiming in the same instant can each get in.
#[must_use]
pub fn width_hold(
    route: &ProjectRoute,
    policy: &Policy,
    tasks: &[crate::Task],
    order: &crate::Order,
) -> Option<String> {
    if !is_improvement_order(order) {
        return None;
    }
    let role = order_role(order);
    let width = policy.width_for(role)?;
    let claimed = claimed_per_role(route, tasks)
        .get(&role)
        .copied()
        .unwrap_or(0);
    (claimed >= usize::from(width)).then(|| {
        format!(
            "the policy's width for {} is {width}, and that many are claimed already",
            role.as_str()
        )
    })
}

/// [`width_hold`] for a project, read from its channel.
#[must_use]
pub fn width_hold_in(route: &ProjectRoute, order: &crate::Order) -> Option<String> {
    if !is_improvement_order(order) {
        return None;
    }
    let (policy, _) = effective(&route.communications, &route.project_id);
    policy.width_for(order_role(order))?;
    let tasks = crate::list_tasks(route).ok()?;
    width_hold(route, &policy, &tasks, order)
}

/// One line per role as a person reads it: how hard it thinks, how many at once, and
/// the class of the engine first in line.
#[must_use]
pub fn role_lines(policy: &Policy, engines: &[Candidate]) -> Vec<String> {
    Role::ALL
        .iter()
        .map(|role| {
            let first = rank(policy, *role, role.tier(), Work::Background, engines)
                .order
                .first()
                .map(|index| &engines[*index]);
            format!(
                "{:<10}effort {}{}, width {}, {}",
                role.as_str(),
                policy.effort_for(*role).as_str(),
                if policy.effort.contains_key(role) {
                    ""
                } else {
                    " (default)"
                },
                policy
                    .width_for(*role)
                    .map_or("unlimited".to_string(), |width| width.to_string()),
                first.map_or("no engine can do it now".to_string(), |engine| format!(
                    "first: {} ({} class)",
                    engine.name,
                    engine.class().as_str()
                )),
            )
        })
        .collect()
}

/// Every engine the fleet published into this channel: valid, signed inventories no
/// older than [`INVENTORY_FRESH_HOURS`].
#[must_use]
pub fn fleet(route: &ProjectRoute, now: DateTime<Utc>) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (inventory, check) in crate::receipts::list_engines(route).unwrap_or_default() {
        if check != SignatureCheck::Valid
            || now.signed_duration_since(inventory.updated_at)
                > Duration::hours(INVENTORY_FRESH_HOURS)
        {
            continue;
        }
        for (order, report) in inventory.engines.iter().enumerate() {
            out.push(Candidate::from_report(
                &inventory.agent,
                &inventory.machine,
                order,
                report,
            ));
        }
    }
    out
}

/// Workers seen lately in this channel and not paused: the machines that are on.
#[must_use]
pub fn online(route: &ProjectRoute, now: DateTime<Utc>) -> Vec<String> {
    crate::receipts::list_presence(route)
        .unwrap_or_default()
        .into_iter()
        .filter(|(presence, check)| {
            *check == SignatureCheck::Valid
                && !presence.paused
                && now.signed_duration_since(presence.seen_at)
                    <= Duration::seconds(PRESENCE_ABSENT_AFTER_SECS)
        })
        .map(|(presence, _)| presence.agent)
        .collect()
}

/// The recommendation for one project, from its channel.
#[must_use]
pub fn recommend_for(route: &ProjectRoute, now: DateTime<Utc>) -> Recommendation {
    recommend(&fleet(route, now), &online(route, now))
}

// --- the master's signed setting ---------------------------------------------------------

/// What the [`ENGINE_POLICY`] file holds.
///
/// A v0.5.17 machine reads this file too, and must not lose the master's `never`,
/// `machines` and `prefer` because the file also says things it has never heard of. So the
/// file carries two views of one signing. The v1 view - `policy` as that release knows it,
/// no `seq` - is what `signature` covers and what an old machine verifies and obeys. The
/// full policy and the sequence number are covered by `signature_v2`; a policy that has
/// anything the old view lacks carries the full one in `policy_v2`, and a machine that
/// understands it reads that and requires `signature_v2` to verify.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "SettingWire", into = "SettingWire")]
pub struct PolicySetting {
    pub project_id: String,
    /// `None`: the master chose auto. The whole policy, whatever the file's `policy` holds.
    pub policy: Option<Policy>,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    /// Over the v1 view: [`setting_payload`].
    pub signature: String,
    /// Whose policy this is, when a delegate signed it. Honoured only under a valid
    /// `improve` delegation from the master.
    pub on_behalf_of: Option<String>,
    /// One more than the highest `seq` the signer saw when signing, so a machine can tell
    /// an older signed policy put back from a newer one. Left out of the file when 0, and
    /// never part of the v1 view, so a policy signed before this existed still verifies.
    pub seq: u64,
    /// Over the full setting, `seq` included: [`setting_payload_v2`]. Absent on a policy
    /// signed by a release that has no v2, which is read as the v1 view it is - unless it
    /// has `seq` or anything else the v1 view lacks, which then cannot be taken without it.
    pub signature_v2: Option<String>,
}

/// The file as written: `policy` is the v1 view, `policy_v2` the whole policy when the
/// two differ.
#[derive(Serialize, Deserialize)]
struct SettingWire {
    project_id: String,
    #[serde(default)]
    policy: Option<Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_v2: Option<Policy>,
    set_at: DateTime<Utc>,
    signed_by: String,
    signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    on_behalf_of: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature_v2: Option<String>,
}

impl From<PolicySetting> for SettingWire {
    fn from(setting: PolicySetting) -> Self {
        let policy_v2 = setting.policy.clone().filter(|policy| !policy.is_v1_only());
        Self {
            project_id: setting.project_id,
            policy: setting.policy.as_ref().map(Policy::v1),
            policy_v2,
            set_at: setting.set_at,
            signed_by: setting.signed_by,
            signature: setting.signature,
            on_behalf_of: setting.on_behalf_of,
            seq: setting.seq,
            signature_v2: setting.signature_v2,
        }
    }
}

impl From<SettingWire> for PolicySetting {
    fn from(wire: SettingWire) -> Self {
        Self {
            project_id: wire.project_id,
            policy: wire.policy_v2.or(wire.policy),
            set_at: wire.set_at,
            signed_by: wire.signed_by,
            signature: wire.signature,
            on_behalf_of: wire.on_behalf_of,
            seq: wire.seq,
            signature_v2: wire.signature_v2,
        }
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// A policy as v0.5.17 had it, field for field: what its signature covers. A field added
/// since is not in here, so it is not in the v1 signature however it is serialised.
#[derive(Serialize)]
struct PolicyV1<'a> {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    prefer: &'a BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    never: &'a Vec<String>,
    #[serde(rename = "where", skip_serializing_if = "Vec::is_empty")]
    machines: &'a Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    caps_usd: &'a BTreeMap<String, f64>,
    protect_subscriptions: bool,
    never_applies_to: NeverScope,
    #[serde(skip_serializing_if = "AutoMerge::is_none")]
    auto_merge: AutoMerge,
}

impl Policy {
    /// This policy as v0.5.17 can use it: what that release's [`PolicyV1`] has, with the
    /// parts it would refuse taken out - the adversary role (a key in `prefer` and
    /// `caps_usd` it cannot parse) and `class:` selectors - because a policy that fails its
    /// own check is ignored whole, and then it would lose `never`, `machines` and the rest.
    #[must_use]
    pub fn v1(&self) -> Policy {
        let known = |selector: &String| !selector.trim().starts_with("class:");
        let mut view = Policy {
            adversary: AdversaryMode::Advisory,
            adversary_never: Vec::new(),
            adversary_agents: Vec::new(),
            effort: BTreeMap::new(),
            width: BTreeMap::new(),
            subscription_roles: Vec::new(),
            ..self.clone()
        };
        view.prefer.remove(Role::Adversary.as_str());
        view.caps_usd.remove(Role::Adversary.as_str());
        for list in view.prefer.values_mut() {
            list.retain(known);
        }
        view.never.retain(known);
        view.machines.retain(known);
        view
    }

    /// The canonical JSON a v0.5.17 machine computes for this policy.
    fn v1_json(&self) -> String {
        let view = self.v1();
        serde_jcs::to_string(&PolicyV1 {
            prefer: &view.prefer,
            never: &view.never,
            machines: &view.machines,
            caps_usd: &view.caps_usd,
            protect_subscriptions: view.protect_subscriptions,
            never_applies_to: view.never_applies_to,
            auto_merge: view.auto_merge,
        })
        .unwrap_or_default()
    }

    /// Whether the v1 view says all there is to say: nothing here that v0.5.17 would not
    /// see, so the v1 signature covers it.
    fn is_v1_only(&self) -> bool {
        serde_jcs::to_string(self).is_ok_and(|full| full == self.v1_json())
    }
}

impl PolicySetting {
    /// `josh`, or `josh via telegram-grouchly`.
    #[must_use]
    pub fn set_by(&self) -> String {
        match &self.on_behalf_of {
            Some(principal) => crate::delegation::label(principal, &self.signed_by),
            None => self.signed_by.clone(),
        }
    }
}

/// Exactly what `signature` covers, byte for byte what v0.5.17 computes: the project, when,
/// the policy's v1 view in canonical JSON (`null` for auto), and for a delegate the
/// principal. No `seq`, and nothing a v0.5.17 policy does not have.
fn setting_payload(setting: &PolicySetting) -> String {
    let policy = match &setting.policy {
        Some(policy) => policy.v1_json(),
        None => "null".to_string(),
    };
    let mut payload = format!(
        "ferryman-engine-policy-v1\n{}\n{}\n{}",
        setting.project_id,
        setting.set_at.to_rfc3339(),
        policy
    );
    if let Some(principal) = &setting.on_behalf_of {
        payload.push_str(&format!("\nfor:{principal}"));
    }
    payload
}

/// What `signature_v2` covers: [`setting_payload`] but with the whole policy and, when
/// non-zero, the sequence number.
fn setting_payload_v2(setting: &PolicySetting) -> String {
    let mut payload = format!(
        "ferryman-engine-policy-v2\n{}\n{}\n{}",
        setting.project_id,
        setting.set_at.to_rfc3339(),
        serde_jcs::to_string(&setting.policy).unwrap_or_default()
    );
    if let Some(principal) = &setting.on_behalf_of {
        payload.push_str(&format!("\nfor:{principal}"));
    }
    if setting.seq != 0 {
        payload.push_str(&format!("\nseq:{}", setting.seq));
    }
    payload
}

impl PolicySetting {
    /// Whether the v1 signature leaves something out that a machine must not take on the
    /// file's word: a sequence number, or any part of the policy the v1 view lacks.
    fn needs_v2(&self) -> bool {
        self.seq != 0
            || self
                .policy
                .as_ref()
                .is_some_and(|policy| !policy.is_v1_only())
    }

    /// Whether the signatures hold: the v1 one always; the v2 one whenever the file has
    /// it, and it must when [`Self::needs_v2`]. So stripping `signature_v2` off a setting
    /// that carries `seq` or a Blocking adversary cannot turn it into a plain one.
    fn signed_validly(&self, roster: &[crate::AgentRoute]) -> bool {
        let valid = |signature: Option<&String>, payload: String| {
            crate::check_signature(Some(&self.signed_by), signature, &payload, roster)
                == SignatureCheck::Valid
        };
        valid(Some(&self.signature), setting_payload(self))
            && match &self.signature_v2 {
                Some(signature) => valid(Some(signature), setting_payload_v2(self)),
                None => !self.needs_v2(),
            }
    }

    /// Sign both views as `signer`.
    fn sign(&mut self, signer: &AgentIdentity) {
        self.signature = signer.sign_bytes(setting_payload(self).as_bytes());
        self.signature_v2 = Some(signer.sign_bytes(setting_payload_v2(self).as_bytes()));
    }
}

// --- the adversary's own policy -----------------------------------------------------------

/// What the master decides about the adversary, and nobody else: whether it runs and what
/// its findings do, which engines it prefers or never uses, which agents may judge, and
/// what it may spend a week. Kept out of the engine policy - which a delegate can sign -
/// so the one who could be checked cannot choose, starve or switch off the check.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AdversaryTerms {
    #[serde(default)]
    pub mode: AdversaryMode,
    /// Selectors, most preferred first: which engine challenges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefer: Vec<String>,
    /// Selectors the adversary never uses. The engine policy's `never` does not apply to
    /// it, so a delegate cannot starve it with one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never: Vec<String>,
    /// The agents whose word counts as an adversary's. Empty: any member whose signed
    /// engine inventory lists an engine the preferences allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
    /// Dollars the adversary may spend in one ISO week; the engine policy's caps do not
    /// apply to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_usd: Option<f64>,
}

impl AdversaryTerms {
    /// Refuse terms with a selector, agent or cap that means nothing.
    pub fn check(&self) -> Result<()> {
        for selector in self.prefer.iter().chain(&self.never) {
            check_selector(selector)?;
        }
        if self.agents.len() > 64 {
            bail!("at most 64 adversary agents can be named");
        }
        for agent in &self.agents {
            if !crate::is_safe_component(agent) {
                bail!("an adversary agent is a path-safe agent name, not '{agent}'");
            }
        }
        if let Some(cap) = self.cap_usd
            && (!cap.is_finite() || cap < 0.0)
        {
            bail!("the adversary cap must be a dollar amount of zero or more");
        }
        Ok(())
    }
}

/// The master's signed adversary policy: the file `ADVERSARY_POLICY`. Honoured only when
/// the master signed it with their own key - there is no delegation for it - and then
/// protected against rollback exactly as the engine policy is, by a `seq` and this
/// machine's own memory of the highest it has seen and the last good one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdversarySetting {
    pub project_id: String,
    pub terms: AdversaryTerms,
    pub set_at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
    /// One more than the highest `seq` the master saw when signing.
    pub seq: u64,
}

impl AdversarySetting {
    /// Exactly what `signature` covers.
    fn payload(&self) -> String {
        format!(
            "ferryman-adversary-policy-v1\n{}\n{}\n{}\nseq:{}",
            self.project_id,
            self.set_at.to_rfc3339(),
            serde_jcs::to_string(&self.terms).unwrap_or_default(),
            self.seq
        )
    }

    fn sign(&mut self, signer: &AgentIdentity) {
        self.signature = signer.sign_bytes(self.payload().as_bytes());
    }

    /// Whether this is the master's own word for `project_id` in `channel`: signed by the
    /// master's key, over exactly what it says. A delegate's signature is not enough.
    fn genuine(&self, channel: &Path, project_id: &str) -> bool {
        let Ok(roster) = crate::read_agent_roster(channel) else {
            return false;
        };
        let Ok(Some(master)) = crate::master::read_master_at(channel, &roster) else {
            return false;
        };
        self.project_id == project_id
            && master.project_id == project_id
            && self.seq >= 1
            && self.signed_by.eq_ignore_ascii_case(&master.master)
            && self.terms.check().is_ok()
            && crate::check_signature(
                Some(&self.signed_by),
                Some(&self.signature),
                &self.payload(),
                &roster,
            ) == SignatureCheck::Valid
    }
}

impl Policy {
    /// The adversary's terms as this (composed) policy carries them.
    #[must_use]
    pub fn adversary_terms(&self) -> AdversaryTerms {
        AdversaryTerms {
            mode: self.adversary,
            prefer: self.preferences(Role::Adversary).to_vec(),
            never: self.adversary_never.clone(),
            agents: self.adversary_agents.clone(),
            cap_usd: self.cap(Role::Adversary),
        }
    }

    /// The engine policy proper: everything about the adversary taken out.
    #[must_use]
    pub fn without_adversary(&self) -> Policy {
        let mut policy = self.clone();
        policy.adversary = AdversaryMode::Advisory;
        policy.adversary_never.clear();
        policy.adversary_agents.clear();
        policy.prefer.remove(Role::Adversary.as_str());
        policy.caps_usd.remove(Role::Adversary.as_str());
        policy
    }

    /// This policy with the adversary's `terms` laid over it, whatever it had.
    #[must_use]
    pub fn with_adversary(mut self, terms: &AdversaryTerms) -> Policy {
        self = self.without_adversary();
        self.adversary = terms.mode;
        self.adversary_never.clone_from(&terms.never);
        self.adversary_agents.clone_from(&terms.agents);
        if !terms.prefer.is_empty() {
            self.prefer
                .insert(Role::Adversary.as_str().to_string(), terms.prefer.clone());
        }
        if let Some(cap) = terms.cap_usd {
            self.caps_usd
                .insert(Role::Adversary.as_str().to_string(), cap);
        }
        self
    }

    /// This policy with the adversary part of `in_force` instead of its own: what a
    /// delegate may sign, since the adversary's terms are the master's alone.
    #[must_use]
    pub fn keeping_adversary_of(&self, in_force: &Policy) -> Policy {
        self.clone().with_adversary(&in_force.adversary_terms())
    }

    /// Whether the master lets the adversary use `engine`: it is not one the adversary's
    /// own `never` names.
    #[must_use]
    pub fn adversary_allows(&self, engine: &Candidate) -> bool {
        !self.adversary_never.iter().any(|s| matches(s, engine))
    }

    /// Whether `engine` matches the adversary's preference selectors; with none named,
    /// every engine does.
    #[must_use]
    pub fn adversary_prefers(&self, engine: &Candidate) -> bool {
        let prefer = self.preferences(Role::Adversary);
        prefer.is_empty() || prefer.iter().any(|s| matches(s, engine))
    }

    /// The policy the adversary is ranked and capped under: its own `never`, and no
    /// `where` - the engine policy's `never` and `where` cannot starve it.
    fn adversary_view(&self) -> Policy {
        Policy {
            never: self.adversary_never.clone(),
            machines: Vec::new(),
            ..self.clone()
        }
    }
}

/// The file's setting as parsed, genuine or not.
#[cfg(test)]
fn read_file_setting(channel: &Path) -> Option<PolicySetting> {
    serde_json::from_slice(&std::fs::read(channel.join(ENGINE_POLICY)).ok()?).ok()
}

/// Whether `setting` is the master's word for `project_id` in `channel`: signed by them or
/// by a delegate holding `improve` now, over exactly what it says.
fn genuine(channel: &Path, project_id: &str, setting: &PolicySetting) -> bool {
    let Ok(roster) = crate::read_agent_roster(channel) else {
        return false;
    };
    let Ok(Some(master)) = crate::master::read_master_at(channel, &roster) else {
        return false;
    };
    let principal = setting
        .on_behalf_of
        .clone()
        .unwrap_or_else(|| setting.signed_by.clone());
    setting.project_id == project_id
        && master.project_id == project_id
        && principal.eq_ignore_ascii_case(&master.master)
        && setting
            .policy
            .as_ref()
            .is_none_or(|policy| policy.check().is_ok())
        && crate::delegation::authority(
            channel,
            project_id,
            &principal,
            &setting.signed_by,
            crate::delegation::IMPROVE,
            Utc::now(),
        )
        .allowed()
        && setting.signed_validly(&roster)
}

/// A signed file this machine tracks for rollback: the engine policy and the adversary
/// policy are each one, with their own file, `seq` and memory.
trait Signed: Clone + PartialEq + Serialize + serde::de::DeserializeOwned {
    /// The file inside the channel.
    const FILE: &'static str;
    /// This machine's state directory for it.
    const STATE: &'static str;
    /// What it is called in a notice.
    const LABEL: &'static str;
    /// The question id stem the master is asked under.
    const QUESTION: &'static str;
    fn seq(&self) -> u64;
    fn set_at(&self) -> DateTime<Utc>;
    /// Whether it is the master's word for `project_id` in `channel`.
    fn is_genuine(&self, channel: &Path, project_id: &str) -> bool;
}

impl Signed for PolicySetting {
    const FILE: &'static str = ENGINE_POLICY;
    const STATE: &'static str = "engine-policy";
    const LABEL: &'static str = "engine policy";
    const QUESTION: &'static str = "engine-policy";
    fn seq(&self) -> u64 {
        self.seq
    }
    fn set_at(&self) -> DateTime<Utc> {
        self.set_at
    }
    fn is_genuine(&self, channel: &Path, project_id: &str) -> bool {
        genuine(channel, project_id, self)
    }
}

impl Signed for AdversarySetting {
    const FILE: &'static str = ADVERSARY_POLICY;
    const STATE: &'static str = "adversary-policy";
    const LABEL: &'static str = "adversary policy";
    const QUESTION: &'static str = "adversary-policy";
    fn seq(&self) -> u64 {
        self.seq
    }
    fn set_at(&self) -> DateTime<Utc> {
        self.set_at
    }
    fn is_genuine(&self, channel: &Path, project_id: &str) -> bool {
        self.genuine(channel, project_id)
    }
}

/// What this machine remembers of a project's policy, in its own state directory: never
/// in the synced channel, so nobody who can write the channel can edit it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Seen<T> {
    /// The highest `seq` this machine has accepted.
    high: u64,
    /// The last good setting, with its signature; verified again whenever it is used.
    setting: Option<T>,
    /// What went wrong with the channel's file, until it is put right.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alert: Option<String>,
}

fn seen_path<T: Signed>(channel: &Path, project_id: &str) -> Option<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let dir = crate::licensing::machine_state_dir()?.join(T::STATE);
    let channel = std::fs::canonicalize(channel).unwrap_or_else(|_| channel.to_path_buf());
    let key = hex::encode(Sha256::digest(
        format!("{}\n{project_id}", channel.display()).as_bytes(),
    ));
    Some(dir.join(format!("{}.json", &key[..24])))
}

fn read_seen<T: Signed>(path: &Path) -> Option<Seen<T>> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Best effort: a machine that cannot remember simply has no rollback protection.
fn write_seen<T: Signed>(path: &Path, seen: &Seen<T>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = crate::atomic_json(path, seen);
}

/// The setting in force and how it was reached.
struct Resolved<T> {
    setting: Option<T>,
    /// The setting is this machine's memory of an earlier one, because the channel's file
    /// went back or is gone.
    from_memory: bool,
    /// The highest `seq` seen, here or in the channel.
    high: u64,
}

fn resolve<T: Signed>(channel: &Path, project_id: &str) -> Resolved<T> {
    let file = std::fs::read(channel.join(T::FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<T>(&bytes).ok())
        .filter(|setting| setting.is_genuine(channel, project_id));
    let file_seq = file.as_ref().map_or(0, Signed::seq);
    let path = seen_path::<T>(channel, project_id);
    let Some(memory) = path.as_deref().and_then(read_seen::<T>) else {
        if let (Some(file), Some(path)) = (&file, &path) {
            write_seen(
                path,
                &Seen {
                    high: file.seq(),
                    setting: Some(file.clone()),
                    alert: None,
                },
            );
        }
        return Resolved {
            setting: file,
            from_memory: false,
            high: file_seq,
        };
    };
    let good = memory
        .setting
        .clone()
        .filter(|setting| setting.is_genuine(channel, project_id));
    let high = memory.high.max(file_seq);
    let remember = |seen: Seen<T>| {
        if let Some(path) = &path
            && seen != memory
        {
            write_seen(path, &seen);
        }
    };
    match file {
        Some(file)
            if file.seq() > memory.high
                || (file.seq() == memory.high
                    && good
                        .as_ref()
                        .is_none_or(|good| *good == file || file.set_at() >= good.set_at())) =>
        {
            remember(Seen {
                high: file.seq(),
                setting: Some(file.clone()),
                alert: None,
            });
            Resolved {
                setting: Some(file),
                from_memory: false,
                high,
            }
        }
        Some(file) => {
            remember(Seen {
                high: memory.high,
                setting: memory.setting.clone(),
                alert: Some(format!(
                    "the channel's {} is at sequence {} but this machine has already seen \
                     sequence {}: an older signed one was put back",
                    T::LABEL,
                    file.seq(),
                    memory.high
                )),
            });
            Resolved {
                from_memory: good.is_some(),
                setting: good.or(Some(file)),
                high,
            }
        }
        None if good.is_some() => {
            remember(Seen {
                high: memory.high,
                setting: memory.setting.clone(),
                alert: Some(format!(
                    "the channel's {} is gone or no longer verifies",
                    T::LABEL
                )),
            });
            Resolved {
                setting: good,
                from_memory: true,
                high,
            }
        }
        None => Resolved {
            setting: None,
            from_memory: false,
            high,
        },
    }
}

/// The master's engine policy setting for the project in `channel`, when there is one
/// and it verifies. Anything else is `None`, which means auto - unless this machine has
/// seen a newer one before, in which case that last known good setting stays in force
/// (see the module documentation on rollback and deletion).
///
/// The setting's policy is the engine policy proper: whatever a file carries about the
/// adversary is dropped here, because the adversary's terms come only from
/// [`adversary_setting`].
#[must_use]
pub fn setting(channel: &Path, project_id: &str) -> Option<PolicySetting> {
    resolve::<PolicySetting>(channel, project_id)
        .setting
        .map(|mut setting| {
            setting.policy = setting.policy.map(|policy| policy.without_adversary());
            setting
        })
}

/// The master's own adversary policy for the project in `channel`, when there is one and
/// it verifies - signed by the master, never by a delegate. `None` means the defaults
/// (advisory, auto choice, no allowlist, no cap) - unless this machine has seen a newer
/// one, in which case the last known good one stays in force.
#[must_use]
pub fn adversary_setting(channel: &Path, project_id: &str) -> Option<AdversarySetting> {
    resolve::<AdversarySetting>(channel, project_id).setting
}

/// What is wrong with the channel's engine policy or adversary policy, when this machine
/// is holding on to an earlier one because the file went back, vanished or stopped
/// verifying.
#[must_use]
pub fn rollback_notice(channel: &Path, project_id: &str) -> Option<String> {
    let notices: Vec<String> = [
        notice::<PolicySetting>(channel, project_id),
        notice::<AdversarySetting>(channel, project_id),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!notices.is_empty()).then(|| notices.join("; "))
}

fn notice<T: Signed>(channel: &Path, project_id: &str) -> Option<String> {
    resolve::<T>(channel, project_id);
    read_seen::<T>(&seen_path::<T>(channel, project_id)?)?.alert
}

/// Ask the master, once per sequence number however many machines notice, what to do
/// about a policy that went back or vanished. Returns whether it was asked now; `false`
/// when nothing is wrong or the question already exists. Re-signing the policy (`ferry
/// engines policy set`, or the dashboard) is the answer: it carries a newer `seq`. The
/// engine policy and the adversary policy are asked about separately.
pub fn ask_rollback(route: &ProjectRoute, identity: &AgentIdentity) -> Result<bool> {
    let engine = ask_rollback_of::<PolicySetting>(route, identity)?;
    let adversary = ask_rollback_of::<AdversarySetting>(route, identity)?;
    Ok(engine || adversary)
}

fn ask_rollback_of<T: Signed>(route: &ProjectRoute, identity: &AgentIdentity) -> Result<bool> {
    let Some(notice) = notice::<T>(&route.communications, &route.project_id) else {
        return Ok(false);
    };
    let high = resolve::<T>(&route.communications, &route.project_id).high;
    crate::questions::ask(
        route,
        identity,
        &format!("{}-rollback-{high}", T::QUESTION),
        crate::questions::POLICY,
        &format!(
            "{}'s {} looks wrong: {notice}. This machine keeps using the last one you \
             signed. If you did not do this, find who can write the channel; to settle it, \
             sign it again as the master (dashboard Teammates page, or `ferry engines \
             policy set`).",
            route.project_id,
            T::LABEL
        ),
        &["Understood".to_string()],
        None,
    )
}

/// The policy in force for a project: the master's engine policy with the master's
/// adversary policy laid over it, or auto's defaults where they set none, chose auto, or
/// the file does not verify. With the engine policy's setting, when there is one.
///
/// The adversary part - mode, engine preferences, `never`, allowed agents, cap - is only
/// ever the master's own adversary policy: nothing in the engine policy reaches it.
#[must_use]
pub fn effective(channel: &Path, project_id: &str) -> (Policy, Option<PolicySetting>) {
    let setting = setting(channel, project_id);
    let terms = adversary_setting(channel, project_id)
        .map(|adversary| adversary.terms)
        .unwrap_or_default();
    (
        setting
            .as_ref()
            .and_then(|setting| setting.policy.clone())
            .unwrap_or_default()
            .with_adversary(&terms),
        setting,
    )
}

/// A warning for a mixed fleet: the policy in force is a v1-only file - signed by v0.5.17,
/// with no sequence number and no v2 signature - while a member that signs v2 is on the
/// roster (its signed inventory carries a v2 signature). Such a file has no rollback
/// protection beyond what each machine saw first, and cannot carry the newer parts; signing
/// it again from a current `ferry` fixes both. `None` when the policy is auto, has a v2
/// signature, or nobody here signs v2.
#[must_use]
pub fn mixed_fleet_warning(route: &ProjectRoute) -> Option<String> {
    let setting = setting(&route.communications, &route.project_id)?;
    if setting.signature_v2.is_some() {
        return None;
    }
    let mut capable: Vec<String> = crate::receipts::list_engines(route)
        .unwrap_or_default()
        .into_iter()
        .filter(|(inventory, check)| {
            *check == SignatureCheck::Valid && inventory.signature_v2.is_some()
        })
        .map(|(inventory, _)| inventory.agent)
        .collect();
    capable.sort();
    capable.dedup();
    if capable.is_empty() {
        return None;
    }
    Some(format!(
        "the engine policy in force is a v1-only file (signed by v0.5.17: no sequence number, \
         no v2 signature) and {} run a release that signs v2. A v1-only file has no rollback \
         protection - an older signed policy can be put back and a machine with nothing \
         remembered takes it - and cannot carry effort, width or the newer parts. Sign it \
         again from a current ferry (`ferry engines policy set`, or the dashboard) once the \
         fleet is upgraded; see \"Mixed fleets and what a fresh machine trusts\" in \
         docs/ENGINE_SETUP.md",
        capable.join(", ")
    ))
}

/// Whether the master has set a policy of their own (not auto) for the project.
#[must_use]
pub fn is_set(channel: &Path, project_id: &str) -> bool {
    setting(channel, project_id).is_some_and(|setting| setting.policy.is_some())
}

/// Set the project's engine policy, signed by its master. `None` goes back to auto.
/// Returns whether anything changed.
///
/// The adversary part of `policy` is not part of the engine policy: when it differs from
/// what is in force it is written as the master's [`ADVERSARY_POLICY`], which only the
/// master can sign.
pub fn set_policy(
    channel: &Path,
    project_id: &str,
    policy: Option<Policy>,
    signer: &AgentIdentity,
) -> Result<bool> {
    set_policy_as(channel, project_id, policy, signer, None)
}

/// [`set_policy`], signed by a delegate for `on_behalf_of`, who must be the master and
/// must have delegated `improve` to the signer. `None` is the signer's own. A delegate
/// signs the engine policy only: a `policy` whose adversary part differs from the one in
/// force is refused, because that needs the master's own signature.
pub fn set_policy_as(
    channel: &Path,
    project_id: &str,
    policy: Option<Policy>,
    signer: &AgentIdentity,
    on_behalf_of: Option<&str>,
) -> Result<bool> {
    if !channel.is_dir() {
        bail!(
            "{project_id}'s channel is not on this machine ({})",
            channel.display()
        );
    }
    if let Some(policy) = &policy {
        policy.check()?;
    }
    let on_behalf_of =
        on_behalf_of.filter(|principal| !principal.eq_ignore_ascii_case(signer.name()));
    match on_behalf_of {
        None => crate::ferry::require_master(channel, project_id, signer, "set the engine policy")?,
        Some(principal) => {
            let Some(master) = crate::ferry::master_of(channel)? else {
                bail!("{project_id} has no master, and only its master sets the engine policy");
            };
            if !principal.eq_ignore_ascii_case(&master) {
                bail!(
                    "only {master}, {project_id}'s master, sets the engine policy - not {principal}"
                );
            }
            if let crate::delegation::Authority::Refused(why) = crate::delegation::authority(
                channel,
                project_id,
                principal,
                signer.name(),
                crate::delegation::IMPROVE,
                Utc::now(),
            ) {
                bail!(
                    "{} cannot set the engine policy for {principal}: {why}",
                    signer.name()
                );
            }
        }
    }
    let resolved = resolve::<PolicySetting>(channel, project_id);
    let adversary = resolve::<AdversarySetting>(channel, project_id);
    let adversary_in_force = adversary
        .setting
        .as_ref()
        .map(|setting| setting.terms.clone())
        .unwrap_or_default();
    // `None` is auto for the engine policy and leaves the adversary's terms alone.
    let adversary_next = policy.as_ref().map(Policy::adversary_terms);
    if let (Some(principal), Some(next)) = (on_behalf_of, &adversary_next)
        && let Some(why) = adversary_change(&adversary_in_force, next)
    {
        bail!(
            "{} signs for {principal} as a delegate, and {why}: that needs {principal}'s own \
             signature",
            signer.name()
        );
    }
    let mut changed = false;
    // Only the master writes the adversary's terms - and when the channel's file is not the
    // one in force (it went back, or is gone), signing the same terms again repairs it.
    if on_behalf_of.is_none()
        && let Some(next) =
            adversary_next.filter(|next| *next != adversary_in_force || adversary.from_memory)
    {
        let seq = adversary
            .high
            .max(adversary.setting.as_ref().map_or(0, |setting| setting.seq))
            + 1;
        let mut written = AdversarySetting {
            project_id: project_id.to_owned(),
            terms: next,
            set_at: Utc::now(),
            signed_by: signer.name().to_owned(),
            signature: String::new(),
            seq,
        };
        written.sign(signer);
        let path = channel.join(ADVERSARY_POLICY);
        crate::atomic_json(&path, &written)
            .with_context(|| format!("writing {}", path.display()))?;
        changed = true;
    }
    // The engine policy proper: nothing about the adversary in it.
    let policy = policy.map(|policy| policy.without_adversary());
    // Unchanged - unless the channel's file is not the setting in force (it went back, or
    // is gone), or is a v1-only file signed by v0.5.17 (no sequence number, no v2
    // signature): signing the same policy again is what repairs or upgrades it.
    if !resolved.from_memory
        && resolved.setting.as_ref().is_some_and(|existing| {
            existing.signature_v2.is_some()
                && existing.policy.clone().map(|p| p.without_adversary()) == policy
        })
    {
        return Ok(changed);
    }
    let seq = resolved
        .high
        .max(resolved.setting.as_ref().map_or(0, |setting| setting.seq))
        + 1;
    let mut setting = PolicySetting {
        project_id: project_id.to_owned(),
        policy,
        set_at: Utc::now(),
        signed_by: signer.name().to_owned(),
        signature: String::new(),
        on_behalf_of: on_behalf_of.map(str::to_owned),
        seq,
        signature_v2: None,
    };
    setting.sign(signer);
    let path = channel.join(ENGINE_POLICY);
    crate::atomic_json(&path, &setting).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

// --- who did each step --------------------------------------------------------------------

/// One improve step, as the agent that did it records it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    /// `gather`, `plan`, `review` or `build`.
    pub step: String,
    /// The policy role it was done under, when it used an engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub at: DateTime<Utc>,
    pub agent: String,
    pub machine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Dollars, where known: what the provider reported, else list prices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// The improvement order, for a build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
    /// How hard the engine was asked to think (`low`, `medium`, `high`), where it ran
    /// with an effort. Left out of the signed JSON when unknown, so older records verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// `done`, or what happened instead: `held: ...`, `failed: ...`.
    pub outcome: String,
}

impl Step {
    /// `plan: nemotron (nvidia/nemotron-70b) on grouchly, $0.00 - done`
    #[must_use]
    pub fn describe(&self) -> String {
        let what = match &self.order {
            Some(order) => format!("{} {order}", self.step),
            None => self.step.clone(),
        };
        let engine = match (&self.engine, &self.model) {
            (Some(engine), Some(model)) => format!("{engine} ({model})"),
            (Some(engine), None) => engine.clone(),
            _ => "no engine".to_string(),
        };
        let cost = self
            .cost_usd
            .map(|cost| format!(", ${cost:.2}"))
            .unwrap_or_default();
        let effort = self
            .effort
            .as_ref()
            .map(|effort| format!(", {effort} effort"))
            .unwrap_or_default();
        format!(
            "{what}: {engine} on {} ({}){effort}{cost} - {}",
            self.machine, self.agent, self.outcome
        )
    }
}

/// One agent's step records for one week, signed by that agent. One writer per file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepLog {
    pub agent: String,
    pub week: String,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// Signs the v1 view: the steps without `effort`, which is what v0.5.17 re-serializes
    /// after dropping it, so an older peer still verifies the log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Signs the whole log, `effort` included. Required by a verifier that knows it
    /// whenever any step carries an effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_v2: Option<String>,
}

impl StepLog {
    fn has_v2_fields(&self) -> bool {
        self.steps.iter().any(|step| step.effort.is_some())
    }

    /// Whether the log is the signing agent's own: v1 always, and v2 as well when a field
    /// the v1 signature does not cover is present.
    fn signed_validly(&self, roster: &[crate::AgentRoute]) -> bool {
        let v1 = crate::check_signature(
            self.signed_by.as_ref(),
            self.signature.as_ref(),
            &steps_payload(self),
            roster,
        ) == SignatureCheck::Valid;
        v1 && (!self.has_v2_fields()
            || crate::check_signature(
                self.signed_by.as_ref(),
                self.signature_v2.as_ref(),
                &steps_payload_v2(self),
                roster,
            ) == SignatureCheck::Valid)
    }
}

/// The steps as v0.5.17 serializes them, without `effort`.
fn steps_v1_json(steps: &[Step]) -> String {
    let mut value = serde_json::to_value(steps).unwrap_or_default();
    if let Some(list) = value.as_array_mut() {
        for step in list {
            if let Some(step) = step.as_object_mut() {
                step.remove("effort");
            }
        }
    }
    serde_jcs::to_string(&value).unwrap_or_default()
}

fn steps_payload(log: &StepLog) -> String {
    format!(
        "ferryman-improve-steps-v1\n{}\n{}\n{}",
        log.agent,
        log.week,
        steps_v1_json(&log.steps)
    )
}

fn steps_payload_v2(log: &StepLog) -> String {
    format!(
        "ferryman-improve-steps-v2\n{}\n{}\n{}",
        log.agent,
        log.week,
        serde_jcs::to_string(&log.steps).unwrap_or_default()
    )
}

fn steps_dir(route: &ProjectRoute, week: &str) -> std::path::PathBuf {
    route
        .communications
        .join("improve")
        .join(week)
        .join("steps")
}

/// Add a step to this agent's signed record for `week`.
pub fn record_step(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    week: &str,
    step: Step,
) -> Result<()> {
    let agent = identity.name();
    if !crate::is_safe_component(agent) || !crate::is_safe_component(week) {
        bail!("agent and week must be path-safe");
    }
    let path = steps_dir(route, week).join(format!("{agent}.json"));
    let _lock = crate::own_files_lock();
    let mut log = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<StepLog>(&bytes).ok())
        .filter(|log| log.agent.eq_ignore_ascii_case(agent) && log.week == week)
        .unwrap_or(StepLog {
            agent: agent.to_string(),
            week: week.to_string(),
            steps: Vec::new(),
            signed_by: None,
            signature: None,
            signature_v2: None,
        });
    log.steps.push(step);
    if log.steps.len() > KEEP_STEPS {
        let excess = log.steps.len() - KEEP_STEPS;
        log.steps.drain(..excess);
    }
    log.signed_by = Some(agent.to_string());
    log.signature = Some(identity.sign_bytes(steps_payload(&log).as_bytes()));
    log.signature_v2 = Some(identity.sign_bytes(steps_payload_v2(&log).as_bytes()));
    crate::atomic_json(&path, &log).with_context(|| format!("writing {}", path.display()))
}

/// Every step recorded for `week` whose log verifies as its agent's, oldest first.
#[must_use]
pub fn read_steps(route: &ProjectRoute, week: &str) -> Vec<Step> {
    let Ok(entries) = std::fs::read_dir(steps_dir(route, week)) else {
        return Vec::new();
    };
    let mut steps: Vec<Step> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<StepLog>(&bytes).ok())
        .filter(|log| {
            log.week == week
                && log
                    .signed_by
                    .as_deref()
                    .is_some_and(|signer| signer.eq_ignore_ascii_case(&log.agent))
                && log.signed_validly(&route.agents)
        })
        .flat_map(|log| {
            let agent = log.agent.clone();
            // A step is the signing agent's statement about itself.
            log.steps
                .into_iter()
                .filter(move |step| step.agent.eq_ignore_ascii_case(&agent))
        })
        .collect();
    steps.sort_by_key(|step| step.at);
    steps
}

/// The newest record of each step (and of each order's build) in `week`.
#[must_use]
pub fn latest_steps(route: &ProjectRoute, week: &str) -> Vec<Step> {
    let mut latest: BTreeMap<(String, String), Step> = BTreeMap::new();
    for step in read_steps(route, week) {
        latest.insert(
            (step.step.clone(), step.order.clone().unwrap_or_default()),
            step,
        );
    }
    let mut out: Vec<Step> = latest.into_values().collect();
    out.sort_by_key(|step| step.at);
    out
}

/// What the fleet spent on one role in `week`, from the signed step records.
#[must_use]
pub fn role_spend(route: &ProjectRoute, week: &str, role: Role) -> f64 {
    read_steps(route, week)
        .iter()
        .filter(|step| step.role.as_deref() == Some(role.as_str()))
        .filter_map(|step| step.cost_usd)
        .sum()
}

/// Why a role's weekly cap stops more of its work, or `None` when it does not.
#[must_use]
pub fn over_cap(route: &ProjectRoute, policy: &Policy, week: &str, role: Role) -> Option<String> {
    let cap = policy.cap(role)?;
    let spent = role_spend(route, week, role);
    (spent >= cap).then(|| {
        format!(
            "the {} cap of ${cap:.2} a week is spent (${spent:.2})",
            role.as_str()
        )
    })
}

// --- asking the master --------------------------------------------------------------------

/// Why a delegate may not turn the adversary's `in_force` terms into `next`, when they
/// differ: its mode switched, its role removed, or anything else about who challenges and
/// at what price. Only the master does that.
fn adversary_change(in_force: &AdversaryTerms, next: &AdversaryTerms) -> Option<String> {
    if in_force == next {
        return None;
    }
    if in_force.mode != next.mode {
        return Some(format!(
            "this changes the adversary mode from {} to {}",
            in_force.mode.as_str(),
            next.mode.as_str()
        ));
    }
    if !in_force.prefer.is_empty() && next.prefer.is_empty() {
        return Some("this removes the adversary role".to_string());
    }
    Some("this changes which engines or agents the adversary may use, or its cap".to_string())
}

/// The team preset laid over the policy in force: the preset's `prefer`, `effort`,
/// `width` and `subscription_roles` replace what `current` has for those roles, and
/// everything else the master chose stays - `never` and its scope, caps, subscription
/// protection, auto-merge, the adversary's mode, and `machines` (the preset's online
/// machines are used only when `current` limits none).
///
/// `subscription_roles` is the preset's as the caller built it: pass `current`'s roles into
/// [`TeamOptions`] unless the person asked for others.
#[must_use]
pub fn apply_team(current: &Policy, preset: &Policy) -> Policy {
    let mut next = current.clone();
    next.prefer.extend(preset.prefer.clone());
    next.effort.extend(preset.effort.clone());
    next.width.extend(preset.width.clone());
    next.subscription_roles
        .clone_from(&preset.subscription_roles);
    if next.machines.is_empty() {
        next.machines.clone_from(&preset.machines);
    }
    next
}

/// The recommendation laid over the policy in force: its engine preferences replace those
/// roles' in `current`, and everything else the master chose stays (as for
/// [`apply_team`]).
#[must_use]
pub fn apply_recommendation(current: &Policy, recommended: &Policy) -> Policy {
    let mut next = current.clone();
    next.prefer.extend(recommended.prefer.clone());
    if next.machines.is_empty() {
        next.machines.clone_from(&recommended.machines);
    }
    next
}

/// Ask the master what to do about held background work: once per role per week,
/// however many machines and hours it stays held. Returns whether it was asked now.
pub fn ask_hold(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    role: Role,
    week: &str,
    why: &str,
) -> Result<bool> {
    crate::questions::ask(
        route,
        identity,
        &format!(
            "engine-hold-{}-{}",
            role.as_str(),
            week.to_ascii_lowercase()
        ),
        crate::questions::POLICY,
        &format!(
            "Self-improve {} work in {} is on hold: {why}.\n\nNothing fell back to an engine \
             the policy blocks. Accept the recommended engine policy, change it (dashboard \
             Teammates page, or Engines on the phone), or keep holding.",
            role.as_str(),
            route.project_id
        ),
        &[ACCEPT_RECOMMENDED.to_string(), KEEP_HOLDING.to_string()],
        None,
    )
}

/// Tell the master a free-tier engine asked for money: once per engine per week. Auto
/// mode already ranks it down; blocking it is their call. Returns whether it was asked.
pub fn ask_free_tier(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    engine: &str,
    week: &str,
    why: &str,
) -> Result<bool> {
    crate::questions::ask(
        route,
        identity,
        &format!(
            "free-tier-{}-{}",
            engine.to_ascii_lowercase(),
            week.to_ascii_lowercase()
        ),
        crate::questions::POLICY,
        &format!(
            "{engine} is marked free-tier, but on {} it {why}. It may no longer be free. \
             Auto mode now ranks it after paid engines with a cap; block it for background \
             work, or keep using it.",
            identity.name()
        ),
        &[format!("Block {engine}"), "Keep using it".to_string()],
        None,
    )
}

/// What an answer to a policy question asks to change, applied to `policy`: accept
/// the recommendation, or block an engine. `None` when the answer changes nothing.
#[must_use]
pub fn answer_changes(answer: &str, policy: &Policy, recommended: &Policy) -> Option<Policy> {
    if answer.eq_ignore_ascii_case(ACCEPT_RECOMMENDED) {
        return Some(apply_recommendation(policy, recommended));
    }
    let engine = answer.strip_prefix("Block ")?.trim();
    let mut changed = policy.clone();
    changed.block(engine).then_some(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    /// A channel whose master is `members[0]`, every member on its roster.
    fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
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

    fn engine(name: &str, tier: &str, paid: &str) -> Candidate {
        Candidate {
            agent: "grouchly".into(),
            machine: "grouchly".into(),
            name: name.into(),
            tier: tier.into(),
            paid: paid.into(),
            state: "up".into(),
            ..Candidate::default()
        }
    }

    fn names(ranking: &Ranking, engines: &[Candidate]) -> Vec<String> {
        ranking
            .order
            .iter()
            .map(|index| engines[*index].name.clone())
            .collect()
    }

    #[test]
    fn selectors_match_by_name_model_glob_paid_class_and_host() {
        let mut nemotron = engine("nvidia", "build", "free-tier");
        nemotron.model = Some("nvidia/llama-3.1-nemotron-70b-instruct".into());
        nemotron.host = Some("integrate.api.nvidia.com".into());
        let mut deepseek = engine("deepseek", "build", "prepaid");
        deepseek.model = Some("deepseek-chat".into());
        deepseek.host = Some("api.deepseek.com".into());
        let claude = engine("claude", "judge", "unknown");

        assert!(matches("nvidia/*nemotron*", &nemotron), "a model glob");
        assert!(matches("model:NVIDIA/*", &nemotron), "case never matters");
        assert!(!matches("model:nvidia/*", &deepseek));
        assert!(
            matches("nemotron", &nemotron),
            "a bare word inside the model"
        );
        assert!(matches("paid:free-tier", &nemotron));
        assert!(matches("paid:free", &nemotron), "free is free-tier");
        assert!(!matches("paid:free-tier", &deepseek));
        assert!(matches("host:deepseek.com", &deepseek), "a subdomain");
        assert!(matches("provider:api.deepseek.com", &deepseek));
        assert!(!matches("host:nvidia.com", &deepseek));
        assert!(matches("deepseek", &deepseek), "a bare word in the host");
        assert!(matches("name:deep*", &deepseek));
        assert!(matches("claude", &claude), "a bare word is the engine name");
        assert!(
            matches("paid:subscription", &claude),
            "an unmarked claude CLI is taken for a subscription"
        );
        assert!(!matches("claude", &deepseek));
        assert!(!matches("", &deepseek));
        assert!(!matches("name:", &deepseek));
        assert!(glob("a*c?e", "abbbcde") && !glob("a*c?e", "abce"));
    }

    #[test]
    fn auto_ranks_local_then_free_then_capped_prepaid_and_never_a_subscription() {
        let mut capped = engine("deepseek", "build", "prepaid");
        capped.capped = true;
        let engines = vec![
            engine("claude", "build", "subscription"),
            engine("uncapped", "build", "prepaid"),
            engine("mystery", "build", "unknown"),
            capped,
            engine("nemotron", "build", "free-tier"),
            engine("ollama", "build", "local"),
        ];
        let ranking = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(
            names(&ranking, &engines),
            ["ollama", "nemotron", "deepseek", "mystery", "uncapped"]
        );
        assert_eq!(ranking.blocked.len(), 1);
        assert_eq!(engines[ranking.blocked[0].0].name, "claude");
        assert!(ranking.blocked[0].1.contains("subscription"));

        // A person's own order is theirs to spend on.
        let direct = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Direct,
            &engines,
        );
        assert!(direct.blocked.is_empty());
        assert_eq!(direct.order[0], 0, "operator order for direct work");

        // With protection off, a subscription is allowed, last.
        let open = Policy {
            protect_subscriptions: false,
            ..Policy::default()
        };
        let ranking = rank(&open, Role::Build, "build", Work::Background, &engines);
        assert_eq!(names(&ranking, &engines).last().unwrap(), "claude");
    }

    #[test]
    fn ties_break_on_trust_then_cost_per_verified_then_operator_order() {
        let mut a = engine("a", "build", "free-tier");
        a.verified = 3;
        a.refuted = 3;
        let mut b = engine("b", "build", "free-tier");
        b.verified = 9;
        b.refuted = 1;
        b.order = 1;
        let mut c = engine("c", "build", "free-tier");
        c.verified = 9;
        c.refuted = 1;
        c.spend_usd = 0.9;
        c.order = 2;
        let mut d = engine("d", "build", "free-tier");
        d.verified = 9;
        d.refuted = 1;
        d.spend_usd = 0.1;
        d.order = 3;
        let mut demoted = engine("e", "build", "local");
        demoted.demoted = true;
        let engines = vec![a, b, c, d, demoted];
        let ranking = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(
            names(&ranking, &engines),
            ["d", "c", "b", "a"],
            "trust first; among equals the cheaper verified result; a demoted engine \
             takes no build work"
        );
    }

    #[test]
    fn a_free_tier_that_asked_for_money_is_ranked_down() {
        let mut flagged = engine("nemotron", "build", "free-tier");
        flagged.flag = Some("returned HTTP 402".into());
        let mut capped = engine("deepseek", "build", "prepaid");
        capped.capped = true;
        let engines = vec![flagged, capped];
        let ranking = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(names(&ranking, &engines), ["deepseek", "nemotron"]);
    }

    #[test]
    fn preferences_order_first_and_never_is_never_for_background_work() {
        let mut nemotron = engine("nvidia", "build", "free-tier");
        nemotron.model = Some("nvidia/nemotron-70b".into());
        let mut deepseek = engine("deepseek", "judge", "prepaid");
        deepseek.host = Some("api.deepseek.com".into());
        let engines = vec![
            engine("claude", "judge", "prepaid"),
            deepseek,
            nemotron,
            engine("ollama", "build", "local"),
        ];
        let mut policy = Policy {
            never: vec!["claude".into()],
            ..Policy::default()
        };
        for role in Role::ALL {
            policy.prefer.insert(
                role.as_str().into(),
                vec!["nvidia/nemotron*".into(), "deepseek".into()],
            );
        }
        let build = rank(&policy, Role::Build, "build", Work::Background, &engines);
        assert_eq!(names(&build, &engines), ["nvidia", "deepseek", "ollama"]);
        assert!(
            build
                .blocked
                .iter()
                .any(|(i, why)| *i == 0 && why.contains("never"))
        );
        // Planning follows the list too: the operator chose nemotron to plan.
        let plan = rank(&policy, Role::Plan, "judge", Work::Background, &engines);
        assert_eq!(names(&plan, &engines)[0], "nvidia");
        // Review is a judge's: only deepseek can.
        let review = rank(&policy, Role::Review, "judge", Work::Background, &engines);
        assert_eq!(names(&review, &engines), ["deepseek"]);

        // `never` leaves a person's own order alone unless it says "all".
        let direct = rank(&policy, Role::Build, "build", Work::Direct, &engines);
        assert!(direct.order.contains(&0));
        policy.never_applies_to = NeverScope::All;
        let direct = rank(&policy, Role::Build, "build", Work::Direct, &engines);
        assert!(!direct.order.contains(&0));

        // Everything blocked or out: nothing, and why.
        let only_claude = vec![engines[0].clone()];
        let none = rank(
            &policy,
            Role::Build,
            "build",
            Work::Background,
            &only_claude,
        );
        assert!(none.order.is_empty());
        assert!(
            none.why_none(Role::Build, &only_claude)
                .contains("claude on grouchly never")
        );
    }

    /// Claude reached through OmniRoute is still Claude: `never claude` and subscription
    /// protection see through the gateway to the route it ends at.
    #[test]
    fn never_and_protection_see_through_a_gateway_route() {
        let gateway = |name: &str, paid: &str, model: &str, route: &[&str]| {
            let mut engine = engine(name, "build", paid);
            engine.model = Some(model.into());
            engine.host = Some("localhost".into());
            engine.route = route.iter().map(ToString::to_string).collect();
            engine
        };
        let engines = vec![
            gateway(
                "omniroute.claude-first",
                "subscription",
                "claude-first",
                &["cc/claude-sonnet-4-6", "nvidia/nemotron-70b:free"],
            ),
            gateway(
                "omniroute.free-stack",
                "free-tier",
                "free-stack",
                &["nvidia/nemotron-70b:free"],
            ),
            gateway(
                "omniroute.or-claude",
                "unknown",
                "openrouter/anthropic/claude-sonnet-4",
                &["openrouter/anthropic/claude-sonnet-4"],
            ),
        ];
        assert!(matches("claude", &engines[0]), "the route names it");
        assert!(matches("provider:cc", &engines[0]));
        assert!(matches("model:*nemotron*", &engines[1]));
        assert!(!matches("claude", &engines[1]));
        let protected = rank(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            &engines,
        );
        assert_eq!(
            names(&protected, &engines),
            ["omniroute.free-stack", "omniroute.or-claude"],
            "a Claude Code step makes the combo a subscription"
        );
        let never = Policy {
            never: vec!["claude".into()],
            ..Policy::default()
        };
        let ranking = rank(&never, Role::Build, "build", Work::Background, &engines);
        assert_eq!(names(&ranking, &engines), ["omniroute.free-stack"]);
        assert_eq!(ranking.blocked.len(), 2);
    }

    #[test]
    fn the_simple_choice_sets_improvement_and_review_and_lists_what_to_pick() {
        let mut policy = Policy::default();
        policy.set_improvement_engine("name:nemotron");
        policy.set_review_engine("name:deepseek");
        assert_eq!(policy.preferences(Role::Plan), ["name:nemotron"]);
        assert_eq!(policy.preferences(Role::Build), ["name:nemotron"]);
        assert_eq!(policy.review_engine(), Some("name:deepseek"));
        policy.check().unwrap();
        let engines = vec![
            engine("nemotron", "build", "free-tier"),
            engine("deepseek", "judge", "prepaid"),
            engine("claude", "judge", "subscription"),
            engine("ollama", "chore", "local"),
        ];
        let recommended = recommend(&engines, &[]).policy;
        let picks = choices(&policy, &engines, &recommended);
        let improve = picks["improve"].as_array().unwrap();
        assert_eq!(improve.len(), 3, "a chore engine cannot improve: {picks}");
        assert_eq!(improve[0]["selector"], "name:nemotron");
        assert_eq!(improve[0]["recommended"], true);
        assert_eq!(improve[0]["paid"], "free-tier");
        let review = picks["review"].as_array().unwrap();
        assert_eq!(review.len(), 2, "only a judge reviews: {picks}");
        assert_eq!(review[0]["recommended"], true);
        assert!(
            review[1]["blocked"]
                .as_str()
                .unwrap()
                .contains("subscription")
        );
        assert_eq!(picks["current"]["improve"], "name:nemotron");
    }

    #[test]
    fn where_limits_background_work_to_the_named_machines() {
        let policy = Policy {
            machines: vec!["grouchly".into()],
            ..Policy::default()
        };
        assert!(policy.allows_machine("wisp", "GROUCHLY"));
        assert!(policy.allows_machine("grouchly", "anything"));
        assert!(!policy.allows_machine("beastly", "beastly"));
        assert!(Policy::default().allows_machine("beastly", "beastly"));
        let mut there = engine("ollama", "build", "local");
        there.agent = "beastly".into();
        there.machine = "beastly".into();
        let ranking = rank(&policy, Role::Build, "build", Work::Background, &[there]);
        assert!(ranking.order.is_empty());
        assert!(ranking.blocked[0].1.contains("not in where"));
    }

    #[test]
    fn the_recommendation_gives_one_reason_per_choice() {
        let mut nemotron = engine("nemotron", "build", "free-tier");
        nemotron.verified = 12;
        let mut judge = engine("deepseek", "judge", "prepaid");
        judge.capped = true;
        judge.verified = 4;
        let mut elsewhere = engine("nemotron", "build", "free-tier");
        elsewhere.machine = "beastly".into();
        elsewhere.verified = 3;
        elsewhere.state = "exhausted".into();
        let engines = vec![
            nemotron,
            judge,
            engine("claude", "judge", "unknown"),
            elsewhere,
        ];
        let proposal = recommend(&engines, &["grouchly".to_string()]);
        assert_eq!(
            proposal.policy.preferences(Role::Build),
            ["name:nemotron", "name:deepseek"]
        );
        assert_eq!(
            proposal.policy.preferences(Role::Review),
            ["name:deepseek"],
            "review is a judge's"
        );
        assert_eq!(
            proposal.policy.preferences(Role::Plan)[0],
            "name:deepseek",
            "a judge plans first"
        );
        assert_eq!(proposal.policy.machines, ["grouchly"]);
        assert!(proposal.policy.protect_subscriptions);
        assert!(
            proposal
                .reasons
                .contains(&"nemotron first for build: free-tier, 15 verified, 0 refuted".into()),
            "{:#?}",
            proposal.reasons
        );
        assert!(
            proposal
                .reasons
                .iter()
                .any(|r| r.starts_with("claude never for background work")),
            "{:#?}",
            proposal.reasons
        );
        proposal.policy.check().unwrap();
    }

    /// Off-the-shelf trust: the master's word, travelling with the channel; nobody
    /// else's, however it got there.
    #[test]
    fn only_the_masters_signed_policy_counts_and_a_forged_one_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let grouchly = person("grouchly", 2);
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;
        let mut mine = Policy::default();
        mine.never.push("claude".into());

        assert!(setting(channel, "demo").is_none(), "auto by default");
        assert!(set_policy(channel, "demo", Some(mine.clone()), &grouchly).is_err());
        let impostor = person("josh", 9);
        assert!(set_policy(channel, "demo", Some(mine.clone()), &impostor).is_err());
        assert!(!channel.join(ENGINE_POLICY).exists());

        assert!(set_policy(channel, "demo", Some(mine.clone()), &josh).unwrap());
        assert!(!set_policy(channel, "demo", Some(mine.clone()), &josh).unwrap());
        assert_eq!(effective(channel, "demo").0, mine);
        assert!(is_set(channel, "demo"));

        // Edited after signing: ignored, and the project runs on auto.
        let path = channel.join(ENGINE_POLICY);
        let mut edited: PolicySetting =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edited.policy.as_mut().unwrap().never.clear();
        crate::atomic_json(&path, &edited).unwrap();
        // The edited file does not count, and this machine keeps what the master last
        // signed rather than dropping to auto.
        assert_eq!(effective(channel, "demo").0, mine);

        // Validly signed, but by a member who is not the master.
        let mut forged = PolicySetting {
            project_id: "demo".into(),
            policy: Some(Policy {
                protect_subscriptions: false,
                ..Policy::default()
            }),
            set_at: Utc::now(),
            signed_by: "grouchly".into(),
            signature: String::new(),
            on_behalf_of: None,
            seq: 99,
            signature_v2: None,
        };
        forged.sign(&grouchly);
        crate::atomic_json(&path, &forged).unwrap();
        assert_eq!(effective(channel, "demo").0, mine);
        // Unsigned.
        forged.signature.clear();
        forged.signature_v2 = None;
        crate::atomic_json(&path, &forged).unwrap();
        assert!(effective(channel, "demo").0.protect_subscriptions);
        // Lifted from another project.
        let mut lifted = forged.clone();
        lifted.project_id = "elsewhere".into();
        lifted.signed_by = "josh".into();
        lifted.sign(&josh);
        crate::atomic_json(&path, &lifted).unwrap();
        assert_eq!(effective(channel, "demo").0, mine);
        // Garbage.
        std::fs::write(&path, "prefer nemotron").unwrap();
        assert_eq!(effective(channel, "demo").0, mine);

        // The master goes back to auto, signed.
        assert!(set_policy(channel, "demo", Some(mine), &josh).unwrap());
        assert!(set_policy(channel, "demo", None, &josh).unwrap());
        assert!(setting(channel, "demo").is_some() && !is_set(channel, "demo"));
    }

    #[test]
    fn a_delegate_sets_the_policy_only_under_an_improve_delegation() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &bridge]);
        let channel = &route.communications;
        let mut policy = Policy::default();
        policy.move_to_top("nemotron");
        assert!(
            set_policy_as(channel, "demo", Some(policy.clone()), &bridge, Some("josh")).is_err()
        );
        crate::delegation::grant(
            channel,
            "demo",
            &josh,
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        assert!(
            set_policy_as(channel, "demo", Some(policy.clone()), &bridge, Some("josh")).unwrap()
        );
        let set = setting(channel, "demo").unwrap();
        assert_eq!(set.set_by(), "josh via telegram-grouchly");
        assert_eq!(
            set.policy.unwrap().preferences(Role::Build),
            ["name:nemotron"]
        );
    }

    #[test]
    fn block_and_move_to_top_edit_the_lists() {
        let mut policy = Policy::default();
        policy.move_to_top("deepseek");
        policy.move_to_top("nemotron");
        assert_eq!(
            policy.preferences(Role::Review),
            ["name:nemotron", "name:deepseek"]
        );
        assert!(policy.block("nemotron"));
        assert!(!policy.block("NEMOTRON"), "once");
        assert_eq!(policy.preferences(Role::Build), ["name:deepseek"]);
        assert_eq!(policy.never, ["name:nemotron"]);
        policy.move_to_top("nemotron");
        assert!(policy.never.is_empty(), "moving it up lifts the block");
        let recommended = Policy {
            machines: vec!["grouchly".into()],
            ..Policy::default()
        };
        assert_eq!(
            answer_changes(ACCEPT_RECOMMENDED, &policy, &recommended),
            Some(Policy {
                machines: vec!["grouchly".into()],
                ..policy.clone()
            }),
            "accepting lays the recommendation over the policy; it does not replace it"
        );
        let blocked = answer_changes("Block claude", &policy, &recommended).unwrap();
        assert_eq!(blocked.never, ["name:claude"]);
        assert!(answer_changes(KEEP_HOLDING, &policy, &recommended).is_none());
        assert!(
            Policy {
                caps_usd: BTreeMap::from([("build".to_string(), -1.0)]),
                ..Policy::default()
            }
            .check()
            .is_err()
        );
        assert!(
            Policy {
                prefer: BTreeMap::from([("dance".to_string(), vec!["x".to_string()])]),
                ..Policy::default()
            }
            .check()
            .is_err()
        );
    }

    /// A policy signed before the adversary role and mode existed carries neither, and
    /// still verifies: the new parts are left out of the signed JSON while they are what an
    /// old policy meant.
    #[test]
    fn a_policy_signed_before_the_adversary_existed_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;

        let mut old = Policy::default();
        old.never.push("claude".into());
        old.prefer
            .insert("build".into(), vec!["name:nemotron".into()]);
        let shape = serde_json::to_value(&old).unwrap();
        assert!(shape.get("adversary").is_none(), "{shape}");
        assert!(shape["prefer"].get("adversary").is_none());

        // Written the way the previous release wrote it: no adversary anywhere.
        let from_old: Policy = serde_json::from_value(shape.clone()).unwrap();
        assert_eq!(from_old, old);
        assert_eq!(from_old.adversary, AdversaryMode::Advisory);
        assert_eq!(
            serde_jcs::to_string(&from_old).unwrap(),
            serde_jcs::to_string(&shape).unwrap(),
            "the bytes the old signature covered are the bytes now"
        );
        let mut signed = PolicySetting {
            project_id: "demo".into(),
            policy: Some(from_old),
            set_at: Utc::now(),
            signed_by: "josh".into(),
            signature: String::new(),
            on_behalf_of: None,
            seq: 0,
            signature_v2: None,
        };
        signed.signature = josh.sign_bytes(setting_payload(&signed).as_bytes());
        crate::atomic_json(&channel.join(ENGINE_POLICY), &signed).unwrap();
        let read = setting(channel, "demo").expect("the old signature verifies");
        assert_eq!(read.policy.unwrap().adversary, AdversaryMode::Advisory);
        assert_eq!(effective(channel, "demo").0, old);
    }

    #[test]
    fn the_adversary_role_and_mode_round_trip_through_a_signed_policy() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;

        let mut policy = Policy {
            adversary: AdversaryMode::Blocking,
            ..Policy::default()
        };
        policy.set_adversary_engine("name:deepseek");
        policy.check().unwrap();
        let shape = serde_json::to_value(&policy).unwrap();
        assert_eq!(shape["adversary"], "blocking");
        assert_eq!(shape["prefer"]["adversary"][0], "name:deepseek");
        assert_eq!(policy.adversary_engine(), Some("name:deepseek"));
        assert!(
            policy
                .describe()
                .iter()
                .any(|line| line.contains("adversary") && line.contains("deepseek")),
            "{:?}",
            policy.describe()
        );

        assert!(set_policy(channel, "demo", Some(policy.clone()), &josh).unwrap());
        let (read, set) = effective(channel, "demo");
        assert!(set.is_some());
        assert_eq!(read, policy);
        assert_eq!(read.adversary, AdversaryMode::Blocking);

        // Off is written too; only the default is left out.
        let off = Policy {
            adversary: AdversaryMode::Off,
            ..Policy::default()
        };
        assert_eq!(serde_json::to_value(&off).unwrap()["adversary"], "off");
        assert!(set_policy(channel, "demo", Some(off.clone()), &josh).unwrap());
        assert_eq!(effective(channel, "demo").0, off);

        // The role is named like the others, and a mode that does not exist is refused.
        assert_eq!(Role::parse("adversary").unwrap(), Role::Adversary);
        assert!(AdversaryMode::parse("sometimes").is_err());
        assert_eq!(
            AdversaryMode::parse("Blocking").unwrap(),
            AdversaryMode::Blocking
        );
        assert_eq!(Role::ALL.len(), Role::BUILDING.len() + 1);
        assert!(!Role::BUILDING.contains(&Role::Adversary));
    }

    fn judge(name: &str, model: &str, verified: u64) -> Candidate {
        let mut found = engine(name, "judge", "prepaid");
        found.model = Some(model.into());
        found.verified = verified;
        found
    }

    fn built_by(engine: &str, model: &str) -> Vec<Builder> {
        vec![Builder {
            engine: engine.into(),
            model: Some(model.into()),
        }]
    }

    #[test]
    fn the_adversary_is_never_the_builder_when_another_engine_is_allowed() {
        let engines = vec![
            judge("claude", "claude-sonnet", 20),
            judge("deepseek", "deepseek-chat", 5),
            judge("qwen", "qwen-max", 1),
        ];
        let policy = Policy::default();
        let against_claude =
            rank_adversary(&policy, &built_by("claude", "claude-sonnet"), &engines);
        let order = names(&against_claude.ranking, &engines);
        assert_eq!(
            order,
            ["deepseek", "qwen", "claude"],
            "the builder is last, not dropped"
        );
        assert_eq!(against_claude.same_engine, [false, false, true]);

        // The policy's own preference does not put the builder back on top.
        let mut prefers_claude = Policy::default();
        prefers_claude.set_adversary_engine("name:claude");
        let still = rank_adversary(
            &prefers_claude,
            &built_by("claude", "claude-sonnet"),
            &engines,
        );
        assert_eq!(names(&still.ranking, &engines)[0], "deepseek");
        // ...but it does decide among the others.
        prefers_claude.set_adversary_engine("name:qwen");
        let chosen = rank_adversary(
            &prefers_claude,
            &built_by("claude", "claude-sonnet"),
            &engines,
        );
        assert_eq!(names(&chosen.ranking, &engines)[0], "qwen");

        // With no builder known, the order is the policy's own.
        let alone = rank_adversary(&policy, &[], &engines);
        assert_eq!(names(&alone.ranking, &engines)[0], "claude");
        assert!(alone.same_engine.iter().all(|same| !same));
    }

    #[test]
    fn the_only_allowed_engine_runs_against_its_own_work_and_says_so() {
        let engines = vec![judge("deepseek", "deepseek-chat", 3)];
        let ranked = rank_adversary(
            &Policy::default(),
            &built_by("deepseek", "deepseek-chat"),
            &engines,
        );
        assert_eq!(ranked.ranking.order, [0]);
        assert_eq!(ranked.same_engine, [true]);

        // Another engine that the policy never allows does not count as "another".
        let engines = vec![
            judge("deepseek", "deepseek-chat", 3),
            judge("claude", "claude-sonnet", 3),
        ];
        let policy = Policy {
            adversary_never: vec!["name:claude".into()],
            ..Policy::default()
        };
        let ranked = rank_adversary(&policy, &built_by("deepseek", "deepseek-chat"), &engines);
        assert_eq!(names(&ranked.ranking, &engines), ["deepseek"]);
        assert_eq!(ranked.same_engine, [true]);

        // The engine policy's `never` and `where` are not the adversary's: a delegate who
        // signs them cannot take its judges away.
        let engine_policy = Policy {
            never: vec!["name:claude".into(), "name:deepseek".into()],
            machines: vec!["nowhere".into()],
            ..Policy::default()
        };
        let ranked = rank_adversary(
            &engine_policy,
            &built_by("deepseek", "deepseek-chat"),
            &engines,
        );
        assert_eq!(names(&ranked.ranking, &engines), ["claude", "deepseek"]);

        // A build-tier engine is not an adversary at all.
        let engines = vec![engine("nemotron", "build", "free-tier")];
        assert!(
            rank_adversary(&Policy::default(), &[], &engines)
                .ranking
                .order
                .is_empty()
        );
    }

    #[test]
    fn a_different_model_family_is_preferred_over_the_builders_own() {
        let engines = vec![
            judge("deepseek-r1", "deepseek-reasoner", 30),
            judge("nemotron", "nemotron-ultra", 1),
            judge("gate", "deepseek/deepseek-v3", 9),
        ];
        let ranked = rank_adversary(
            &Policy::default(),
            &built_by("deepseek-chat", "deepseek-chat"),
            &engines,
        );
        // Nobody here built it, so only the family decides: the other family first, though
        // its record is the shortest.
        assert_eq!(names(&ranked.ranking, &engines)[0], "nemotron");
        assert_eq!(ranked.same_family, [false, true, true]);
        assert!(ranked.same_engine.iter().all(|same| !same));
        assert_eq!(family_of(&engines[0]), "deepseek");
        assert_eq!(family_of(&engines[1]), "nvidia");
        // A gateway named neutrally is read by its model, not its name.
        assert_eq!(family_of(&engines[2]), "deepseek");
        // An engine nothing recognises is its own family.
        assert_eq!(family_of(&engine("homebrew", "judge", "local")), "homebrew");
    }

    #[test]
    fn the_recommendation_picks_an_adversary_from_another_family_than_the_builder() {
        let mut nemotron = engine("nemotron", "build", "free-tier");
        nemotron.model = Some("nemotron-super".into());
        nemotron.verified = 12;
        let engines = vec![
            nemotron,
            judge("deepseek", "deepseek-chat", 4),
            judge("claude", "claude-sonnet", 4),
        ];
        let proposal = recommend(&engines, &["grouchly".to_string()]);
        assert!(
            !proposal.policy.preferences(Role::Adversary).is_empty(),
            "{:#?}",
            proposal.policy
        );
        let line = proposal
            .reasons
            .iter()
            .find(|reason| reason.contains("for adversary"))
            .unwrap_or_else(|| panic!("no adversary reason in {:#?}", proposal.reasons));
        assert!(line.contains("different family"), "{line}");
        assert!(line.contains("nemotron"), "{line}");
        assert_eq!(proposal.policy.adversary, AdversaryMode::Advisory);
        proposal.policy.check().unwrap();

        // Nothing at judge tier: the proposal says so instead of inventing one.
        let only_builders = vec![engine("nemotron", "build", "free-tier")];
        let proposal = recommend(&only_builders, &["grouchly".to_string()]);
        assert!(proposal.policy.preferences(Role::Adversary).is_empty());
        assert!(
            proposal
                .reasons
                .iter()
                .any(|reason| reason.starts_with("nothing for adversary")),
            "{:#?}",
            proposal.reasons
        );
    }

    /// Held work asks the master once a week per role, however often it is held.
    #[test]
    fn a_hold_is_asked_once_per_role_per_week() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let route = route(dir.path(), &[&josh, &wisp]);
        assert!(ask_hold(&route, &wisp, Role::Build, "2026-W40", "all blocked").unwrap());
        assert!(!ask_hold(&route, &wisp, Role::Build, "2026-W40", "still").unwrap());
        assert!(ask_hold(&route, &wisp, Role::Plan, "2026-W40", "all blocked").unwrap());
        assert!(ask_hold(&route, &wisp, Role::Build, "2026-W41", "again").unwrap());
        let pending = crate::questions::pending(&route);
        assert_eq!(pending.len(), 3);
        assert!(pending.iter().all(|q| q.kind == crate::questions::POLICY));
        assert_eq!(pending[0].options, [ACCEPT_RECOMMENDED, KEEP_HOLDING]);
        assert!(ask_free_tier(&route, &wisp, "nemotron", "2026-W40", "returned 402").unwrap());
        assert!(!ask_free_tier(&route, &wisp, "nemotron", "2026-W40", "again").unwrap());
    }

    #[test]
    fn step_records_are_signed_by_their_agent_and_a_forged_one_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let route = route(dir.path(), &[&josh, &wisp]);
        let step = |name: &str, cost: f64| Step {
            step: name.into(),
            role: Some(if name == "build" { "build" } else { name }.into()),
            at: Utc::now(),
            agent: "wisp".into(),
            machine: "grouchly".into(),
            engine: Some("nemotron".into()),
            model: Some("nvidia/nemotron".into()),
            cost_usd: Some(cost),
            order: None,
            effort: None,
            outcome: "done".into(),
        };
        record_step(&route, &wisp, "2026-W40", step("plan", 0.25)).unwrap();
        record_step(&route, &wisp, "2026-W40", step("plan", 0.5)).unwrap();
        record_step(&route, &wisp, "2026-W40", step("review", 1.0)).unwrap();
        assert_eq!(read_steps(&route, "2026-W40").len(), 3);
        assert_eq!(latest_steps(&route, "2026-W40").len(), 2);
        assert!((role_spend(&route, "2026-W40", Role::Plan) - 0.75).abs() < 1e-9);
        let capped = Policy {
            caps_usd: BTreeMap::from([("plan".to_string(), 0.5)]),
            ..Policy::default()
        };
        assert!(over_cap(&route, &capped, "2026-W40", Role::Plan).is_some());
        assert!(over_cap(&route, &capped, "2026-W40", Role::Build).is_none());
        assert!(
            latest_steps(&route, "2026-W40")[0]
                .describe()
                .contains("nemotron (nvidia/nemotron) on grouchly (wisp), $0.50 - done")
        );

        // Somebody else writes a log in wisp's name.
        let mut forged = StepLog {
            agent: "wisp".into(),
            week: "2026-W40".into(),
            steps: vec![step("plan", 99.0)],
            signed_by: Some("josh".into()),
            signature: None,
            signature_v2: None,
        };
        forged.signature = Some(josh.sign_bytes(steps_payload(&forged).as_bytes()));
        crate::atomic_json(&steps_dir(&route, "2026-W40").join("wisp.json"), &forged).unwrap();
        assert!(read_steps(&route, "2026-W40").is_empty());
    }

    // v0.5.17's step shapes, copied so the test does not follow the live structs.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct OldStep {
        step: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        at: DateTime<Utc>,
        agent: String,
        machine: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        engine: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        order: Option<String>,
        outcome: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct OldStepLog {
        agent: String,
        week: String,
        #[serde(default)]
        steps: Vec<OldStep>,
        #[serde(default)]
        signed_by: Option<String>,
        #[serde(default)]
        signature: Option<String>,
    }

    fn old_peer_accepts_steps(bytes: &[u8], roster: &[AgentRoute]) -> bool {
        let Ok(old) = serde_json::from_slice::<OldStepLog>(bytes) else {
            return false;
        };
        let payload = format!(
            "ferryman-improve-steps-v1\n{}\n{}\n{}",
            old.agent,
            old.week,
            serde_jcs::to_string(&old.steps).unwrap_or_default()
        );
        crate::check_signature(
            old.signed_by.as_ref(),
            old.signature.as_ref(),
            &payload,
            roster,
        ) == SignatureCheck::Valid
    }

    #[test]
    fn a_step_log_with_effort_verifies_on_a_v0_5_17_peer_and_effort_cannot_be_forged() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let route = route(dir.path(), &[&josh, &wisp]);
        let step = |effort: Option<&str>| Step {
            step: "build".into(),
            role: Some("build".into()),
            at: Utc::now(),
            agent: "wisp".into(),
            machine: "grouchly".into(),
            engine: Some("nemotron".into()),
            model: None,
            cost_usd: Some(0.5),
            order: Some("o-1".into()),
            effort: effort.map(str::to_string),
            outcome: "done".into(),
        };
        record_step(&route, &wisp, "2026-W40", step(Some("high"))).unwrap();
        let path = steps_dir(&route, "2026-W40").join("wisp.json");
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            old_peer_accepts_steps(&bytes, &route.agents),
            "an old peer must not drop a log because a step carries an effort"
        );
        let steps = read_steps(&route, "2026-W40");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].effort.as_deref(), Some("high"));

        // Changing the effort, or stripping the v2 signature, is not accepted by a new peer.
        let log: StepLog = serde_json::from_slice(&bytes).unwrap();
        let mut forged = log.clone();
        forged.steps[0].effort = Some("low".into());
        crate::atomic_json(&path, &forged).unwrap();
        assert!(read_steps(&route, "2026-W40").is_empty());
        let mut stripped = log.clone();
        stripped.signature_v2 = None;
        crate::atomic_json(&path, &stripped).unwrap();
        assert!(read_steps(&route, "2026-W40").is_empty());
        // A log with no effort anywhere is the v1 file and verifies without a v2 signature.
        let mut plain = StepLog {
            steps: vec![step(None)],
            signature: None,
            signature_v2: None,
            ..log
        };
        plain.signature = Some(wisp.sign_bytes(steps_payload(&plain).as_bytes()));
        crate::atomic_json(&path, &plain).unwrap();
        assert_eq!(read_steps(&route, "2026-W40").len(), 1);
    }

    // --- effort, class, width, subscription_roles and the team preset ---------------------

    /// A policy signed before effort, width and subscription_roles existed carries none
    /// of them and still verifies; one that uses them round-trips through a signed file.
    #[test]
    fn a_policy_signed_before_effort_width_and_subscriptions_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;

        let mut old = Policy::default();
        old.never.push("claude".into());
        let shape = serde_json::to_value(&old).unwrap();
        for key in ["effort", "width", "subscription_roles"] {
            assert!(shape.get(key).is_none(), "{key} is left out: {shape}");
        }
        let from_old: Policy = serde_json::from_value(shape.clone()).unwrap();
        assert_eq!(from_old, old);
        assert!(from_old.effort.is_empty() && from_old.width.is_empty());
        assert!(from_old.subscription_roles.is_empty());
        assert_eq!(
            serde_jcs::to_string(&from_old).unwrap(),
            serde_jcs::to_string(&shape).unwrap(),
            "the bytes the old signature covered are the bytes now"
        );
        assert!(set_policy(channel, "demo", Some(old.clone()), &josh).unwrap());
        assert_eq!(effective(channel, "demo").0, old);

        let mut new = old.clone();
        new.effort.insert(Role::Build, Effort::Low);
        new.width.insert(Role::Chore, 4);
        new.subscription_roles = vec![Role::Build, Role::Chore];
        new.check().unwrap();
        let shape = serde_json::to_value(&new).unwrap();
        assert_eq!(shape["effort"]["build"], "low");
        assert_eq!(shape["width"]["chore"], 4);
        assert_eq!(shape["subscription_roles"][1], "chore");
        assert!(set_policy(channel, "demo", Some(new.clone()), &josh).unwrap());
        let (read, set) = effective(channel, "demo");
        assert!(set.is_some(), "the signature over the new fields verifies");
        assert_eq!(read, new);

        let zero = Policy {
            width: BTreeMap::from([(Role::Build, 0)]),
            ..Policy::default()
        };
        assert!(zero.check().is_err(), "a width of zero is refused");
    }

    #[test]
    fn effort_has_defaults_per_role_and_the_policy_overrides_them() {
        let mut policy = Policy::default();
        assert_eq!(policy.effort_for(Role::Plan), Effort::High);
        assert_eq!(policy.effort_for(Role::Review), Effort::High);
        assert_eq!(policy.effort_for(Role::Adversary), Effort::High);
        assert_eq!(policy.effort_for(Role::Build), Effort::Medium);
        assert_eq!(policy.effort_for(Role::Chore), Effort::Low);
        policy.effort.insert(Role::Build, Effort::High);
        assert_eq!(policy.effort_for(Role::Build), Effort::High);
        assert_eq!(policy.effort_for(Role::Chore), Effort::Low);
        assert_eq!(Effort::parse("Medium").unwrap(), Effort::Medium);
        assert!(Effort::parse("extreme").is_err());
        assert!(Effort::Low < Effort::Medium && Effort::Medium < Effort::High);
    }

    #[test]
    fn a_model_class_is_guessed_from_its_name() {
        let small = [
            "claude-haiku-4",
            "gpt-5-mini",
            "o4-mini",
            "gpt-5-nano",
            "gemini-2.5-flash-lite",
            "mistral-small-3",
            "meta/llama-3.1-8b-instruct",
            "qwen2.5-coder-1.5b",
            "phi-3-mini-4k",
            "llama3.2:3b",
        ];
        let large = [
            "claude-opus-4",
            "gemini-2.5-pro",
            "deepseek-v4-pro",
            "gemini-ultra",
            "mistral-large-2",
            "deepseek-reasoner",
            "deepseek-r1",
            "meta/llama-3.3-70b-instruct",
            "gpt-oss-120b",
            "nvidia/nemotron-70b",
        ];
        let medium = [
            "claude-sonnet-4",
            "gemini-2.5-flash",
            "deepseek-chat",
            "nvidia/llama-3.3-nemotron-super-49b-v1",
            "nvidia/nemotron-3-super-120b-a12b",
            "gpt-5",
            "kimi-k2",
            "qwen/qwen3-coder-480b-a35b-instruct",
            "glm-4.6",
        ];
        for model in small {
            assert_eq!(guess_class(model), ModelClass::Small, "{model}");
        }
        for model in large {
            assert_eq!(guess_class(model), ModelClass::Large, "{model}");
        }
        for model in medium {
            assert_eq!(guess_class(model), ModelClass::Medium, "{model}");
        }
        assert_eq!(ModelClass::parse("Small").unwrap(), ModelClass::Small);
        assert!(ModelClass::parse("huge").is_err());
    }

    #[test]
    fn a_declared_class_wins_and_class_is_a_selector() {
        let mut sonnet = engine("claude", "build", "subscription");
        sonnet.model = Some("claude-sonnet-4".into());
        assert_eq!(sonnet.class(), ModelClass::Medium, "guessed");
        sonnet.class = Some(ModelClass::Small);
        assert_eq!(sonnet.class(), ModelClass::Small, "declared wins");
        assert!(matches("class:small", &sonnet));
        assert!(!matches("class:large", &sonnet));
        assert!(check_selector("class:small").is_ok());
        assert!(check_selector("class:enormous").is_err());
        // With no model the name is what is guessed from.
        assert_eq!(
            engine("haiku", "chore", "free-tier").class(),
            ModelClass::Small
        );
    }

    fn task(id: &str, tier: &str, improvement: bool, claimed: Option<(&str, i64)>) -> crate::Task {
        let tags: Vec<&str> = if improvement {
            vec![IMPROVEMENT_TAG]
        } else {
            vec![]
        };
        crate::Task {
            order: crate::Order {
                id: id.into(),
                project_id: "demo".into(),
                issued_by: "boss".into(),
                assigned_to: None,
                created_at: Utc::now(),
                payload: serde_json::json!({ "tier": tier, "tags": tags }),
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
            },
            claims: claimed
                .map(|(agent, age)| crate::Claim {
                    order_id: id.into(),
                    agent: agent.into(),
                    claimed_at: Utc::now() - Duration::seconds(age),
                })
                .into_iter()
                .collect(),
            results: Vec::new(),
            reviews: Vec::new(),
            recommendations: Vec::new(),
            heartbeats: Vec::new(),
            releases: Vec::new(),
            kills: Vec::new(),
        }
    }

    #[test]
    fn the_width_cap_counts_current_claims_of_the_role_and_not_stale_ones() {
        let policy = Policy {
            width: BTreeMap::from([(Role::Build, 2), (Role::Chore, 1)]),
            ..Policy::default()
        };
        let stale = (crate::HEARTBEAT_STALE_MULTIPLE + 5) * crate::HEARTBEAT_INTERVAL_SECS;
        let dir = tempfile::tempdir().unwrap();
        let boss = person("boss", 1);
        let route = route(dir.path(), &[&boss]);
        let mut tasks = vec![
            task("b1", "build", true, Some(("wisp", 5))),
            task("b2", "build", true, Some(("fang", 5))),
            task("b-stale", "build", true, Some(("old", stale))),
            task("c1", "chore", true, Some(("wisp", 5))),
            // Not an improvement order: a person's own, never counted or capped.
            task("direct", "build", false, Some(("wisp", 5))),
            task("open-build", "build", true, None),
            task("open-chore", "chore", true, None),
            task("open-direct", "build", false, None),
        ];
        for task in &mut tasks {
            boss.sign_order(&mut task.order);
        }
        // A claimed order nobody signed is not an order anyone would act on, so it does
        // not count against the width either.
        let forged = task("forged", "build", true, Some(("wisp", 5)));
        assert_eq!(forged.order.signature, None);
        let honest = claimed_per_role(&route, &tasks);
        let mut with_forged = tasks.clone();
        with_forged.push(forged);
        assert_eq!(claimed_per_role(&route, &with_forged), honest);
        let counts = claimed_per_role(&route, &tasks);
        assert_eq!(
            counts.get(&Role::Build),
            Some(&2),
            "stale and direct are not counted"
        );
        assert_eq!(counts.get(&Role::Chore), Some(&1));
        let find = |id: &str| tasks.iter().find(|t| t.order.id == id).unwrap();
        let hold =
            width_hold(&route, &policy, &tasks, &find("open-build").order).expect("build is at 2");
        assert!(hold.contains("width for build is 2"), "{hold}");
        assert!(width_hold(&route, &policy, &tasks, &find("open-chore").order).is_some());
        assert_eq!(
            width_hold(&route, &policy, &tasks, &find("open-direct").order),
            None,
            "a person's own order is never capped"
        );
        // One fewer claimed and there is room; a role with no width is never held.
        let fewer: Vec<crate::Task> = tasks
            .iter()
            .filter(|t| t.order.id != "b2")
            .cloned()
            .collect();
        assert_eq!(
            width_hold(&route, &policy, &fewer, &find("open-build").order),
            None
        );
        assert_eq!(
            width_hold(
                &route,
                &Policy::default(),
                &tasks,
                &find("open-build").order
            ),
            None
        );
    }

    fn sized(name: &str, model: &str, tier: &str, paid: &str) -> Candidate {
        let mut found = engine(name, tier, paid);
        found.model = Some(model.into());
        found
    }

    fn fleet_for_team() -> Vec<Candidate> {
        vec![
            sized("opus", "claude-opus-4", "judge", "prepaid"),
            sized("pro", "deepseek-v4-pro", "judge", "prepaid"),
            sized(
                "nemotron",
                "nvidia/llama-3.3-nemotron-super-49b-v1",
                "build",
                "free-tier",
            ),
            sized("deepseek", "deepseek-chat", "build", "prepaid"),
            sized("haiku-local", "llama3.2:3b", "chore", "local"),
            sized("mini", "gpt-5-mini", "chore", "free-tier"),
        ]
    }

    fn list(policy: &Policy, role: Role) -> Vec<String> {
        policy.preferences(role).to_vec()
    }

    #[test]
    fn the_team_plans_large_builds_medium_and_does_chores_small() {
        let proposal = team(
            &fleet_for_team(),
            &["grouchly".into()],
            &TeamOptions::default(),
        );
        let policy = &proposal.policy;
        policy.check().unwrap();
        // Large judges plan and review; the free medium engines build, before the prepaid.
        assert_eq!(list(policy, Role::Plan)[0], "name:opus");
        assert_eq!(list(policy, Role::Review)[0], "name:opus");
        assert_eq!(list(policy, Role::Build)[0], "name:nemotron");
        assert_eq!(list(policy, Role::Chore)[0], "name:haiku-local");
        // The fallback is kept after the right size.
        assert!(list(policy, Role::Build).contains(&"name:opus".to_string()));
        assert!(list(policy, Role::Chore).contains(&"name:nemotron".to_string()));
        // Effort and width are the preset's.
        assert_eq!(policy.effort_for(Role::Plan), Effort::High);
        assert_eq!(policy.effort_for(Role::Build), Effort::Medium);
        assert_eq!(policy.effort_for(Role::Chore), Effort::Low);
        assert_eq!(policy.width_for(Role::Plan), Some(1));
        assert_eq!(policy.width_for(Role::Build), Some(3));
        assert_eq!(policy.width_for(Role::Chore), Some(4));
        assert_eq!(policy.adversary, AdversaryMode::Advisory);
        assert_eq!(policy.machines, ["grouchly"]);
        // Every engine placed has a reason that says its class and its effort.
        let build = proposal
            .reasons
            .iter()
            .find(|line| line.starts_with("nemotron first for build"))
            .expect("a reason for the top builder");
        assert!(
            build.contains("medium class") && build.contains("medium effort"),
            "{build}"
        );
        assert!(
            proposal
                .reasons
                .iter()
                .any(|line| line.contains("up to 3 at once"))
        );
    }

    #[test]
    fn the_teams_adversary_is_a_large_judge_of_another_family_than_the_top_builder() {
        // The top builder is deepseek-chat; the two large judges are deepseek-v4-pro (the
        // builder's family) and claude-opus (not). The adversary must be the latter even
        // though the former is listed first by every other ranking.
        let engines = vec![
            sized("pro", "deepseek-v4-pro", "judge", "local"),
            sized("opus", "claude-opus-4", "judge", "prepaid"),
            sized("deepseek", "deepseek-chat", "build", "free-tier"),
        ];
        let proposal = team(&engines, &[], &TeamOptions::default());
        assert_eq!(list(&proposal.policy, Role::Build)[0], "name:deepseek");
        let adversaries = list(&proposal.policy, Role::Adversary);
        assert_eq!(adversaries[0], "name:opus", "{adversaries:?}");
        assert!(adversaries.contains(&"name:pro".to_string()), "kept, last");
        let line = proposal
            .reasons
            .iter()
            .find(|line| line.starts_with("opus first for adversary"))
            .unwrap();
        assert!(
            line.contains("a different family (anthropic) from deepseek"),
            "{line}"
        );
        assert!(line.contains("high effort"), "{line}");
        assert_eq!(proposal.policy.effort_for(Role::Adversary), Effort::High);
    }

    #[test]
    fn subscription_roles_are_honoured_only_for_an_engine_with_a_weekly_cap() {
        let mut sonnet = sized("claude-sonnet", "claude-sonnet-4", "build", "subscription");
        let mut haiku = sized("claude-haiku", "claude-haiku-4", "chore", "subscription");
        let mut engines_with = |sonnet_cap: Option<u64>, haiku_cap: Option<u64>| {
            sonnet.weekly_requests = sonnet_cap;
            haiku.weekly_requests = haiku_cap;
            vec![sonnet.clone(), haiku.clone()]
        };
        // Protected, and nothing opted in: neither is used, and the reasons say why.
        let none = team(
            &engines_with(Some(200), Some(500)),
            &[],
            &TeamOptions::default(),
        );
        assert!(list(&none.policy, Role::Build).is_empty());
        assert!(list(&none.policy, Role::Chore).is_empty());
        assert!(
            none.reasons
                .iter()
                .any(|line| line.contains("claude-sonnet never")),
            "{:?}",
            none.reasons
        );

        let options = TeamOptions {
            subscription_roles: vec![Role::Chore, Role::Build, Role::Build],
            ..TeamOptions::default()
        };
        // Both capped: build gets sonnet, chore gets haiku; plan, review and the
        // adversary are not opted in, so they get nobody.
        let opted = team(&engines_with(Some(200), Some(500)), &[], &options);
        assert_eq!(
            opted.policy.subscription_roles,
            [Role::Build, Role::Chore],
            "sorted, once"
        );
        assert_eq!(list(&opted.policy, Role::Build)[0], "name:claude-sonnet");
        assert_eq!(list(&opted.policy, Role::Chore)[0], "name:claude-haiku");
        assert!(list(&opted.policy, Role::Review).is_empty());
        let line = opted
            .reasons
            .iter()
            .find(|line| line.starts_with("claude-haiku first for chore"))
            .unwrap();
        assert!(
            line.contains("small class") && line.contains("weekly cap of 500"),
            "{line}"
        );

        // Sonnet has no cap: the opt-in is not honoured for it, and the reason says so.
        let uncapped = team(&engines_with(None, Some(500)), &[], &options);
        assert!(!list(&uncapped.policy, Role::Build).contains(&"name:claude-sonnet".to_string()));
        assert_eq!(list(&uncapped.policy, Role::Chore)[0], "name:claude-haiku");
        assert!(
            uncapped.reasons.iter().any(|line| {
                line.contains("claude-sonnet not used for build")
                    && line.contains("weekly_requests")
            }),
            "{:?}",
            uncapped.reasons
        );
        // The rule is the policy's own, so a hand-set policy cannot get around it either.
        let policy = Policy {
            subscription_roles: vec![Role::Build],
            ..Policy::default()
        };
        sonnet.weekly_requests = None;
        assert!(
            policy
                .blocked_for(&sonnet, Work::Background, Some(Role::Build))
                .is_some()
        );
        sonnet.weekly_requests = Some(10);
        assert!(
            policy
                .blocked_for(&sonnet, Work::Background, Some(Role::Build))
                .is_none()
        );
        assert!(
            policy
                .blocked_for(&sonnet, Work::Background, Some(Role::Plan))
                .is_some()
        );
        assert!(policy.blocked(&sonnet, Work::Background).is_some());
    }

    #[test]
    fn team_options_replace_the_presets_width_and_effort() {
        let options = TeamOptions {
            width: BTreeMap::from([(Role::Build, 6)]),
            effort: BTreeMap::from([(Role::Build, Effort::High)]),
            ..TeamOptions::default()
        };
        let policy = team(&fleet_for_team(), &[], &options).policy;
        assert_eq!(policy.width_for(Role::Build), Some(6));
        assert_eq!(policy.width_for(Role::Chore), Some(4));
        assert_eq!(policy.effort_for(Role::Build), Effort::High);
        assert!(policy.check().is_ok());
        // The proposal survives a signed round trip.
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        assert!(set_policy(&route.communications, "demo", Some(policy.clone()), &josh).unwrap());
        assert_eq!(effective(&route.communications, "demo").0, policy);
    }

    #[test]
    fn a_step_records_its_effort_and_an_old_record_still_verifies() {
        let old = Step {
            step: "build".into(),
            role: Some("build".into()),
            at: Utc::now(),
            agent: "wisp".into(),
            machine: "grouchly".into(),
            engine: Some("nemotron".into()),
            model: None,
            cost_usd: None,
            order: None,
            effort: None,
            outcome: "done".into(),
        };
        assert!(serde_json::to_value(&old).unwrap().get("effort").is_none());
        let with = Step {
            effort: Some("medium".into()),
            ..old
        };
        assert_eq!(serde_json::to_value(&with).unwrap()["effort"], "medium");
        assert!(
            with.describe().contains("medium effort"),
            "{}",
            with.describe()
        );
    }

    #[test]
    fn a_subscription_opt_in_warns_when_the_engine_has_no_weekly_cap() {
        let mut sonnet = sized("claude-sonnet", "claude-sonnet-4", "build", "subscription");
        let policy = Policy {
            subscription_roles: vec![Role::Build, Role::Chore],
            ..Policy::default()
        };
        assert!(subscription_warnings(&Policy::default(), &[sonnet.clone()]).is_empty());
        let uncapped = subscription_warnings(&policy, &[sonnet.clone()]);
        assert!(
            uncapped
                .iter()
                .any(|line| line.contains("claude-sonnet") && line.contains("build, chore")),
            "{uncapped:?}"
        );
        assert!(uncapped.iter().any(|line| line.contains("changes nothing")));
        sonnet.weekly_requests = Some(200);
        assert!(subscription_warnings(&policy, &[sonnet]).is_empty());
        // No subscription at all: the opt-in does nothing, and says so.
        let none = subscription_warnings(&policy, &fleet_for_team());
        assert_eq!(none.len(), 1, "{none:?}");
    }

    // --- the preset keeps the master's security settings -----------------------------------

    fn hardened() -> Policy {
        let mut policy = Policy {
            never: vec!["name:claude".into()],
            never_applies_to: NeverScope::All,
            machines: vec!["grouchly".into()],
            caps_usd: BTreeMap::from([("build".to_string(), 5.0)]),
            protect_subscriptions: false,
            auto_merge: AutoMerge::LowRisk,
            adversary: AdversaryMode::Blocking,
            subscription_roles: vec![Role::Chore],
            ..Policy::default()
        };
        policy.set_adversary_engine("name:deepseek");
        policy
    }

    #[test]
    fn accepting_the_team_preset_keeps_what_the_master_set_for_security() {
        let current = hardened();
        let options = TeamOptions {
            subscription_roles: current.subscription_roles.clone(),
            ..TeamOptions::default()
        };
        let preset = team(&fleet_for_team(), &["wisp".into(), "fang".into()], &options).policy;
        assert_ne!(
            preset.machines, current.machines,
            "the preset names its own"
        );
        let merged = apply_team(&current, &preset);
        merged.check().unwrap();
        // What the preset is for.
        assert_eq!(list(&merged, Role::Plan), list(&preset, Role::Plan));
        assert_eq!(list(&merged, Role::Build), list(&preset, Role::Build));
        assert_eq!(merged.effort, preset.effort);
        assert_eq!(merged.width, preset.width);
        // What it must not touch.
        assert_eq!(merged.never, current.never);
        assert_eq!(merged.never_applies_to, NeverScope::All);
        assert_eq!(merged.auto_merge, AutoMerge::LowRisk);
        assert_eq!(merged.caps_usd, current.caps_usd);
        assert!(!merged.protect_subscriptions);
        assert_eq!(merged.adversary, AdversaryMode::Blocking);
        assert_eq!(merged.machines, ["grouchly"], "an existing where stays");
        assert_eq!(merged.subscription_roles, [Role::Chore]);
        assert_eq!(
            merged.adversary_engine(),
            preset.adversary_engine().or(current.adversary_engine())
        );

        // With no where of its own the preset's online machines are used.
        let open = Policy {
            machines: Vec::new(),
            ..current.clone()
        };
        assert_eq!(apply_team(&open, &preset).machines, preset.machines);
        // Subscription roles are the preset's only when the caller passed some.
        let asked = TeamOptions {
            subscription_roles: vec![Role::Build],
            ..TeamOptions::default()
        };
        let preset = team(&fleet_for_team(), &[], &asked).policy;
        assert_eq!(
            apply_team(&current, &preset).subscription_roles,
            [Role::Build]
        );
    }

    #[test]
    fn accepting_the_recommendation_keeps_what_the_master_set_for_security() {
        let current = hardened();
        let recommended = recommend(&fleet_for_team(), &["wisp".into()]).policy;
        let merged = answer_changes(ACCEPT_RECOMMENDED, &current, &recommended).unwrap();
        assert_eq!(list(&merged, Role::Build), list(&recommended, Role::Build));
        assert_eq!(merged.never, current.never);
        assert_eq!(merged.caps_usd, current.caps_usd);
        assert_eq!(merged.auto_merge, AutoMerge::LowRisk);
        assert_eq!(merged.adversary, AdversaryMode::Blocking);
        assert_eq!(merged.machines, ["grouchly"]);
        assert!(!merged.protect_subscriptions);
    }

    // --- rollback and deletion --------------------------------------------------------------

    #[test]
    fn an_older_signed_policy_put_back_or_a_deleted_one_does_not_roll_the_machine_back() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        let path = channel.join(ENGINE_POLICY);

        let strict = hardened();
        let lax = Policy::default();
        assert!(set_policy(channel, "demo", Some(lax.clone()), &josh).unwrap());
        let old = std::fs::read(&path).unwrap();
        assert_eq!(setting(channel, "demo").unwrap().seq, 1);
        assert!(set_policy(channel, "demo", Some(strict.clone()), &josh).unwrap());
        assert_eq!(setting(channel, "demo").unwrap().seq, 2);
        assert!(rollback_notice(channel, "demo").is_none());
        assert!(!ask_rollback(&route, &josh).unwrap(), "nothing to ask yet");

        // The older, genuinely signed file is put back: still the strict policy, and one
        // question - however often anyone looks.
        std::fs::write(&path, &old).unwrap();
        assert_eq!(effective(channel, "demo").0, strict);
        assert!(rollback_notice(channel, "demo").unwrap().contains("older"));
        assert!(ask_rollback(&route, &josh).unwrap());
        assert!(!ask_rollback(&route, &josh).unwrap());
        assert_eq!(
            crate::questions::list(&route)
                .iter()
                .filter(|(q, _)| q.id.starts_with("engine-policy-rollback-"))
                .count(),
            1
        );

        // Deleted: same.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(effective(channel, "demo").0, strict);
        assert!(rollback_notice(channel, "demo").is_some());

        // Signing the same policy again repairs the file, with a newer sequence.
        assert!(set_policy(channel, "demo", Some(strict.clone()), &josh).unwrap());
        assert_eq!(setting(channel, "demo").unwrap().seq, 3);
        assert!(rollback_notice(channel, "demo").is_none());
        assert_eq!(effective(channel, "demo").0, strict);
        // And going to a laxer policy on purpose still works: that is a newer signing.
        assert!(set_policy(channel, "demo", Some(lax.clone()), &josh).unwrap());
        assert_eq!(effective(channel, "demo").0, lax);
    }

    #[test]
    fn a_policy_signed_before_seq_existed_is_read_and_the_next_signing_numbers_past_it() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        // What the release before seq could write: only the fields it had.
        let legacy = Policy {
            never: vec!["name:claude".into()],
            machines: vec!["grouchly".into()],
            auto_merge: AutoMerge::LowRisk,
            ..Policy::default()
        };
        let mut old = PolicySetting {
            project_id: "demo".into(),
            policy: Some(legacy.clone()),
            set_at: Utc::now(),
            signed_by: "josh".into(),
            signature: String::new(),
            on_behalf_of: None,
            seq: 0,
            signature_v2: None,
        };
        old.signature = josh.sign_bytes(setting_payload(&old).as_bytes());
        let wire = serde_json::to_value(&old).unwrap();
        assert!(
            wire.get("seq").is_none(),
            "seq 0 stays off the wire: {wire}"
        );
        crate::atomic_json(&channel.join(ENGINE_POLICY), &old).unwrap();
        assert_eq!(effective(channel, "demo").0, legacy);
        assert!(set_policy(channel, "demo", Some(Policy::default()), &josh).unwrap());
        assert_eq!(setting(channel, "demo").unwrap().seq, 1);
    }

    // --- what a delegate cannot change --------------------------------------------------------

    #[test]
    fn a_delegate_cannot_change_the_adversary_mode_or_remove_its_role() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &bridge]);
        let channel = &route.communications;
        crate::delegation::grant(
            channel,
            "demo",
            &josh,
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        let strict = hardened();
        assert!(set_policy(channel, "demo", Some(strict.clone()), &josh).unwrap());
        let as_delegate =
            |policy: Policy| set_policy_as(channel, "demo", Some(policy), &bridge, Some("josh"));

        let off = Policy {
            adversary: AdversaryMode::Off,
            ..strict.clone()
        };
        let error = as_delegate(off).unwrap_err().to_string();
        assert!(
            error.contains("adversary mode") && error.contains("josh's own signature"),
            "{error}"
        );
        let mut no_role = strict.clone();
        no_role.prefer.remove("adversary");
        let error = as_delegate(no_role).unwrap_err().to_string();
        assert!(error.contains("removes the adversary role"), "{error}");
        let mut other_engine = strict.clone();
        other_engine.set_adversary_engine("name:claude");
        let error = as_delegate(other_engine).unwrap_err().to_string();
        assert!(error.contains("josh's own signature"), "{error}");
        let mut capped = strict.clone();
        capped.caps_usd.insert("adversary".into(), 0.01);
        assert!(as_delegate(capped).is_err(), "starving it is the same");
        let mut never = strict.clone();
        never.adversary_never = vec!["name:deepseek".into()];
        assert!(as_delegate(never).is_err());
        assert_eq!(effective(channel, "demo").0, strict, "nothing changed");

        // Anything else is still the delegate's to change.
        let mut other = strict.clone();
        other.never.push("name:grok".into());
        assert!(as_delegate(other.clone()).unwrap());
        assert_eq!(effective(channel, "demo").0, other);
        // The master changes the mode in their own name.
        let off = Policy {
            adversary: AdversaryMode::Off,
            ..other
        };
        assert!(set_policy(channel, "demo", Some(off.clone()), &josh).unwrap());
        assert_eq!(effective(channel, "demo").0, off);
        // Auto, from a delegate, is the engine policy going back to auto: the adversary's
        // terms are not part of it and stay as the master signed them.
        assert!(as_delegate_auto(channel, &bridge).unwrap());
        let (after, setting) = effective(channel, "demo");
        assert!(setting.is_some_and(|setting| setting.policy.is_none()));
        assert_eq!(after.adversary, AdversaryMode::Off);
        assert_eq!(after.adversary_engine(), Some("name:deepseek"));
    }

    /// A fleet with the master `josh` and a delegate `telegram-grouchly` who holds `improve`.
    fn with_a_delegate() -> (
        tempfile::TempDir,
        ProjectRoute,
        AgentIdentity,
        AgentIdentity,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let bridge = person("telegram-grouchly", 3);
        let route = route(dir.path(), &[&josh, &bridge]);
        crate::delegation::grant(
            &route.communications,
            "demo",
            &josh,
            "telegram-grouchly",
            &["improve".to_string()],
            None,
        )
        .unwrap();
        (dir, route, josh, bridge)
    }

    #[test]
    fn the_master_signs_the_adversary_policy_and_a_delegate_signed_one_is_ignored() {
        let (_dir, route, josh, bridge) = with_a_delegate();
        let channel = &route.communications;
        let mut strict = hardened();
        strict.adversary_agents = vec!["wisp".into()];
        strict.adversary_never = vec!["name:grok".into()];
        assert!(set_policy(channel, "demo", Some(strict.clone()), &josh).unwrap());
        let signed = adversary_setting(channel, "demo").expect("the master's file");
        assert_eq!(signed.signed_by, "josh");
        assert_eq!(signed.terms.mode, AdversaryMode::Blocking);
        assert_eq!(signed.terms.agents, ["wisp"]);
        assert_eq!(effective(channel, "demo").0, strict);
        let path = channel.join(ADVERSARY_POLICY);
        let good = std::fs::read(&path).unwrap();

        // The delegate - who holds `improve`, which is enough for the engine policy -
        // writes an adversary policy of their own, with a newer sequence number.
        let mut forged = AdversarySetting {
            project_id: "demo".into(),
            terms: AdversaryTerms {
                mode: AdversaryMode::Off,
                ..AdversaryTerms::default()
            },
            set_at: Utc::now(),
            signed_by: "telegram-grouchly".into(),
            signature: String::new(),
            seq: signed.seq + 1,
        };
        forged.sign(&bridge);
        crate::atomic_json(&path, &forged).unwrap();
        assert!(
            !forged.genuine(channel, "demo"),
            "a delegate is not the master"
        );
        assert_eq!(effective(channel, "demo").0, strict, "still the master's");

        // Claiming to be the master with the delegate's key does not verify either.
        let mut as_master = forged.clone();
        as_master.signed_by = "josh".into();
        as_master.sign(&bridge);
        crate::atomic_json(&path, &as_master).unwrap();
        assert!(!as_master.genuine(channel, "demo"));
        assert_eq!(
            effective(channel, "demo").0.adversary,
            AdversaryMode::Blocking
        );

        // The master's own file is honoured again once it is back; and the terms signed
        // for one project are no use in another.
        std::fs::write(&path, &good).unwrap();
        assert_eq!(effective(channel, "demo").0, strict);
        assert!(!signed.genuine(channel, "other"));
        // No delegation can reach it through `set_policy_as` either.
        let error = set_policy_as(
            channel,
            "demo",
            Some(Policy {
                adversary: AdversaryMode::Off,
                ..strict.clone()
            }),
            &bridge,
            Some("josh"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("josh's own signature"), "{error}");
        assert_eq!(effective(channel, "demo").0, strict);
    }

    #[test]
    fn a_delegates_engine_policy_cannot_touch_the_adversarys_selection_mode_or_budget() {
        let (_dir, route, josh, bridge) = with_a_delegate();
        let channel = &route.communications;
        let mut strict = hardened();
        strict.adversary_never = vec!["name:grok".into()];
        strict.caps_usd.insert("adversary".into(), 5.0);
        assert!(set_policy(channel, "demo", Some(strict.clone()), &josh).unwrap());
        let (in_force, _) = effective(channel, "demo");
        assert_eq!(in_force.adversary, AdversaryMode::Blocking);
        assert_eq!(in_force.adversary_engine(), Some("name:deepseek"));
        assert_eq!(in_force.cap(Role::Adversary), Some(5.0));

        // A delegate-signed engine policy - written straight to the file, the way a
        // compromised delegate would - that says everything it can about the adversary:
        // off, a different engine, a cap of nothing, and a `never` and `where` that match
        // every engine and machine.
        let mut hostile = strict.without_adversary();
        hostile.adversary = AdversaryMode::Off;
        hostile
            .prefer
            .insert("adversary".into(), vec!["name:claude".into()]);
        hostile.caps_usd.insert("adversary".into(), 0.0);
        hostile.never = vec!["name:deepseek".into(), "name:claude".into()];
        hostile.machines = vec!["nowhere".into()];
        let mut file = PolicySetting {
            project_id: "demo".into(),
            policy: Some(hostile),
            set_at: Utc::now(),
            signed_by: "telegram-grouchly".into(),
            signature: String::new(),
            on_behalf_of: Some("josh".into()),
            seq: 9,
            signature_v2: None,
        };
        file.sign(&bridge);
        assert!(genuine(channel, "demo", &file), "a valid delegate signing");
        crate::atomic_json(&channel.join(ENGINE_POLICY), &file).unwrap();

        let (read, _) = effective(channel, "demo");
        assert_eq!(
            read.never,
            ["name:deepseek", "name:claude"],
            "the engine policy took effect"
        );
        assert_eq!(read.machines, ["nowhere"]);
        // But the adversary is exactly what the master signed.
        assert_eq!(read.adversary, AdversaryMode::Blocking);
        assert_eq!(read.adversary_engine(), Some("name:deepseek"));
        assert_eq!(read.cap(Role::Adversary), Some(5.0));
        assert_eq!(read.adversary_never, ["name:grok"]);
        // ...and it is still ranked: neither `never` nor `where` reaches it.
        let engines = vec![
            judge("deepseek", "deepseek-chat", 3),
            judge("claude", "claude-sonnet", 3),
        ];
        let ranked = rank_adversary(&read, &[], &engines);
        assert_eq!(names(&ranked.ranking, &engines), ["deepseek", "claude"]);
    }

    #[test]
    fn an_older_adversary_policy_put_back_or_deleted_does_not_roll_the_machine_back() {
        let (_dir, route, josh, _bridge) = with_a_delegate();
        let channel = &route.communications;
        let path = channel.join(ADVERSARY_POLICY);
        let blocking = Policy {
            adversary: AdversaryMode::Blocking,
            ..Policy::default()
        };
        let off = Policy {
            adversary: AdversaryMode::Off,
            ..Policy::default()
        };
        assert!(set_policy(channel, "demo", Some(blocking.clone()), &josh).unwrap());
        let old = std::fs::read(&path).unwrap();
        assert_eq!(adversary_setting(channel, "demo").unwrap().seq, 1);
        assert!(set_policy(channel, "demo", Some(off.clone()), &josh).unwrap());
        assert_eq!(adversary_setting(channel, "demo").unwrap().seq, 2);
        assert!(rollback_notice(channel, "demo").is_none());

        // The earlier, genuinely signed file is put back: the adversary stays off here,
        // and the master is asked once.
        std::fs::write(&path, &old).unwrap();
        assert_eq!(effective(channel, "demo").0.adversary, AdversaryMode::Off);
        let notice = rollback_notice(channel, "demo").unwrap();
        assert!(notice.contains("adversary policy"), "{notice}");
        assert!(ask_rollback(&route, &josh).unwrap());
        assert!(!ask_rollback(&route, &josh).unwrap());
        assert_eq!(
            crate::questions::list(&route)
                .iter()
                .filter(|(q, _)| q.id.starts_with("adversary-policy-rollback-"))
                .count(),
            1
        );

        // Deleted: the same. Removing the file does not turn the check back on or off.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(effective(channel, "demo").0.adversary, AdversaryMode::Off);
        assert!(rollback_notice(channel, "demo").is_some());

        // Signing again, as the master, supersedes it with a newer sequence.
        assert!(set_policy(channel, "demo", Some(off.clone()), &josh).unwrap());
        assert_eq!(adversary_setting(channel, "demo").unwrap().seq, 3);
        assert!(rollback_notice(channel, "demo").is_none());
        // Putting the engine policy back to auto leaves the adversary's terms alone.
        set_policy(channel, "demo", None, &josh).unwrap();
        assert_eq!(effective(channel, "demo").0.adversary, AdversaryMode::Off);
    }

    fn as_delegate_auto(channel: &Path, bridge: &AgentIdentity) -> Result<bool> {
        set_policy_as(channel, "demo", None, bridge, Some("josh"))
    }

    // --- a mixed fleet: v0.5.17 machines read the same file ----------------------------------

    /// The v0.5.17 `Policy`, copied: seven fields, no adversary, effort, width or
    /// subscription roles.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct OldPolicy {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        prefer: BTreeMap<String, Vec<String>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        never: Vec<String>,
        #[serde(default, rename = "where", skip_serializing_if = "Vec::is_empty")]
        machines: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        caps_usd: BTreeMap<String, f64>,
        #[serde(default = "yes")]
        protect_subscriptions: bool,
        #[serde(default)]
        never_applies_to: NeverScope,
        #[serde(default, skip_serializing_if = "AutoMerge::is_none")]
        auto_merge: AutoMerge,
    }

    impl OldPolicy {
        /// v0.5.17's `Policy::check`: four roles, and no `class:` selector.
        fn check(&self) -> bool {
            let role =
                |role: &String| ["plan", "build", "review", "chore"].contains(&role.as_str());
            let selector = |selector: &String| {
                !selector.trim().starts_with("class:") && check_selector(selector).is_ok()
            };
            self.prefer
                .iter()
                .all(|(name, list)| role(name) && list.iter().all(selector))
                && self.never.iter().chain(&self.machines).all(selector)
                && self.caps_usd.keys().all(role)
        }
    }

    /// The v0.5.17 `PolicySetting`, copied: no `seq`, no second signature.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct OldPolicySetting {
        project_id: String,
        #[serde(default)]
        policy: Option<OldPolicy>,
        set_at: DateTime<Utc>,
        signed_by: String,
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        on_behalf_of: Option<String>,
    }

    /// v0.5.17's `setting_payload`, copied.
    fn old_payload(setting: &OldPolicySetting) -> String {
        let mut payload = format!(
            "ferryman-engine-policy-v1\n{}\n{}\n{}",
            setting.project_id,
            setting.set_at.to_rfc3339(),
            serde_jcs::to_string(&setting.policy).unwrap_or_default()
        );
        if let Some(principal) = &setting.on_behalf_of {
            payload.push_str(&format!("\nfor:{principal}"));
        }
        payload
    }

    /// What a v0.5.17 machine makes of the channel's policy file: the setting if it parses,
    /// verifies against the roster and passes its own check; else nothing, which is auto.
    fn old_machine_reads(channel: &Path) -> Option<OldPolicySetting> {
        let old: OldPolicySetting =
            serde_json::from_slice(&std::fs::read(channel.join(ENGINE_POLICY)).ok()?).ok()?;
        let roster = crate::read_agent_roster(channel).ok()?;
        (old.policy.as_ref().is_none_or(OldPolicy::check)
            && crate::check_signature(
                Some(&old.signed_by),
                Some(&old.signature),
                &old_payload(&old),
                &roster,
            ) == SignatureCheck::Valid)
            .then_some(old)
    }

    /// The policy the master signs once this release has put a Blocking adversary, an
    /// adversary engine, an effort, a width, a subscription role and a `class:` selector on
    /// top of what v0.5.17 knew.
    fn upgraded_policy() -> Policy {
        let mut policy = hardened();
        policy.never.push("class:small".into());
        policy.caps_usd.insert("adversary".into(), 2.0);
        policy.effort.insert(Role::Build, Effort::High);
        policy.width.insert(Role::Build, 3);
        policy
    }

    #[test]
    fn a_v0_5_17_machine_still_obeys_a_policy_signed_with_the_new_fields() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        let policy = upgraded_policy();
        policy.check().unwrap();
        assert!(set_policy(channel, "demo", Some(policy.clone()), &josh).unwrap());

        // The old machine verifies the signature and passes its own check...
        let old = old_machine_reads(channel).expect("the old machine accepts it");
        let seen = old.policy.unwrap();
        // ...and keeps everything it understands, minus only what it could not parse.
        assert_eq!(
            seen.never,
            ["name:claude"],
            "the class selector is not its to read"
        );
        assert_eq!(seen.machines, ["grouchly"]);
        assert_eq!(seen.caps_usd, BTreeMap::from([("build".to_string(), 5.0)]));
        assert!(!seen.protect_subscriptions);
        assert_eq!(seen.never_applies_to, NeverScope::All);
        assert_eq!(seen.auto_merge, AutoMerge::LowRisk);
        assert!(!seen.prefer.contains_key("adversary"), "{:?}", seen.prefer);

        // A new machine reads all of it.
        let (read, set) = effective(channel, "demo");
        assert_eq!(read, policy);
        assert_eq!(read.adversary, AdversaryMode::Blocking);
        assert!(set.unwrap().signature_v2.is_some());

        // The file says so: the v1 view in `policy`, the whole of it in `policy_v2` - which
        // has nothing about the adversary, that being the master's own file.
        let wire: serde_json::Value =
            serde_json::from_slice(&std::fs::read(channel.join(ENGINE_POLICY)).unwrap()).unwrap();
        assert!(wire["policy"].get("adversary").is_none(), "{wire}");
        assert!(wire["policy_v2"].get("adversary").is_none(), "{wire}");
        assert!(wire["policy_v2"]["prefer"].get("adversary").is_none());
        assert!(wire["policy_v2"]["caps_usd"].get("adversary").is_none());
        assert_eq!(wire["seq"], 1);
        let adversary: serde_json::Value =
            serde_json::from_slice(&std::fs::read(channel.join(ADVERSARY_POLICY)).unwrap())
                .unwrap();
        assert_eq!(adversary["terms"]["mode"], "blocking", "{adversary}");
        assert_eq!(adversary["terms"]["cap_usd"], 2.0, "{adversary}");

        // A policy of only what v0.5.17 knew is the file v0.5.17 wrote, plus two lines.
        let plain = Policy {
            never: vec!["name:claude".into()],
            ..Policy::default()
        };
        assert!(set_policy(channel, "demo", Some(plain.clone()), &josh).unwrap());
        let wire: serde_json::Value =
            serde_json::from_slice(&std::fs::read(channel.join(ENGINE_POLICY)).unwrap()).unwrap();
        assert!(wire.get("policy_v2").is_none(), "{wire}");
        assert_eq!(
            old_machine_reads(channel).unwrap().policy.unwrap().never,
            ["name:claude"]
        );
        assert_eq!(effective(channel, "demo").0, plain);
        // And auto.
        assert!(set_policy(channel, "demo", None, &josh).unwrap());
        assert!(old_machine_reads(channel).is_some_and(|old| old.policy.is_none()));
    }

    #[test]
    fn the_new_fields_and_the_sequence_cannot_be_forged_or_stripped_on_a_new_machine() {
        let dir = tempfile::tempdir().unwrap();
        let (josh, grouchly) = (person("josh", 1), person("grouchly", 2));
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;
        let strict = upgraded_policy();
        assert!(set_policy(channel, "demo", Some(strict.clone()), &josh).unwrap());
        let good = read_file_setting(channel).unwrap();
        assert!(genuine(channel, "demo", &good));

        // The adversary switched off, with every signature left as it was.
        let mut off = good.clone();
        off.policy.as_mut().unwrap().adversary = AdversaryMode::Off;
        assert!(
            !genuine(channel, "demo", &off),
            "the v1 signature still holds; v2 does not"
        );
        // The sequence number changed.
        let mut renumbered = good.clone();
        renumbered.seq = 9;
        assert!(!genuine(channel, "demo", &renumbered));
        // The v2 signature taken off, so only the v1 view is signed.
        let mut stripped = good.clone();
        stripped.signature_v2 = None;
        assert!(
            !genuine(channel, "demo", &stripped),
            "a Blocking policy needs its v2"
        );
        // A v2 signature by someone else on the roster.
        let mut other = good.clone();
        other.signature_v2 = Some(grouchly.sign_bytes(setting_payload_v2(&other).as_bytes()));
        assert!(!genuine(channel, "demo", &other));
        // A selector added to the policy in the file, under both signatures as they were.
        let mut weaker = good.clone();
        weaker
            .policy
            .as_mut()
            .unwrap()
            .never
            .push("name:grok".into());
        assert!(!genuine(channel, "demo", &weaker));

        // Taken down to exactly the v1 view - no `policy_v2`, no `seq`, no v2 - the file is
        // what an old master could have signed. A machine that has seen the newer one
        // refuses it as an older signing and keeps the strict policy.
        let downgraded = PolicySetting {
            policy: Some(strict.v1()),
            seq: 0,
            signature_v2: None,
            ..good.clone()
        };
        assert!(
            genuine(channel, "demo", &downgraded),
            "it is a valid v1 setting"
        );
        assert_eq!(effective(channel, "demo").0, strict);
        crate::atomic_json(&channel.join(ENGINE_POLICY), &downgraded).unwrap();
        assert_eq!(effective(channel, "demo").0, strict, "not the downgrade");
        assert!(rollback_notice(channel, "demo").is_some());
    }

    #[test]
    fn a_v1_only_policy_is_warned_about_when_a_member_that_signs_v2_is_on_the_roster() {
        let dir = tempfile::tempdir().unwrap();
        let (josh, grouchly) = (person("josh", 1), person("grouchly", 2));
        let route = route(dir.path(), &[&josh, &grouchly]);
        let channel = &route.communications;
        let mut old = OldPolicySetting {
            project_id: "demo".into(),
            policy: Some(OldPolicy {
                prefer: BTreeMap::new(),
                never: vec!["name:claude".into()],
                machines: Vec::new(),
                caps_usd: BTreeMap::new(),
                protect_subscriptions: true,
                never_applies_to: NeverScope::Background,
                auto_merge: AutoMerge::None,
            }),
            set_at: Utc::now(),
            signed_by: "josh".into(),
            signature: String::new(),
            on_behalf_of: None,
        };
        old.signature = josh.sign_bytes(old_payload(&old).as_bytes());
        crate::atomic_json(&channel.join(ENGINE_POLICY), &old).unwrap();
        assert!(setting(channel, "demo").is_some_and(|read| read.signature_v2.is_none()));
        assert!(
            mixed_fleet_warning(&route).is_none(),
            "nobody here signs v2 yet"
        );

        // A member that signs inventories as this release does joins the fleet.
        crate::receipts::refresh_engines(
            &route,
            &grouchly,
            "grouchly-machine",
            "0.5.18",
            vec![crate::receipts::EngineReport {
                name: "deepseek".into(),
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
        let warning = mixed_fleet_warning(&route).expect("a v1-only policy in a mixed fleet");
        assert!(warning.contains("v1-only"), "{warning}");
        assert!(
            warning.contains("grouchly"),
            "names who signs v2: {warning}"
        );
        assert!(
            warning.contains("Mixed fleets"),
            "points at the docs: {warning}"
        );

        // Signing it again from a current ferry gives it a sequence number and a v2
        // signature, and the warning goes.
        let (read, _) = effective(channel, "demo");
        assert!(set_policy(channel, "demo", Some(read.clone()), &josh).unwrap());
        assert!(setting(channel, "demo").is_some_and(|read| read.signature_v2.is_some()));
        assert!(mixed_fleet_warning(&route).is_none());
    }

    #[test]
    fn a_policy_signed_by_v0_5_17_verifies_on_a_new_machine() {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let route = route(dir.path(), &[&josh]);
        let channel = &route.communications;
        let mut old = OldPolicySetting {
            project_id: "demo".into(),
            policy: Some(OldPolicy {
                prefer: BTreeMap::from([("build".to_string(), vec!["name:nemotron".to_string()])]),
                never: vec!["name:claude".into()],
                machines: vec!["grouchly".into()],
                caps_usd: BTreeMap::from([("build".to_string(), 5.0)]),
                protect_subscriptions: true,
                never_applies_to: NeverScope::All,
                auto_merge: AutoMerge::LowRisk,
            }),
            set_at: Utc::now(),
            signed_by: "josh".into(),
            signature: String::new(),
            on_behalf_of: None,
        };
        old.signature = josh.sign_bytes(old_payload(&old).as_bytes());
        crate::atomic_json(&channel.join(ENGINE_POLICY), &old).unwrap();

        let read = setting(channel, "demo").expect("a v0.5.17 signature verifies here");
        assert_eq!(read.seq, 0);
        assert!(read.signature_v2.is_none());
        let (policy, _) = effective(channel, "demo");
        assert_eq!(policy.never, ["name:claude"]);
        assert_eq!(policy.machines, ["grouchly"]);
        assert_eq!(policy.auto_merge, AutoMerge::LowRisk);
        assert_eq!(policy.adversary, AdversaryMode::Advisory);
        // The next signing numbers past it and is read by both generations.
        let mut next = policy;
        next.never.push("name:grok".into());
        assert!(set_policy(channel, "demo", Some(next.clone()), &josh).unwrap());
        assert_eq!(setting(channel, "demo").unwrap().seq, 1);
        assert_eq!(effective(channel, "demo").0, next);
        assert_eq!(
            old_machine_reads(channel).unwrap().policy.unwrap().never,
            ["name:claude", "name:grok"]
        );
    }
}

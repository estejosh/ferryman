//! The smart router, part 2: choosing the engine.
//!
//! The rule is **use the cheapest engine that will most likely do it well**, and escalate
//! only when a cheaper engine has failed at that kind of work. Part 1 decided what an engine
//! can do ([`crate::capability`]) and what an order needs ([`crate::work`]); this decides
//! which engine gets it, and writes down why.
//!
//! # What runs before any scoring
//!
//! [`route`] starts from [`crate::policy::rank`], so everything the engine policy already
//! decides is decided first and exactly as before: the `never` list, `protect_subscriptions`
//! and `subscription_roles` (with their weekly caps), `caps_usd` (checked by the caller),
//! `where`, an engine that is out of credit, and the tiers - a chore engine never builds, a
//! demoted engine only does chore work, review is a judge's alone. The adversary is never
//! routed: [`Role::Adversary`] is returned in its own policy order whatever the policy says.
//! Scoring only ever chooses among engines that ranking let through.
//!
//! # The filters the router adds
//!
//! - **Modalities.** The engine must have every modality the work needs; code work needs
//!   `code`, which only a `cli` engine can have. An engine whose profile is empty (a hand
//!   built candidate, or a worker that published none) counts as text-only.
//! - **HTTP engines are text only.** An `http` engine is asked once, in text, and answers in
//!   text: `chat_body` sends no images, audio or files. So an `http` engine is never given
//!   work that needs anything but `text`, whatever its profile says - a `vision` guessed
//!   from a model name, or even declared, would still receive no image. To route vision work,
//!   point a `cli` engine at the model and declare `vision` on it. (Sending images to an
//!   endpoint - OpenAI-style `image_url` parts - is a separate feature; until it exists this
//!   rule is the honest one.)
//! - **Context.** An engine whose window is known and smaller than the work wants is out. An
//!   unknown window is not a reason to exclude.
//! - **Code needs an engine that can edit files, unless there is none.** When no engine the
//!   policy lets through has `code` (a fleet of `http` engines only), code work is not
//!   held: the router drops the `code` requirement, as builds on such a fleet always ran,
//!   and the reason says so. With one cli engine up, http engines are never given code work.
//! - **Planning** prefers a judge-tier engine only as a tie-break (the existing rule: a plan
//!   a judge wrote needs no second reading); a builder the operator listed, or one that is
//!   cheaper and sufficient, can plan, marked unreviewed as before.
//! - **Escalation.** An engine that already failed this order (a result of this worker's
//!   own, refuted by its own evidence or sent back with changes requested; an engine is the
//!   engine of one agent on one machine, so another machine's `claude` failing says nothing
//!   about this one) is left out of the sufficient set, and the next engine is *preferred*
//!   to have a higher success estimate than the failed one had: that is a bar the sufficient
//!   set must clear, not a rule. When no engine clears it the highest estimate wins as
//!   always, even at or below the failed one's; and when the failed engines are the only
//!   ones that can do the work, the likeliest of them is tried again, and the reason says
//!   so, rather than the order waiting for an engine that is never coming. The estimate to
//!   beat is worked out from this worker's own ledger, never read from a result's payload,
//!   which anyone who can write one could set to 1.0.
//! - **Opus.** In smart background work an engine whose model is Claude Opus is left out
//!   unless the role's prefer list names it (`name:`, `model:` or its bare name; `paid:` and
//!   `class:` selectors do not count). Opus has a profile, so it scores well when it is
//!   named or when work is asked for directly, but the router does not spend it by itself.
//! - **Work that edits files** (see `work::routing_needs`) needs `code` whatever its kind:
//!   background build and chore orders, and any order with declared `touches` or that
//!   requires changes, so a text-only engine is not sent an order it can only fail.
//!
//! # The success estimate
//!
//! For one engine and one kind of work, `p` is a Beta posterior. Its prior mean comes from
//! one of two places.
//!
//! **A model the router knows.** [`crate::models`] holds a curated table of model families
//! (Claude opus, sonnet and haiku, GPT-5 and codex, Gemini, DeepSeek, Nemotron, Qwen, GLM,
//! Llama, Mistral, Kimi) with a conservative prior for each kind of work, so Claude Haiku
//! starts well on chores and not on plans, and a 14b Qwen starts as a fair writer and not
//! a reviewer. The engine's model string is matched (its name only when it has no model).
//! When a model matches, **the profile wins**: the engine's size class is not used (it is a
//! guess made from the same name), and large work takes 0.05 off a medium model and 0.10
//! off a small one. Declared or guessed strengths still add 0.05 each, to 0.10, for the kinds they
//! help, except the tags the profile has already priced in, so a name is not counted twice.
//!
//! **A model it does not know.** The engine's size class sets the prior, exactly as it
//! always did: large 0.80, medium 0.70, small 0.55, plus 0.05 for every strength tag that
//! matches the kind (`code` for code-change, `tests` and `code` for tests, `docs`, `review`
//! and `reasoning`, ...), at most 0.10; minus 0.10 for every class the engine is below the
//! size of the work (a small engine on large work). An operator's declared `class` and
//! `strengths` count here in full.
//!
//! Either prior counts for [`PRIOR_WEIGHT`] observations. The evidence is the worker's
//! ledger of this engine's results for this kind, verified or refuted by the worker's own
//! checks, each weighted by `0.5^(age / 14 days)` so that old results fade: [`Outcome`].
//! `p = (prior * 4 + verified) / (4 + verified + refuted)`. So the table only says where a
//! model starts; its own results move it from there.
//!
//! `ferry route simulate` and `explain` say which it was beside every `p`: `p 0.87 (model
//! profile: claude-sonnet)` or `p 0.70 (class medium)`, with the ledger's count once it has
//! one.
//!
//! # The threshold
//!
//! Review and plan need 0.80 ([`REASONING_THRESHOLD`]): only an engine that is actually
//! good at judging or planning gets that work, and a medium one that is not proven must
//! earn it. Docs, chore, tests and research need 0.70 ([`TEXT_THRESHOLD`]), so a free
//! engine that writes well does that work from the start and loses it as soon as its results
//! are refuted. Code changes, translation and media need 0.75 ([`DEFAULT_THRESHOLD`]).
//! Large work of any kind adds 0.05 ([`LARGE_WORK_MARGIN`]) to its default. A threshold the
//! policy sets for a kind is the operator's word and is used as it is, large work or not.
//!
//! # The expected cost
//!
//! One call is estimated at 3k/1k, 12k/3k or 48k/10k tokens in/out for small, medium and
//! large work (more input when the work wants a bigger context), times the engine's price.
//!
//! - local and free-tier engines: 0;
//! - a free tier that asked for money (flagged): priced as an unpriced paid engine, until
//!   the flag lapses;
//! - a priced engine: its price;
//! - an **unpriced** paid engine (prepaid or unknown, no `cost_*` declared) is not free: it
//!   is assumed to cost [`ASSUMED_COST`] - $5 in / $25 out per million tokens, a frontier
//!   model's list price - so a declared price always beats a guess;
//! - a subscription costs nothing per call, but its scarcity is priced: [`SCARCITY_BASE_USD`]
//!   scaled up to ten times as the weekly request cap runs down (`1 + 9 * (1 - left)^2`).
//!   With no cap known, half is assumed to be left. It is priced **per request, against its
//!   cap**: 300 a week is the reference, so a request on a 2000 a week cap is about 6.7 times
//!   cheaper, and with two subscriptions that both clear the bar the bigger cap is the
//!   cheaper to use up and takes the work. The smaller one only gets what the bigger one does
//!   not clear.
//!
//! # The choice
//!
//! The *sufficient set* is every engine with `p` at or above the threshold for the kind
//! ([`default_threshold`]: 0.80 for review and plan, 0.70 for docs, chore, tests and
//! research, 0.75 for the rest, and 0.05 more for large work; `thresholds` in the policy
//! per kind, used exactly as set) - and above the failed engine's `p` when escalating. The
//! winner is the cheapest of them. Costs within 10% (or half a tenth of a cent) of the
//! cheapest count as tied, and ties go to the operator's **bias** (the policy's `bias`
//! weights, then the engine's place in the role's `prefer` list), then to the engine that
//! costs least in kind: **truly free (local, free tier) before a subscription (nothing per
//! call, but a capped week) before paid**; then the nearer tier, then the **higher `p`**
//! (within 0.005), then the faster engine, then the order the policy and the engine list
//! already gave (how engines nothing else distinguishes were always told apart, so a fleet
//! of look-alikes behaves as it did), and last the name. With an empty sufficient set the
//! winner is the highest `p` (within 0.005, the cheaper) *of the engines that can do the
//! work* - which, on a retry, may be at or below the `p` of the engine that failed: an
//! escalation is preferred, never required (see Escalation above). Bias never lets a dearer
//! engine beat a cheaper sufficient one; to force an order use `routing = "ordered"`.
//!
//! # Explainability
//!
//! [`route`] returns a [`Decision`]: every candidate with its `p`, price and, when it was
//! left out, why; the winner; and one line - `nvidia: free, p 0.81 for docs >= 0.70,
//! cheapest sufficient`. Workers record it beside the step and in the result;
//! `ferry route explain`, `ferry route simulate` and the dashboard show it.

use std::cmp::Ordering;

use chrono::{DateTime, Datelike, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    capability::{Cost, Modality},
    models,
    policy::{Candidate, ModelClass, Policy, Role, Routing, Work, rank},
    work::{Needs, Size, WorkKind, resolve_modalities},
};

/// The success probability an engine must reach to count as sufficient, unless the policy
/// says otherwise for the kind: for work that changes code, translation, and media.
pub const DEFAULT_THRESHOLD: f64 = 0.75;
/// The same for work whose result is words (docs, research) and for the small jobs a
/// person can check at a glance (chores, tests). A free engine that writes well, such as
/// NVIDIA's nemotron, is sufficient for these from the start, and the ledger takes it out
/// of the running the moment it is refuted; a small engine still has to earn it.
pub const TEXT_THRESHOLD: f64 = 0.70;
/// For review and plan: judging and planning are where a weak engine does the most harm
/// quietly, so only an engine that is actually good at them - a large one, or a model whose
/// profile says so - gets that work until another has proved itself.
pub const REASONING_THRESHOLD: f64 = 0.80;
/// Added to a kind's default threshold for large work of any kind: a long job is a bigger
/// loss when it fails.
pub const LARGE_WORK_MARGIN: f64 = 0.05;

/// The threshold for `kind` at `size` when the policy sets none.
#[must_use]
pub fn default_threshold(kind: WorkKind, size: Size) -> f64 {
    let base = match kind {
        WorkKind::Review | WorkKind::Plan => REASONING_THRESHOLD,
        WorkKind::Docs | WorkKind::Chore | WorkKind::Tests | WorkKind::Research => TEXT_THRESHOLD,
        _ => DEFAULT_THRESHOLD,
    };
    round3(if size == Size::Large {
        base + LARGE_WORK_MARGIN
    } else {
        base
    })
}

/// How long it takes a ledger result to count for half as much.
pub const HALF_LIFE_DAYS: f64 = 14.0;
/// How many observations the class prior is worth.
pub const PRIOR_WEIGHT: f64 = 4.0;
/// Added to the prior for each strength tag that matches the kind of work.
pub const STRENGTH_BONUS: f64 = 0.05;
/// The most the matching strengths add.
pub const STRENGTH_CAP: f64 = 0.10;
/// Taken off the prior for each class an engine is below the size of the work.
pub const SIZE_PENALTY: f64 = 0.10;
/// What an unpriced paid engine is assumed to cost: a frontier model's list price.
pub const ASSUMED_COST: Cost = Cost {
    per_call_usd: 0.0,
    per_mtok_in_usd: 5.0,
    per_mtok_out_usd: 25.0,
};
/// What one call on a subscription with its whole weekly cap left is worth, in dollars,
/// when the cap is [`SCARCITY_REFERENCE_CAP`] requests a week.
pub const SCARCITY_BASE_USD: f64 = 0.02;
/// The weekly request cap [`SCARCITY_BASE_USD`] is for. A request on a bigger cap uses up a
/// smaller share of the week, so it is worth proportionally less: at 2000 a week a request
/// is about 6.7 times cheaper than at 300, and a subscription with a small cap is the one
/// to keep for the work only it clears.
pub const SCARCITY_REFERENCE_CAP: f64 = 300.0;
/// Costs this close (dollars) to the cheapest are tied, whatever their size.
pub const TIE_ABSOLUTE_USD: f64 = 0.0005;
/// Costs within this share of the cheapest are tied.
pub const TIE_RELATIVE: f64 = 0.10;
/// Success estimates this close are tied when none is sufficient.
pub const P_TIE: f64 = 0.005;
/// The most candidates a recorded decision keeps (the ones that mattered, best first).
pub const MAX_RECORDED: usize = 12;

// --- the ledger: how an engine's work of each kind has turned out -------------------------

/// How one engine's work of one kind has turned out: verified and refuted results,
/// age-weighted, in thousandths of a result so the figure signs and compares exactly.
/// Published (v2-only) inside the engine's trust line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// The kind of work: `docs`, `code-change`, ...
    pub kind: String,
    /// Results the worker's checks agreed with, as of [`Self::at`], in thousandths.
    pub verified_milli: u64,
    /// Results the worker's checks refuted, as of [`Self::at`], in thousandths.
    pub refuted_milli: u64,
    /// When the weights were last brought up to date.
    pub at: DateTime<Utc>,
}

/// The share of a result's weight left after `age`: 1 at once, a half after
/// [`HALF_LIFE_DAYS`]. A clock that went backwards counts as no time.
#[must_use]
pub fn decay(age: Duration) -> f64 {
    let days = age.num_seconds() as f64 / 86_400.0;
    if days <= 0.0 {
        1.0
    } else {
        0.5_f64.powf(days / HALF_LIFE_DAYS)
    }
}

impl Outcome {
    /// The weights as of `now`: (verified, refuted), in results.
    #[must_use]
    pub fn weights(&self, now: DateTime<Utc>) -> (f64, f64) {
        let fade = decay(now.signed_duration_since(self.at));
        (
            self.verified_milli as f64 / 1000.0 * fade,
            self.refuted_milli as f64 / 1000.0 * fade,
        )
    }

    /// Count one result as of `now`, after fading what was counted before.
    pub fn record(&mut self, verified: bool, now: DateTime<Utc>) {
        let (v, r) = self.weights(now);
        let (v, r) = if verified { (v + 1.0, r) } else { (v, r + 1.0) };
        self.verified_milli = (v * 1000.0).round() as u64;
        self.refuted_milli = (r * 1000.0).round() as u64;
        if now > self.at {
            self.at = now;
        }
    }

    /// The share of decided results that were verified, and how many are counted, as of
    /// `now`. `None` before anything is counted.
    #[must_use]
    pub fn rate(&self, now: DateTime<Utc>) -> Option<(f64, f64)> {
        let (v, r) = self.weights(now);
        (v + r > 0.001).then(|| (v / (v + r), v + r))
    }
}

/// Count one verified (`true`) or refuted (`false`) result for `kind` in `list`.
/// Kinds that have faded to nothing are dropped, so the list stays short.
pub fn record_outcome(list: &mut Vec<Outcome>, kind: &str, verified: bool, now: DateTime<Utc>) {
    match list.iter_mut().find(|outcome| outcome.kind == kind) {
        Some(outcome) => outcome.record(verified, now),
        None => {
            let mut outcome = Outcome {
                kind: kind.to_string(),
                verified_milli: 0,
                refuted_milli: 0,
                at: now,
            };
            outcome.record(verified, now);
            list.push(outcome);
        }
    }
    list.retain(|outcome| outcome.rate(now).is_some());
}

/// One engine's best kinds as (kind, share verified, results counted), most decided results
/// first.
#[must_use]
pub fn top_kinds(
    outcomes: &[Outcome],
    now: DateTime<Utc>,
    limit: usize,
) -> Vec<(String, f64, f64)> {
    let mut found: Vec<(String, f64, f64)> = outcomes
        .iter()
        .filter_map(|outcome| {
            outcome
                .rate(now)
                .map(|(rate, decided)| (outcome.kind.clone(), rate, decided))
        })
        .collect();
    found.sort_by(|a, b| {
        b.2.total_cmp(&a.2)
            .then(b.1.total_cmp(&a.1))
            .then(a.0.cmp(&b.0))
    });
    found.truncate(limit);
    found
}

// --- the estimate --------------------------------------------------------------------------

/// The strength tags that help with a kind of work.
#[must_use]
pub fn strength_tags(kind: WorkKind) -> &'static [&'static str] {
    match kind {
        WorkKind::CodeChange => &["code"],
        WorkKind::Tests => &["tests", "code"],
        WorkKind::Docs => &["docs"],
        WorkKind::Review => &["review", "reasoning"],
        WorkKind::Plan => &["reasoning"],
        WorkKind::Research => &["reasoning", "long-context"],
        WorkKind::Translate => &["translation"],
        _ => &[],
    }
}

/// How an engine's success estimate for some work came about.
#[derive(Debug, Clone, PartialEq)]
pub struct Estimate {
    /// The probability the engine does this work well.
    pub p: f64,
    /// Before the ledger: the model's profile or the class, strengths and size.
    pub prior: f64,
    /// The ledger's age-weighted verified and refuted results for this kind.
    pub verified: f64,
    pub refuted: f64,
    /// Where the prior came from, in words: `model profile: claude-sonnet` or `class
    /// medium`, and the ledger's count once there is one.
    pub basis: String,
}

/// The prior mean for an engine on work: the profile of its model when the router knows
/// the model, else its class, plus matching strengths, minus the size of the work above
/// the class.
#[must_use]
pub fn prior(engine: &Candidate, needs: &Needs) -> f64 {
    prior_and_basis(engine, needs).0
}

/// [`prior`], and where it came from.
fn prior_and_basis(engine: &Candidate, needs: &Needs) -> (f64, String) {
    let matched_strengths = |credited: &dyn Fn(&str) -> bool| {
        strength_tags(needs.kind)
            .iter()
            .filter(|tag| engine.capabilities.has_strength(tag) && !credited(tag))
            .count()
    };
    // A model the router knows: its profile wins over its class. Strengths still add their
    // bonus, except the tags the profile already priced in.
    if let Some(profile) = models::profile_for(engine.model.as_deref(), &engine.name)
        && let Some(base) = profile.prior(needs.kind, needs.size)
    {
        let matched = matched_strengths(&|tag| profile.credits(tag));
        let bonus = (matched as f64 * STRENGTH_BONUS).min(STRENGTH_CAP);
        return (
            (base + bonus).clamp(0.05, 0.95),
            format!("model profile: {}", profile.family),
        );
    }
    (
        class_prior(engine, needs, matched_strengths(&|_| false)),
        format!("class {}", engine.class().as_str()),
    )
}

/// The prior from the size class alone: what every model had before profiles, and still
/// what a model the router does not know has.
fn class_prior(engine: &Candidate, needs: &Needs, matched: usize) -> f64 {
    let class = engine.class();
    let base = match class {
        ModelClass::Large => 0.80,
        ModelClass::Medium => 0.70,
        ModelClass::Small => 0.55,
    };
    let bonus = (matched as f64 * STRENGTH_BONUS).min(STRENGTH_CAP);
    let size = match needs.size {
        Size::Small => 0,
        Size::Medium => 1,
        Size::Large => 2,
    };
    let gap = size - class as i32;
    let penalty = if gap > 0 {
        f64::from(gap) * SIZE_PENALTY
    } else {
        0.0
    };
    (base + bonus - penalty).clamp(0.05, 0.95)
}

/// The success estimate of `engine` for `needs` as of `now`.
#[must_use]
pub fn estimate(engine: &Candidate, needs: &Needs, now: DateTime<Utc>) -> Estimate {
    let (prior, mut basis) = prior_and_basis(engine, needs);
    let kind = needs.kind.as_str();
    let (verified, refuted) = engine
        .outcomes
        .iter()
        .filter(|outcome| outcome.kind == kind)
        .fold((0.0, 0.0), |(v, r), outcome| {
            let (more_v, more_r) = outcome.weights(now);
            (v + more_v, r + more_r)
        });
    let p = (prior * PRIOR_WEIGHT + verified) / (PRIOR_WEIGHT + verified + refuted);
    if verified + refuted >= 0.5 {
        basis.push_str(&format!(
            ", ledger {verified:.0} verified {refuted:.0} refuted"
        ));
    }
    Estimate {
        p: p.clamp(0.0, 1.0),
        prior,
        verified,
        refuted,
        basis,
    }
}

// --- the price -------------------------------------------------------------------------------

/// How an engine is paid for, as far as breaking a tie in price goes: an engine that costs
/// nothing at all comes before one on a subscription (nothing per call, but a capped week
/// that other work needs), and both before one that is paid for by use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Economy {
    /// Local, or a free tier that has not asked for money.
    Free,
    Subscription,
    /// Priced, unpriced, or a free tier that is flagged for asking for money.
    Paid,
}

/// What one call on an engine is expected to cost, and how that was worked out.
#[derive(Debug, Clone, PartialEq)]
pub struct Price {
    pub usd: f64,
    /// How it is paid for, which settles a tie in price.
    pub economy: Economy,
    /// `free`, `local`, `~$0.012`, `unpriced, assumed ~$0.21`, `subscription, cap 300/wk,
    /// 72% of the weekly cap left`.
    pub note: String,
}

/// The tokens one call is estimated to read and write: by size, and at least the context
/// the work wants.
#[must_use]
pub fn tokens(needs: &Needs) -> (u64, u64) {
    let (read, wrote) = match needs.size {
        Size::Small => (3_000, 1_000),
        Size::Medium => (12_000, 3_000),
        Size::Large => (48_000, 10_000),
    };
    (read.max(u64::from(needs.min_context_k) * 1_000), wrote)
}

/// `2026-W40`: the ISO week `now` falls in, as workers write it.
#[must_use]
pub fn iso_week(now: DateTime<Utc>) -> String {
    let week = now.iso_week();
    format!("{}-W{:02}", week.year(), week.week())
}

/// How much of a weekly request cap is left, `None` without a cap. Only this week's count
/// counts.
#[must_use]
pub fn cap_left(engine: &Candidate, now: DateTime<Utc>) -> Option<f64> {
    let cap = engine.weekly_requests.filter(|cap| *cap > 0)?;
    let used = if engine.week == iso_week(now) {
        engine.requests
    } else {
        0
    };
    Some((1.0 - used as f64 / cap as f64).clamp(0.0, 1.0))
}

fn money(usd: f64) -> String {
    if usd >= 0.1 {
        format!("~${usd:.2}")
    } else if usd >= 0.001 {
        format!("~${usd:.3}")
    } else {
        format!("~${usd:.4}")
    }
}

/// The expected price of one call of `engine` on `needs`.
#[must_use]
pub fn price(engine: &Candidate, needs: &Needs, now: DateTime<Utc>) -> Price {
    let (read, wrote) = tokens(needs);
    let caps = &engine.capabilities;
    let paid = engine.paid_class();
    let priced = |cost: &Cost| cost.estimate(read, wrote);
    // How it is paid for decides first: a subscription is scarce wherever its endpoint
    // is, and only then does being local make a call free.
    if paid == "subscription" {
        let left = cap_left(engine, now);
        // A request is a smaller share of a bigger cap: scarcity is per request.
        let cap = engine.weekly_requests.filter(|cap| *cap > 0);
        let share = cap.map_or(1.0, |cap| {
            (SCARCITY_REFERENCE_CAP / cap as f64).clamp(0.05, 20.0)
        });
        let scarcity =
            SCARCITY_BASE_USD * share * (1.0 + 9.0 * (1.0 - left.unwrap_or(0.5)).powi(2));
        let own = caps.cost.as_ref().map_or(0.0, priced);
        return Price {
            usd: own + scarcity,
            economy: Economy::Subscription,
            note: match (left, cap) {
                (Some(left), Some(cap)) => format!(
                    "subscription, cap {cap}/wk, {:.0}% of the weekly cap left",
                    (left * 100.0).round()
                ),
                _ => "subscription, no weekly cap known".to_string(),
            },
        };
    }
    if paid == "local" || caps.local {
        return Price {
            usd: caps.cost.as_ref().map_or(0.0, priced),
            economy: Economy::Free,
            note: "local".to_string(),
        };
    }
    if paid == "free-tier" {
        if engine.flag.is_some() {
            let usd = priced(&ASSUMED_COST);
            return Price {
                usd,
                economy: Economy::Paid,
                note: format!(
                    "free tier but flagged for asking for money, assumed {}",
                    money(usd)
                ),
            };
        }
        return Price {
            usd: caps.cost.as_ref().map_or(0.0, priced),
            economy: Economy::Free,
            note: "free".to_string(),
        };
    }
    match &caps.cost {
        Some(cost) if cost.is_free() => Price {
            usd: 0.0,
            economy: Economy::Free,
            note: "free".to_string(),
        },
        Some(cost) => {
            let usd = priced(cost);
            Price {
                usd,
                economy: Economy::Paid,
                note: money(usd),
            }
        }
        None => {
            let usd = priced(&ASSUMED_COST);
            Price {
                usd,
                economy: Economy::Paid,
                note: format!("unpriced, assumed {}", money(usd)),
            }
        }
    }
}

// --- bias ----------------------------------------------------------------------------------------

/// The operator's weight for an engine in a role: the largest policy `bias` whose selector
/// matches it, plus up to one point for its place in the role's `prefer` list (the first
/// entry the most). Higher goes first among engines of equal price.
#[must_use]
pub fn bias(policy: &Policy, role: Role, engine: &Candidate) -> f64 {
    let explicit = policy
        .bias
        .iter()
        .filter(|(selector, _)| crate::policy::matches(selector, engine))
        .map(|(_, weight)| *weight)
        .fold(None, |best: Option<f64>, weight| {
            Some(best.map_or(weight, |best| best.max(weight)))
        })
        .unwrap_or(0.0);
    let listed = policy.preferences(role).len();
    let place = policy
        .preference(role, engine)
        .map_or(0.0, |place| (listed - place) as f64 / (listed + 1) as f64);
    explicit + place
}

// --- the decision ----------------------------------------------------------------------------------

/// One engine the router looked at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Considered {
    pub engine: String,
    pub agent: String,
    pub machine: String,
    /// The success estimate for this kind of work. `None` for an engine the policy set
    /// aside before it was scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<f64>,
    /// The expected dollars for one call, as [`Price`] works it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// How that was worked out: `free`, `subscription, cap 300/wk, 72% of the weekly cap
    /// left`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    /// Where `p` came from: `model profile: claude-sonnet`, `class medium`. For showing
    /// only: it is stripped from signed steps (see [`Decision::for_signed_step`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
    /// Reached the threshold (and beat a failed engine's estimate, when escalating).
    #[serde(default)]
    pub sufficient: bool,
    /// Why it was left out, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded: Option<String>,
}

/// The engine the router chose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pick {
    pub engine: String,
    pub agent: String,
    pub machine: String,
    pub p: f64,
    pub cost_usd: f64,
}

/// Why this engine: recorded beside the step, in the result and shown by
/// `ferry route explain`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    /// `smart` or `ordered`.
    pub routing: String,
    pub role: String,
    pub kind: String,
    pub size: String,
    /// The modalities the work needs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    /// The success probability that counts as sufficient for this kind.
    pub threshold: f64,
    /// Engines looked at: the winner and the rest in the order they would be tried, then
    /// the ones left out with why.
    pub candidates: Vec<Considered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner: Option<Pick>,
    /// One line: `nvidia: free, p 0.81 for docs >= 0.75, cheapest sufficient`.
    pub reason: String,
    /// Engines that failed this order earlier, when this is a retry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    /// The success estimate a retry had to beat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_beat: Option<f64>,
}

impl Decision {
    /// The decision as a signed improve step records it: everything but the fields that
    /// are for showing only.
    ///
    /// Steps are signed over their exact serialization, and a peer on an older version
    /// reads a step into its own structs, drops any field it does not know and signs or
    /// verifies the re-serialized bytes, so the signature fails and the agent's whole
    /// week of steps is dropped. **A field added to [`Decision`] or [`Considered`] must not
    /// reach a signed step until the step signature is bumped to cover it.** `basis` is
    /// live-only: `simulate`, `explain` and the result's `routing` show it, the step does
    /// not carry it.
    #[must_use]
    pub fn for_signed_step(&self) -> Decision {
        let mut decision = self.clone();
        for candidate in &mut decision.candidates {
            candidate.basis = None;
        }
        decision
    }

    /// What `ferry route explain` prints, one line each.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "routing {} for {} work ({}, {}), threshold {:.2}",
            self.routing, self.kind, self.role, self.size, self.threshold
        )];
        if !self.failed.is_empty() {
            out.push(format!(
                "  retry: {} failed this order{}",
                self.failed.join(", "),
                self.must_beat
                    .map(|p| format!("; the next engine needs p above {p:.2}"))
                    .unwrap_or_default()
            ));
        }
        for candidate in &self.candidates {
            let mark = match (&candidate.excluded, self.winner.as_ref()) {
                (Some(_), _) => "x",
                (None, Some(win))
                    if win.engine == candidate.engine && win.machine == candidate.machine =>
                {
                    ">"
                }
                (None, _) if candidate.sufficient => "+",
                _ => "-",
            };
            let basis = candidate
                .basis
                .as_ref()
                .map(|basis| format!(" ({basis})"))
                .unwrap_or_default();
            let facts = match (&candidate.p, &candidate.price) {
                (Some(p), Some(price)) => format!("p {p:.2}{basis}, {price}"),
                (Some(p), None) => format!("p {p:.2}{basis}"),
                _ => String::new(),
            };
            out.push(format!(
                "  {mark} {:<14} {:<12} {}{}",
                candidate.engine,
                candidate.machine,
                facts,
                candidate
                    .excluded
                    .as_ref()
                    .map(|why| format!("out: {why}"))
                    .unwrap_or_default()
            ));
        }
        out.push(format!("  => {}", self.reason));
        out
    }
}

/// The recorded reason in a result payload (`routing.reason`), when a worker wrote one.
#[must_use]
pub fn reason_of(payload: &Value) -> Option<String> {
    payload
        .get("routing")?
        .get("reason")?
        .as_str()
        .map(str::to_string)
}

/// The recorded decision in a result payload, when a worker wrote one.
#[must_use]
pub fn decision_of(payload: &Value) -> Option<Decision> {
    serde_json::from_value(payload.get("routing")?.clone()).ok()
}

/// An engine that already failed this order, where, and the estimate it had. A failure
/// belongs to the engine on the machine of the worker that ran it: another machine's
/// `claude` that failed is not this machine's `claude`.
#[derive(Debug, Clone, PartialEq)]
pub struct Failed {
    pub agent: String,
    /// Empty when the record does not say which machine: any machine of that agent.
    pub machine: String,
    pub engine: String,
    /// An estimate from the record, used only when the engine is not among those being
    /// routed. The router works the bar out from its own ledger first: a record can say
    /// anything.
    pub p: Option<f64>,
}

impl Failed {
    /// Whether this is the failure of `engine`.
    #[must_use]
    pub fn is(&self, engine: &Candidate) -> bool {
        self.engine == engine.name
            && self.agent == engine.agent
            && (self.machine.is_empty() || self.machine == engine.machine)
    }
}

/// What a routing call is told besides the engines and the policy.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub now: DateTime<Utc>,
    /// Engines to leave out: already asked in this attempt (out of credit, or down).
    pub tried: &'a [String],
    /// Engines that failed this order: left out, and the next must beat their estimate.
    /// When nothing else can do the work they are tried again, the likeliest first.
    pub failed: &'a [Failed],
}

impl Context<'_> {
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now,
            tried: &[],
            failed: &[],
        }
    }
}

/// The decision and the engines in the order they should be tried: indexes into the
/// engines given, the winner first.
#[derive(Debug, Clone, PartialEq)]
pub struct Routed {
    pub decision: Decision,
    pub order: Vec<usize>,
}

/// The role work of a kind is done under: planning plans, review reviews, chores are
/// chores; everything else builds.
#[must_use]
pub fn role_for(kind: WorkKind) -> Role {
    match kind {
        WorkKind::Plan => Role::Plan,
        WorkKind::Review => Role::Review,
        WorkKind::Chore => Role::Chore,
        _ => Role::Build,
    }
}

/// What the improve loop's own steps need, which no order carries: planning is large
/// reasoning work, review is medium, a chore small.
#[must_use]
pub fn needs_for_role(role: Role) -> Needs {
    let (kind, size) = match role {
        Role::Plan => (WorkKind::Plan, Size::Large),
        Role::Review | Role::Adversary => (WorkKind::Review, Size::Medium),
        Role::Chore => (WorkKind::Chore, Size::Small),
        Role::Build => (WorkKind::CodeChange, Size::Medium),
    };
    Needs {
        modalities: resolve_modalities(&[], kind),
        kind,
        size,
        min_context_k: 0,
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

struct Scored {
    index: usize,
    estimate: Estimate,
    price: Price,
    bias: f64,
    distance: i16,
    /// Where `rank` put it among the engines this call may use: the policy's order, then the
    /// operator's own, which is what settles engines nothing else tells apart.
    place: usize,
    sufficient: bool,
}

/// Choose among `engines` for `needs` done under `role` at `tier`. Everything the policy
/// decides comes first - see the module notes - and with `routing = "ordered"` (or for the
/// adversary) nothing else does: the order is [`rank`]'s, as it always was.
#[must_use]
pub fn route(
    policy: &Policy,
    role: Role,
    tier: &str,
    work: Work,
    needs: &Needs,
    engines: &[Candidate],
    context: &Context,
) -> Routed {
    let ranking = rank(policy, role, tier, work, engines);
    let threshold = policy.threshold_for(needs.kind, needs.size);
    let smart = policy.routing == Routing::Smart && role != Role::Adversary;
    let mut decision = Decision {
        routing: if smart { "smart" } else { "ordered" }.to_string(),
        role: role.as_str().to_string(),
        kind: needs.kind.as_str().to_string(),
        size: needs.size.as_str().to_string(),
        needs: needs.modalities.iter().map(ToString::to_string).collect(),
        threshold,
        candidates: Vec::new(),
        winner: None,
        reason: String::new(),
        failed: context.failed.iter().map(|f| f.engine.clone()).collect(),
        must_beat: None,
    };
    let considered = |engine: &Candidate, excluded: Option<String>| Considered {
        engine: engine.name.clone(),
        agent: engine.agent.clone(),
        machine: engine.machine.clone(),
        p: None,
        cost_usd: None,
        price: None,
        basis: None,
        sufficient: false,
        excluded,
    };
    let mut excluded: Vec<Considered> = Vec::new();
    for (index, why) in ranking.out.iter().chain(&ranking.blocked) {
        excluded.push(considered(&engines[*index], Some(why.clone())));
    }

    // Only a cli engine can edit files, so code work goes to one. But a fleet of http
    // engines only has always been able to take build orders (they answer in text and own
    // up to changing nothing), so when no engine at all could do the work with `code`
    // required, `code` is not required: nothing is worse than a hold.
    let relaxed_code = smart
        && needs.modalities.contains(&Modality::Code)
        && !ranking
            .order
            .iter()
            .any(|&index| unable(&engines[index], needs).is_ok());
    let relaxed;
    let needs_here = if relaxed_code {
        relaxed = Needs {
            modalities: needs
                .modalities
                .iter()
                .filter(|modality| **modality != Modality::Code)
                .cloned()
                .collect(),
            ..needs.clone()
        };
        &relaxed
    } else {
        needs
    };

    // What the policy let through, less what this call leaves out. An engine that failed
    // this order is out - unless it is all there is, below.
    let mut pool: Vec<usize> = Vec::new();
    let mut failed_pool: Vec<(usize, String)> = Vec::new();
    for &index in &ranking.order {
        let engine = &engines[index];
        let left_out = if context.tried.contains(&engine.name) {
            Some("already asked in this attempt".to_string())
        } else if !smart {
            None
        } else if work == Work::Background
            && models::is_opus(engine.model.as_deref(), &engine.name)
            && !named_in_prefer(policy, role, engine)
        {
            Some(
                "claude opus is not used for background work unless the policy prefers it by \
                 name"
                    .to_string(),
            )
        } else if let Some(failed) = context.failed.iter().find(|f| f.is(engine)) {
            match unable(engine, needs_here) {
                Err(why) => Some(why),
                Ok(()) => {
                    failed_pool.push((
                        index,
                        match failed.p {
                            Some(p) => format!("failed this order earlier at p {p:.2}"),
                            None => "failed this order earlier".to_string(),
                        },
                    ));
                    continue;
                }
            }
        } else {
            unable(engine, needs_here).err()
        };
        match left_out {
            Some(why) => excluded.push(considered(engine, Some(why))),
            None => pool.push(index),
        }
    }
    // Nothing waits for want of an engine that failed once: when every engine that can do
    // the work has already failed this order, the likeliest of them tries again, and the
    // reason says so.
    let retrying = pool.is_empty() && !failed_pool.is_empty();
    if retrying {
        pool = failed_pool.iter().map(|(index, _)| *index).collect();
    } else {
        for (index, why) in failed_pool {
            excluded.push(considered(&engines[index], Some(why)));
        }
    }

    if !smart {
        // Today's order, scored only so the record says what it would have meant.
        let mut candidates = Vec::new();
        for &index in &pool {
            let engine = &engines[index];
            let estimate = estimate(engine, needs, context.now);
            let price = price(engine, needs, context.now);
            candidates.push(Considered {
                p: Some(round3(estimate.p)),
                cost_usd: Some(round3(price.usd)),
                price: Some(price.note),
                basis: Some(estimate.basis),
                sufficient: estimate.p + 1e-9 >= threshold,
                ..considered(engine, None)
            });
        }
        if let Some(&first) = pool.first() {
            let engine = &engines[first];
            let estimate = estimate(engine, needs, context.now);
            let price = price(engine, needs, context.now);
            decision.reason = if role == Role::Adversary {
                format!(
                    "{}: the adversary is never routed; first in its own policy order",
                    engine.name
                )
            } else {
                format!(
                    "{}: first allowed engine in the policy order (routing is ordered)",
                    engine.name
                )
            };
            decision.winner = Some(Pick {
                engine: engine.name.clone(),
                agent: engine.agent.clone(),
                machine: engine.machine.clone(),
                p: round3(estimate.p),
                cost_usd: round3(price.usd),
            });
        } else {
            decision.reason = none_reason(&ranking.why_none(role, engines), &excluded);
        }
        decision.candidates = finish(candidates, excluded);
        return Routed {
            decision,
            order: pool,
        };
    }

    // Smart: score what is left.
    // What a retry must beat: what this worker's own ledger says of each failed engine now.
    // An estimate carried by a result is only a fallback for an engine that is not here
    // (a payload is whatever its writer says), and not at all when retrying the same
    // engines, which have nothing better to be compared with.
    let floor = if retrying {
        None
    } else {
        context
            .failed
            .iter()
            .filter_map(|failed| {
                engines
                    .iter()
                    .find(|engine| failed.is(engine))
                    .map(|engine| estimate(engine, needs, context.now).p)
                    .or(failed.p)
            })
            .fold(None, |best: Option<f64>, p| {
                Some(best.map_or(p, |best| best.max(p)))
            })
    };
    decision.must_beat = floor.map(round3);
    let wanted = crate::policy::tier_level(tier);
    let scored: Vec<Scored> = pool
        .iter()
        .enumerate()
        .map(|(place, &index)| {
            let engine = &engines[index];
            let estimate = estimate(engine, needs, context.now);
            let sufficient = !retrying
                && estimate.p + 1e-9 >= threshold
                && floor.is_none_or(|f| estimate.p > f + 1e-9);
            let level = i16::from(engine.level());
            Scored {
                index,
                place,
                estimate,
                price: price(engine, needs, context.now),
                bias: bias(policy, role, engine),
                // As `rank` measures it: a judge plans first, a builder builds first and a
                // judge builds last.
                distance: if role == Role::Plan {
                    2 - level
                } else {
                    level - i16::from(wanted)
                },
                sufficient,
            }
        })
        .collect();

    // The order they would be tried in: the winner among the sufficient first, and so on.
    let mut order_positions: Vec<usize> = Vec::new();
    let mut left: Vec<usize> = (0..scored.len()).collect();
    let mut tied_with_winner: Vec<usize> = Vec::new();
    while !left.is_empty() {
        let sufficient: Vec<usize> = left
            .iter()
            .copied()
            .filter(|position| scored[*position].sufficient)
            .collect();
        let (pick, tied) = if sufficient.is_empty() {
            best_estimate(&left, &scored, engines)
        } else {
            best_priced(&sufficient, &scored, engines)
        };
        if order_positions.is_empty() {
            tied_with_winner = tied;
        }
        order_positions.push(pick);
        left.retain(|position| *position != pick);
    }

    let candidates: Vec<Considered> = order_positions
        .iter()
        .map(|&position| {
            let s = &scored[position];
            let engine = &engines[s.index];
            Considered {
                p: Some(round3(s.estimate.p)),
                cost_usd: Some(round3(s.price.usd)),
                price: Some(s.price.note.clone()),
                basis: Some(s.estimate.basis.clone()),
                sufficient: s.sufficient,
                ..considered(engine, None)
            }
        })
        .collect();
    match order_positions.first().map(|&position| &scored[position]) {
        Some(win) => {
            let engine = &engines[win.index];
            decision.winner = Some(Pick {
                engine: engine.name.clone(),
                agent: engine.agent.clone(),
                machine: engine.machine.clone(),
                p: round3(win.estimate.p),
                cost_usd: round3(win.price.usd),
            });
            decision.reason = winner_reason(
                win,
                engine,
                needs,
                threshold,
                &tied_with_winner,
                &scored,
                engines,
                floor,
            );
            if relaxed_code {
                decision.reason.push_str(
                    "; no engine that can edit files is up, so a text-only one takes it as \
                     it always has",
                );
            }
            if retrying {
                decision.reason.push_str(
                    "; every engine that can do this work has already failed this order, so \
                     the likeliest of them tries again",
                );
            }
        }
        None => decision.reason = none_reason(&ranking.why_none(role, engines), &excluded),
    }
    decision.candidates = finish(candidates, excluded);
    // `scored` was built from `pool` in order, so a position in one is a place in the other.
    let order = order_positions
        .iter()
        .map(|position| pool[*position])
        .collect();
    Routed { decision, order }
}

/// Whether the role's prefer list names this engine by its name or model - `name:opus`,
/// `model:claude-opus*`, or a bare word that is its name - and not by what it costs or how
/// big it is (`paid:subscription`, `class:large`), which says nothing about it in particular.
fn named_in_prefer(policy: &Policy, role: Role, engine: &Candidate) -> bool {
    policy.preferences(role).iter().any(|selector| {
        let lower = selector.trim().to_ascii_lowercase();
        let by_kind = matches!(
            lower.split_once(':'),
            Some(("name" | "engine" | "model", _))
        );
        let bare = !lower.contains(':')
            && (lower == engine.name.to_ascii_lowercase() || lower.contains("opus"));
        (by_kind || bare) && crate::policy::matches(selector, engine)
    })
}

/// Whether the engine can do work that needs this at all.
fn unable(engine: &Candidate, needs: &Needs) -> Result<(), String> {
    let caps = &engine.capabilities;
    let has = |modality: &Modality| {
        if caps.modalities.is_empty() {
            *modality == Modality::Text
        } else {
            caps.has(modality)
        }
    };
    let missing: Vec<String> = needs
        .modalities
        .iter()
        .filter(|modality| !has(modality))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "cannot do {}: it lacks {}",
            needs.kind.as_str(),
            missing.join("+")
        ));
    }
    if engine.http {
        let beyond: Vec<String> = needs
            .modalities
            .iter()
            .filter(|modality| **modality != Modality::Text)
            .map(ToString::to_string)
            .collect();
        if !beyond.is_empty() {
            return Err(format!(
                "an http engine is sent text only, so it cannot take {} work; a cli engine \
                 that declares it can",
                beyond.join("+")
            ));
        }
    }
    if let Some(window) = caps.context_k
        && window < needs.min_context_k
    {
        return Err(format!(
            "its {window}k context is under the {}k this work wants",
            needs.min_context_k
        ));
    }
    Ok(())
}

/// A success estimate in steps of [`P_TIE`], so two engines whose estimates are that close
/// compare as equal and the comparison stays a total order.
fn p_step(scored: &Scored) -> f64 {
    (scored.estimate.p / P_TIE).round()
}

/// The tie-break after price: bias (higher first), how it is paid for (free outright, then
/// a subscription, then paid), the nearer tier, the higher success estimate, the faster
/// engine, then the order the policy and the engine list already gave - which is how
/// engines that look the same to the router were always told apart, so a fleet whose
/// engines nothing distinguishes behaves as it did - and last the name and machine.
fn tie_break(a: &Scored, b: &Scored, engines: &[Candidate]) -> Ordering {
    let (ea, eb) = (&engines[a.index], &engines[b.index]);
    b.bias
        .total_cmp(&a.bias)
        .then(a.price.economy.cmp(&b.price.economy))
        .then(a.distance.cmp(&b.distance))
        .then_with(|| p_step(b).total_cmp(&p_step(a)))
        .then(
            ea.latency_ms
                .unwrap_or(u64::MAX)
                .cmp(&eb.latency_ms.unwrap_or(u64::MAX)),
        )
        .then(a.place.cmp(&b.place))
        .then(ea.name.cmp(&eb.name))
        .then(ea.machine.cmp(&eb.machine))
        .then(a.index.cmp(&b.index))
}

/// The cheapest of `pool` (positions in `scored`), costs within the tie band counting as
/// equal and settled by [`tie_break`]; and who was in that band.
fn best_priced(pool: &[usize], scored: &[Scored], engines: &[Candidate]) -> (usize, Vec<usize>) {
    let cheapest = pool
        .iter()
        .map(|position| scored[*position].price.usd)
        .fold(f64::INFINITY, f64::min);
    let band = (cheapest * TIE_RELATIVE).max(TIE_ABSOLUTE_USD);
    let mut tied: Vec<usize> = pool
        .iter()
        .copied()
        .filter(|position| scored[*position].price.usd <= cheapest + band)
        .collect();
    tied.sort_by(|a, b| tie_break(&scored[*a], &scored[*b], engines));
    (tied[0], tied)
}

/// The most likely to succeed of `pool`, estimates within [`P_TIE`] counting as equal and
/// settled by price, then [`tie_break`].
fn best_estimate(pool: &[usize], scored: &[Scored], engines: &[Candidate]) -> (usize, Vec<usize>) {
    let best = pool
        .iter()
        .map(|position| scored[*position].estimate.p)
        .fold(f64::NEG_INFINITY, f64::max);
    let mut tied: Vec<usize> = pool
        .iter()
        .copied()
        .filter(|position| scored[*position].estimate.p >= best - P_TIE)
        .collect();
    tied.sort_by(|a, b| {
        scored[*a]
            .price
            .usd
            .total_cmp(&scored[*b].price.usd)
            .then_with(|| tie_break(&scored[*a], &scored[*b], engines))
    });
    (tied[0], tied)
}

#[allow(clippy::too_many_arguments)]
fn winner_reason(
    win: &Scored,
    engine: &Candidate,
    needs: &Needs,
    threshold: f64,
    tied: &[usize],
    scored: &[Scored],
    engines: &[Candidate],
    floor: Option<f64>,
) -> String {
    let kind = needs.kind.as_str();
    let mut text = if win.sufficient {
        format!(
            "{}: {}, p {:.2} for {kind} >= {threshold:.2}, cheapest sufficient",
            engine.name, win.price.note, win.estimate.p
        )
    } else {
        format!(
            "{}: {}, p {:.2} for {kind}, the highest of the engines that can do it (none reach \
             {threshold:.2}{})",
            engine.name,
            win.price.note,
            win.estimate.p,
            floor
                .map(|p| format!(" and beat the {p:.2} of the engine that failed"))
                .unwrap_or_default()
        )
    };
    let rivals: Vec<&Scored> = tied
        .iter()
        .map(|position| &scored[*position])
        .filter(|other| other.index != win.index)
        .collect();
    if win.sufficient && !rivals.is_empty() {
        let names: Vec<&str> = rivals
            .iter()
            .map(|other| engines[other.index].name.as_str())
            .collect();
        let decider = if rivals.iter().any(|other| other.bias < win.bias) {
            "bias put it first"
        } else if rivals
            .iter()
            .any(|other| other.price.economy != win.price.economy)
        {
            "how it is paid for put it first: free, then a subscription, then paid"
        } else if rivals.iter().any(|other| other.distance != win.distance) {
            "the nearer tier put it first"
        } else if rivals.iter().any(|other| p_step(other) != p_step(win)) {
            "its higher p put it first"
        } else {
            "speed and its place in the list put it first"
        };
        text.push_str(&format!(
            "; tied on price with {}, {decider}",
            names.join(", ")
        ));
    }
    // On a subscription, the bigger cap is the cheaper to use up: say so when it was the
    // reason a smaller one did not get the work.
    let cap_of = |engine: &Candidate| engine.weekly_requests.filter(|cap| *cap > 0);
    if win.sufficient
        && win.price.economy == Economy::Subscription
        && let Some(cap) = cap_of(engine)
    {
        let smaller: Vec<String> = scored
            .iter()
            .filter(|other| {
                other.sufficient
                    && other.index != win.index
                    && other.price.economy == Economy::Subscription
                    && cap_of(&engines[other.index]).is_some_and(|other_cap| other_cap < cap)
            })
            .map(|other| {
                let rival = &engines[other.index];
                format!("{} {}/wk", rival.name, cap_of(rival).unwrap_or(0))
            })
            .collect();
        if !smaller.is_empty() {
            text.push_str(&format!(
                "; preferred over a smaller cap ({})",
                smaller.join(", ")
            ));
        }
    }
    if let Some(p) = floor
        && win.sufficient
    {
        text.push_str(&format!(
            "; escalated: it beats the {p:.2} of the engine that failed"
        ));
    }
    text
}

fn none_reason(why: &str, excluded: &[Considered]) -> String {
    let left_out: Vec<String> = excluded
        .iter()
        .filter_map(|candidate| {
            candidate
                .excluded
                .as_ref()
                .map(|reason| format!("{} {reason}", candidate.engine))
        })
        .collect();
    if left_out.is_empty() {
        format!("no engine: {why}")
    } else {
        format!("no engine can take it now: {}", left_out.join("; "))
    }
}

/// Candidates scored, then those left out, cut to what a record keeps.
fn finish(mut scored: Vec<Considered>, excluded: Vec<Considered>) -> Vec<Considered> {
    scored.extend(excluded);
    scored.truncate(MAX_RECORDED);
    scored
}

// --- simulating ----------------------------------------------------------------------------------------

/// What `ferry route simulate` and the dashboard run: the ranking for work of this kind and
/// size over `engines`, under the project's policy, without running anything. The engines
/// are what the fleet published, so a machine's own view can differ only in how fresh its
/// ledger is.
#[must_use]
pub fn simulate(
    policy: &Policy,
    engines: &[Candidate],
    needs: &Needs,
    now: DateTime<Utc>,
) -> Routed {
    let role = role_for(needs.kind);
    route(
        policy,
        role,
        role.tier(),
        Work::Background,
        needs,
        engines,
        &Context::new(now),
    )
}

/// The work a simulation is asked about: a kind, a size, and any modalities beyond what the
/// kind implies.
pub fn simulated_needs(kind: &str, size: &str, extra: &[String]) -> anyhow::Result<Needs> {
    let kind = WorkKind::parse(kind)?;
    let size = Size::parse(size)?;
    let mut signals = Vec::new();
    for word in extra {
        signals.extend(Modality::parse_list(word)?);
    }
    Ok(Needs {
        modalities: resolve_modalities(&signals, kind),
        kind,
        size,
        min_context_k: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capabilities;

    fn now() -> DateTime<Utc> {
        "2026-10-02T12:00:00Z".parse().unwrap()
    }

    fn caps(modalities: &[Modality], cost: Option<Cost>) -> Capabilities {
        Capabilities {
            modalities: modalities.to_vec(),
            strengths: Vec::new(),
            context_k: None,
            cost,
            local: false,
        }
    }

    fn per_call(usd: f64) -> Option<Cost> {
        Some(Cost {
            per_call_usd: usd,
            ..Cost::default()
        })
    }

    /// A cli engine at build tier with the class, payment and price given.
    fn engine(name: &str, class: ModelClass, paid: &str, cost: Option<Cost>) -> Candidate {
        Candidate {
            agent: "wisp".into(),
            machine: "box".into(),
            name: name.into(),
            tier: "build".into(),
            paid: paid.into(),
            class: Some(class),
            state: "up".into(),
            capabilities: caps(&[Modality::Text, Modality::Code], cost),
            ..Candidate::default()
        }
    }

    fn http(name: &str, class: ModelClass, paid: &str) -> Candidate {
        Candidate {
            http: true,
            capabilities: caps(&[Modality::Text], Some(Cost::FREE)),
            ..engine(name, class, paid, Some(Cost::FREE))
        }
    }

    fn needs(kind: WorkKind, size: Size) -> Needs {
        Needs {
            modalities: resolve_modalities(&[], kind),
            kind,
            size,
            min_context_k: 0,
        }
    }

    fn pick(routed: &Routed, engines: &[Candidate]) -> Option<String> {
        routed.order.first().map(|i| engines[*i].name.clone())
    }

    fn run(policy: &Policy, needs: &Needs, engines: &[Candidate]) -> Routed {
        let role = role_for(needs.kind);
        route(
            policy,
            role,
            role.tier(),
            Work::Background,
            needs,
            engines,
            &Context::new(now()),
        )
    }

    /// A failure of the test engine's own agent and machine.
    fn failure(engine: &str, p: Option<f64>) -> Failed {
        Failed {
            agent: "wisp".into(),
            machine: "box".into(),
            engine: engine.into(),
            p,
        }
    }

    fn retry(failed: &[Failed], engines: &[Candidate], needs: &Needs) -> Routed {
        route(
            &Policy::default(),
            Role::Build,
            "build",
            Work::Background,
            needs,
            engines,
            &Context {
                now: now(),
                tried: &[],
                failed,
            },
        )
    }

    #[test]
    fn a_result_counts_for_half_as_much_after_fourteen_days() {
        assert!((decay(Duration::days(14)) - 0.5).abs() < 1e-9);
        assert!((decay(Duration::days(28)) - 0.25).abs() < 1e-9);
        assert_eq!(decay(Duration::days(-3)), 1.0, "a clock gone backwards");
        let mut list = Vec::new();
        let then = now() - Duration::days(14);
        record_outcome(&mut list, "docs", true, then);
        record_outcome(&mut list, "docs", true, then);
        let (v, r) = list[0].weights(now());
        assert!(
            (v - 1.0).abs() < 0.01 && r == 0.0,
            "two results, half left: {v}"
        );
        // A new result is counted at full weight beside the faded ones.
        record_outcome(&mut list, "docs", false, now());
        let (v, r) = list[0].weights(now());
        assert!((v - 1.0).abs() < 0.01 && (r - 1.0).abs() < 0.01);
        // And what has faded to nothing is dropped.
        let mut old = Vec::new();
        record_outcome(&mut old, "docs", true, now() - Duration::days(400));
        record_outcome(&mut old, "tests", true, now());
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].kind, "tests");
    }

    #[test]
    fn the_prior_follows_class_strengths_and_the_size_of_the_work() {
        let mut large = engine("a", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let medium = engine("b", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let small = engine("c", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let docs = needs(WorkKind::Docs, Size::Small);
        assert!((prior(&large, &docs) - 0.80).abs() < 1e-9);
        assert!((prior(&medium, &docs) - 0.70).abs() < 1e-9);
        assert!((prior(&small, &docs) - 0.55).abs() < 1e-9);
        // A matching strength adds 0.05 each, to 0.10: tests matches `tests` and `code`.
        let tests = needs(WorkKind::Tests, Size::Small);
        large.capabilities.strengths = vec!["code".into()];
        assert!((prior(&large, &tests) - 0.85).abs() < 1e-9);
        large.capabilities.strengths = vec!["code".into(), "tests".into(), "docs".into()];
        assert!(
            (prior(&large, &tests) - 0.90).abs() < 1e-9,
            "capped at +0.10"
        );
        assert!(
            (prior(&large, &docs) - 0.85).abs() < 1e-9,
            "docs matches docs only"
        );
        // Work bigger than the class costs 0.10 a step.
        let big = needs(WorkKind::Docs, Size::Large);
        assert!((prior(&small, &big) - 0.35).abs() < 1e-9);
        assert!((prior(&medium, &big) - 0.60).abs() < 1e-9);
        assert!((prior(&medium, &needs(WorkKind::Docs, Size::Medium)) - 0.70).abs() < 1e-9);
    }

    #[test]
    fn the_ledger_moves_the_estimate_for_that_kind_only() {
        let mut medium = engine("b", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let docs = needs(WorkKind::Docs, Size::Medium);
        assert!((estimate(&medium, &docs, now()).p - 0.70).abs() < 1e-9);
        for _ in 0..4 {
            record_outcome(&mut medium.outcomes, "docs", true, now());
        }
        // (0.7*4 + 4) / (4 + 4) = 0.85
        assert!((estimate(&medium, &docs, now()).p - 0.85).abs() < 1e-3);
        // Other kinds are untouched.
        let tests = needs(WorkKind::Tests, Size::Medium);
        assert!((estimate(&medium, &tests, now()).p - 0.70).abs() < 1e-9);
        // Refutations pull it down, and they fade.
        for _ in 0..4 {
            record_outcome(&mut medium.outcomes, "tests", false, now());
        }
        assert!(estimate(&medium, &tests, now()).p < 0.40);
        let later = now() + Duration::days(140);
        assert!(
            (estimate(&medium, &tests, later).p - 0.70).abs() < 0.01,
            "ten half-lives on, it is the prior again"
        );
    }

    #[test]
    fn free_and_large_wins_and_the_line_says_why() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let metered = engine(
            "metered",
            ModelClass::Medium,
            "prepaid",
            Some(Cost {
                per_call_usd: 0.0,
                per_mtok_in_usd: 3.0,
                per_mtok_out_usd: 15.0,
            }),
        );
        let engines = [metered, nvidia];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("nvidia"));
        assert_eq!(
            routed.decision.reason,
            "nvidia: free, p 0.80 for docs >= 0.70, cheapest sufficient"
        );
        assert_eq!(routed.decision.routing, "smart");
        assert_eq!(routed.decision.winner.as_ref().unwrap().cost_usd, 0.0);
        // The loser is recorded with its own p and price.
        let metered = &routed.decision.candidates[1];
        assert_eq!(metered.engine, "metered");
        assert!(
            metered.sufficient && metered.p == Some(0.7),
            "sufficient, but dearer"
        );
        assert!(metered.cost_usd.unwrap() > 0.0);
    }

    #[test]
    fn a_cheaper_engine_that_is_not_sufficient_does_not_win() {
        let free_small = engine("tiny", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let paid_large = engine("big", ModelClass::Large, "prepaid", per_call(0.01));
        let engines = [free_small, paid_large];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("big"));
        assert!(routed.decision.reason.contains("cheapest sufficient"));
    }

    #[test]
    fn proving_itself_lets_a_cheap_engine_take_the_work_and_failing_takes_it_back() {
        let mut tiny = engine("tiny", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let big = engine("big", ModelClass::Large, "prepaid", per_call(0.05));
        let docs = needs(WorkKind::Docs, Size::Small);
        for _ in 0..6 {
            record_outcome(&mut tiny.outcomes, "docs", true, now());
        }
        let engines = [tiny.clone(), big.clone()];
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("tiny"),
            "six verified docs results lift 0.55 to 0.82"
        );
        // It is proven for docs, not for code: the ledger is per kind.
        let code = needs(WorkKind::CodeChange, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &code, &engines), &engines).as_deref(),
            Some("big")
        );
        for _ in 0..8 {
            record_outcome(&mut tiny.outcomes, "docs", false, now());
        }
        let engines = [tiny, big];
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("big")
        );
    }

    #[test]
    fn with_nothing_sufficient_the_highest_estimate_wins() {
        let a = engine("a", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let b = engine("b", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let engines = [a, b];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Large),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("b"));
        assert!(
            routed
                .decision
                .reason
                .contains("the highest of the engines that can do it")
                && routed.decision.reason.contains("none reach 0.75"),
            "{}",
            routed.decision.reason
        );
        assert!(routed.decision.candidates.iter().all(|c| !c.sufficient));
    }

    #[test]
    fn the_threshold_is_the_policys_per_kind() {
        let small = engine("m", ModelClass::Small, "free-tier", Some(Cost::FREE));
        let large = engine("l", ModelClass::Large, "prepaid", per_call(0.01));
        let engines = [small, large];
        let docs = needs(WorkKind::Docs, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("l")
        );
        let mut lax = Policy::default();
        lax.thresholds.insert("docs".into(), 0.55);
        lax.check().unwrap();
        let routed = run(&lax, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("m"));
        assert!(
            routed.decision.reason.contains(">= 0.55"),
            "{}",
            routed.decision.reason
        );
        // Another kind keeps the default.
        let code = needs(WorkKind::CodeChange, Size::Small);
        assert_eq!(
            pick(&run(&lax, &code, &engines), &engines).as_deref(),
            Some("l")
        );
        let mut bad = Policy::default();
        bad.thresholds.insert("docs".into(), 1.5);
        assert!(bad.check().is_err());
        bad.thresholds.clear();
        bad.thresholds.insert("nonsense".into(), 0.5);
        assert!(bad.check().is_err());
    }

    #[test]
    fn bias_and_the_prefer_list_break_ties_in_price_and_nothing_else() {
        let a = engine("alpha", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let b = engine("beta", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let engines = [a, b];
        let docs = needs(WorkKind::Docs, Size::Small);
        // No bias: the name settles it.
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("alpha")
        );
        // The prefer list is a bias.
        let mut prefer = Policy::default();
        prefer.prefer.insert(
            "build".into(),
            vec!["name:beta".into(), "name:alpha".into()],
        );
        let routed = run(&prefer, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("beta"));
        assert!(
            routed
                .decision
                .reason
                .contains("tied on price with alpha, bias put it first")
        );
        // An explicit weight outranks list position.
        let mut weighted = prefer.clone();
        weighted.bias.insert("name:alpha".into(), 5.0);
        weighted.check().unwrap();
        assert_eq!(
            pick(&run(&weighted, &docs, &engines), &engines).as_deref(),
            Some("alpha")
        );
        // But bias never lets a dearer engine win.
        let dear = engine("dear", ModelClass::Large, "prepaid", per_call(0.5));
        let all = [engines[0].clone(), engines[1].clone(), dear];
        let mut loud = Policy::default();
        loud.bias.insert("name:dear".into(), 100.0);
        assert_ne!(
            pick(&run(&loud, &docs, &all), &all).as_deref(),
            Some("dear")
        );
    }

    /// Josh's fleet, as ENGINE_SETUP.md describes it: an NVIDIA judge on the free tier, Claude
    /// Sonnet and Haiku on a capped subscription (with the prices they declare), and a local
    /// ollama model.
    fn josh_fleet() -> Vec<Candidate> {
        let mut nvidia = http("nemotron", ModelClass::Medium, "free-tier");
        nvidia.tier = "judge".into();
        let mut sonnet = engine(
            "claude-sonnet",
            ModelClass::Medium,
            "subscription",
            Some(Cost {
                per_call_usd: 0.0,
                per_mtok_in_usd: 3.0,
                per_mtok_out_usd: 15.0,
            }),
        );
        sonnet.weekly_requests = Some(500);
        let mut haiku = engine(
            "claude-haiku",
            ModelClass::Small,
            "subscription",
            Some(Cost {
                per_call_usd: 0.0,
                per_mtok_in_usd: 1.0,
                per_mtok_out_usd: 5.0,
            }),
        );
        haiku.weekly_requests = Some(500);
        let mut ollama = http("ollama", ModelClass::Small, "local");
        ollama.capabilities.local = true;
        vec![haiku, sonnet, ollama, nvidia]
    }

    fn josh_policy() -> Policy {
        Policy {
            protect_subscriptions: false,
            ..Policy::default()
        }
    }

    /// A chore that edits files: small work that needs `code`.
    fn editing_chore() -> Needs {
        Needs {
            modalities: vec![Modality::Text, Modality::Code],
            ..needs(WorkKind::Chore, Size::Small)
        }
    }

    #[test]
    fn josh_example_words_and_chores_go_to_nemotron_and_judgement_to_a_model_good_at_it() {
        let fleet = josh_fleet();
        let policy = josh_policy();
        // Nemotron writes and tidies well enough, and it is free.
        for needs in [
            needs(WorkKind::Docs, Size::Medium),
            needs(WorkKind::Chore, Size::Small),
        ] {
            let routed = run(&policy, &needs, &fleet);
            assert_eq!(
                pick(&routed, &fleet).as_deref(),
                Some("nemotron"),
                "{} work: {}",
                needs.kind.as_str(),
                routed.decision.reason
            );
            assert!(routed.decision.reason.contains("cheapest sufficient"));
        }
        // It is a 0.70 planner, under the 0.80 bar: Sonnet plans.
        let routed = run(&policy, &needs(WorkKind::Plan, Size::Medium), &fleet);
        assert_eq!(
            pick(&routed, &fleet).as_deref(),
            Some("claude-sonnet"),
            "{}",
            routed.decision.reason
        );
        // Review is a judge's alone, and Nemotron is the only judge: it still gets it,
        // and the line says it was the best there was and not that it was good enough.
        let routed = run(&policy, &needs(WorkKind::Review, Size::Medium), &fleet);
        assert_eq!(pick(&routed, &fleet).as_deref(), Some("nemotron"));
        assert!(
            routed.decision.reason.contains("none reach 0.80"),
            "{}",
            routed.decision.reason
        );
    }
    #[test]
    fn josh_example_code_edits_go_to_sonnet() {
        let fleet = josh_fleet();
        let routed = run(
            &josh_policy(),
            &needs(WorkKind::CodeChange, Size::Medium),
            &fleet,
        );
        assert_eq!(
            pick(&routed, &fleet).as_deref(),
            Some("claude-sonnet"),
            "{}",
            routed.decision.reason
        );
        // The engines that cannot edit files say so.
        for name in ["nemotron", "ollama"] {
            let out = routed
                .decision
                .candidates
                .iter()
                .find(|c| c.engine == name)
                .unwrap();
            assert!(
                out.excluded
                    .as_ref()
                    .is_some_and(|why| why.contains("code")),
                "{name}: {:?}",
                out.excluded
            );
        }
    }

    #[test]
    fn josh_example_a_small_chore_that_edits_files_goes_to_haiku_until_it_is_refuted() {
        let fleet = josh_fleet();
        let chore = editing_chore();
        // Haiku is a chore model (0.82 against the 0.70 default) and the cheaper of the
        // two engines that can edit files.
        let routed = run(&josh_policy(), &chore, &fleet);
        assert_eq!(
            pick(&routed, &fleet).as_deref(),
            Some("claude-haiku"),
            "{}",
            routed.decision.reason
        );
        assert!(routed.decision.reason.contains("cheapest sufficient"));
        // Eight refuted chores take the work away from it: Sonnet.
        let mut refuted = fleet.clone();
        for _ in 0..8 {
            record_outcome(&mut refuted[0].outcomes, "chore", false, now());
        }
        let routed = run(&josh_policy(), &chore, &refuted);
        assert_eq!(pick(&routed, &refuted).as_deref(), Some("claude-sonnet"));
        // Chores that edit nothing still go to the free engine.
        let routed = run(&josh_policy(), &needs(WorkKind::Chore, Size::Small), &fleet);
        assert_eq!(pick(&routed, &fleet).as_deref(), Some("nemotron"));
    }
    #[test]
    fn josh_example_local_models_are_eligible() {
        let mut fleet = josh_fleet();
        let docs = needs(WorkKind::Docs, Size::Medium);
        // With NVIDIA out of credit, the next sufficient engine is Haiku (a 0.78 writer
        // and cheaper than Sonnet)...
        fleet[3].state = "exhausted".into();
        let routed = run(&josh_policy(), &docs, &fleet);
        assert_eq!(pick(&routed, &fleet).as_deref(), Some("claude-haiku"));
        // ...until the local model has proven itself at docs: free beats a subscription.
        for _ in 0..8 {
            record_outcome(&mut fleet[2].outcomes, "docs", true, now());
        }
        let routed = run(&josh_policy(), &docs, &fleet);
        assert_eq!(
            pick(&routed, &fleet).as_deref(),
            Some("ollama"),
            "{}",
            routed.decision.reason
        );
        assert_eq!(routed.decision.winner.as_ref().unwrap().cost_usd, 0.0);
    }
    #[test]
    fn a_subscription_is_scarce_even_behind_a_local_address() {
        // The same model on a subscription, reached through a local gateway: it declares
        // itself local, but how it is paid for decides, so it is not free.
        let mut gateway = http("gateway", ModelClass::Large, "subscription");
        gateway.capabilities.local = true;
        gateway.weekly_requests = Some(100);
        let price = price(&gateway, &needs(WorkKind::Docs, Size::Small), now());
        assert!(price.usd > 0.0, "{price:?}");
        assert!(price.note.starts_with("subscription"), "{}", price.note);
        // A prepaid engine behind one is the same: not local by its address.
        let mut prepaid = http("metered", ModelClass::Large, "prepaid");
        prepaid.capabilities.local = false;
        prepaid.capabilities.cost = None;
        assert!(
            super::price(&prepaid, &needs(WorkKind::Docs, Size::Small), now()).usd > 0.0,
            "unpriced and paid is never free"
        );
    }
    #[test]
    fn a_retry_leaves_out_the_failed_engine_and_needs_a_higher_estimate() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut steady = engine("steady", ModelClass::Large, "prepaid", per_call(0.01));
        steady.capabilities.strengths = vec!["docs".into()];
        let mut quick = engine("quick", ModelClass::Medium, "prepaid", per_call(0.001));
        quick.capabilities.strengths = vec!["docs".into()];
        let engines = [quick, nvidia, steady];
        let docs = needs(WorkKind::Docs, Size::Small);
        let first = run(&Policy::default(), &docs, &engines);
        assert_eq!(pick(&first, &engines).as_deref(), Some("nvidia"));
        let failed = [failure("nvidia", Some(0.80))];
        let again = retry(&failed, &engines, &docs);
        // Haiku is sufficient on its own (0.75) but must beat 0.80; steady does (0.85).
        assert_eq!(
            pick(&again, &engines).as_deref(),
            Some("steady"),
            "{:?}",
            again.decision
        );
        assert!(again.decision.reason.contains("escalated"));
        assert_eq!(again.decision.must_beat, Some(0.8));
        let left_out = again
            .decision
            .candidates
            .iter()
            .find(|c| c.engine == "nvidia")
            .unwrap();
        assert!(
            left_out
                .excluded
                .as_ref()
                .unwrap()
                .contains("failed this order earlier at p 0.80")
        );
        // With only engines that cannot beat it, the best of them still does the work.
        let weak = [engines[0].clone()];
        let again = retry(&failed, &weak, &docs);
        assert_eq!(pick(&again, &weak).as_deref(), Some("quick"));
        assert!(again.decision.reason.contains("none reach"));
        // And when every engine failed, nothing waits: the likeliest of them tries again.
        let all = [
            failure("quick", None),
            failure("nvidia", None),
            failure("steady", None),
        ];
        let again = retry(&all, &engines, &docs);
        assert_eq!(pick(&again, &engines).as_deref(), Some("steady"));
        assert_eq!(again.order.len(), 3, "all of them, likeliest first");
        assert!(
            again
                .decision
                .reason
                .contains("every engine that can do this work has already failed this order"),
            "{}",
            again.decision.reason
        );
        assert_eq!(again.decision.must_beat, None);
        assert!(
            again
                .decision
                .candidates
                .iter()
                .all(|c| c.excluded.is_none())
        );
        // No engines at all is still none.
        let none = retry(&all, &[], &docs);
        assert!(none.order.is_empty());
        assert!(none.decision.reason.starts_with("no engine"));
    }

    #[test]
    fn a_single_engine_that_failed_is_tried_again_rather_than_left_waiting() {
        let only = engine("only", ModelClass::Large, "prepaid", per_call(0.01));
        let engines = [only];
        let code = needs(WorkKind::CodeChange, Size::Small);
        let first = retry(&[], &engines, &code);
        assert_eq!(pick(&first, &engines).as_deref(), Some("only"));
        let again = retry(&[failure("only", Some(0.8))], &engines, &code);
        assert_eq!(pick(&again, &engines).as_deref(), Some("only"));
        assert!(
            again.decision.reason.contains("tries again"),
            "{}",
            again.decision.reason
        );
        assert!(!again.decision.candidates[0].sufficient);
    }

    #[test]
    fn the_bar_a_retry_must_beat_comes_from_the_local_ledger_not_the_record() {
        let cheap = engine("cheap", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        let big = engine("big", ModelClass::Large, "prepaid", per_call(0.01));
        let engines = [cheap, big];
        let docs = needs(WorkKind::Docs, Size::Small);
        // A record that says the cheap engine failed at p 1.0 (anyone who can write a
        // result can say so) must not make everything else look insufficient.
        let routed = retry(&[failure("cheap", Some(1.0))], &engines, &docs);
        assert_eq!(
            routed.decision.must_beat,
            Some(0.7),
            "the ledger's own figure"
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("big"));
        let big_out = routed
            .decision
            .candidates
            .iter()
            .find(|c| c.engine == "big")
            .unwrap();
        assert!(big_out.sufficient, "0.80 clears the 0.70 it must beat");
        // Without a record's figure it is the same.
        let routed = retry(&[failure("cheap", None)], &engines, &docs);
        assert_eq!(routed.decision.must_beat, Some(0.7));
        // A refutation already in this machine's ledger lowers the bar it set.
        let mut worse = engines.clone();
        record_outcome(&mut worse[0].outcomes, "docs", false, now());
        let routed = retry(&[failure("cheap", Some(1.0))], &worse, &docs);
        assert!(
            routed.decision.must_beat.unwrap() < 0.6,
            "{:?}",
            routed.decision
        );
    }

    #[test]
    fn an_order_with_an_attached_picture_waits_in_plain_words_until_an_engine_can_see() {
        // The picture is attached, so vision is needed (unlike a picture merely named in the
        // text, which the classifier no longer counts). Nothing can see it: the order holds
        // and says why, rather than being sent to an engine that cannot read it.
        let coder = engine("coder", ModelClass::Large, "prepaid", per_call(0.01));
        let mut seer = coder.clone();
        seer.name = "seer".into();
        seer.capabilities.modalities.push(Modality::Vision);
        let mut shot = needs(WorkKind::CodeChange, Size::Medium);
        shot.modalities = resolve_modalities(&[Modality::Vision], WorkKind::CodeChange);
        let held = run(&Policy::default(), &shot, std::slice::from_ref(&coder));
        assert!(held.order.is_empty());
        assert!(
            held.decision.reason.contains("coder") && held.decision.reason.contains("lacks vision"),
            "{}",
            held.decision.reason
        );
        // An engine that can see takes it.
        let engines = [coder, seer];
        let routed = run(&Policy::default(), &shot, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("seer"));
    }

    #[test]
    fn a_failure_belongs_to_the_engine_on_that_agents_machine() {
        // Two agents each run a `claude`; one failed, the other did not.
        let mut wisp = engine("claude", ModelClass::Medium, "prepaid", per_call(0.01));
        wisp.agent = "wisp".into();
        wisp.machine = "box".into();
        let mut ember = wisp.clone();
        ember.agent = "ember".into();
        ember.machine = "laptop".into();
        let mut other_box = wisp.clone();
        other_box.machine = "second".into();
        let engines = [wisp, ember, other_box];
        let docs = needs(WorkKind::Docs, Size::Small);
        let failed = [Failed {
            agent: "wisp".into(),
            machine: "box".into(),
            engine: "claude".into(),
            p: Some(0.70),
        }];
        let routed = retry(&failed, &engines, &docs);
        assert!(
            routed.order.iter().all(|index| *index != 0),
            "wisp's claude on box failed: {:?}",
            routed.order
        );
        assert_eq!(routed.order.len(), 2, "ember's claude and wisp's other box");
        let out = routed
            .decision
            .candidates
            .iter()
            .find(|c| c.agent == "wisp" && c.machine == "box")
            .unwrap();
        assert!(out.excluded.as_ref().unwrap().contains("failed this order"));
        // A record that does not say where it ran counts for that agent's every machine, and
        // never for another agent.
        let anywhere = [Failed {
            agent: "wisp".into(),
            machine: String::new(),
            engine: "claude".into(),
            p: None,
        }];
        let routed = retry(&anywhere, &engines, &docs);
        assert_eq!(routed.order, vec![1]);
    }

    #[test]
    fn work_needs_the_modalities_and_an_http_engine_gets_text_only() {
        let mut seer = engine("seer", ModelClass::Large, "prepaid", Some(Cost::FREE));
        seer.capabilities.modalities = vec![Modality::Text, Modality::Vision, Modality::Code];
        let blind = engine("blind", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut api = http("api", ModelClass::Large, "free-tier");
        api.capabilities.modalities = vec![Modality::Text, Modality::Vision];
        let engines = [blind, api, seer];
        let vision = Needs {
            modalities: resolve_modalities(&[Modality::Vision], WorkKind::Docs),
            kind: WorkKind::Docs,
            size: Size::Small,
            min_context_k: 0,
        };
        let routed = run(&Policy::default(), &vision, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("seer"));
        let why = |name: &str| {
            routed
                .decision
                .candidates
                .iter()
                .find(|c| c.engine == name)
                .and_then(|c| c.excluded.clone())
                .unwrap()
        };
        assert!(why("blind").contains("lacks vision"));
        assert!(
            why("api").contains("http engine is sent text only"),
            "{}",
            why("api")
        );
        // Code-change needs a cli engine that has `code`: with one up, the http engine is out.
        let code = needs(WorkKind::CodeChange, Size::Small);
        let only_api = [http("api", ModelClass::Large, "free-tier")];
        let with_cli = [
            http("api", ModelClass::Large, "free-tier"),
            engine("cli", ModelClass::Large, "prepaid", per_call(0.5)),
        ];
        let routed = run(&Policy::default(), &code, &with_cli);
        assert_eq!(
            pick(&routed, &with_cli).as_deref(),
            Some("cli"),
            "only a cli engine edits files, however much cheaper the http one is"
        );
        assert!(
            routed.decision.candidates.iter().any(|c| c.engine == "api"
                && c.excluded
                    .as_ref()
                    .is_some_and(|why| why.contains("lacks code"))),
            "{:?}",
            routed.decision
        );
        // With no engine that can edit files at all, the work is not held: a fleet of http
        // engines only has always taken build orders, and still does - and says so.
        let routed = run(&Policy::default(), &code, &only_api);
        assert_eq!(pick(&routed, &only_api).as_deref(), Some("api"));
        assert!(
            routed
                .decision
                .reason
                .contains("no engine that can edit files"),
            "{}",
            routed.decision.reason
        );
        // An http engine does text work.
        let text = needs(WorkKind::Docs, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &text, &only_api), &only_api).as_deref(),
            Some("api")
        );
        // A window smaller than the work wants is out; an unknown one is not.
        let mut small_window = engine("window", ModelClass::Large, "free-tier", Some(Cost::FREE));
        small_window.capabilities.context_k = Some(8);
        let mut wide = needs(WorkKind::Docs, Size::Small);
        wide.min_context_k = 32;
        let both = [
            small_window,
            engine("open", ModelClass::Large, "free-tier", Some(Cost::FREE)),
        ];
        let routed = run(&Policy::default(), &wide, &both);
        assert_eq!(pick(&routed, &both).as_deref(), Some("open"));
        assert!(routed.decision.candidates.iter().any(|c| {
            c.excluded
                .as_ref()
                .is_some_and(|why| why.contains("8k context is under the 32k"))
        }));
    }

    #[test]
    fn an_engine_with_no_profile_is_text_only() {
        let mut bare = engine("bare", ModelClass::Large, "free-tier", Some(Cost::FREE));
        bare.capabilities = Capabilities::default();
        let engines = [bare];
        assert_eq!(
            pick(
                &run(
                    &Policy::default(),
                    &needs(WorkKind::Docs, Size::Small),
                    &engines
                ),
                &engines
            )
            .as_deref(),
            Some("bare")
        );
        // Beside an engine that can edit files, it is out of code work.
        let both = [
            engines[0].clone(),
            engine("cli", ModelClass::Large, "prepaid", per_call(0.5)),
        ];
        assert_eq!(
            pick(
                &run(
                    &Policy::default(),
                    &needs(WorkKind::CodeChange, Size::Small),
                    &both
                ),
                &both
            )
            .as_deref(),
            Some("cli")
        );
    }

    #[test]
    fn an_unpriced_paid_engine_is_not_free() {
        let unpriced = engine("mystery", ModelClass::Large, "prepaid", None);
        let priced = engine("priced", ModelClass::Large, "prepaid", per_call(0.02));
        let docs = needs(WorkKind::Docs, Size::Medium);
        let p = price(&unpriced, &docs, now());
        // 12k in at $5/M plus 3k out at $25/M.
        assert!((p.usd - 0.135).abs() < 1e-9, "{}", p.usd);
        assert!(p.note.starts_with("unpriced, assumed ~$0.1"), "{}", p.note);
        let engines = [unpriced, priced];
        assert_eq!(
            pick(&run(&Policy::default(), &docs, &engines), &engines).as_deref(),
            Some("priced"),
            "a declared price beats a guess"
        );
        // A free tier that asked for money is priced like an unpriced one while flagged.
        let mut flagged = engine("flagged", ModelClass::Large, "free-tier", Some(Cost::FREE));
        assert_eq!(price(&flagged, &docs, now()).usd, 0.0);
        flagged.flag = Some("asked for payment".into());
        assert!(price(&flagged, &docs, now()).usd > 0.1);
    }

    #[test]
    fn a_subscription_costs_more_as_its_weekly_cap_runs_down() {
        let mut sub = engine("sub", ModelClass::Large, "subscription", Some(Cost::FREE));
        sub.weekly_requests = Some(300);
        let docs = needs(WorkKind::Docs, Size::Small);
        let fresh = price(&sub, &docs, now());
        assert!((fresh.usd - SCARCITY_BASE_USD).abs() < 1e-9);
        assert_eq!(
            fresh.note,
            "subscription, cap 300/wk, 100% of the weekly cap left"
        );
        sub.week = iso_week(now());
        sub.requests = 150;
        let half = price(&sub, &docs, now());
        sub.requests = 270;
        let low = price(&sub, &docs, now());
        sub.requests = 300;
        let empty = price(&sub, &docs, now());
        assert!(fresh.usd < half.usd && half.usd < low.usd && low.usd < empty.usd);
        assert!((empty.usd - SCARCITY_BASE_USD * 10.0).abs() < 1e-9);
        // Last week's count says nothing about this one.
        sub.week = "2026-W01".into();
        assert_eq!(price(&sub, &docs, now()).note, fresh.note);
        // With no cap known, half is assumed.
        sub.weekly_requests = None;
        assert_eq!(
            price(&sub, &docs, now()).note,
            "subscription, no weekly cap known"
        );
        // Free beats a subscription.
        let free = engine("free", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let engines = [sub, free];
        let open = Policy {
            protect_subscriptions: false,
            ..Policy::default()
        };
        assert_eq!(
            pick(&run(&open, &docs, &engines), &engines).as_deref(),
            Some("free")
        );
    }

    #[test]
    fn the_policys_background_rules_run_before_any_scoring() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let claude = engine(
            "claude",
            ModelClass::Large,
            "subscription",
            Some(Cost::FREE),
        );
        let engines = [nvidia, claude];
        let docs = needs(WorkKind::Docs, Size::Small);
        // A subscription is protected: it is out however good it is.
        let routed = run(&Policy::default(), &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("nvidia"));
        let blocked = routed
            .decision
            .candidates
            .iter()
            .find(|c| c.engine == "claude")
            .unwrap();
        assert!(
            blocked
                .excluded
                .as_ref()
                .unwrap()
                .contains("protect_subscriptions")
        );
        // `never` is final, and `where` too.
        let never = Policy {
            never: vec!["name:nvidia".into()],
            ..Policy::default()
        };
        assert!(
            run(&never, &docs, &engines).order.is_empty(),
            "never falls back to a blocked engine"
        );
        let elsewhere = Policy {
            machines: vec!["other".into()],
            ..Policy::default()
        };
        assert!(run(&elsewhere, &docs, &engines).order.is_empty());
        // A chore engine never builds, however cheap and sure.
        let mut chore = engine("chore", ModelClass::Large, "free-tier", Some(Cost::FREE));
        chore.tier = "chore".into();
        let only = [chore];
        assert!(
            run(
                &Policy::default(),
                &needs(WorkKind::CodeChange, Size::Small),
                &only
            )
            .order
            .is_empty()
        );
        let chores = needs(WorkKind::Chore, Size::Small);
        assert_eq!(
            pick(&run(&Policy::default(), &chores, &only), &only).as_deref(),
            Some("chore")
        );
        // Out of credit is out.
        let mut spent = engine("spent", ModelClass::Large, "free-tier", Some(Cost::FREE));
        spent.state = "exhausted".into();
        assert!(run(&Policy::default(), &docs, &[spent]).order.is_empty());
    }

    #[test]
    fn ordered_keeps_the_policy_order_and_the_adversary_is_never_routed() {
        let cheap = engine("cheap", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let dear = engine("dear", ModelClass::Large, "prepaid", per_call(1.0));
        let engines = [cheap, dear];
        let mut ordered = Policy {
            routing: Routing::Ordered,
            ..Policy::default()
        };
        ordered.prefer.insert(
            "build".into(),
            vec!["name:dear".into(), "name:cheap".into()],
        );
        let docs = needs(WorkKind::Docs, Size::Small);
        let routed = run(&ordered, &docs, &engines);
        let by_rank = rank(&ordered, Role::Build, "build", Work::Background, &engines).order;
        assert_eq!(routed.order, by_rank, "exactly rank's order");
        assert_eq!(pick(&routed, &engines).as_deref(), Some("dear"));
        assert_eq!(routed.decision.routing, "ordered");
        assert!(
            routed
                .decision
                .reason
                .starts_with("dear: first allowed engine in the policy order")
        );
        // Smart, the same lists are only a bias: the free one wins.
        let mut smart = ordered.clone();
        smart.routing = Routing::Smart;
        assert_eq!(
            pick(&run(&smart, &docs, &engines), &engines).as_deref(),
            Some("cheap")
        );
        // The adversary is ranked as it always was, even under smart.
        let mut judge = engine("judge", ModelClass::Large, "free-tier", Some(Cost::FREE));
        judge.tier = "judge".into();
        let pair = [
            judge,
            engine("builder", ModelClass::Large, "free-tier", Some(Cost::FREE)),
        ];
        let adversary = route(
            &smart,
            Role::Adversary,
            "judge",
            Work::Background,
            &needs_for_role(Role::Adversary),
            &pair,
            &Context::new(now()),
        );
        assert_eq!(adversary.decision.routing, "ordered");
        assert_eq!(
            adversary.order,
            rank(&smart, Role::Adversary, "judge", Work::Background, &pair).order
        );
        assert!(adversary.decision.reason.contains("never routed"));
        // Tried engines are skipped in ordered mode too.
        let tried = ["dear".to_string()];
        let routed = route(
            &ordered,
            Role::Build,
            "build",
            Work::Background,
            &docs,
            &engines,
            &Context {
                now: now(),
                tried: &tried,
                failed: &[],
            },
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("cheap"));
    }

    #[test]
    fn a_judge_plans_first_among_equals_and_a_cheaper_builder_still_can() {
        let mut judge = engine("judge", ModelClass::Large, "prepaid", per_call(0.3));
        judge.tier = "judge".into();
        let builder = engine("builder", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let plan = needs_for_role(Role::Plan);
        let plans = |engines: &[Candidate]| {
            let routed = route(
                &Policy::default(),
                Role::Plan,
                "judge",
                Work::Background,
                &plan,
                engines,
                &Context::new(now()),
            );
            pick(&routed, engines)
        };
        // A free builder that is sufficient plans, as cheapest sufficient (a plan it writes
        // is marked unreviewed, as before).
        assert_eq!(
            plans(&[builder.clone(), judge.clone()]).as_deref(),
            Some("builder")
        );
        // Among engines that cost the same, the judge plans: a plan it wrote needs no
        // second reading.
        let mut free_judge = judge.clone();
        free_judge.capabilities.cost = Some(Cost::FREE);
        free_judge.paid = "free-tier".into();
        assert_eq!(
            plans(&[builder.clone(), free_judge]).as_deref(),
            Some("judge")
        );
        // With no judge, a builder plans.
        let alone = [builder];
        let routed = route(
            &Policy::default(),
            Role::Plan,
            "judge",
            Work::Background,
            &plan,
            &alone,
            &Context::new(now()),
        );
        assert_eq!(pick(&routed, &alone).as_deref(), Some("builder"));
    }

    #[test]
    fn a_decision_survives_its_json_and_names_its_reason() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let engines = [nvidia];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        let value = serde_json::to_value(&routed.decision).unwrap();
        let payload = serde_json::json!({ "routing": value });
        assert_eq!(
            reason_of(&payload).as_deref(),
            Some("nvidia: free, p 0.80 for docs >= 0.70, cheapest sufficient")
        );
        assert_eq!(decision_of(&payload).unwrap(), routed.decision);
        assert!(reason_of(&serde_json::json!({})).is_none());
        let lines = routed.decision.lines().join("\n");
        assert!(
            lines.contains("> nvidia") && lines.contains("=> nvidia: free"),
            "{lines}"
        );
    }

    #[test]
    fn simulating_runs_the_same_choice_without_an_order() {
        let nvidia = engine("nvidia", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let mut seer = engine("seer", ModelClass::Large, "prepaid", Some(Cost::FREE));
        seer.capabilities.modalities = vec![Modality::Text, Modality::Vision];
        let engines = [nvidia, seer];
        let wanted = simulated_needs("docs", "small", &[]).unwrap();
        assert_eq!(
            pick(
                &simulate(&Policy::default(), &engines, &wanted, now()),
                &engines
            )
            .as_deref(),
            Some("nvidia")
        );
        let vision = simulated_needs("docs", "small", &["vision".to_string()]).unwrap();
        assert_eq!(
            pick(
                &simulate(&Policy::default(), &engines, &vision, now()),
                &engines
            )
            .as_deref(),
            Some("seer")
        );
        assert!(simulated_needs("sorcery", "small", &[]).is_err());
        assert!(simulated_needs("docs", "huge", &[]).is_err());
        assert!(simulated_needs("docs", "small", &["telepathy".to_string()]).is_err());
    }

    #[test]
    fn the_top_kinds_are_the_most_decided_ones() {
        let mut list = Vec::new();
        for _ in 0..5 {
            record_outcome(&mut list, "docs", true, now());
        }
        record_outcome(&mut list, "docs", false, now());
        for _ in 0..2 {
            record_outcome(&mut list, "tests", true, now());
        }
        record_outcome(&mut list, "plan", true, now());
        let top = top_kinds(&list, now(), 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "docs");
        assert!((top[0].1 - 5.0 / 6.0).abs() < 1e-3 && (top[0].2 - 6.0).abs() < 1e-3);
        assert_eq!(top[1].0, "tests");
    }

    // --- model profiles, thresholds and the new tie-breaks ------------------------------

    /// An engine whose model the router may know. `class` is what its worker would have
    /// guessed or the operator declared; a model with a profile ignores it.
    fn modeled(name: &str, model: &str, class: ModelClass, paid: &str) -> Candidate {
        Candidate {
            model: Some(model.into()),
            ..http(name, class, paid)
        }
    }

    #[test]
    fn a_known_model_takes_its_prior_from_its_profile_and_not_from_its_class() {
        // Declared large, but the model is Nemotron super: it reviews like one.
        let nemotron = modeled(
            "nvidia",
            "nvidia/nemotron-3-super-120b-a12b",
            ModelClass::Large,
            "free-tier",
        );
        let review = needs(WorkKind::Review, Size::Medium);
        assert!((prior(&nemotron, &review) - 0.72).abs() < 1e-9);
        let docs = needs(WorkKind::Docs, Size::Medium);
        assert!((prior(&nemotron, &docs) - 0.78).abs() < 1e-9);
        assert_eq!(
            estimate(&nemotron, &review, now()).basis,
            "model profile: nemotron-super"
        );
        // A model the router does not know keeps the class rule, to the digit.
        let mystery = modeled("mystery", "my-own-finetune", ModelClass::Large, "free-tier");
        assert!((prior(&mystery, &review) - 0.80).abs() < 1e-9);
        assert_eq!(estimate(&mystery, &review, now()).basis, "class large");
        // The model string comes first; the engine name is only the fallback.
        let by_model = modeled("sonnet-box", "haiku", ModelClass::Large, "subscription");
        assert_eq!(
            estimate(&by_model, &review, now()).basis,
            "model profile: claude-haiku"
        );
        // The name is read only when there is no model: a finetune served by an engine
        // called claude-sonnet is scored by its class.
        let by_name = modeled(
            "claude-sonnet",
            "an-unlisted-model",
            ModelClass::Small,
            "subscription",
        );
        assert_eq!(estimate(&by_name, &review, now()).basis, "class small");
        let nameless = engine("claude-opus", ModelClass::Small, "subscription", None);
        assert!(prior(&nameless, &review) > 0.90, "opus by its name");
    }

    #[test]
    fn declared_strengths_still_add_their_bonus_to_a_profile_but_never_twice() {
        let mut haiku = modeled("h", "haiku", ModelClass::Small, "subscription");
        let review = needs(WorkKind::Review, Size::Medium);
        assert!((prior(&haiku, &review) - 0.70).abs() < 1e-9);
        haiku.capabilities.strengths = vec!["review".into()];
        assert!((prior(&haiku, &review) - 0.75).abs() < 1e-9);
        haiku.capabilities.strengths = vec!["review".into(), "reasoning".into()];
        assert!((prior(&haiku, &review) - 0.80).abs() < 1e-9, "to +0.10");
        // A tag the profile has already priced in (`code` on a -coder) adds nothing...
        let mut coder = modeled("c", "qwen2.5-coder:32b", ModelClass::Medium, "local");
        let code = needs(WorkKind::CodeChange, Size::Medium);
        let base = prior(&coder, &code);
        coder.capabilities.strengths = vec!["code".into()];
        assert!((prior(&coder, &code) - base).abs() < 1e-9);
        // ...but a tag it has not does: tests are helped by `tests` as well.
        let tests = needs(WorkKind::Tests, Size::Medium);
        coder.capabilities.strengths = vec![];
        let base = prior(&coder, &tests);
        coder.capabilities.strengths = vec!["code".into(), "tests".into()];
        assert!((prior(&coder, &tests) - (base + 0.05)).abs() < 1e-9);
        // And a model that is not known to be a coder is helped by saying so.
        let mut flash = modeled("g", "gemini-flash", ModelClass::Medium, "free-tier");
        let base = prior(&flash, &code);
        flash.capabilities.strengths = vec!["code".into()];
        assert!((prior(&flash, &code) - (base + 0.05)).abs() < 1e-9);
    }

    #[test]
    fn a_profile_is_a_prior_the_ledger_still_moves_and_the_line_shows_it() {
        let mut haiku = modeled("h", "haiku", ModelClass::Small, "subscription");
        let chore = needs(WorkKind::Chore, Size::Small);
        assert!((estimate(&haiku, &chore, now()).p - 0.82).abs() < 1e-9);
        for _ in 0..4 {
            record_outcome(&mut haiku.outcomes, "chore", true, now());
        }
        let moved = estimate(&haiku, &chore, now());
        // (0.82 * 4 + 4) / 8
        assert!((moved.p - 0.91).abs() < 1e-3, "{}", moved.p);
        assert_eq!(
            moved.basis,
            "model profile: claude-haiku, ledger 4 verified 0 refuted"
        );
        for _ in 0..12 {
            record_outcome(&mut haiku.outcomes, "chore", false, now());
        }
        assert!(estimate(&haiku, &chore, now()).p < 0.40, "refuted again");
    }

    #[test]
    fn large_work_is_a_step_harder_for_a_smaller_model() {
        let mini = modeled("m", "gpt-5-mini", ModelClass::Medium, "prepaid");
        let medium = prior(&mini, &needs(WorkKind::Docs, Size::Medium));
        let large = prior(&mini, &needs(WorkKind::Docs, Size::Large));
        assert!((medium - large - 0.05).abs() < 1e-9);
        let gpt = modeled("g", "gpt-5", ModelClass::Medium, "prepaid");
        let a = prior(&gpt, &needs(WorkKind::Docs, Size::Medium));
        let b = prior(&gpt, &needs(WorkKind::Docs, Size::Large));
        assert!((a - b).abs() < 1e-9, "a large model loses nothing");
    }

    #[test]
    fn review_and_plan_need_point_eight_and_large_work_a_little_more() {
        let engines = [modeled(
            "d",
            "deepseek-v4-pro",
            ModelClass::Large,
            "free-tier",
        )];
        for (kind, size, want) in [
            (WorkKind::Review, Size::Medium, 0.80),
            (WorkKind::Plan, Size::Small, 0.80),
            (WorkKind::Review, Size::Large, 0.85),
            (WorkKind::Plan, Size::Large, 0.85),
            (WorkKind::Docs, Size::Small, 0.70),
            (WorkKind::Docs, Size::Large, 0.75),
            (WorkKind::Chore, Size::Large, 0.75),
            (WorkKind::CodeChange, Size::Medium, 0.75),
            (WorkKind::CodeChange, Size::Large, 0.80),
        ] {
            let routed = run(&Policy::default(), &needs(kind, size), &engines);
            let got = routed.decision.threshold;
            assert!((got - want).abs() < 1e-9, "{kind:?} {size:?}: {got}");
        }
        // What the policy signs is used as set, large or not.
        let mut set = Policy::default();
        set.thresholds.insert("review".into(), 0.70);
        let routed = run(&set, &needs(WorkKind::Review, Size::Large), &engines);
        assert!((routed.decision.threshold - 0.70).abs() < 1e-9);
    }

    #[test]
    fn only_a_model_that_is_good_at_it_gets_review_and_a_free_one_keeps_the_words() {
        let mut nemotron = modeled(
            "nvidia",
            "nvidia/nemotron-3-super-120b-a12b",
            ModelClass::Medium,
            "free-tier",
        );
        nemotron.tier = "judge".into();
        let mut sonnet = modeled("claude-sonnet", "sonnet", ModelClass::Medium, "prepaid");
        sonnet.tier = "judge".into();
        sonnet.capabilities.cost = per_call(0.01);
        let engines = [sonnet, nemotron];
        let policy = Policy::default();
        for kind in [WorkKind::Docs, WorkKind::Chore] {
            let routed = run(&policy, &needs(kind, Size::Medium), &engines);
            assert_eq!(
                pick(&routed, &engines).as_deref(),
                Some("nvidia"),
                "{kind:?}: {}",
                routed.decision.reason
            );
        }
        // Nemotron is a 0.72 reviewer and a 0.70 planner; Sonnet is over the 0.80 bar.
        for kind in [WorkKind::Review, WorkKind::Plan] {
            let routed = run(&policy, &needs(kind, Size::Medium), &engines);
            assert_eq!(
                pick(&routed, &engines).as_deref(),
                Some("claude-sonnet"),
                "{kind:?}: {}",
                routed.decision.reason
            );
            assert!(routed.decision.reason.contains("cheapest sufficient"));
        }
    }

    #[test]
    fn among_equal_prices_a_truly_free_engine_comes_before_a_paid_one_whatever_its_speed() {
        // Costs within half a tenth of a cent are tied. The paid one is listed first and
        // is faster, and the free one still wins.
        let mut paid = engine("paid", ModelClass::Large, "prepaid", per_call(0.0002));
        paid.latency_ms = Some(10);
        let mut free = engine("free", ModelClass::Large, "free-tier", Some(Cost::FREE));
        free.latency_ms = Some(900);
        let engines = [paid, free];
        let routed = run(
            &Policy::default(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("free"));
        assert!(
            routed
                .decision
                .reason
                .contains("tied on price with paid, how it is paid for put it first"),
            "{}",
            routed.decision.reason
        );
    }

    #[test]
    fn among_equal_prices_a_subscription_comes_before_a_paid_engine() {
        // A subscription with no cap known is priced at 0.065, a paid engine at 0.066:
        // tied, and the subscription goes first though the paid one is listed first.
        let mut paid = engine("paid", ModelClass::Large, "prepaid", per_call(0.066));
        paid.latency_ms = Some(10);
        let sub = engine("sub", ModelClass::Large, "subscription", Some(Cost::FREE));
        let engines = [paid, sub];
        let routed = run(
            &josh_policy(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("sub"));
        assert!(routed.decision.reason.contains("tied on price with paid"));
        // The same two the other way round, as listed.
        let engines = [engines[1].clone(), engines[0].clone()];
        let routed = run(
            &josh_policy(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("sub"));
    }

    #[test]
    fn among_equal_prices_the_higher_p_comes_before_speed_and_bias_still_comes_first() {
        let mut quick = engine("quick", ModelClass::Medium, "free-tier", Some(Cost::FREE));
        quick.latency_ms = Some(10);
        let mut steady = engine("steady", ModelClass::Large, "free-tier", Some(Cost::FREE));
        steady.latency_ms = Some(900);
        let engines = [quick, steady];
        let docs = needs(WorkKind::Docs, Size::Small);
        // Both are sufficient (0.70 and 0.80) and free: the likelier one first.
        let routed = run(&Policy::default(), &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("steady"));
        assert!(
            routed
                .decision
                .reason
                .contains("tied on price with quick, its higher p put it first"),
            "{}",
            routed.decision.reason
        );
        // With p equal it is speed again.
        let mut same = engines.clone();
        same[1].class = Some(ModelClass::Medium);
        let routed = run(&Policy::default(), &docs, &same);
        assert_eq!(pick(&routed, &same).as_deref(), Some("quick"));
        // The operator's bias is still the first word.
        let mut prefer = Policy::default();
        prefer
            .prefer
            .insert("build".into(), vec!["name:quick".into()]);
        let routed = run(&prefer, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("quick"));
        assert!(routed.decision.reason.contains("bias put it first"));
    }

    #[test]
    fn a_signed_step_keeps_the_decision_and_loses_only_what_is_for_showing() {
        let sonnet = modeled("claude-sonnet", "sonnet", ModelClass::Large, "subscription");
        let plain = http("plain", ModelClass::Medium, "free-tier");
        let engines = [sonnet, plain];
        let routed = run(
            &josh_policy(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        let live = routed.decision;
        assert!(live.candidates.iter().all(|c| c.basis.is_some()));
        let signed = live.for_signed_step();
        assert!(signed.candidates.iter().all(|c| c.basis.is_none()));
        // Everything else is as it was, and the live decision is untouched.
        let mut same = live.clone();
        for candidate in &mut same.candidates {
            candidate.basis = None;
        }
        assert_eq!(signed, same);
        assert!(live.candidates.iter().all(|c| c.basis.is_some()));
        // No `basis` in what is signed.
        assert!(!serde_json::to_string(&signed).unwrap().contains("basis"));
    }
    #[test]
    fn the_lines_say_where_each_p_came_from_and_an_old_record_still_reads() {
        let sonnet = modeled("claude-sonnet", "sonnet", ModelClass::Large, "subscription");
        let plain = http("plain", ModelClass::Medium, "free-tier");
        let engines = [sonnet, plain];
        let routed = run(
            &josh_policy(),
            &needs(WorkKind::Docs, Size::Small),
            &engines,
        );
        let text = routed.decision.lines().join("\n");
        assert!(
            text.contains("p 0.86 (model profile: claude-sonnet), subscription"),
            "{text}"
        );
        assert!(text.contains("p 0.70 (class medium), free"), "{text}");
        // The basis is recorded with the decision and survives its JSON.
        let back: Decision =
            serde_json::from_value(serde_json::to_value(&routed.decision).unwrap()).unwrap();
        assert_eq!(back, routed.decision);
        // A record written before profiles has no basis and still reads.
        let old: Considered = serde_json::from_str(
            r#"{"engine":"a","agent":"w","machine":"m","p":0.7,"sufficient":true}"#,
        )
        .unwrap();
        assert!(old.basis.is_none());
    }

    /// A subscription engine on a model the router knows, with its weekly cap.
    fn subscribed(name: &str, model: &str, cap: u64) -> Candidate {
        let mut engine = engine(name, ModelClass::Large, "subscription", Some(Cost::FREE));
        engine.model = Some(model.into());
        engine.weekly_requests = Some(cap);
        engine
    }

    #[test]
    fn a_request_on_a_bigger_weekly_cap_is_cheaper_to_use_up() {
        let big = subscribed("claude-haiku", "haiku", 2000);
        let small = subscribed("claude-sonnet", "sonnet", 300);
        let docs = needs(WorkKind::Docs, Size::Small);
        let (big_price, small_price) = (price(&big, &docs, now()), price(&small, &docs, now()));
        // 300 is the reference cap, so it keeps the base scarcity; 2000 is 6.67 times less.
        assert!((small_price.usd - SCARCITY_BASE_USD).abs() < 1e-9);
        assert!((small_price.usd / big_price.usd - 2000.0 / 300.0).abs() < 1e-6);
        assert_eq!(
            big_price.note,
            "subscription, cap 2000/wk, 100% of the weekly cap left"
        );
        assert_eq!(big_price.economy, Economy::Subscription);
    }

    #[test]
    fn haiku_takes_what_it_clears_and_sonnet_only_what_haiku_does_not() {
        let haiku = subscribed("claude-haiku", "haiku", 2000);
        let sonnet = subscribed("claude-sonnet", "sonnet", 300);
        let engines = [sonnet, haiku];
        let policy = josh_policy();
        // Both clear a small chore: the bigger cap is cheaper to use up, whatever p says.
        let routed = run(&policy, &needs(WorkKind::Chore, Size::Small), &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("claude-haiku"));
        assert!(
            routed
                .decision
                .reason
                .contains("preferred over a smaller cap (claude-sonnet 300/wk)"),
            "{}",
            routed.decision.reason
        );
        // Haiku is 0.72 at code against the 0.75 bar: only Sonnet clears it.
        let routed = run(
            &policy,
            &needs(WorkKind::CodeChange, Size::Medium),
            &engines,
        );
        assert_eq!(pick(&routed, &engines).as_deref(), Some("claude-sonnet"));
        assert!(!routed.decision.reason.contains("smaller cap"));
        // Free still comes first, and paid still comes after both subscriptions.
        let free = engine("free", ModelClass::Large, "free-tier", Some(Cost::FREE));
        let paid = engine("paid", ModelClass::Large, "prepaid", per_call(0.05));
        let all = [paid, engines[0].clone(), engines[1].clone(), free];
        let routed = run(&policy, &needs(WorkKind::Chore, Size::Small), &all);
        assert_eq!(
            routed
                .order
                .iter()
                .map(|i| all[*i].name.as_str())
                .collect::<Vec<_>>(),
            ["free", "claude-haiku", "claude-sonnet", "paid"]
        );
    }

    #[test]
    fn opus_is_not_picked_for_background_work_unless_the_policy_names_it() {
        let opus = subscribed("claude-opus", "opus", 300);
        let sonnet = subscribed("claude-sonnet", "sonnet", 300);
        let engines = [opus, sonnet];
        let docs = needs(WorkKind::Docs, Size::Small);
        let policy = josh_policy();
        let routed = run(&policy, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("claude-sonnet"));
        let left_out = routed
            .decision
            .candidates
            .iter()
            .find(|c| c.engine == "claude-opus")
            .unwrap();
        assert!(
            left_out
                .excluded
                .as_ref()
                .is_some_and(|why| why.contains("opus is not used for background work")),
            "{left_out:?}"
        );
        // What the engine costs or how big it is does not name it.
        let mut by_kind = josh_policy();
        by_kind.prefer.insert(
            "build".into(),
            vec!["paid:subscription".into(), "class:large".into()],
        );
        let routed = run(&by_kind, &docs, &engines);
        assert_eq!(pick(&routed, &engines).as_deref(), Some("claude-sonnet"));
        // Naming it (by name, or by model) lets it compete, and the bias puts it first.
        for selector in ["name:claude-opus", "model:opus", "claude-opus"] {
            let mut named = josh_policy();
            named
                .prefer
                .insert("build".into(), vec![selector.to_string()]);
            let routed = run(&named, &docs, &engines);
            assert_eq!(
                pick(&routed, &engines).as_deref(),
                Some("claude-opus"),
                "{selector}: {}",
                routed.decision.reason
            );
        }
        // Work somebody asked for directly is not background work.
        let routed = route(
            &policy,
            Role::Build,
            "build",
            Work::Direct,
            &docs,
            &engines,
            &Context::new(now()),
        );
        assert!(
            routed
                .decision
                .candidates
                .iter()
                .any(|c| c.engine == "claude-opus" && c.excluded.is_none())
        );
    }
}

//! The smart router, part 1: working out what an order needs, with a model when the rules
//! cannot.
//!
//! [`ferryman_channel::work::classify`] decides from the signed order and its payload
//! alone: explicit `needs`, then deterministic rules. When the rules are unsure it says so
//! (a confidence under [`ferryman_channel::work::CONFIDENCE_THRESHOLD`]) and this module
//! takes the one step that needs an engine: [`classify_order`].
//!
//! # The model-assisted step
//!
//! One call to the cheapest `http` text engine (never a cli one: a cli engine is an agent,
//! not a question-answerer), local preferred, asking for a JSON label. Which
//! engine ([`pick_classifier`]) is decided by the same rules that bound any background
//! work: the policy's `never` list, `protect_subscriptions` and `subscription_roles`
//! (a subscription engine only when the policy lists the `chore` role *and* the engine
//! has a weekly request cap), its weekly caps and its `where`. It must have the `text`
//! modality and be up or at least not out of credit. Among those: local first, then by
//! how it is paid for (free tier, capped prepaid, ...), then by what one small call
//! costs, then a smaller model before a larger, then the operator's order.
//!
//! The answer is cached per order id on this machine (see
//! [`ferryman_channel::work::CacheEntry`] for where, and why it is not signed), so the
//! model is asked at most once per order here. An unusable answer is remembered for an
//! hour so a model that cannot follow the format is not billed on every pass. If nothing
//! can be asked, or the answer is no use, the rules' unsure classification is returned
//! with the reason added: routing never stops for want of a label.
//!
//! The engine runner is injected ([`TextRunner`]) so the whole path is tested with fake
//! engines; [`LiveRunner`] is the real one, going through [`crate::agent::ask`] so usage
//! is counted and an exhausted engine is marked like any other call.

use std::future::Future;

use anyhow::Result;
use chrono::{DateTime, Utc};
use ferryman_channel::{
    Order, ProjectRoute,
    capability::Modality,
    policy::{Policy, Role, Work},
    work::{self, CacheEntry, Classification, FAILURE_RETRY_SECS},
};

use crate::{
    agent::AgentConfig,
    engines::{self, Availability, EngineSpec, Ledger},
};

/// Asks one engine one question and returns its text answer. The seam that lets the
/// model-assisted path run against fake engines in tests.
pub trait TextRunner {
    /// Errors are not distinguished here: whatever went wrong, the caller falls back to
    /// the rules. (A real runner records out-of-credit on the engine's ledger itself.)
    fn ask(&self, engine: &EngineSpec, prompt: &str)
    -> impl Future<Output = Result<String>> + Send;
}

/// The real runner: [`crate::agent::ask`] with `engine` in place of the configured one.
pub struct LiveRunner<'a> {
    pub route: &'a ProjectRoute,
    pub config: &'a AgentConfig,
}

impl TextRunner for LiveRunner<'_> {
    fn ask(
        &self,
        engine: &EngineSpec,
        prompt: &str,
    ) -> impl Future<Output = Result<String>> + Send {
        let config = self.config.with_engine(engine);
        let route = self.route;
        let prompt = prompt.to_string();
        async move {
            // A labelling call that hangs must not hold the order: it is one question.
            tokio::time::timeout(
                std::time::Duration::from_secs(CLASSIFY_TIMEOUT_SECS),
                crate::agent::ask(route, &config, &prompt),
            )
            .await
            .map_err(|_| anyhow::anyhow!("no answer within {CLASSIFY_TIMEOUT_SECS} seconds"))?
        }
    }
}

/// How long a labelling call may take before the order is routed on the rules' label.
pub const CLASSIFY_TIMEOUT_SECS: u64 = 45;

/// Settle an improvement order's label before it is routed: when the rules are unsure and
/// the policy routes smartly, ask a model once ([`classify_order_live`]) and let the answer
/// be cached for this order, which is where the router reads it
/// ([`ferryman_channel::work::classify_cached`]). Everything else - a sure label, a person's
/// own order, `routing = "ordered"` - asks nothing. The reply is only ever one of the known
/// kinds (see [`ferryman_channel::work::parse_model_reply`]) and only an `http` engine is
/// asked ([`pick_classifier`]), never an agent with tools, because the order's text is not
/// to be trusted.
pub async fn settle_classification(
    route: &ProjectRoute,
    config: &AgentConfig,
    order: &Order,
    improvement: bool,
) -> Classification {
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    if !improvement || policy.routing != ferryman_channel::policy::Routing::Smart {
        return work::classify_cached(order, route);
    }
    classify_order_live(route, config, order).await
}

/// What the model-assisted step needs to know about this machine: its engines and how they
/// stand, and the policy that bounds background work.
pub struct Assist<'a> {
    pub specs: &'a [EngineSpec],
    pub ledger: &'a Ledger,
    pub policy: &'a Policy,
    /// This worker's agent name and machine label.
    pub agent: &'a str,
    pub machine: &'a str,
    pub now: DateTime<Utc>,
}

/// The engine to ask: the cheapest allowed text engine, local first, or why there is none.
///
/// Never a subscription engine unless the policy's `subscription_roles` lists `chore` and
/// the engine has a weekly request cap - checked here on top of the policy's own
/// `protect_subscriptions`, so turning that off does not open a subscription to a
/// labelling call.
pub fn pick_classifier<'a>(assist: &Assist<'a>) -> std::result::Result<&'a EngineSpec, String> {
    if !assist.policy.allows_machine(assist.agent, assist.machine) {
        return Err(format!(
            "the engine policy does not allow background work on {} ({})",
            assist.agent, assist.machine
        ));
    }
    let candidates = engines::candidates(
        assist.agent,
        assist.machine,
        assist.specs,
        assist.ledger,
        assist.now,
    );
    struct Rank {
        not_local: bool,
        paid: u8,
        cost: f64,
        down: bool,
        class: u8,
        index: usize,
    }
    let mut ranked: Vec<Rank> = Vec::new();
    let mut why: Vec<String> = Vec::new();
    for (index, (spec, candidate)) in assist.specs.iter().zip(&candidates).enumerate() {
        let caps = &candidate.capabilities;
        // A cli engine is an agent, run in a scratch directory with a model's habits and
        // a project's credentials: labelling is one question and an answer, which only an
        // endpoint is asked.
        if spec.kind != engines::Kind::Http {
            why.push(format!(
                "{}: a cli engine is not asked to label orders, only an http one",
                spec.name
            ));
            continue;
        }
        if !caps.has(&Modality::Text) {
            why.push(format!("{}: no text modality", spec.name));
            continue;
        }
        if let Some(reason) =
            assist
                .policy
                .blocked_for(candidate, Work::Background, Some(Role::Chore))
        {
            why.push(format!("{}: {reason}", spec.name));
            continue;
        }
        if candidate.paid_class() == "subscription"
            && !(assist.policy.subscriptions_for(Role::Chore)
                && candidate.weekly_requests.is_some())
        {
            why.push(format!(
                "{}: a subscription is not spent on labelling unless subscription_roles lists \
                 chore and it has a weekly cap",
                spec.name
            ));
            continue;
        }
        let state = assist.ledger.state(&spec.name);
        let availability = engines::availability(spec, &state, assist.now);
        if let Availability::Exhausted { reason, .. } = &availability {
            why.push(format!("{}: {reason}", spec.name));
            continue;
        }
        ranked.push(Rank {
            not_local: !caps.local,
            paid: ferryman_channel::policy::auto_rank(candidate),
            // What one small labelling call costs; an unpriced engine ranks after any
            // priced one.
            cost: caps.cost.map_or(f64::MAX, |cost| cost.estimate(1_500, 100)),
            down: matches!(availability, Availability::Down(_)),
            class: spec.class() as u8,
            index,
        });
    }
    ranked.sort_by(|a, b| {
        (a.not_local, a.paid)
            .cmp(&(b.not_local, b.paid))
            .then(a.cost.total_cmp(&b.cost))
            .then(a.down.cmp(&b.down))
            .then(a.class.cmp(&b.class))
            .then(a.index.cmp(&b.index))
    });
    match ranked.first() {
        Some(best) => Ok(&assist.specs[best.index]),
        None if why.is_empty() => Err("no engine is configured".to_string()),
        None => Err(why.join("; ")),
    }
}

/// An order's classification: explicit `needs`, then the rules, then - only when those are
/// unsure - one model call, cached per order id. Always returns something: when no engine
/// may be asked, or its answer is unusable, it is the rules' answer with the reason added.
pub async fn classify_order<R: TextRunner>(
    route: &ProjectRoute,
    order: &Order,
    assist: &Assist<'_>,
    runner: &R,
) -> Classification {
    let rules = work::classify(order, route);
    if rules.is_sure() {
        return rules;
    }
    let note = |why: String| {
        let mut unsure = rules.clone();
        unsure.reasons.push(why);
        unsure
    };
    if let Some(entry) = work::read_cache(route, &order.id) {
        if let Some(done) = entry.classification {
            return done;
        }
        if let Some(why) = &entry.failed
            && assist.now.signed_duration_since(entry.at)
                < chrono::Duration::seconds(FAILURE_RETRY_SECS)
            && assist.now >= entry.at
        {
            return note(format!(
                "a model could not label it earlier ({} said: {why}); not asked again yet",
                entry.engine
            ));
        }
    }
    let spec = match pick_classifier(assist) {
        Ok(spec) => spec,
        Err(why) => return note(format!("no model was asked: {why}")),
    };
    let reply = match runner.ask(spec, &work::model_prompt(order, &rules)).await {
        Ok(reply) => reply,
        // An engine that could not be reached or is out of credit says so on its own
        // ledger; this is not cached, so the next pass may use another engine.
        Err(error) => return note(format!("the model call to {} failed: {error:#}", spec.name)),
    };
    let explicit = order.needs.as_ref();
    match work::parse_model_reply(&reply) {
        Ok(verdict) => {
            let mut classified = rules.with_model(&verdict, explicit);
            classified
                .reasons
                .push(format!("labelled by {}", spec.name));
            let entry = CacheEntry {
                order_id: order.id.clone(),
                engine: spec.name.clone(),
                at: assist.now,
                classification: Some(classified.clone()),
                failed: None,
            };
            if let Err(error) = work::write_cache(route, &entry) {
                tracing::warn!(
                    "could not cache the classification of {}: {error:#}",
                    order.id
                );
            }
            classified
        }
        Err(error) => {
            let why = format!("{error:#}");
            let entry = CacheEntry {
                order_id: order.id.clone(),
                engine: spec.name.clone(),
                at: assist.now,
                classification: None,
                failed: Some(why.clone()),
            };
            if let Err(error) = work::write_cache(route, &entry) {
                tracing::warn!(
                    "could not cache the classification of {}: {error:#}",
                    order.id
                );
            }
            note(format!("{} answered, but not usably: {why}", spec.name))
        }
    }
}

/// [`classify_order`] on this machine's own engines, ledger and policy, asking through
/// [`LiveRunner`]. Respects the policy's weekly cap for the chore role: over it, no model
/// is asked and the rules' answer is returned.
pub async fn classify_order_live(
    route: &ProjectRoute,
    config: &AgentConfig,
    order: &Order,
) -> Classification {
    let rules = work::classify(order, route);
    if rules.is_sure() {
        return rules;
    }
    let now = Utc::now();
    let (policy, _) = ferryman_channel::policy::effective(&route.communications, &route.project_id);
    if let Some(over) =
        ferryman_channel::policy::over_cap(route, &policy, &engines::iso_week(now), Role::Chore)
    {
        let mut unsure = rules;
        unsure.reasons.push(format!("no model was asked: {over}"));
        return unsure;
    }
    let ledger = Ledger::load(&config.agent);
    let machine = ferryman_channel::receipts::machine_label();
    let specs = engines::effective_specs(&config.engines, &ledger);
    let assist = Assist {
        specs: &specs,
        ledger: &ledger,
        policy: &policy,
        agent: &config.agent,
        machine: &machine,
        now,
    };
    classify_order(route, order, &assist, &LiveRunner { route, config }).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ferryman_channel::{
        capability::{Cost, Declared},
        work::{ExplicitNeeds, Size, Source, WorkKind},
    };
    use serde_json::json;

    use super::*;
    use crate::engines::{Kind, Paid, Tier};

    /// Answers from a script, by engine name, and remembers who was asked what.
    #[derive(Default)]
    struct Fake {
        answers: Vec<(
            &'static str,
            std::result::Result<&'static str, &'static str>,
        )>,
        asked: Mutex<Vec<(String, String)>>,
    }

    impl Fake {
        fn saying(engine: &'static str, answer: &'static str) -> Self {
            Self {
                answers: vec![(engine, Ok(answer))],
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<String> {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .map(|(engine, _)| engine.clone())
                .collect()
        }
    }

    impl TextRunner for Fake {
        fn ask(
            &self,
            engine: &EngineSpec,
            prompt: &str,
        ) -> impl Future<Output = Result<String>> + Send {
            self.asked
                .lock()
                .unwrap()
                .push((engine.name.clone(), prompt.to_string()));
            let answer = self
                .answers
                .iter()
                .find(|(name, _)| *name == engine.name)
                .map(|(_, answer)| *answer);
            async move {
                match answer {
                    Some(Ok(text)) => Ok(text.to_string()),
                    Some(Err(why)) => Err(anyhow::anyhow!(why)),
                    None => Err(anyhow::anyhow!("nobody answers for this engine")),
                }
            }
        }
    }

    fn http(name: &str, paid: Paid, url: &str) -> EngineSpec {
        let mut spec = EngineSpec::implicit("c", &[], Some("some-model"));
        spec.name = name.into();
        spec.kind = Kind::Http;
        spec.tier = Tier::Chore;
        spec.paid = paid;
        spec.command = String::new();
        spec.base_url = Some(url.into());
        spec
    }

    fn route(dir: &std::path::Path) -> ProjectRoute {
        ProjectRoute {
            project_id: "p".into(),
            workspace: dir.to_path_buf(),
            attachment: dir.to_path_buf(),
            communications: dir.to_path_buf(),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn order(id: &str, task: &str) -> Order {
        Order {
            id: id.into(),
            project_id: "p".into(),
            issued_by: "josh".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": task }),
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
        }
    }

    struct World {
        specs: Vec<EngineSpec>,
        ledger: Ledger,
        policy: Policy,
    }

    impl World {
        fn new(specs: Vec<EngineSpec>) -> Self {
            Self {
                specs,
                ledger: Ledger::default(),
                policy: Policy::default(),
            }
        }

        fn assist(&self) -> Assist<'_> {
            Assist {
                specs: &self.specs,
                ledger: &self.ledger,
                policy: &self.policy,
                agent: "wisp",
                machine: "box",
                now: Utc::now(),
            }
        }
    }

    const UNSURE: &str = "hello there";

    // --- which engine is asked --------------------------------------------------------

    #[test]
    fn a_local_engine_is_asked_before_a_cheaper_looking_remote_one() {
        let mut free = http(
            "nvidia",
            Paid::FreeTier,
            "https://integrate.api.nvidia.com/v1",
        );
        free.declared.cost = Some(Cost::FREE);
        let local = http("llama", Paid::Local, "http://localhost:11434/v1");
        let world = World::new(vec![free, local]);
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "llama");
    }

    #[test]
    fn without_a_local_engine_the_free_tier_comes_before_prepaid() {
        let paid = http("deepseek", Paid::Prepaid, "https://api.deepseek.com/v1");
        let free = http(
            "nvidia",
            Paid::FreeTier,
            "https://integrate.api.nvidia.com/v1",
        );
        let world = World::new(vec![paid, free]);
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "nvidia");
    }

    #[test]
    fn among_equals_the_cheaper_call_then_the_smaller_model_then_the_listed_order() {
        let mut dear = http("dear", Paid::Prepaid, "https://a.example/v1");
        dear.declared.cost = Some(Cost {
            per_call_usd: 0.0,
            per_mtok_in_usd: 10.0,
            per_mtok_out_usd: 30.0,
        });
        let mut cheap = http("cheap", Paid::Prepaid, "https://b.example/v1");
        cheap.declared.cost = Some(Cost {
            per_call_usd: 0.0,
            per_mtok_in_usd: 0.1,
            per_mtok_out_usd: 0.3,
        });
        let unpriced = http("unpriced", Paid::Prepaid, "https://c.example/v1");
        let world = World::new(vec![unpriced, dear.clone(), cheap]);
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "cheap");
        // Same price: the smaller class wins, then the order.
        let mut big = http("big", Paid::Local, "http://localhost:1/v1");
        big.model = Some("llama-3.1-70b".into());
        let mut small = http("small", Paid::Local, "http://localhost:2/v1");
        small.model = Some("llama-3.2-3b".into());
        let first = http("first", Paid::Local, "http://localhost:3/v1");
        let world = World::new(vec![big.clone(), small.clone()]);
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "small");
        let mut same = first.clone();
        same.model = Some("llama-3.2-3b".into());
        let world = World::new(vec![same, small]);
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "first");
        drop((big, dear));
    }

    #[test]
    fn an_engine_that_cannot_read_text_is_never_asked() {
        let mut whisper = http("whisper", Paid::Local, "http://localhost:9000/v1");
        whisper.declared = Declared {
            modalities: vec![Modality::AudioIn],
            ..Declared::default()
        };
        let world = World::new(vec![whisper]);
        let why = pick_classifier(&world.assist()).unwrap_err();
        assert!(why.contains("whisper: no text modality"), "{why}");
        let mut declared = http("e", Paid::Local, "http://localhost:1/v1");
        declared.declared = Declared {
            modalities: vec![Modality::Vision],
            ..Declared::default()
        };
        let world = World::new(vec![declared]);
        assert!(pick_classifier(&world.assist()).is_err());
    }

    #[test]
    fn a_cli_engine_is_never_asked_to_label_an_order() {
        // Even a free local cli engine: it is an agent, not a question-answerer.
        let cli = EngineSpec::implicit("llama-cli", &[], Some("llama-3.2-3b"));
        let mut world = World::new(vec![cli]);
        let why = pick_classifier(&world.assist()).unwrap_err();
        assert!(why.contains("a cli engine is not asked to label"), "{why}");
        // An http one beside it is the one asked.
        world.specs.push(http(
            "nvidia",
            Paid::FreeTier,
            "https://integrate.api.nvidia.com/v1",
        ));
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "nvidia");
    }

    #[test]
    fn a_subscription_is_never_used_unless_the_policy_lists_chore_and_it_has_a_weekly_cap() {
        let mut claude = http("claude", Paid::Subscription, "https://api.example.com/v1");
        claude.weekly_requests = Some(200);
        let mut world = World::new(vec![claude]);
        let why = pick_classifier(&world.assist()).unwrap_err();
        assert!(why.contains("claude:"), "{why}");

        // Turning protect_subscriptions off does not open it to a labelling call.
        world.policy.protect_subscriptions = false;
        let why = pick_classifier(&world.assist()).unwrap_err();
        assert!(why.contains("not spent on labelling"), "{why}");

        // The chore role listed, and the cap set: allowed.
        world.policy.protect_subscriptions = true;
        world.policy.subscription_roles = vec![Role::Chore];
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "claude");

        // The chore role listed but no weekly cap: refused.
        world.specs[0].weekly_requests = None;
        assert!(pick_classifier(&world.assist()).is_err());

        // Another role listed is not chore.
        world.specs[0].weekly_requests = Some(200);
        world.policy.subscription_roles = vec![Role::Build];
        assert!(pick_classifier(&world.assist()).is_err());
    }

    #[test]
    fn a_free_engine_is_chosen_over_a_subscription_even_when_the_subscription_is_allowed() {
        let mut claude = http("claude", Paid::Subscription, "https://api.example.com/v1");
        claude.weekly_requests = Some(200);
        let free = http(
            "nvidia",
            Paid::FreeTier,
            "https://integrate.api.nvidia.com/v1",
        );
        let mut world = World::new(vec![claude, free]);
        world.policy.subscription_roles = vec![Role::Chore];
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "nvidia");
    }

    #[test]
    fn the_policy_never_list_and_machine_rules_bound_the_choice() {
        let local = http("llama", Paid::Local, "http://localhost:11434/v1");
        let free = http(
            "nvidia",
            Paid::FreeTier,
            "https://integrate.api.nvidia.com/v1",
        );
        let mut world = World::new(vec![local, free]);
        world.policy.never = vec!["llama".into()];
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "nvidia");
        world.policy.never = vec!["llama".into(), "nvidia".into()];
        let why = pick_classifier(&world.assist()).unwrap_err();
        assert!(why.contains("never"), "{why}");
        world.policy.never = Vec::new();
        world.policy.machines = vec!["someone-else".into()];
        let why = pick_classifier(&world.assist()).unwrap_err();
        assert!(why.contains("does not allow background work"), "{why}");
    }

    #[test]
    fn an_exhausted_engine_is_skipped_and_none_configured_is_said() {
        let local = http("llama", Paid::Local, "http://localhost:11434/v1");
        let free = http(
            "nvidia",
            Paid::FreeTier,
            "https://integrate.api.nvidia.com/v1",
        );
        let mut world = World::new(vec![local, free]);
        let now = Utc::now();
        world
            .ledger
            .engines
            .entry("llama".into())
            .or_default()
            .exhausted_until = Some(now + chrono::Duration::hours(2));
        assert_eq!(pick_classifier(&world.assist()).unwrap().name, "nvidia");
        let empty = World::new(Vec::new());
        assert_eq!(
            pick_classifier(&empty.assist()).unwrap_err(),
            "no engine is configured"
        );
    }

    // --- the whole step ---------------------------------------------------------------

    #[tokio::test]
    async fn a_sure_classification_never_calls_a_model() {
        let dir = tempfile::tempdir().unwrap();
        let world = World::new(vec![http("llama", Paid::Local, "http://localhost:1/v1")]);
        let fake = Fake::default();
        let got = classify_order(
            &route(dir.path()),
            &order("t-sure-1", "Summarize the meeting notes"),
            &world.assist(),
            &fake,
        )
        .await;
        assert_eq!(got.source, Source::Rules);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn an_unsure_order_is_labelled_by_the_cheapest_engine_and_the_answer_is_cached() {
        let dir = tempfile::tempdir().unwrap();
        let r = route(dir.path());
        let world = World::new(vec![
            http("paid", Paid::Prepaid, "https://api.example.com/v1"),
            http("llama", Paid::Local, "http://localhost:11434/v1"),
        ]);
        let fake = Fake::saying(
            "llama",
            "```json\n{\"kind\":\"plan\",\"size\":\"large\",\"confidence\":0.8}\n```",
        );
        let o = order("t-model-1", UNSURE);
        let got = classify_order(&r, &o, &world.assist(), &fake).await;
        assert_eq!(got.source, Source::Model);
        assert_eq!(got.needs.kind, WorkKind::Plan);
        assert_eq!(got.needs.size, Size::Large);
        assert!((got.confidence - 0.8).abs() < 1e-6);
        assert_eq!(
            fake.calls(),
            ["llama"],
            "only the cheapest engine was asked"
        );
        assert!(got.reasons.iter().any(|r| r == "labelled by llama"));
        // The prompt carried the order, fenced as data.
        let prompt = fake.asked.lock().unwrap()[0].1.clone();
        assert!(prompt.contains("<<<ORDER\nhello there\nORDER>>>"));

        // Asked again - a worker's next pass - it is answered from the cache.
        let again = classify_order(&r, &o, &world.assist(), &fake).await;
        assert_eq!(again, got);
        assert_eq!(
            fake.calls().len(),
            1,
            "one call per order, not one per pass"
        );
        // The read-only surfaces see the same thing without any engine.
        assert_eq!(work::classify_cached(&o, &r), got);
        assert!(
            r.attachment
                .join("routing/classify/t-model-1.json")
                .is_file()
        );
    }

    #[tokio::test]
    async fn a_model_never_overrides_what_the_issuer_fixed() {
        let dir = tempfile::tempdir().unwrap();
        let world = World::new(vec![http("llama", Paid::Local, "http://localhost:1/v1")]);
        let mut o = order("t-model-2", UNSURE);
        o.needs = Some(ExplicitNeeds {
            size: Some(Size::Large),
            ..ExplicitNeeds::default()
        });
        let fake = Fake::saying("llama", "{\"kind\":\"docs\",\"size\":\"small\"}");
        let got = classify_order(&route(dir.path()), &o, &world.assist(), &fake).await;
        assert_eq!(got.needs.kind, WorkKind::Docs, "the model filled the kind");
        assert_eq!(got.needs.size, Size::Large, "the issuer's size held");
        assert_eq!(got.source, Source::Model);
    }

    #[tokio::test]
    async fn an_explicit_kind_means_no_model_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let world = World::new(vec![http("llama", Paid::Local, "http://localhost:1/v1")]);
        let mut o = order("t-explicit-1", UNSURE);
        o.needs = Some(ExplicitNeeds {
            kind: Some(WorkKind::Review),
            ..ExplicitNeeds::default()
        });
        let fake = Fake::default();
        let got = classify_order(&route(dir.path()), &o, &world.assist(), &fake).await;
        assert_eq!(got.source, Source::Explicit);
        assert_eq!(got.needs.kind, WorkKind::Review);
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn no_allowed_engine_falls_back_to_the_unsure_rules_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let claude = http("claude", Paid::Subscription, "https://api.example.com/v1");
        let world = World::new(vec![claude]);
        let fake = Fake::default();
        let got = classify_order(
            &route(dir.path()),
            &order("t-none-1", UNSURE),
            &world.assist(),
            &fake,
        )
        .await;
        assert_eq!(got.source, Source::Rules);
        assert!(!got.is_sure());
        assert!(
            got.reasons
                .last()
                .unwrap()
                .starts_with("no model was asked: claude:"),
            "{:?}",
            got.reasons
        );
        assert!(fake.calls().is_empty(), "a subscription was not touched");
        // Nothing is cached for "could not ask": a later pass may have an engine.
        assert!(!dir.path().join("routing").exists());
    }

    #[tokio::test]
    async fn a_failed_call_is_not_cached_so_the_next_pass_can_try_again() {
        let dir = tempfile::tempdir().unwrap();
        let r = route(dir.path());
        let world = World::new(vec![http("llama", Paid::Local, "http://localhost:1/v1")]);
        let down = Fake {
            answers: vec![("llama", Err("connection refused"))],
            ..Fake::default()
        };
        let o = order("t-fail-1", UNSURE);
        let got = classify_order(&r, &o, &world.assist(), &down).await;
        assert_eq!(got.source, Source::Rules);
        assert!(got.reasons.last().unwrap().contains("connection refused"));
        assert!(work::read_cache(&r, "t-fail-1").is_none());
        let up = Fake::saying("llama", "{\"kind\":\"docs\"}");
        let got = classify_order(&r, &o, &world.assist(), &up).await;
        assert_eq!(got.source, Source::Model);
    }

    #[tokio::test]
    async fn an_unusable_answer_is_remembered_for_an_hour_and_then_asked_again() {
        let dir = tempfile::tempdir().unwrap();
        let r = route(dir.path());
        let world = World::new(vec![http("llama", Paid::Local, "http://localhost:1/v1")]);
        let babble = Fake::saying("llama", "I would rather talk about the weather.");
        let o = order("t-babble-1", UNSURE);
        let got = classify_order(&r, &o, &world.assist(), &babble).await;
        assert_eq!(got.source, Source::Rules);
        assert!(got.reasons.last().unwrap().contains("not usably"));
        assert_eq!(babble.calls().len(), 1);

        // A minute later: not asked again.
        let mut soon = world.assist();
        soon.now += chrono::Duration::minutes(1);
        let got = classify_order(&r, &o, &soon, &babble).await;
        assert!(got.reasons.last().unwrap().contains("not asked again yet"));
        assert_eq!(babble.calls().len(), 1);

        // Two hours later: asked again, and this time it answers.
        let mut later = world.assist();
        later.now += chrono::Duration::hours(2);
        let good = Fake::saying("llama", "{\"kind\":\"research\"}");
        let got = classify_order(&r, &o, &later, &good).await;
        assert_eq!(got.source, Source::Model);
        assert_eq!(got.needs.kind, WorkKind::Research);
    }

    #[tokio::test]
    async fn a_model_that_invents_a_kind_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let world = World::new(vec![http("llama", Paid::Local, "http://localhost:1/v1")]);
        let fake = Fake::saying(
            "llama",
            "{\"kind\":\"world-domination\",\"size\":\"small\"}",
        );
        let got = classify_order(
            &route(dir.path()),
            &order("t-invent-1", UNSURE),
            &world.assist(),
            &fake,
        )
        .await;
        assert_eq!(got.source, Source::Rules);
        assert_eq!(got.needs.kind, WorkKind::Other);
    }

    #[tokio::test]
    async fn the_fallback_engine_is_tried_only_by_a_later_pass_never_in_the_same_one() {
        // Two usable engines; the cheaper is asked, fails, and the order is not sent to the
        // dearer one in the same pass: a label is not worth a second paid call.
        let dir = tempfile::tempdir().unwrap();
        let world = World::new(vec![
            http("llama", Paid::Local, "http://localhost:1/v1"),
            http("deepseek", Paid::Prepaid, "https://api.deepseek.com/v1"),
        ]);
        let fake = Fake {
            answers: vec![
                ("llama", Err("out of memory")),
                ("deepseek", Ok("{\"kind\":\"docs\"}")),
            ],
            ..Fake::default()
        };
        let got = classify_order(
            &route(dir.path()),
            &order("t-one-1", UNSURE),
            &world.assist(),
            &fake,
        )
        .await;
        assert_eq!(got.source, Source::Rules);
        assert_eq!(fake.calls(), ["llama"]);
    }
}

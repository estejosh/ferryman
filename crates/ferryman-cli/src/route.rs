//! `ferry route`: the smart router, from the command line.
//!
//! `ferry route classify <order>`: what an order needs, where that came from (the signed
//! order, the rules, or a model) and why. See [`ferryman_channel::work`] for the rules and
//! [`ferryman_ops::route`] for the model-assisted step.
//!
//! `ferry route explain <order>`: why it went where it did, from the decisions workers
//! recorded. `ferry route simulate --kind docs --size small`: where work like that would
//! go now. See [`ferryman_channel::router`].

use std::path::PathBuf;

use anyhow::{Context, Result};
use ferryman_channel::{
    Order, ProjectRoute, Task,
    policy::{self, Candidate},
    router::{self, Decision},
    work::{self, Classification, Source},
};
use serde_json::json;

#[derive(clap::Subcommand, Clone)]
pub(crate) enum RouteCommand {
    /// What an order needs - kind, size, the modalities an engine must have - and where
    /// that came from: `explicit` (signed into the order with --kind/--needs/--size),
    /// `rules` (read from the task text, attachments, touched files and tier) or `model`
    /// (the rules were unsure, so the cheapest allowed text engine was asked once).
    ///
    /// Without --model this never calls an engine: when the rules are unsure it shows an
    /// earlier model answer if one is cached, and otherwise says that a worker would ask.
    Classify {
        /// The order id, e.g. t-4f2a.
        order: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// When the rules are unsure and nothing is cached, ask the model now, as a worker
        /// would: the cheapest text engine this machine may use for background work, local
        /// first, never a subscription unless the policy's subscription_roles lists chore.
        #[arg(long)]
        model: bool,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Why an order went to the engine it did: what it needs, the decision each worker
    /// recorded when it took the order (every engine's success estimate, price and why the
    /// others were out), the improve steps' records, and what the router would pick right
    /// now, with the engines that already failed it left out.
    Explain {
        /// The order id, e.g. t-4f2a.
        order: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Run the router for work of a kind and size over the fleet's engines and this
    /// project's policy, without running anything: who would get it, and why.
    ///
    /// `ferry route simulate --kind docs --size small`. Add `--needs vision` (or audio_in,
    /// image, ...) to see where work that needs a modality would go.
    Simulate {
        /// code-change, docs, tests, review, plan, chore, research, translate, transcribe, image,
        /// video, audio or other.
        #[arg(long)]
        kind: String,
        /// small, medium or large.
        #[arg(long, default_value = "medium")]
        size: String,
        /// Modalities beyond what the kind implies, comma separated: vision, audio_in,
        /// audio_out, image, video, embed.
        #[arg(long, value_delimiter = ',')]
        needs: Vec<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// The engines in a simulated or explained order, winner first, by name.
fn order_names(routed: &ferryman_channel::router::Routed, fleet: &[Candidate]) -> Vec<String> {
    routed
        .order
        .iter()
        .filter_map(|&index| fleet.get(index))
        .map(|engine| format!("{} on {}", engine.name, engine.machine))
        .collect()
}

pub(crate) async fn command(command: RouteCommand) -> Result<()> {
    match command {
        RouteCommand::Simulate {
            kind,
            size,
            needs,
            workspace,
            json,
        } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = ferryman_channel::route_for(&start)?;
            let needs = router::simulated_needs(&kind, &size, &needs)?;
            let now = chrono::Utc::now();
            let (policy, _) = policy::effective(&route.communications, &route.project_id);
            let fleet = policy::fleet(&route, now);
            let routed = router::simulate(&policy, &fleet, &needs, now);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "project": route.project_id,
                        "engines": fleet.len(),
                        "decision": routed.decision,
                        "order": order_names(&routed, &fleet),
                    }))?
                );
            } else {
                println!("{}: {} engine(s) published", route.project_id, fleet.len());
                for line in routed.decision.lines() {
                    println!("{line}");
                }
                let order = order_names(&routed, &fleet);
                if order.len() > 1 {
                    println!("  order tried: {}", order.join(" -> "));
                }
            }
            Ok(())
        }
        RouteCommand::Explain {
            order,
            workspace,
            json,
        } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = ferryman_channel::route_for(&start)?;
            let task = ferryman_channel::read_task(&route, &order)
                .with_context(|| format!("read order {order}"))?;
            let now = chrono::Utc::now();
            let classification = work::classify_cached(&task.order, &route);
            let (policy, _) = policy::effective(&route.communications, &route.project_id);
            let fleet = policy::fleet(&route, now);
            let failed = ferryman_ops::agent::failed_engines(&task);
            let role = policy::order_role(&task.order);
            let mut context = router::Context::new(now);
            context.failed = &failed;
            let current = router::route(
                &policy,
                if ferryman_ops::improve::is_improvement(&task) {
                    role
                } else {
                    router::role_for(classification.needs.kind)
                },
                role.tier(),
                policy::Work::Background,
                &classification.needs,
                &fleet,
                &context,
            );
            let recorded = recorded_decisions(&route, &task);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "order": task.order.id,
                        "classification": classification,
                        "recorded": recorded
                            .iter()
                            .map(|(who, decision)| json!({ "by": who, "decision": decision }))
                            .collect::<Vec<_>>(),
                        "failed": failed
                            .iter()
                            .map(|f| json!({ "engine": f.engine, "p": f.p }))
                            .collect::<Vec<_>>(),
                        "now": {
                            "decision": current.decision,
                            "order": order_names(&current, &fleet),
                        },
                    }))?
                );
                return Ok(());
            }
            for line in lines(&route, &task.order, &classification, false) {
                println!("{line}");
            }
            if recorded.is_empty() {
                println!(
                    "recorded: nothing yet - a worker records its routing decision beside \
                     each result and improve step it does (workers older than the smart \
                     router record none)"
                );
            }
            for (who, decision) in &recorded {
                println!("recorded by {who}:");
                for line in decision.lines() {
                    println!("{line}");
                }
            }
            println!("if it were routed now:");
            for line in current.decision.lines() {
                println!("{line}");
            }
            Ok(())
        }
        RouteCommand::Classify {
            order,
            workspace,
            model,
            json,
        } => {
            let start = match workspace {
                Some(path) => path,
                None => std::env::current_dir().context("read the current directory")?,
            };
            let route = ferryman_channel::route_for(&start)?;
            let task = ferryman_channel::read_task(&route, &order)
                .with_context(|| format!("read order {order}"))?;
            let order = task.order;
            let signature = ferryman_channel::verify_order_in(&route, &order);
            let classification = if model {
                let config = ferryman_ops::agent::AgentConfig::load(&route.attachment)
                    .context("--model needs this machine's agent.toml for its engines")?;
                ferryman_ops::route::classify_order_live(&route, &config, &order).await
            } else {
                work::classify_cached(&order, &route)
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "order": order.id,
                        "signature": format!("{signature:?}"),
                        "sure": classification.is_sure(),
                        "threshold": work::CONFIDENCE_THRESHOLD,
                        "classification": classification,
                    }))?
                );
            } else {
                for line in lines(&route, &order, &classification, model) {
                    println!("{line}");
                }
                if signature != ferryman_channel::SignatureCheck::Valid {
                    println!(
                        "  note: the order's signature is {signature:?}; a worker would not run it"
                    );
                }
            }
            Ok(())
        }
    }
}

/// The routing decisions recorded for an order, oldest first, with who recorded each: the
/// worker's note in each result, and the improve steps (plan, review, build) in the weeks
/// around the order. A decision that appears in both is listed once.
fn recorded_decisions(route: &ProjectRoute, task: &Task) -> Vec<(String, Decision)> {
    let mut found: Vec<(String, Decision)> = Vec::new();
    for result in &task.results {
        if let Some(decision) = router::decision_of(&result.payload) {
            found.push((
                format!("{} (result {})", result.agent, result.revision),
                decision,
            ));
        }
    }
    let mut weeks = vec![
        router::iso_week(task.order.created_at),
        router::iso_week(chrono::Utc::now()),
    ];
    weeks.dedup();
    for week in weeks {
        for step in policy::read_steps(route, &week) {
            if step.order.as_deref() != Some(task.order.id.as_str()) {
                continue;
            }
            if let Some(decision) = step.route
                && !found.iter().any(|(_, known)| *known == decision)
            {
                found.push((format!("{} ({} step)", step.agent, step.step), decision));
            }
        }
    }
    found
}

/// The text `ferry route classify` prints.
fn lines(
    route: &ProjectRoute,
    order: &Order,
    classification: &Classification,
    asked: bool,
) -> Vec<String> {
    let needs = &classification.needs;
    let mut out = vec![format!("{}: {}", order.id, classification.summary())];
    out.push(format!("  kind        {}", needs.kind.as_str()));
    out.push(format!("  size        {}", needs.size.as_str()));
    out.push(format!(
        "  needs       {}",
        needs
            .modalities
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push(format!(
        "  context     at least {}k tokens",
        needs.min_context_k
    ));
    let from = match classification.source {
        Source::Explicit => match &order.signed_by {
            Some(by) => format!("explicit - signed into the order by {by}"),
            None => "explicit - on the order (unsigned)".to_string(),
        },
        Source::Rules => "rules - read from the order, no model involved".to_string(),
        Source::Model => {
            "model - the rules were unsure, so a text engine was asked once".to_string()
        }
    };
    out.push(format!("  source      {from}"));
    out.push(format!(
        "  confidence  {:.2} ({} the {:.2} below which a model is asked)",
        classification.confidence,
        if classification.is_sure() {
            "at or above"
        } else {
            "below"
        },
        work::CONFIDENCE_THRESHOLD
    ));
    for reason in &classification.reasons {
        out.push(format!("  - {reason}"));
    }
    if !classification.is_sure() && classification.source != Source::Model {
        out.push(if asked {
            "  no model could label it (see above); routing goes on with the rules' best read"
                .to_string()
        } else {
            format!(
                "  unsure: a worker asks the cheapest allowed text engine, local first, and \
                 keeps the answer ({}). `ferry route classify {} --model` does that now; \
                 `ferry channel order --kind ... --size ...` settles it for good",
                work::cache_path(route, &order.id).map_or_else(
                    || "no cache for this id".to_string(),
                    |path| path.display().to_string()
                ),
                order.id
            )
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use ferryman_channel::work::{ExplicitNeeds, WorkKind};

    use super::*;

    fn route() -> ProjectRoute {
        let dir = std::env::temp_dir();
        ProjectRoute {
            project_id: "p".into(),
            workspace: dir.clone(),
            attachment: dir.clone(),
            communications: dir,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn order(task: &str) -> Order {
        Order {
            id: "t-route-1".into(),
            project_id: "p".into(),
            issued_by: "josh".into(),
            assigned_to: None,
            created_at: chrono::Utc::now(),
            payload: json!({ "task": task }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: Some("josh".into()),
            signature: None,
            result_contract: None,
            interface: None,
            touches: Vec::new(),
            needs: None,
            allow_overlap: false,
        }
    }

    #[test]
    fn a_rules_classification_says_it_came_from_the_rules() {
        let route = route();
        let o = order("Summarize the meeting notes");
        let text = lines(&route, &o, &work::classify(&o, &route), false).join("\n");
        assert!(
            text.contains("rules, confidence 0.75: docs, small"),
            "{text}"
        );
        assert!(
            text.contains("source      rules - read from the order"),
            "{text}"
        );
        assert!(text.contains("at or above the 0.55"), "{text}");
        assert!(text.contains("'summarize'"), "the reason is shown: {text}");
        assert!(!text.contains("unsure"), "{text}");
    }

    #[test]
    fn a_simulated_order_names_the_engines_winner_first() {
        let free = Candidate {
            agent: "wisp".into(),
            machine: "box".into(),
            name: "nvidia".into(),
            tier: "build".into(),
            paid: "free".into(),
            state: "up".into(),
            ..Candidate::default()
        };
        let fleet = vec![free];
        let needs = router::simulated_needs("docs", "small", &[]).unwrap();
        let routed = router::simulate(
            &policy::Policy::default(),
            &fleet,
            &needs,
            chrono::Utc::now(),
        );
        assert_eq!(routed.decision.kind, "docs");
        let names = order_names(&routed, &fleet);
        assert!(
            names.first().is_some_and(|name| name == "nvidia on box"),
            "{names:?} {:?}",
            routed.decision.reason
        );
        assert!(router::simulated_needs("nonsense", "small", &[]).is_err());
        assert!(router::simulated_needs("docs", "huge", &[]).is_err());
    }

    #[test]
    fn explain_lists_the_decisions_workers_recorded_beside_their_results() {
        let route = route();
        let decision = |reason: &str| {
            json!({
                "routing": "smart", "role": "build", "kind": "docs", "size": "small",
                "threshold": 0.75,
                "candidates": [
                    { "engine": "nvidia", "agent": "wisp", "machine": "box", "p": 0.8,
                      "cost_usd": 0.0, "price": "free", "sufficient": true },
                    { "engine": "claude", "agent": "wisp", "machine": "box",
                      "sufficient": false, "excluded": "never" }
                ],
                "winner": { "engine": "nvidia", "agent": "wisp", "machine": "box",
                            "p": 0.8, "cost_usd": 0.0 },
                "reason": reason,
            })
        };
        let result = |revision: u32, payload: serde_json::Value| ferryman_channel::TaskResult {
            order_id: "t-route-1".into(),
            agent: "wisp".into(),
            revision,
            submitted_at: chrono::Utc::now(),
            payload,
            signed_by: None,
            signature: None,
        };
        let task = Task {
            order: order("Summarize the meeting notes"),
            claims: Vec::new(),
            results: vec![
                result(
                    1,
                    json!({ "output": "x", "routing": decision("nvidia: first") }),
                ),
                result(2, json!({ "output": "y" })),
                result(
                    3,
                    json!({ "output": "z", "routing": decision("claude: second") }),
                ),
            ],
            reviews: Vec::new(),
            recommendations: Vec::new(),
            heartbeats: Vec::new(),
            releases: Vec::new(),
            kills: Vec::new(),
        };
        let found = recorded_decisions(&route, &task);
        let who: Vec<&str> = found.iter().map(|(who, _)| who.as_str()).collect();
        assert_eq!(who, ["wisp (result 1)", "wisp (result 3)"], "none for r2");
        assert_eq!(found[0].1.reason, "nvidia: first");
        let text = found[0].1.lines().join("\n");
        assert!(text.contains("> nvidia"), "{text}");
        assert!(
            text.contains("x claude") && text.contains("out: never"),
            "{text}"
        );
        assert!(text.contains("=> nvidia: first"), "{text}");
        assert!(
            recorded_decisions(
                &route,
                &Task {
                    results: Vec::new(),
                    ..task
                }
            )
            .is_empty()
        );
    }

    #[test]
    fn an_explicit_classification_names_who_signed_it() {
        let route = route();
        let mut o = order("hello there");
        o.needs = Some(ExplicitNeeds {
            kind: Some(WorkKind::Review),
            ..ExplicitNeeds::default()
        });
        let text = lines(&route, &o, &work::classify(&o, &route), false).join("\n");
        assert!(
            text.contains("explicit - signed into the order by josh"),
            "{text}"
        );
        assert!(text.contains("kind        review"), "{text}");
    }

    #[test]
    fn an_unsure_order_says_what_a_worker_would_do_and_how_to_settle_it() {
        let route = route();
        let o = order("hello there");
        let text = lines(&route, &o, &work::classify(&o, &route), false).join("\n");
        assert!(text.contains("below the 0.55"), "{text}");
        assert!(
            text.contains("a worker asks the cheapest allowed text engine"),
            "{text}"
        );
        assert!(text.contains("--model"), "{text}");
        assert!(text.contains("--kind"), "{text}");
        // After asking and getting nothing usable, it says so instead.
        let text = lines(&route, &o, &work::classify(&o, &route), true).join("\n");
        assert!(text.contains("no model could label it"), "{text}");
    }
}

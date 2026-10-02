//! `ferry route`: the smart router, from the command line.
//!
//! So far one command, `ferry route classify <order>`: what an order needs, where that
//! came from (the signed order, the rules, or a model) and why. See
//! [`ferryman_channel::work`] for the rules and [`ferryman_ops::route`] for the
//! model-assisted step.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ferryman_channel::{
    Order, ProjectRoute,
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
}

pub(crate) async fn command(command: RouteCommand) -> Result<()> {
    match command {
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

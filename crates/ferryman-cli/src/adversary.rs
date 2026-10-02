//! `ferry adversary`: read what the adversary found, ask it now, and sign the master's
//! override of a Block. See [`ferryman_channel::adversary`] for the data and
//! [`ferryman_ops::adversary`] for the three moments it is asked.
//!
//! Which engine challenges, and whether a Block binds, are part of the engine policy:
//! `ferry engines policy set --role adversary --prefer deepseek --adversary blocking`.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ferryman_channel::{
    ProjectRoute,
    adversary::{self as data, Standing, Trigger},
};
use serde_json::Value;

use super::{Targets, mastered_signer, target_configs};

#[derive(clap::Subcommand, Clone)]
pub(crate) enum AdversaryCommand {
    /// What the adversary found about an order, or about a contract (`name@version`): every
    /// moment and revision, the engine that said it, and whether a Block was overridden.
    Show {
        /// An order id, or a contract as `name@version`.
        subject: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Every finding in this project, newest first.
    List {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Go ahead despite a Block, signed as the project's master. Needed only in `blocking`
    /// mode: for a contract it is what `ferry contract lock <ref> --override` records; for
    /// an improvement it lets the review engine's key be granted.
    Override {
        /// An order id, or a contract as `name@version`.
        subject: String,
        /// Which moment's Block: contract-lock, repeat-failure or pre-done. Default: the
        /// newest Block still standing.
        #[arg(long, value_name = "MOMENT")]
        trigger: Option<String>,
        /// Why - kept in the signed override.
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Ask the adversary now about everything waiting for it: contracts waiting for a lock
    /// and improvements waiting for the review engine. `ferry improve review` does the
    /// same on its schedule; the policy decides which engine is asked.
    Check {
        #[command(flatten)]
        at: Targets,
    },
}

fn here(workspace: Option<PathBuf>) -> Result<ProjectRoute> {
    let start = match workspace {
        Some(path) => path,
        None => std::env::current_dir().context("read the current directory")?,
    };
    ferryman_channel::route_for(&start)
}

/// One line for a screen: `adversary: blocking, 3 finding(s), 1 block, 1 concern; standing:
/// t-1 r2 (pre-done)`. `None` when there is nothing worth a line (the default mode and no
/// findings). Takes the JSON of a [`ferryman_ops::adversary::Summary`].
pub(crate) fn status_line(summary: &Value) -> Option<String> {
    let summary = summary.as_object()?;
    let count = |key: &str| summary.get(key).and_then(Value::as_u64).unwrap_or_default();
    let mode = summary
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("advisory");
    if count("findings") == 0 && mode == "advisory" {
        return None;
    }
    let mut line = format!(
        "adversary: {mode}, {} finding(s), {} block, {} concern",
        count("findings"),
        count("blocks"),
        count("concerns")
    );
    let unresolved: Vec<&str> = summary
        .get("unresolved")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !unresolved.is_empty() {
        line.push_str(&format!("; standing Block: {}", unresolved.join(", ")));
    }
    Some(line)
}

/// The lines under a heading for one standing finding: who said it, what was done about a
/// Block, and the worst issues.
pub(crate) fn lines(standing: &Standing, worst: usize) -> Vec<String> {
    let finding = &standing.finding;
    let mut out = vec![format!(
        "{} r{}, {}: {}",
        finding.subject,
        finding.revision,
        finding.trigger.label(),
        finding.describe()
    )];
    out.push(format!(
        "  by {}{} on {}, {} UTC; status: {}",
        finding.engine,
        finding
            .model
            .as_deref()
            .map(|model| format!(" ({model})"))
            .unwrap_or_default(),
        finding.machine,
        finding.created_at.format("%Y-%m-%d %H:%M"),
        standing.status()
    ));
    if let Some(over) = &standing.overridden
        && !over.reason.trim().is_empty()
    {
        out.push(format!("  override reason: {}", over.reason.trim()));
    }
    for issue in finding.top(worst) {
        out.push(format!(
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
    out
}

/// What the adversary last said about `subject` (an order or a contract), at any moment:
/// the standing findings, newest revision of each moment, in moment order.
pub(crate) fn standings(route: &ProjectRoute, subject: &str) -> Vec<Standing> {
    Trigger::ALL
        .iter()
        .filter_map(|trigger| data::latest_standing(route, subject, *trigger))
        .collect()
}

/// The one-line verdict beside a contract or an order, for lists.
pub(crate) fn headline(route: &ProjectRoute, subject: &str) -> Option<String> {
    standings(route, subject)
        .last()
        .map(|standing| format!("adversary {}", standing.status()))
}

pub(crate) async fn command(command: AdversaryCommand) -> Result<()> {
    match command {
        AdversaryCommand::Show {
            subject,
            workspace,
            json,
        } => {
            let route = here(workspace)?;
            let mut all: Vec<Standing> = data::for_subject(&route, &subject)
                .into_iter()
                .filter_map(|finding| {
                    data::standing(&route, &finding.subject, finding.revision, finding.trigger)
                })
                .collect();
            all.sort_by_key(|standing| (standing.finding.revision, standing.finding.trigger));
            if json {
                let views: Vec<Value> = all.iter().map(Standing::view).collect();
                println!("{}", serde_json::to_string_pretty(&views)?);
                return Ok(());
            }
            if all.is_empty() {
                println!(
                    "the adversary has not read {subject} in {} (yet, or ever: it is off, or \
                     nothing it may use was up)",
                    route.project_id
                );
                return Ok(());
            }
            for standing in &all {
                for line in lines(standing, 6) {
                    println!("{line}");
                }
            }
        }
        AdversaryCommand::List { workspace, json } => {
            let route = here(workspace)?;
            let mut all: Vec<Standing> = data::list(&route)
                .into_iter()
                .filter_map(|finding| {
                    data::standing(&route, &finding.subject, finding.revision, finding.trigger)
                })
                .collect();
            all.sort_by_key(|standing| std::cmp::Reverse(standing.finding.created_at));
            if json {
                let views: Vec<Value> = all.iter().map(Standing::view).collect();
                println!("{}", serde_json::to_string_pretty(&views)?);
                return Ok(());
            }
            if all.is_empty() {
                println!(
                    "the adversary has not challenged anything in {}",
                    route.project_id
                );
            }
            for standing in &all {
                let finding = &standing.finding;
                println!(
                    "{:<28} r{:<3} {:<15} {:<8} {:<12} {}",
                    finding.subject,
                    finding.revision,
                    finding.trigger.as_str(),
                    finding.verdict.as_str(),
                    finding.engine,
                    if standing.overridden.is_some() {
                        "overridden"
                    } else if standing.unresolved_block() {
                        "standing"
                    } else {
                        ""
                    }
                );
            }
        }
        AdversaryCommand::Override {
            subject,
            trigger,
            reason,
            workspace,
        } => {
            let route = here(workspace)?;
            let triggers: Vec<Trigger> = match trigger.as_deref() {
                Some(trigger) => vec![Trigger::parse(trigger)?],
                None => Trigger::ALL.to_vec(),
            };
            let Some(standing) = triggers
                .iter()
                .filter_map(|trigger| data::latest_standing(&route, &subject, *trigger))
                .filter(Standing::unresolved_block)
                .max_by_key(|standing| standing.finding.created_at)
            else {
                bail!(
                    "{subject} has no Block standing in {}: nothing to override (see `ferry \
                     adversary show {subject}`)",
                    route.project_id
                );
            };
            let (master, identity) =
                mastered_signer(&route.communications, &route.attachment, None)?;
            let given = data::override_block(
                &route,
                &subject,
                standing.finding.revision,
                standing.finding.trigger,
                reason.as_deref(),
                &master,
                &identity,
            )?;
            println!(
                "overrode the adversary's Block on {subject} r{} ({}), signed by {}",
                standing.finding.revision,
                standing.finding.trigger.label(),
                given.from()
            );
            if standing.finding.trigger == Trigger::ContractLock {
                println!("  now lock it: ferry contract lock {subject}");
            }
        }
        AdversaryCommand::Check { at } => {
            let report = ferryman_ops::Stdout;
            for (route, config) in target_configs(&at)? {
                let (policy, _) =
                    ferryman_channel::policy::effective(&route.communications, &route.project_id);
                let challenged = ferryman_ops::adversary::pass(
                    &route,
                    &config,
                    &policy,
                    chrono::Utc::now(),
                    &report,
                )
                .await;
                println!("{}: challenged {challenged}", route.project_id);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: AdversaryCommand,
    }

    #[test]
    fn the_subcommands_parse() {
        assert!(Cli::try_parse_from(["adversary", "show", "t-1", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["adversary", "show", "user-api@1"]).is_ok());
        assert!(Cli::try_parse_from(["adversary", "list", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["adversary", "check"]).is_ok());
        let cli = Cli::try_parse_from([
            "adversary",
            "override",
            "t-1",
            "--trigger",
            "pre-done",
            "--reason",
            "docs only",
        ])
        .unwrap();
        let AdversaryCommand::Override {
            subject,
            trigger,
            reason,
            ..
        } = cli.command
        else {
            panic!("not override")
        };
        assert_eq!(subject, "t-1");
        assert_eq!(trigger.as_deref(), Some("pre-done"));
        assert_eq!(reason.as_deref(), Some("docs only"));
        assert!(
            Cli::try_parse_from(["adversary", "show"]).is_err(),
            "a subject is needed"
        );
    }

    #[test]
    fn the_status_line_is_quiet_by_default_and_names_a_standing_block() {
        assert_eq!(status_line(&Value::Null), None);
        assert_eq!(
            status_line(
                &json!({ "mode": "advisory", "findings": 0, "blocks": 0, "concerns": 0,
                                  "passes": 0, "unresolved": [] })
            ),
            None
        );
        assert_eq!(
            status_line(
                &json!({ "mode": "blocking", "findings": 0, "blocks": 0, "concerns": 0,
                                  "passes": 0, "unresolved": [] })
            )
            .unwrap(),
            "adversary: blocking, 0 finding(s), 0 block, 0 concern"
        );
        let line = status_line(&json!({ "mode": "advisory", "findings": 3, "blocks": 1,
            "concerns": 1, "passes": 1, "unresolved": ["t-1 r2 (pre-done)"] }))
        .unwrap();
        assert!(line.contains("3 finding(s), 1 block, 1 concern"), "{line}");
        assert!(line.contains("standing Block: t-1 r2 (pre-done)"), "{line}");
    }
}

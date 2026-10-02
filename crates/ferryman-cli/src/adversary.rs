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
        /// The finding you read: the digest `ferry adversary show` prints (at least 8
        /// characters), or `none` to go ahead with no adversary's reading at all. Without it
        /// the finding is shown and you are asked to confirm; the override is refused if the
        /// finding is not the one you read.
        #[arg(long, value_name = "DIGEST")]
        finding: Option<String>,
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
        .filter_map(|trigger| data::decision_standing(route, subject, *trigger))
        .collect()
}

/// Ask `question` of a person at a terminal. `false` when nobody is there to answer: a
/// decision that binds the master is never taken on their behalf.
pub(crate) fn confirm(question: &str) -> Result<bool> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// What the master looked at, to bind a decision to: the digest they named (`flag`), or -
/// at a terminal, when they named none - `seen`, which has just been shown to them, once they
/// confirm. Without either the decision is refused and the flag is named.
pub(crate) fn looked_at(
    flag: Option<&str>,
    seen: &str,
    question: &str,
    flag_name: &str,
) -> Result<String> {
    if let Some(flag) = flag {
        return Ok(flag.trim().to_string());
    }
    if confirm(question)? {
        return Ok(seen.to_string());
    }
    bail!(
        "not done: there was no one to confirm (or you said no). Read it, then pass {flag_name} \
         <what you read> to decide without a prompt"
    )
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
            let survey = data::survey(&route, &subject);
            let all = &survey.standings;
            if json {
                let mut views: Vec<Value> = all.iter().map(Standing::view).collect();
                views.extend(survey.ignored.iter().map(data::Ignored::view));
                println!("{}", serde_json::to_string_pretty(&views)?);
                return Ok(());
            }
            if all.is_empty() && survey.ignored.is_empty() {
                println!(
                    "the adversary has not read {subject} in {} (yet, or ever: it is off, or \
                     nothing it may use was up)",
                    route.project_id
                );
                return Ok(());
            }
            for standing in all {
                for line in lines(standing, 6) {
                    println!("{line}");
                }
            }
            for ignored in &survey.ignored {
                println!("{}", ignored.line());
            }
        }
        AdversaryCommand::List { workspace, json } => {
            let route = here(workspace)?;
            let survey = data::list_standings(&route);
            let all = &survey.standings;
            if json {
                let mut views: Vec<Value> = all.iter().map(Standing::view).collect();
                views.extend(survey.ignored.iter().map(data::Ignored::view));
                println!("{}", serde_json::to_string_pretty(&views)?);
                return Ok(());
            }
            if all.is_empty() {
                println!(
                    "the adversary has not challenged anything in {}",
                    route.project_id
                );
            }
            for standing in all {
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
            finding,
            reason,
            workspace,
        } => {
            let route = here(workspace)?;
            let triggers: Vec<Trigger> = match trigger.as_deref() {
                Some(trigger) => vec![Trigger::parse(trigger)?],
                None => Trigger::ALL.to_vec(),
            };
            let (master, identity) =
                mastered_signer(&route.communications, &route.attachment, None)?;
            let blocked = triggers
                .iter()
                .filter_map(|trigger| data::decision_standing(&route, &subject, *trigger))
                .filter(Standing::unresolved_block)
                .max_by_key(|standing| standing.finding.created_at);
            let given = if let Some(standing) = blocked {
                let (revision, trigger) = (standing.finding.revision, standing.finding.trigger);
                for line in lines(&standing, 6) {
                    println!("{line}");
                }
                let seen = standing.digest();
                println!("  finding digest: {}", seen.get(..16).unwrap_or(&seen));
                let expected = looked_at(
                    finding.as_deref(),
                    &seen,
                    &format!("Override this Block on {subject} r{revision}?"),
                    "--finding",
                )?;
                data::override_block(
                    &route,
                    &subject,
                    revision,
                    trigger,
                    &expected,
                    reason.as_deref(),
                    &master,
                    &identity,
                )?
            } else {
                // Nothing blocks. In `blocking` mode the work still waits for an eligible
                // adversary's reading - or for the master to say, signed, to go on without.
                let trigger = match triggers.as_slice() {
                    [one] => *one,
                    _ if subject.contains('@') => Trigger::ContractLock,
                    _ => Trigger::PreDone,
                };
                let Some(revision) = data::decision_revision(&route, &subject, trigger) else {
                    bail!(
                        "{subject} has nothing at the {} moment in {} (see `ferry adversary \
                         show {subject}`)",
                        trigger.as_str(),
                        route.project_id
                    );
                };
                if let Some(standing) = data::standing(&route, &subject, revision, trigger) {
                    bail!(
                        "{subject} r{revision} has no Block standing ({}): nothing to override",
                        standing.status()
                    );
                }
                println!(
                    "no adversary that could be heard has read {subject} r{revision} ({}); \
                     going ahead means going ahead with no adversary's reading of it",
                    trigger.label()
                );
                let expected = looked_at(
                    finding.as_deref(),
                    data::NO_FINDING,
                    &format!("Go ahead on {subject} r{revision} with no finding?"),
                    "--finding none",
                )?;
                data::waive(
                    &route,
                    &subject,
                    revision,
                    trigger,
                    &expected,
                    reason.as_deref(),
                    &master,
                    &identity,
                )?
            };
            println!(
                "{} the adversary on {subject} r{} ({}), signed by {}",
                if given.finding == data::NO_FINDING {
                    "waived"
                } else {
                    "overrode"
                },
                given.revision,
                given.trigger.label(),
                given.from()
            );
            if given.trigger == Trigger::ContractLock {
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

    /// A decision binds the master to what they read: the flag they pass is what is bound;
    /// without one, and with no terminal to ask at, nothing is decided for them.
    #[test]
    fn a_decision_is_bound_to_what_the_master_named_and_never_confirmed_for_them() {
        // A flag is taken as given, trimmed.
        assert_eq!(
            looked_at(Some(" abcdef0123456789 "), "ffff", "Lock?", "--digest").unwrap(),
            "abcdef0123456789"
        );
        // (Without a flag it asks at a terminal and refuses anywhere else; that path is not
        // run here, where a developer's own terminal would be asked.)
        let cli = Cli::try_parse_from([
            "adversary",
            "override",
            "t-1",
            "--finding",
            "0123456789abcdef",
        ])
        .unwrap();
        let AdversaryCommand::Override { finding, .. } = cli.command else {
            panic!("not override")
        };
        assert_eq!(finding.as_deref(), Some("0123456789abcdef"));
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

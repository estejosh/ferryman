//! Task sources: pluggable adapters that map external work - an issue tracker, a
//! spreadsheet export, a script's stdout - into orders on the channel.
//!
//! This mirrors groundcrew's `adapterDefinition`: a named, replaceable way to
//! fetch work, so the agent core never has to know where a task came from. Only
//! the `shell` source is built today; a Linear or Jira source fits the same
//! shape and is added by implementing [`TaskSource::fetch`].
//!
//! Ferryman's difference from groundcrew is what happens next: an imported
//! ticket does not just become work, it becomes a *signed order* with a ledger
//! entry, so the provenance of a task imported from a tracker is exactly as
//! checkable as one issued by hand.

use std::process::Command;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, Order, ProjectRoute};

/// One item of external work, as a source hands it over.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceTicket {
    pub id: String,
    pub task: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
}

/// A named way to fetch work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskSource {
    /// Run a command that prints one JSON [`SourceTicket`] per line to stdout.
    Shell { name: String, command: String },
}

impl TaskSource {
    /// The source's name, for logging and for deriving order ids.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Shell { name, .. } => name,
        }
    }

    /// Fetch the tickets this source currently reports.
    pub fn fetch(&self) -> Result<Vec<SourceTicket>> {
        match self {
            Self::Shell { command, .. } => {
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .output()
                    .with_context(|| format!("run the source command: {command}"))?;
                if !output.status.success() {
                    bail!(
                        "source command failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                let mut tickets = Vec::new();
                for (line_no, line) in String::from_utf8_lossy(&output.stdout).lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let ticket: SourceTicket = serde_json::from_str(line).with_context(|| {
                        format!("source printed a non-ticket line {line_no}: {line}")
                    })?;
                    tickets.push(ticket);
                }
                Ok(tickets)
            }
        }
    }
}

/// Map a ticket into an order. Pure, so it can be tested without a channel.
///
/// The order id derives from the source name and the ticket id rather than a
/// fresh uuid, so importing the same source twice does not create two orders.
#[must_use]
pub fn to_order(
    source_name: &str,
    ticket: &SourceTicket,
    project_id: &str,
    issued_by: &str,
) -> Order {
    Order {
        id: order_id(source_name, &ticket.id),
        project_id: project_id.to_string(),
        issued_by: issued_by.to_string(),
        assigned_to: ticket.assigned_to.clone(),
        created_at: Utc::now(),
        payload: serde_json::json!({
            "task": ticket.task,
            "source": source_name,
            "source_id": ticket.id,
        }),
        requires_review: true,
        signed_by: None,
        signature: None,
    }
}

/// The deterministic, path-safe order id for a source/ticket pair.
#[must_use]
pub fn order_id(source_name: &str, ticket_id: &str) -> String {
    format!("{}-{}", slug(source_name), slug(ticket_id))
}

/// Import a source's current tickets into the channel as signed orders.
///
/// Returns the number of orders newly issued. Existing orders are left alone:
/// a source may report the same ticket again on the next poll, and the second
/// sighting must not fabricate a duplicate task.
pub fn import(
    route: &ProjectRoute,
    source: &TaskSource,
    issued_by: &str,
    identity: &AgentIdentity,
) -> Result<usize> {
    let tickets = source.fetch()?;
    let mut imported = 0;
    for ticket in &tickets {
        let mut order = to_order(source.name(), ticket, &route.project_id, issued_by);
        if crate::task_dir(route, &order.id).join("order.json").exists() {
            continue; // already imported; importing again would be a duplicate
        }
        identity.sign_order(&mut order);
        crate::issue_order(route, &order)?;
        crate::ledger::append_ledger_entry(
            route,
            identity,
            "order",
            issued_by,
            &format!("imported order {} from {}", order.id, source.name()),
            Some(&order.id),
        )?;
        imported += 1;
    }
    Ok(imported)
}

/// Lowercase, map runs of non-alphanumerics to a dash, and collapse dashes, so
/// an order id derived from arbitrary source/ticket ids is always path-safe.
#[must_use]
pub fn slug(value: &str) -> String {
    let mapped: String = value
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let slugged = mapped.trim_matches('-').to_string();
    if slugged.is_empty() {
        "ticket".to_string()
    } else {
        slugged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_path_safe_and_deterministic() {
        assert_eq!(slug("My Task (v2)!"), "my-task--v2");
        assert_eq!(slug("  leading  "), "leading");
        assert_eq!(slug(""), "ticket");
    }

    #[test]
    fn an_order_id_derives_from_source_and_ticket() {
        assert_eq!(order_id("Linear", "ENG-42"), "linear-eng-42");
        assert_eq!(order_id("Linear", "ENG-42"), order_id("Linear", "ENG-42"));
    }

    #[test]
    fn a_ticket_becomes_a_shaped_order() {
        let ticket = SourceTicket {
            id: "ENG-1".into(),
            task: "fix the totals".into(),
            assigned_to: Some("nebra".into()),
        };
        let order = to_order("Linear", &ticket, "p", "orchestrator");
        assert_eq!(order.id, "linear-eng-1");
        assert_eq!(order.assigned_to.as_deref(), Some("nebra"));
        assert_eq!(order.payload["source"], "Linear");
        assert_eq!(order.payload["task"], "fix the totals");
        assert!(order.requires_review);
    }

    #[test]
    fn fetch_parses_one_ticket_per_line_and_ignores_blank_lines() {
        let source = TaskSource::Shell {
            name: "jira".into(),
            command: "printf '%s\\n' '{\"id\":\"J-1\",\"task\":\"do it\"}' '' '{\"id\":\"J-2\",\"task\":\"and this\"}'"
                .into(),
        };
        let tickets = source.fetch().unwrap();
        assert_eq!(tickets.len(), 2);
        assert_eq!(tickets[1].id, "J-2");
    }

    #[test]
    fn fetch_rejects_a_line_that_is_not_a_ticket() {
        let source = TaskSource::Shell {
            name: "broken".into(),
            command: "printf '%s\\n' 'not json'".into(),
        };
        assert!(source.fetch().is_err());
    }
}


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

use std::path::PathBuf;
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
        requires_approval: false,
        depends_on: Vec::new(),
        signed_by: None,
        signature: None,
        result_contract: None,
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
        match crate::issue_order(route, &order) {
            Ok(_) => {}
            Err(e) => {
                // Another importer may have won the race to issue this order. If it
                // now exists, that is a duplicate rather than a failure.
                if crate::task_dir(route, &order.id).join("order.json").exists() {
                    continue;
                }
                return Err(e);
            }
        }
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

/// A source plus how often to re-poll it. This is Ferryman's "always-on"
/// trigger: a running worker re-fetches the source on an interval and imports
/// anything new, so orders appear from a tracker or a script without a human
/// issuing them. Mirrors the trigger half of groundcrew's dispatcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceTrigger {
    pub name: String,
    pub command: String,
    /// Seconds between polls. Defaults to 60.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}

fn default_interval() -> u64 {
    60
}

impl SourceTrigger {
    #[must_use]
    pub fn source(&self) -> TaskSource {
        TaskSource::Shell {
            name: self.name.clone(),
            command: self.command.clone(),
        }
    }
}

/// The `sources.toml` file: the list of sources a worker re-polls. Present only
/// when the project wants always-on imports; absent means behaviour unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceConfig {
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceTrigger>,
}

/// Load the project's configured triggers. A missing or unreadable file is not
/// an error: no sources means no always-on polling, which is the historical
/// behaviour.
pub fn load_triggers(route: &ProjectRoute) -> Result<Vec<SourceTrigger>> {
    let path = route.attachment.join("sources.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let config: SourceConfig =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(config.sources)
}

/// The marker recording when a source was last polled, so an interval is
/// honoured across restarts rather than reset every time the worker starts.
fn last_import_path(route: &ProjectRoute, name: &str) -> PathBuf {
    route
        .attachment
        .join("sources")
        .join(format!("{}.last", slug(name)))
}

fn last_import_at(route: &ProjectRoute, name: &str) -> Option<chrono::DateTime<Utc>> {
    let raw = std::fs::read_to_string(last_import_path(route, name)).ok()?;
    let secs: i64 = raw.trim().parse().ok()?;
    chrono::DateTime::from_timestamp(secs, 0)
}

fn write_last_import(route: &ProjectRoute, name: &str) -> Result<()> {
    let path = last_import_path(route, name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, Utc::now().timestamp().to_string())?;
    Ok(())
}

/// Poll a trigger and import anything new, but only when its interval has
/// elapsed. Returns the number of orders imported (0 when not due).
pub fn poll_if_due(
    route: &ProjectRoute,
    trigger: &SourceTrigger,
    issued_by: &str,
    identity: &AgentIdentity,
) -> Result<usize> {
    if let Some(last) = last_import_at(route, &trigger.name) {
        let elapsed = Utc::now().signed_duration_since(last);
        if elapsed.num_seconds() < trigger.interval_secs as i64 {
            return Ok(0);
        }
    }
    let imported = import(route, &trigger.source(), issued_by, identity)?;
    if imported > 0 {
        write_last_import(route, &trigger.name)?;
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

    fn route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    #[test]
    fn load_triggers_reads_sources_toml_and_is_empty_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        std::fs::create_dir_all(&route.attachment).unwrap();
        // No file: no sources, not an error.
        assert!(load_triggers(&route).unwrap().is_empty());
        std::fs::write(
            route.attachment.join("sources.toml"),
            "[[source]]\nname = \"linear\"\ncommand = \"linear issues --jsonl\"\n\n[[source]]\nname = \"report\"\ncommand = \"report-tickets\"\ninterval_secs = 3600\n",
        )
        .unwrap();
        let triggers = load_triggers(&route).unwrap();
        assert_eq!(triggers.len(), 2);
        assert_eq!(triggers[0].interval_secs, 60, "the default interval");
        assert_eq!(triggers[1].interval_secs, 3600);
        assert_eq!(triggers[0].name, "linear");
    }

    #[test]
    fn a_trigger_polls_once_and_then_waits_for_its_interval() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        std::fs::create_dir_all(&route.attachment).unwrap();
        let identity = crate::AgentIdentity::load_or_create("orchestrator", &route.attachment).unwrap();
        let trigger = SourceTrigger {
            name: "tickets".into(),
            command: "printf '%s\\n' '{\"id\":\"E-1\",\"task\":\"do it\"}'".into(),
            interval_secs: 3600,
        };
        let n = poll_if_due(&route, &trigger, "orchestrator", &identity).unwrap();
        assert_eq!(n, 1, "the first poll imports the ticket");
        // The interval has not elapsed: not due, so nothing is imported again.
        let again = poll_if_due(&route, &trigger, "orchestrator", &identity).unwrap();
        assert_eq!(again, 0);
        // And the order really exists, signed.
        let order = crate::read_task(&route, "tickets-e-1").unwrap();
        assert_eq!(order.order.issued_by, "orchestrator");
    }
}



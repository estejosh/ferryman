//! Native event adapters: turn GitHub/Linear/webhook events into signed orders.
//!
//! The GitHub adapter speaks the `gh` CLI rather than calling the REST API, so
//! the host's existing authentication (and any proxy/CA setup) is reused and no
//! new dependency is required. `gh` emits JSON; we map it to the same
//! [`SourceTicket`] shape used by the generic shell source, so an imported
//! issue becomes a signed order exactly like any other external task.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::source::{SourceTicket, TaskSource};

/// Build a shell source that lists open GitHub issues as signed-order tickets.
///
/// The command asks `gh` for `number,title,assignees` and uses `gh`'s built-in
/// `--jq` filter to flatten the array into one [`SourceTicket`] JSON object per
/// line, which is the format [`TaskSource::Shell::fetch`] already understands.
#[must_use]
pub fn github_source(repo: &str) -> TaskSource {
    let command = format!(
        "gh issue list --repo {} --state open --json number,title,assignees --jq '.[] | {{id: (\"ENG-\" + (.number|tostring)), task: .title, assigned_to: .assignees[0].login}}'",
        shell_quote(repo)
    );
    TaskSource::Shell {
        name: format!("github-{repo}"),
        command,
    }
}

/// Parse the raw `gh issue list --json number,title,assignees` array into tickets.
pub fn gh_json_to_tickets(raw: &str) -> Result<Vec<SourceTicket>> {
    let issues: Vec<GhIssue> = serde_json::from_str(raw).context("parse GitHub issue JSON")?;
    Ok(issues
        .into_iter()
        .map(|issue| SourceTicket {
            id: format!("ENG-{}", issue.number),
            task: issue.title,
            assigned_to: issue.assignees.first().map(|a| a.login.clone()),
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct GhIssue {
    number: u64,
    title: String,
    #[serde(default)]
    assignees: Vec<GhAssignee>,
}

#[derive(Debug, Deserialize)]
struct GhAssignee {
    login: String,
}

/// Quote a value for embedding in a POSIX `sh -c` command.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_json_to_tickets_maps_number_title_and_assignees() {
        let raw = r#"[
          {"number": 42, "title": "Fix the signer race", "assignees": [{"login": "alice"}]},
          {"number": 43, "title": "Draft a benchmark", "assignees": []}
        ]"#;
        let tickets = gh_json_to_tickets(raw).unwrap();
        assert_eq!(tickets.len(), 2);
        assert_eq!(tickets[0].id, "ENG-42");
        assert_eq!(tickets[0].task, "Fix the signer race");
        assert_eq!(tickets[0].assigned_to.as_deref(), Some("alice"));
        assert_eq!(tickets[1].id, "ENG-43");
        assert_eq!(tickets[1].assigned_to, None);
    }

    #[test]
    fn github_source_commands_gh_and_quotes_the_repo() {
        let source = github_source("owner/repo");
        assert_eq!(source.name(), "github-owner/repo");
        match source {
            TaskSource::Shell { command, .. } => {
                assert!(command.contains("gh issue list --repo 'owner/repo'"));
                assert!(command.contains("--json number,title,assignees"));
            }
        }
    }
}

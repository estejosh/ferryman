//! `ferry mcp` — serve this project over the Model Context Protocol.
//!
//! MCP is JSON-RPC 2.0 over stdio. This module speaks the small server slice a
//! read-only client needs: `initialize`, `tools/list`, `tools/call`, and `ping`.
//! The tools are Ferryman's *query* surface — tasks, memory, roster, ledger,
//! learnings, skills, and the discovery manifest — so an MCP client (Claude
//! Desktop, Codex, Claude Code, …) can observe and answer questions about a
//! fleet without any write authority. Write tools are deliberately absent: an
//! MCP connection is a stranger, not the operator.
//!
//! This is the executable half of the MCP-agent designation in
//! `ferryman_channel::discovery`: the designated agent is the one you point an
//! MCP client at, and it runs this server.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use ferryman_channel::{ProjectRoute, TaskState};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the MCP server on stdio until the client closes stdin.
pub fn serve(workspace: Option<PathBuf>) -> Result<()> {
    let start = workspace.unwrap_or(std::env::current_dir().context("read the current directory")?);
    let route = ferryman_channel::route_for(&start)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.context("read from stdin")?;
        if let Some(response) = handle_line(&route, line.trim()) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// Dispatch one JSON-RPC line and return the response, if one is owed.
/// Notifications carry no id and therefore get no response.
fn handle_line(route: &ProjectRoute, line: &str) -> Option<String> {
    let request: Value = serde_json::from_str(line).ok()?;
    let method = request.get("method")?.as_str()?;
    let id = request.get("id").cloned()?;
    let response = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "ferryman", "version": env!("CARGO_PKG_VERSION") },
            },
        }),
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "tools/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": tools() } }),
        "tools/call" => json!({ "jsonrpc": "2.0", "id": id, "result": call_tool(route, &request) }),
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "method not found" },
        }),
    };
    Some(response.to_string())
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "channel_status",
            "description": "Summarize this Ferryman project: id, agent count, task counts by state, and the MCP agent if one is designated.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        }),
        json!({
            "name": "discover",
            "description": "The fleet discovery manifest: every agent with role, capabilities, specialization summary and public key, the operator's skills, and the MCP agent.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        }),
        json!({
            "name": "list_tasks",
            "description": "List the channel's tasks, optionally filtered to one state (open, claimed, awaiting_review, changes_requested, accepted, done).",
            "inputSchema": {
                "type": "object",
                "properties": { "state": { "type": "string" } },
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "get_task",
            "description": "Full detail for one task: the order, its claims, results, and reviews.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"],
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "read_memory",
            "description": "Read the shared project memory bank: list its files, or return one file's contents.",
            "inputSchema": {
                "type": "object",
                "properties": { "file": { "type": "string" } },
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "list_ledger",
            "description": "The most recent ledger entries (who did what, signed), newest first.",
            "inputSchema": {
                "type": "object",
                "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 500 } },
                "additionalProperties": false,
            },
        }),
        json!({
            "name": "list_learnings",
            "description": "The most recent learning records (which engine did what, and whether it was kept), newest first.",
            "inputSchema": {
                "type": "object",
                "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 500 } },
                "additionalProperties": false,
            },
        }),
    ]
}

fn call_tool(route: &ProjectRoute, request: &Value) -> Value {
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let outcome: Result<Value> = match name {
        "channel_status" => channel_status(route),
        "discover" => ferryman_channel::discovery::manifest(route),
        "list_tasks" => list_tasks(route, &args),
        "get_task" => get_task(route, &args),
        "read_memory" => read_memory(route, &args),
        "list_ledger" => list_ledger(route, &args),
        "list_learnings" => list_learnings(route, &args),
        other => Err(anyhow::anyhow!("unknown tool: {other}")),
    };
    match outcome {
        Ok(value) => json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            }],
            "isError": false,
        }),
        Err(err) => json!({
            "content": [{ "type": "text", "text": format!("{err:#}") }],
            "isError": true,
        }),
    }
}

fn state_name(state: &TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
        TaskState::Claimed { .. } => "claimed",
        TaskState::AwaitingReview { .. } => "awaiting_review",
        TaskState::ChangesRequested { .. } => "changes_requested",
        TaskState::Accepted => "accepted",
        TaskState::Done => "done",
    }
}

fn channel_status(route: &ProjectRoute) -> Result<Value> {
    let tasks = ferryman_channel::list_tasks(route)?;
    let mut counts = std::collections::BTreeMap::new();
    for task in &tasks {
        *counts.entry(state_name(&task.state())).or_insert(0usize) += 1;
    }
    Ok(json!({
        "project": route.project_id,
        "agents": route.agents.len(),
        "tasks": counts,
        "mcp_agent": ferryman_channel::discovery::mcp_agent(route).map(|a| &a.name),
    }))
}

fn list_tasks(route: &ProjectRoute, args: &Value) -> Result<Value> {
    let filter = args.get("state").and_then(Value::as_str);
    let tasks = ferryman_channel::list_tasks(route)?;
    let items: Vec<Value> = tasks
        .iter()
        .filter(|task| filter.is_none_or(|f| f == state_name(&task.state())))
        .map(|task| {
            json!({
                "id": task.order.id,
                "task": task.order.payload.get("task").and_then(Value::as_str).unwrap_or(""),
                "state": state_name(&task.state()),
                "holder": task.holder(),
                "assigned_to": task.order.assigned_to,
                "requires_review": task.order.requires_review,
                "requires_approval": task.order.requires_approval,
                "result_count": task.results.len(),
            })
        })
        .collect();
    Ok(Value::Array(items))
}

fn get_task(route: &ProjectRoute, args: &Value) -> Result<Value> {
    let Some(id) = args.get("id").and_then(Value::as_str) else {
        bail!("get_task needs an 'id' argument");
    };
    let task = ferryman_channel::read_task(route, id)?;
    let results: Vec<Value> = task
        .results
        .iter()
        .map(|r| json!({ "revision": r.revision, "agent": r.agent, "output": result_text(&r.payload) }))
        .collect();
    let reviews: Vec<Value> = task
        .reviews
        .iter()
        .map(|r| json!({ "revision": r.revision, "reviewer": r.reviewer, "accepted": r.accepted, "notes": r.notes }))
        .collect();
    Ok(json!({
        "id": task.order.id,
        "issued_by": task.order.issued_by,
        "assigned_to": task.order.assigned_to,
        "created_at": task.order.created_at.to_rfc3339(),
        "task": task.order.payload.get("task").and_then(Value::as_str).unwrap_or(""),
        "state": state_name(&task.state()),
        "holder": task.holder(),
        "claims": task.claims.iter().map(|c| json!({ "agent": c.agent, "at": c.claimed_at.to_rfc3339() })).collect::<Vec<_>>(),
        "results": results,
        "reviews": reviews,
    }))
}

/// The readable text of a result payload, whatever shape the agent chose.
fn result_text(payload: &Value) -> String {
    match payload {
        Value::String(text) => text.clone(),
        other => other
            .get("output")
            .or_else(|| other.get("result"))
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_else(|| serde_json::to_string(other).unwrap_or_default()),
    }
}

fn read_memory(route: &ProjectRoute, args: &Value) -> Result<Value> {
    let memory_dir = route.communications.join("memory-bank");
    let requested = args.get("file").and_then(Value::as_str).map(String::from);
    let mut files = Vec::new();
    if memory_dir.is_dir() {
        for entry in std::fs::read_dir(&memory_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            files.push((name, content));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    match requested {
        Some(name) => match files.into_iter().find(|(n, _)| *n == name) {
            Some((_, content)) => Ok(json!({ "file": name, "content": content })),
            None => bail!("no memory file named {name}"),
        },
        None => Ok(json!({
            "files": files.into_iter().map(|(name, _)| name).collect::<Vec<_>>(),
        })),
    }
}

fn list_ledger(route: &ProjectRoute, args: &Value) -> Result<Value> {
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .min(500) as usize;
    let log = ferryman_channel::ledger::read_ledger(route)?;
    let entries: Vec<Value> = log
        .entries
        .iter()
        .rev()
        .take(limit)
        .map(|e| {
            json!({
                "kind": e.kind,
                "actor": e.actor,
                "summary": e.summary,
                "reference": e.reference,
                "at": e.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(json!({ "intact": log.intact, "entries": entries }))
}

fn list_learnings(route: &ProjectRoute, args: &Value) -> Result<Value> {
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .min(500) as usize;
    let learnings = ferryman_channel::learning::read_learnings(route)?;
    let items: Vec<Value> = learnings
        .iter()
        .rev()
        .take(limit)
        .map(|l| {
            json!({
                "engine": l.engine,
                "task_id": l.task_id,
                "source": l.source,
                "accepted": l.accepted,
                "note": l.note,
                "at": l.at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Value::Array(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> ProjectRoute {
        let workspace = PathBuf::from("/tmp/ferryman-mcp-test/workspace");
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
    fn initialize_advertises_tools() {
        let response = handle_line(
            &route(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(v["result"]["serverInfo"]["name"], "ferryman");
    }

    #[test]
    fn tools_list_has_the_query_surface() {
        let response = handle_line(
            &route(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&response).unwrap();
        assert!(v["result"]["tools"].as_array().unwrap().len() >= 7);
    }

    #[test]
    fn a_notification_gets_no_response() {
        assert!(
            handle_line(
                &route(),
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
        );
    }

    #[test]
    fn calling_an_unknown_tool_returns_is_error() {
        let response = handle_line(
            &route(),
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope"}}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["result"]["isError"], true);
    }

    #[test]
    fn channel_status_reports_the_project() {
        let response = handle_line(
            &route(),
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"channel_status"}}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["result"]["isError"], false);
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("ferryman"));
    }
}

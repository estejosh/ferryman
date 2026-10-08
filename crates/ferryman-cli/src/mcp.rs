//! `ferry mcp` — serve this project over the Model Context Protocol.
//!
//! MCP is JSON-RPC 2.0 over stdio. This module speaks the small server slice a
//! read-only client needs: `initialize`, `tools/list`, `tools/call`, and `ping`.
//! The tools are Ferryman's *query* surface — tasks, memory, roster, ledger,
//! learnings, skills, and the discovery manifest — so an MCP client (Claude
//! Desktop, Codex, Claude Code, …) can observe and answer questions about a
//! fleet without any write authority. Write tools are deliberately absent: an
//! MCP connection is a stranger, not the operator. The one exception is the
//! librarian's `library_remember`, the weakest write there is: a fact signed as
//! this server's own agent, which waits as *unconfirmed* until the owner confirms
//! it, and is refused if it looks like a secret. See `ferryman_channel::library`.
//!
//! This is the executable half of the MCP-agent designation in
//! `ferryman_channel::discovery`: the designated agent is the one you point an
//! MCP client at, and it runs this server.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::mcp_client::McpClient;
use ferryman_channel::{ProjectRoute, TaskState};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Resolve the project route for a `ferry mcp` subcommand.
pub fn route_for(workspace: Option<PathBuf>) -> Result<ProjectRoute> {
    let start = workspace.unwrap_or(std::env::current_dir().context("read the current directory")?);
    ferryman_channel::route_for(&start)
}

/// Run the MCP server on stdio until the client closes stdin. Besides Ferryman's
/// own tools, any external server in `.ferryman/mcp.toml` is connected and its
/// tools proxied under a `name_` prefix, so one connection serves the whole
/// fleet's tool surface.
pub fn serve(workspace: Option<PathBuf>) -> Result<()> {
    let route = route_for(workspace)?;
    let mut gateways = Vec::new();
    for (name, spec) in load_servers(&route)? {
        match McpClient::connect(&spec) {
            Ok(mut client) => match client.list_tools_raw() {
                Ok(raw) => {
                    let prefix = format!("{name}_");
                    let tools = raw
                        .into_iter()
                        .map(|mut tool| {
                            if let Some(original) = tool.get("name").and_then(Value::as_str) {
                                tool["name"] = Value::String(format!("{prefix}{original}"));
                            }
                            tool
                        })
                        .collect();
                    gateways.push(Gateway {
                        prefix,
                        tools,
                        client,
                    });
                }
                Err(err) => eprintln!("mcp server '{name}' failed to list tools: {err:#}"),
            },
            Err(err) => eprintln!("mcp server '{name}' failed to start: {err:#}"),
        }
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.context("read from stdin")?;
        if let Some(response) = handle_line(&route, &mut gateways, line.trim()) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// An external MCP server connected at startup, with its tools prefixed so the
/// gateway can route a `tools/call` back to the right server.
struct Gateway {
    prefix: String,
    tools: Vec<Value>,
    client: McpClient,
}

/// Dispatch one JSON-RPC line and return the response, if one is owed.
/// Notifications carry no id and therefore get no response.
fn handle_line(route: &ProjectRoute, gateways: &mut [Gateway], line: &str) -> Option<String> {
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
        "tools/list" => {
            json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": all_tools(gateways) } })
        }
        "tools/call" => {
            json!({ "jsonrpc": "2.0", "id": id, "result": call_any(route, gateways, &request) })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "method not found" },
        }),
    };
    Some(response.to_string())
}

/// Ferryman's own tools plus every connected external server's prefixed tools.
fn all_tools(gateways: &[Gateway]) -> Vec<Value> {
    let mut all = tools();
    all.extend(crate::library::mcp_tools());
    for gateway in gateways {
        all.extend(gateway.tools.iter().cloned());
    }
    all
}

/// Route a `tools/call` to an external server when the tool name carries its
/// prefix, otherwise to Ferryman's own tools.
fn call_any(route: &ProjectRoute, gateways: &mut [Gateway], request: &Value) -> Value {
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    for gateway in gateways.iter_mut() {
        if let Some(tool) = name.strip_prefix(&gateway.prefix) {
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            return match gateway.client.call_tool(tool, args) {
                Ok(result) => result,
                Err(err) => json!({
                    "content": [{ "type": "text", "text": format!("{err:#}") }],
                    "isError": true,
                }),
            };
        }
    }
    call_tool(route, request)
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
        json!({
            "name": "list_engines",
            "description": "Which engines each worker on this channel can run right now: tier, how it is paid, up, down or out of credit until when. Read-only; no credentials.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        }),
    ]
}

fn list_engines(route: &ProjectRoute) -> Result<Value> {
    let rows: Vec<Value> = ferryman_channel::receipts::list_engines(route)?
        .into_iter()
        .map(|(inventory, check)| json!({ "signature": format!("{check:?}"), "inventory": inventory }))
        .collect();
    Ok(json!(rows))
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
        "list_engines" => list_engines(route),
        // The librarian: ask, search, one fact, and the one write (an unconfirmed fact,
        // signed as this server's own agent and never as the master).
        library if crate::library::is_mcp_tool(library) => {
            crate::library::mcp_call(route, library, &args)
        }
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
        TaskState::Offered { .. } => "offered",
        TaskState::Claimed { .. } => "claimed",
        TaskState::Stale { .. } => "stale",
        TaskState::AwaitingReview { .. } => "awaiting_review",
        TaskState::ChangesRequested { .. } => "changes_requested",
        TaskState::Accepted => "accepted",
        TaskState::Done => "done",
        TaskState::Refuted { .. } => "refuted",
        TaskState::Killed { .. } => "killed",
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

/// One configured external MCP server in `.ferryman/mcp.toml`.
#[derive(serde::Serialize, serde::Deserialize)]
struct McpServerConfig {
    name: String,
    command: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct McpConfig {
    #[serde(default)]
    servers: Vec<McpServerConfig>,
}

fn mcp_toml_path(route: &ProjectRoute) -> PathBuf {
    route.attachment.join("mcp.toml")
}

/// The external MCP servers configured for this project, as `(name, command)`.
pub fn load_servers(route: &ProjectRoute) -> Result<Vec<(String, String)>> {
    let path = mcp_toml_path(route);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let config: McpConfig =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(config
        .servers
        .into_iter()
        .map(|server| (server.name, server.command))
        .collect())
}

/// Add or replace a configured external MCP server.
pub fn add_server(route: &ProjectRoute, name: &str, command: &str) -> Result<()> {
    let mut servers = load_servers(route)?;
    servers.retain(|(existing, _)| existing != name);
    servers.push((name.to_string(), command.to_string()));
    servers.sort_by(|a, b| a.0.cmp(&b.0));
    write_servers(route, &servers)
}

/// Remove a configured external MCP server, erroring if it is not there.
pub fn remove_server(route: &ProjectRoute, name: &str) -> Result<()> {
    let mut servers = load_servers(route)?;
    let before = servers.len();
    servers.retain(|(existing, _)| existing != name);
    if servers.len() == before {
        bail!("no MCP server named '{name}' is configured");
    }
    write_servers(route, &servers)
}

fn write_servers(route: &ProjectRoute, servers: &[(String, String)]) -> Result<()> {
    let config = McpConfig {
        servers: servers
            .iter()
            .map(|(name, command)| McpServerConfig {
                name: name.clone(),
                command: command.clone(),
            })
            .collect(),
    };
    std::fs::write(mcp_toml_path(route), toml::to_string(&config)?)?;
    Ok(())
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
            &mut [],
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
            &mut [],
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
                &mut [],
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
        );
    }

    #[test]
    fn calling_an_unknown_tool_returns_is_error() {
        let response = handle_line(
            &route(),
            &mut [],
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
            &mut [],
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"channel_status"}}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["result"]["isError"], false);
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("ferryman"));
    }

    #[test]
    fn config_add_list_remove_round_trips() {
        let dir = std::env::temp_dir().join(format!("ferryman-mcp-config-{}", std::process::id()));
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        std::fs::create_dir_all(&attachment).unwrap();
        let route = ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        add_server(
            &route,
            "github",
            "npx -y @modelcontextprotocol/server-github",
        )
        .unwrap();
        add_server(
            &route,
            "filesystem",
            "npx -y @modelcontextprotocol/server-filesystem",
        )
        .unwrap();
        let servers = load_servers(&route).unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].0, "filesystem"); // sorted by name
        remove_server(&route, "github").unwrap();
        assert_eq!(load_servers(&route).unwrap().len(), 1);
        assert!(remove_server(&route, "github").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A minimal stdio MCP server driven by line number, mirroring the client test.
    ///
    /// Gated with its test: unconditional, it is an unused constant on Windows and
    /// `clippy -D warnings` fails there only.
    #[cfg(unix)]
    const FIXTURE: &str = r#"n=0
while IFS= read -r line; do
  n=$((n+1))
  case "$n" in
    1) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}';;
    3) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo a value","inputSchema":{"type":"object"}}]}}';;
    4) printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"fixture-ok"}],"isError":false}}';;
  esac
done
"#;

    #[cfg(unix)]
    #[test]
    fn gateway_merges_and_routes_external_tools() {
        let dir = std::env::temp_dir().join(format!("ferryman-mcp-gw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fixture.sh");
        std::fs::write(&script, FIXTURE).unwrap();
        let mut client = McpClient::connect(&format!("sh {}", script.display())).unwrap();
        let raw = client.list_tools_raw().unwrap();
        let prefix = "github_".to_string();
        let tools: Vec<Value> = raw
            .into_iter()
            .map(|mut tool| {
                if let Some(name) = tool.get("name").and_then(Value::as_str) {
                    tool["name"] = Value::String(format!("{prefix}{name}"));
                }
                tool
            })
            .collect();
        let mut gateways = vec![Gateway {
            prefix: prefix.clone(),
            tools,
            client,
        }];
        // tools/list merges Ferryman's own tools with the prefixed external one.
        assert!(
            all_tools(&gateways)
                .iter()
                .any(|t| t["name"] == "github_echo")
        );
        // tools/call routes the prefixed name back to the external server.
        let request = json!({ "params": { "name": "github_echo", "arguments": { "text": "hi" } } });
        let result = call_any(&route(), &mut gateways, &request);
        assert_eq!(result["content"][0]["text"], "fixture-ok");
        assert_eq!(result["isError"], false);
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// The librarian's tools, over the same JSON-RPC the other tools use.
#[cfg(test)]
mod library_tests {
    use super::*;
    use ferryman_channel::{AgentIdentity, AgentRoute, library};

    const HOME: &str = "ferryman";

    fn call(route: &ProjectRoute, tool: &str, arguments: &Value) -> (bool, Value) {
        let request = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        });
        let response = handle_line(route, &mut [], &request.to_string()).unwrap();
        let v: Value = serde_json::from_str(&response).unwrap();
        let text = v["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let failed = v["result"]["isError"] == true;
        (
            failed,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// A home channel mastered by josh with `grouchly` on the roster, and an MCP workspace
    /// whose own keys (and `agent.toml`) are `agent`'s.
    fn world(dir: &std::path::Path, agent: &str) -> (ProjectRoute, AgentIdentity) {
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            std::env::temp_dir().join(format!("ferryman-cli-library-{}", std::process::id())),
        );
        let channel = dir.join("ferryman-ferryman");
        std::fs::create_dir_all(&channel).unwrap();
        let attachment = dir.join("workspace").join(".ferryman");
        std::fs::create_dir_all(&attachment).unwrap();
        std::fs::write(
            attachment.join("agent.toml"),
            format!("agent = \"{agent}\"\ncommand = \"claude\"\n"),
        )
        .unwrap();
        let me = AgentIdentity::load_or_create(agent, &attachment).unwrap();
        let josh = AgentIdentity::from_seed("josh", [1; 32]);
        let mut home_route = ProjectRoute {
            project_id: HOME.into(),
            workspace: dir.join("ferryman"),
            attachment: dir.join("home-attachment"),
            communications: channel.clone(),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        let mut members: Vec<&AgentIdentity> = vec![&josh];
        if agent != "josh" {
            members.push(&me);
        }
        for member in members {
            let entry = AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            ferryman_channel::register_agent(&home_route, &entry).unwrap();
            home_route.agents.push(entry);
        }
        ferryman_channel::master::initialize_master(&home_route, &josh, "josh").unwrap();
        crate::library::TEST_HOME.with(|home| {
            *home.borrow_mut() = Some(library::Home {
                project: HOME.into(),
                channel,
                attachment: dir.join("home-attachment"),
            });
        });
        let route = ProjectRoute {
            project_id: "bullship".into(),
            workspace: dir.join("workspace"),
            attachment,
            communications: dir.join("workspace-comms"),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        (route, josh)
    }

    #[test]
    fn the_library_tools_are_listed_and_ask_search_remember_and_show_a_fact() {
        let dir = tempfile::tempdir().unwrap();
        let (route, josh) = world(dir.path(), "grouchly");
        let home = crate::library::TEST_HOME
            .with(|home| home.borrow().clone())
            .unwrap();
        // The master has written one fact already.
        library::remember(
            &home.channel,
            HOME,
            &josh,
            None,
            library::NewFact {
                subject: "grouchly".into(),
                text: "grouchly is the always-on Ubuntu box that runs n8n".into(),
                source: "josh".into(),
                ..library::NewFact::default()
            },
        )
        .unwrap();

        let listed: Value = serde_json::from_str(
            &handle_line(
                &route,
                &mut [],
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        for tool in [
            "library_ask",
            "library_search",
            "library_remember",
            "library_fact",
        ] {
            assert!(names.contains(&tool), "{tool} in {names:?}");
        }

        // Remember: signed as the server's agent, unconfirmed.
        let (failed, written) = call(
            &route,
            "library_remember",
            &json!({"text": "the dashboard on grouchly listens on 7821", "subject": "dashboard port", "tags": ["ops"], "source": "bullship worker"}),
        );
        assert!(!failed, "{written}");
        assert_eq!(written["status"], "unconfirmed");
        assert_eq!(written["signed_by"], "grouchly");
        let id = written["id"].as_str().unwrap().to_string();

        // Search finds both, with standing and date.
        let (failed, found) = call(
            &route,
            "library_search",
            &json!({"query": "which machine is always on"}),
        );
        assert!(!failed);
        assert_eq!(found[0]["subject"], "grouchly");
        assert_eq!(found[0]["status"], "confirmed");
        let (_, found) = call(
            &route,
            "library_search",
            &json!({"query": "dashboard port"}),
        );
        assert_eq!(found[0]["id"], id.as_str());
        assert_eq!(found[0]["status"], "unconfirmed");

        // Fact: who wrote it, how it was claimed, whether it is confirmed.
        let (failed, fact) = call(&route, "library_fact", &json!({"id": id}));
        assert!(!failed);
        assert_eq!(fact["fact"]["author"], "grouchly");
        assert_eq!(fact["fact"]["status"], "unconfirmed");
        assert!(fact["fact"]["source"].as_str().unwrap().contains("via MCP"));
        assert!(
            fact["fact"]["source"]
                .as_str()
                .unwrap()
                .contains("bullship worker")
        );
        assert_eq!(fact["history"].as_array().unwrap().len(), 1);
        assert!(call(&route, "library_fact", &json!({"id": "f-0000000000"})).0);

        // Ask with no model: the facts, never an invented answer; nothing relevant, nothing.
        let (failed, answer) = call(
            &route,
            "library_ask",
            &json!({"question": "which machine is always on?", "no_model": true}),
        );
        assert!(!failed);
        assert_eq!(answer["known"], true);
        assert_eq!(answer["facts"][0]["subject"], "grouchly");
        let (_, answer) = call(
            &route,
            "library_ask",
            &json!({"question": "what is the capital of France?"}),
        );
        assert_eq!(answer["known"], false);
        assert!(
            answer["answer"]
                .as_str()
                .unwrap()
                .starts_with("I don't know")
        );
        // Without a worker configuration at home there is no model to ask: facts only.
        let (_, answer) = call(
            &route,
            "library_ask",
            &json!({"question": "which machine is always on?"}),
        );
        assert_eq!(answer["known"], true);
        assert_eq!(answer["answer"], "");

        // A correction is a new fact that names the old one.
        let (failed, fixed) = call(
            &route,
            "library_remember",
            &json!({"text": "the dashboard on grouchly listens on 7822", "subject": "dashboard port", "supersedes": [id]}),
        );
        assert!(!failed, "{fixed}");
        let (_, old) = call(&route, "library_fact", &json!({"id": id}));
        assert_eq!(old["replaced_by"][0]["id"], fixed["id"]);
    }

    #[test]
    fn a_secret_is_refused_over_mcp_and_never_echoed_and_the_master_is_never_impersonated() {
        let dir = tempfile::tempdir().unwrap();
        let (route, _) = world(dir.path(), "grouchly");
        let token = format!(
            "ghp_{}",
            ["q8Zr3LmX0", "vB2nC6dF9", "gH1jK4pT7", "wY5sA3eR8"].concat()
        );
        let (failed, refused) = call(
            &route,
            "library_remember",
            &json!({"text": format!("use {token} for deploys")}),
        );
        assert!(failed);
        let text = refused.as_str().unwrap();
        assert!(text.contains("pointer") && !text.contains(&token), "{text}");
        let home = crate::library::TEST_HOME
            .with(|home| home.borrow().clone())
            .unwrap();
        assert!(library::Library::load(&home.channel, HOME).facts.is_empty());
        for bad in [
            json!({}),
            json!({"text": ""}),
            json!({"text": "x", "tags": ["Not A Tag"]}),
        ] {
            assert!(call(&route, "library_remember", &bad).0, "{bad}");
        }
        // A tool call cannot name another author.
        let (_, written) = call(
            &route,
            "library_remember",
            &json!({"text": "fine fact", "author": "josh", "signed_by": "josh"}),
        );
        assert_eq!(written["signed_by"], "grouchly");

        // A server that holds the master's own key still writes no confirmed fact.
        let other = tempfile::tempdir().unwrap();
        let (master_route, _) = world(other.path(), "josh");
        let (failed, refused) = call(
            &master_route,
            "library_remember",
            &json!({"text": "from the master"}),
        );
        assert!(failed);
        assert!(
            refused
                .as_str()
                .unwrap()
                .contains("never writes as the master"),
            "{refused}"
        );
    }
}

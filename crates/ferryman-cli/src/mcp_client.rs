//! MCP client over stdio: connect to an external MCP server, list its tools,
//! and call them. The mirror image of `mcp.rs`, which serves Ferryman's own
//! tools — this is the "consume" half of Ferryman's MCP support.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Split a `--server` string ("cmd arg1 arg2") into command + args. No shell
/// interpretation — quoting is deliberately unsupported.
pub fn split_server(spec: &str) -> Result<(String, Vec<String>)> {
    let mut parts = spec.split_whitespace();
    let command = parts.next().context("server command must not be empty")?;
    Ok((command.to_string(), parts.map(String::from).collect()))
}

/// A connected MCP server process. Killed when dropped.
pub struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl McpClient {
    /// Spawn the server and complete the MCP handshake.
    pub fn connect(spec: &str) -> Result<Self> {
        let (command, args) = split_server(spec)?;
        let mut child = Command::new(&command)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawn MCP server '{command}'"))?;
        let stdin = child.stdin.take().context("pipe the server's stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("pipe the server's stdout")?);
        let mut client = McpClient {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        client.request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "ferryman", "version": env!("CARGO_PKG_VERSION") },
            }),
        )?;
        writeln!(
            client.stdin,
            "{}",
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
        )?;
        client.stdin.flush()?;
        Ok(client)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.stdin,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
        )?;
        self.stdin.flush()?;
        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .context("read from MCP server")?;
        if n == 0 {
            bail!("MCP server closed the connection during '{method}'");
        }
        let response: Value = serde_json::from_str(line.trim()).context("parse MCP response")?;
        if let Some(err) = response.get("error") {
            bail!("MCP error: {err}");
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Every tool the server advertises, as raw JSON objects (name, description,
    /// inputSchema). `list_tools` is the flattened form for display.
    pub fn list_tools_raw(&mut self) -> Result<Vec<Value>> {
        let result = self.request("tools/list", json!({}))?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Every tool the server advertises, as `(name, description)`.
    pub fn list_tools(&mut self) -> Result<Vec<(String, String)>> {
        Ok(self
            .list_tools_raw()?
            .into_iter()
            .map(|t| {
                (
                    t.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    t.get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                )
            })
            .collect())
    }

    /// Call a tool and return the parsed result object.
    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value> {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }
}

/// `ferry mcp list`: print the tools an external server advertises.
pub fn list(spec: &str) -> Result<()> {
    let mut client = McpClient::connect(spec)?;
    let tools = client.list_tools()?;
    if tools.is_empty() {
        println!("no tools advertised");
    } else {
        for (name, description) in tools {
            println!("  {name:<32} {description}");
        }
    }
    Ok(())
}

/// `ferry mcp call`: call one tool and print its text result.
pub fn call(spec: &str, tool: &str, arguments: Option<String>) -> Result<()> {
    let arguments: Value = match arguments {
        Some(text) => serde_json::from_str(&text).context("--arguments must be a JSON object")?,
        None => json!({}),
    };
    let mut client = McpClient::connect(spec)?;
    let result = client.call_tool(tool, arguments)?;
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| {
            content
                .iter()
                .find_map(|item| item.get("text").and_then(Value::as_str))
        })
        .map(String::from)
        .unwrap_or_else(|| serde_json::to_string_pretty(&result).unwrap_or_default());
    println!("{text}");
    if result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("tool '{tool}' reported an error");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal stdio MCP server driven by line number: line 1 is initialize,
    /// line 2 the initialized notification, line 3 tools/list, line 4 tools/call.
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
    fn lists_and_calls_tools_on_an_external_server() {
        let dir = std::env::temp_dir().join(format!("ferryman-mcp-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fixture.sh");
        std::fs::write(&script, FIXTURE).unwrap();
        let spec = format!("sh {}", script.display());
        let mut client = McpClient::connect(&spec).unwrap();
        let tools = client.list_tools().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0, "echo");
        let result = client.call_tool("echo", json!({ "text": "hi" })).unwrap();
        assert_eq!(result["content"][0]["text"], "fixture-ok");
        assert_eq!(result["isError"], false);
    }
}

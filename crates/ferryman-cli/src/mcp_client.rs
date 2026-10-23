//! MCP client over stdio: connect to an external MCP server, list its tools,
//! and call them. The mirror image of `mcp.rs`, which serves Ferryman's own
//! tools — this is the "consume" half of Ferryman's MCP support.
//!
//! Every request has a deadline. A server that starts and never answers used to hang the
//! caller forever (`ferry mcp list`, and the gateway at `ferry mcp serve` start-up); now it
//! is killed and reported. `FERRYMAN_MCP_TIMEOUT_SECS` changes the default.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// How long the handshake and listing requests may take.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a tool call may take; tools legitimately run longer than a handshake.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

fn default_timeout() -> Duration {
    std::env::var("FERRYMAN_MCP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map_or(DEFAULT_TIMEOUT, Duration::from_secs)
}

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
    /// Lines from the server's stdout, read on a thread so a silent server can time out.
    lines: Receiver<std::io::Result<String>>,
    next_id: u64,
    timeout: Duration,
    call_timeout: Duration,
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl McpClient {
    /// Spawn the server and complete the MCP handshake, with the default deadlines.
    pub fn connect(spec: &str) -> Result<Self> {
        let timeout = default_timeout();
        let call = timeout.max(CALL_TIMEOUT);
        Self::connect_with(spec, timeout, call)
    }

    /// [`Self::connect`] with explicit deadlines: `timeout` for the handshake and listing,
    /// `call_timeout` for each tool call.
    pub fn connect_with(spec: &str, timeout: Duration, call_timeout: Duration) -> Result<Self> {
        let (command, args) = split_server(spec)?;
        let mut child = Command::new(&command)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawn MCP server '{command}'"))?;
        let stdin = child.stdin.take().context("pipe the server's stdin")?;
        let stdout = child.stdout.take().context("pipe the server's stdout")?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let _ = sender.send(Err(std::io::ErrorKind::UnexpectedEof.into()));
                        return;
                    }
                    Ok(_) => {
                        if sender.send(Ok(line)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        return;
                    }
                }
            }
        });
        let mut client = McpClient {
            child,
            stdin,
            lines,
            next_id: 1,
            timeout,
            call_timeout,
        };
        client.request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "ferryman", "version": env!("CARGO_PKG_VERSION") },
            }),
            timeout,
        )?;
        writeln!(
            client.stdin,
            "{}",
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
        )?;
        client.stdin.flush()?;
        Ok(client)
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.stdin,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
        )?;
        self.stdin.flush()?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    bail!("MCP server closed the connection during '{method}'")
                }
                Ok(Err(error)) => return Err(error).context("read from MCP server"),
                Err(RecvTimeoutError::Timeout) => {
                    // A server that will not answer is not left running.
                    let _ = self.child.kill();
                    bail!(
                        "MCP server did not answer '{method}' within {} s; it was stopped",
                        timeout.as_secs_f32().ceil()
                    )
                }
                Err(RecvTimeoutError::Disconnected) => {
                    bail!("MCP server closed the connection during '{method}'")
                }
            };
            let Ok(response) = serde_json::from_str::<Value>(line.trim()) else {
                continue; // a log line on stdout is not an answer
            };
            // Notifications and answers to other requests are not ours.
            if response.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = response.get("error") {
                bail!("MCP error: {err}");
            }
            return Ok(response.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Every tool the server advertises, as raw JSON objects (name, description,
    /// inputSchema). `list_tools` is the flattened form for display.
    pub fn list_tools_raw(&mut self) -> Result<Vec<Value>> {
        let timeout = self.timeout;
        let result = self.request("tools/list", json!({}), timeout)?;
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
        let timeout = self.call_timeout;
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
            timeout,
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

// The whole module is unix-only because its tests drive a `sh` fixture. Gated at the
// module rather than per item: with only the test gated, the import and the fixture constant
// it feeds become unused on Windows, and `clippy -D warnings` fails there while passing on
// Linux - which is how this reached a release branch unnoticed.
#[cfg(all(test, unix))]
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

    fn script(name: &str, body: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("ferryman-mcp-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fixture.sh");
        std::fs::write(&script, body).unwrap();
        let spec = format!("sh {}", script.display());
        (dir, spec)
    }

    #[test]
    fn lists_and_calls_tools_on_an_external_server() {
        let (dir, spec) = script("fixture", FIXTURE);
        let mut client = McpClient::connect(&spec).unwrap();
        let tools = client.list_tools().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].0, "echo");
        let result = client.call_tool("echo", json!({ "text": "hi" })).unwrap();
        assert_eq!(result["content"][0]["text"], "fixture-ok");
        assert_eq!(result["isError"], false);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_server_that_never_answers_times_out_instead_of_hanging() {
        // Reads its input and says nothing, ever.
        let (dir, spec) = script("silent", "cat > /dev/null\n");
        let started = Instant::now();
        let error = McpClient::connect_with(
            &spec,
            Duration::from_millis(300),
            Duration::from_millis(300),
        )
        .err()
        .expect("a silent server must not connect");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(format!("{error:#}").contains("did not answer"), "{error:#}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_tool_call_that_stalls_times_out_after_a_good_handshake() {
        // Answers initialize and tools/list, then goes quiet on the call.
        let body = FIXTURE.replace("    4) printf", "    4) sleep 30; printf");
        let (dir, spec) = script("stall", &body);
        let mut client =
            McpClient::connect_with(&spec, Duration::from_secs(5), Duration::from_millis(300))
                .unwrap();
        assert_eq!(client.list_tools().unwrap().len(), 1);
        let error = client.call_tool("echo", json!({})).unwrap_err();
        assert!(format!("{error:#}").contains("did not answer"), "{error:#}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_server_that_exits_is_reported_as_closed() {
        let (dir, spec) = script("exits", "exit 0\n");
        let error = McpClient::connect_with(&spec, Duration::from_secs(5), Duration::from_secs(5))
            .err()
            .expect("an exited server must not connect");
        assert!(format!("{error:#}").contains("closed"), "{error:#}");
        std::fs::remove_dir_all(&dir).ok();
    }
}

//! `ferry mcp serve` through the real binary over stdio: initialize, list, join.
//!
//! The unit tests drive the handler directly; this one proves the process boundary: the
//! flags parse, the server speaks newline-delimited JSON-RPC, answers in order, and exits
//! when stdin closes.

use ferryman_channel::ferry::Root;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn the_server_speaks_json_rpc_over_stdio() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let root = Root::create_with_layout(&base.join("ferry"), 1).unwrap();
    let channel = root.comms().join("alpha-ferryman");
    fs::create_dir_all(channel.join("agents")).unwrap();
    let repo = root.repos().join("alpha");
    let bridge = repo.join(".ferryman").join("bridge.toml");
    fs::create_dir_all(bridge.parent().unwrap()).unwrap();
    fs::write(
        &bridge,
        format!(
            "project = \"alpha\"\nworkspace = \"{}\"\nattachment = \"{}\"\ncommunications = \"{}\"\n",
            repo.display(),
            repo.join(".ferryman").display(),
            channel.display()
        ),
    )
    .unwrap();
    assert!(root.adopt("alpha", &channel, Some(&repo)).unwrap());
    let state = base.join("state");
    fs::create_dir_all(&state).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ferry"))
        .args(["mcp", "serve", "--as", "smoke-app", "--project", "alpha"])
        .arg("--workspace")
        .arg(&repo)
        .current_dir(base)
        .env("FERRYMAN_ROOT", &root.path)
        .env("FERRYMAN_STATE_DIR", &state)
        .env("LOCALAPPDATA", &state)
        .env("HOME", base)
        .env("USERPROFILE", base)
        .env("FERRYMAN_MCP_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |request: Value| -> Value {
        writeln!(stdin, "{request}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"))
    };

    let init = ask(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}));
    assert!(
        init["result"]["serverInfo"]["version"]
            .as_str()
            .unwrap()
            .ends_with("-beta")
    );
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("ferry_join")
    );

    let listed = ask(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "ferry_ask_human",
            "ferry_catchup",
            "ferry_join",
            "ferry_orders",
            "ferry_primary",
            "ferry_talk"
        ]
    );

    let joined = ask(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"ferry_join","arguments":{}}}));
    assert_eq!(
        joined["result"]["structuredContent"]["agent"], "smoke-app",
        "{joined}"
    );
    let pong = ask(json!({"jsonrpc":"2.0","id":4,"method":"ping"}));
    assert_eq!(pong["id"], 4);

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

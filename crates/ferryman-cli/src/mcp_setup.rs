//! `ferry mcp setup --client codex|claude-code|claude-desktop|cursor`: put Ferryman into an
//! MCP client's own config file, so adding the server is one command and a restart.
//!
//! The entry is the same for every client: this binary's absolute path, `mcp serve` and
//! `FERRYMAN_ROOT`. It is merged into what is already there; another server's entry, and
//! anything else in the file, stays as it was. A file that cannot be read as what it should
//! be is left alone and named, never overwritten.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

/// The server's name in every client's list.
const NAME: &str = "ferryman";

/// The clients this knows the config file of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Codex,
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
}

impl Client {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "codex" => Ok(Self::Codex),
            "claude-code" => Ok(Self::ClaudeCode),
            "claude-desktop" => Ok(Self::ClaudeDesktop),
            "cursor" => Ok(Self::Cursor),
            other => bail!(
                "'{other}' is not a client this can set up: codex, claude-code, claude-desktop or cursor. For claude.ai, use ferry mcp serve --http"
            ),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::Cursor => "Cursor",
        }
    }

    /// What to do so the client picks the new entry up.
    fn restart(self) -> &'static str {
        match self {
            Self::Codex => "Restart Codex (close the session and start `codex` again).",
            Self::ClaudeCode => "Restart Claude Code (or run /mcp to reconnect).",
            Self::ClaudeDesktop => "Quit Claude Desktop completely and open it again.",
            Self::Cursor => "Restart Cursor (or toggle ferryman in Settings, MCP).",
        }
    }
}

/// The entry to write: how a client starts the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub command: String,
    pub args: Vec<String>,
    pub root: Option<String>,
}

impl Spec {
    /// This binary, by absolute path, and the ferry root it is run from.
    pub fn here() -> Result<Self> {
        let exe = std::env::current_exe().context("find this program's path")?;
        Ok(Self {
            command: exe.display().to_string(),
            args: vec!["mcp".into(), "serve".into()],
            root: ferryman_channel::ferry::find_root().map(|root| root.path.display().to_string()),
        })
    }
}

fn home() -> Result<PathBuf> {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(|key| std::env::var_os(key))
        .map(PathBuf::from)
        .find(|path| path.is_dir())
        .context("cannot find your home folder; pass --config <file>")
}

/// Where `client` keeps its server list.
pub fn config_path(client: Client) -> Result<PathBuf> {
    Ok(match client {
        Client::Codex => match std::env::var_os("CODEX_HOME") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("config.toml"),
            _ => home()?.join(".codex").join("config.toml"),
        },
        Client::ClaudeCode => home()?.join(".claude.json"),
        Client::Cursor => home()?.join(".cursor").join("mcp.json"),
        Client::ClaudeDesktop => {
            if cfg!(windows) {
                let appdata = std::env::var_os("APPDATA")
                    .map(PathBuf::from)
                    .map_or_else(|| home().map(|h| h.join("AppData").join("Roaming")), Ok)?;
                appdata.join("Claude").join("claude_desktop_config.json")
            } else if cfg!(target_os = "macos") {
                home()?
                    .join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json")
            } else {
                home()?
                    .join(".config")
                    .join("Claude")
                    .join("claude_desktop_config.json")
            }
        }
    })
}

fn toml_table(spec: &Spec) -> toml::Table {
    let mut entry = toml::Table::new();
    entry.insert("command".into(), toml::Value::String(spec.command.clone()));
    entry.insert(
        "args".into(),
        toml::Value::Array(spec.args.iter().cloned().map(toml::Value::String).collect()),
    );
    if let Some(root) = &spec.root {
        let mut env = toml::Table::new();
        env.insert("FERRYMAN_ROOT".into(), toml::Value::String(root.clone()));
        entry.insert("env".into(), toml::Value::Table(env));
    }
    entry
}

/// The block Codex reads, as a complete TOML document.
pub fn render_toml(spec: &Spec) -> String {
    let mut servers = toml::Table::new();
    servers.insert(NAME.into(), toml::Value::Table(toml_table(spec)));
    let mut top = toml::Table::new();
    top.insert("mcp_servers".into(), toml::Value::Table(servers));
    toml::to_string(&top).unwrap_or_default()
}

/// `existing` with Ferryman added to `[mcp_servers]`. Text that is not mentioning Ferryman
/// is appended to, not rewritten, so comments and other servers stay byte for byte.
pub fn merge_toml(existing: &str, spec: &Spec) -> Result<String> {
    let parsed: toml::Table = toml::from_str(existing)
        .context("the Codex config is not valid TOML; fix it or move it aside, nothing was changed")?;
    let has = parsed
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .is_some_and(|servers| servers.contains_key(NAME));
    if !has {
        let mut out = existing.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&render_toml(spec));
        return Ok(out);
    }
    // Already listed exactly so: leave the file as it is, comments and all.
    let listed = parsed
        .get("mcp_servers")
        .and_then(|servers| servers.get(NAME))
        .and_then(toml::Value::as_table);
    if listed == Some(&toml_table(spec)) {
        return Ok(existing.to_string());
    }
    // Listed differently: replace its table, keep every other server.
    let mut table = parsed;
    if let Some(servers) = table
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
    {
        servers.insert(NAME.into(), toml::Value::Table(toml_table(spec)));
    }
    Ok(toml::to_string(&table)?)
}

fn json_entry(spec: &Spec, client: Client) -> Value {
    let mut entry = Map::new();
    if client == Client::ClaudeCode {
        entry.insert("type".into(), json!("stdio"));
    }
    entry.insert("command".into(), json!(spec.command));
    entry.insert("args".into(), json!(spec.args));
    if let Some(root) = &spec.root {
        entry.insert("env".into(), json!({ "FERRYMAN_ROOT": root }));
    }
    Value::Object(entry)
}

/// The block a JSON client reads, as a complete document.
pub fn render_json(spec: &Spec, client: Client) -> String {
    serde_json::to_string_pretty(&json!({ "mcpServers": { NAME: json_entry(spec, client) } }))
        .unwrap_or_default()
}

/// `existing` with Ferryman added under `mcpServers`, everything else as it was.
pub fn merge_json(existing: &str, spec: &Spec, client: Client) -> Result<String> {
    let mut doc: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing).with_context(|| {
            format!(
                "the {} config is not valid JSON; fix it or move it aside, nothing was changed",
                client.label()
            )
        })?
    };
    let Some(top) = doc.as_object_mut() else {
        bail!(
            "the {} config is not a JSON object; nothing was changed",
            client.label()
        );
    };
    let servers = top.entry("mcpServers").or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        bail!("mcpServers in the config is not an object; nothing was changed");
    };
    servers.insert(NAME.into(), json_entry(spec, client));
    Ok(serde_json::to_string_pretty(&doc)? + "\n")
}

/// The new file text for `client`, given what is there now.
pub fn merged(client: Client, existing: &str, spec: &Spec) -> Result<String> {
    match client {
        Client::Codex => merge_toml(existing, spec),
        _ => merge_json(existing, spec, client),
    }
}

fn read_existing(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// `ferry mcp setup`: print (`--print`) or write the entry, and say how to restart.
pub fn run(client: &str, print: bool, config: Option<PathBuf>) -> Result<()> {
    let client = Client::parse(client)?;
    let spec = Spec::here()?;
    let path = match config {
        Some(path) => path,
        None => config_path(client)?,
    };
    if print {
        println!("# {} reads this from {}", client.label(), path.display());
        match client {
            Client::Codex => print!("{}", render_toml(&spec)),
            _ => println!("{}", render_json(&spec, client)),
        }
        return Ok(());
    }
    let existing = read_existing(&path)?;
    let text = merged(client, &existing, &spec)?;
    if text == existing {
        println!("{} already has Ferryman: {}", client.label(), path.display());
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        if !existing.is_empty() {
            let backup = path.with_extension("ferryman-backup");
            if !backup.exists() {
                std::fs::write(&backup, &existing)
                    .with_context(|| format!("write {}", backup.display()))?;
            }
        }
        let temporary = path.with_extension("ferryman-new");
        std::fs::write(&temporary, &text)
            .with_context(|| format!("write {}", temporary.display()))?;
        std::fs::rename(&temporary, &path)
            .with_context(|| format!("write {}", path.display()))?;
        println!("added Ferryman to {}", path.display());
    }
    if spec.root.is_none() {
        println!(
            "note: no ferry root was found here, so FERRYMAN_ROOT is not set; run `ferry enable` in a project first, then this again"
        );
    }
    println!("{}", client.restart());
    println!("Then ask it to call ferry_join. Nothing else to set up.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec {
            command: r"C:\tools\ferry.exe".into(),
            args: vec!["mcp".into(), "serve".into()],
            root: Some(r"X:\ferry".into()),
        }
    }

    #[test]
    fn codex_print_is_a_valid_config_toml_block() {
        let text = render_toml(&spec());
        let parsed: toml::Table = toml::from_str(&text).unwrap();
        let entry = &parsed["mcp_servers"]["ferryman"];
        assert_eq!(entry["command"].as_str().unwrap(), r"C:\tools\ferry.exe");
        assert_eq!(entry["args"].as_array().unwrap().len(), 2);
        assert_eq!(entry["env"]["FERRYMAN_ROOT"].as_str().unwrap(), r"X:\ferry");
    }

    #[test]
    fn writing_codex_keeps_every_other_server_and_comment() {
        let before = "# my codex\nmodel = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"npx\"\nargs = [\"-y\", \"thing\"]\n";
        let after = merge_toml(before, &spec()).unwrap();
        assert!(after.starts_with(before), "the existing text is untouched");
        let parsed: toml::Table = toml::from_str(&after).unwrap();
        assert_eq!(parsed["model"].as_str().unwrap(), "gpt-5");
        assert_eq!(parsed["mcp_servers"]["other"]["command"].as_str().unwrap(), "npx");
        assert!(parsed["mcp_servers"]["ferryman"]["command"].is_str());
        // Again: same file, and an out-of-date entry is replaced, not duplicated.
        assert_eq!(merge_toml(&after, &spec()).unwrap(), after);
        let moved = Spec {
            command: "/new/ferry".into(),
            ..spec()
        };
        let updated: toml::Table = toml::from_str(&merge_toml(&after, &moved).unwrap()).unwrap();
        assert_eq!(updated["mcp_servers"]["ferryman"]["command"].as_str().unwrap(), "/new/ferry");
        assert!(updated["mcp_servers"]["other"].is_table());
    }

    #[test]
    fn json_clients_keep_their_other_servers_and_settings() {
        for client in [Client::ClaudeCode, Client::ClaudeDesktop, Client::Cursor] {
            let before = r#"{"theme":"dark","mcpServers":{"github":{"command":"gh-mcp"}}}"#;
            let after: Value = serde_json::from_str(&merge_json(before, &spec(), client).unwrap()).unwrap();
            assert_eq!(after["theme"], "dark");
            assert_eq!(after["mcpServers"]["github"]["command"], "gh-mcp");
            assert_eq!(after["mcpServers"]["ferryman"]["args"], json!(["mcp", "serve"]));
            assert_eq!(after["mcpServers"]["ferryman"]["env"]["FERRYMAN_ROOT"], r"X:\ferry");
            // From nothing at all.
            let fresh: Value = serde_json::from_str(&merge_json("", &spec(), client).unwrap()).unwrap();
            assert!(fresh["mcpServers"]["ferryman"].is_object());
        }
    }

    #[test]
    fn a_file_that_is_not_what_it_should_be_is_refused_not_overwritten() {
        assert!(merge_toml("[mcp_servers\nbroken", &spec()).is_err());
        assert!(merge_json("{not json", &spec(), Client::Cursor).is_err());
        assert!(merge_json("[1,2]", &spec(), Client::Cursor).is_err());
        assert!(merge_json(r#"{"mcpServers":[]}"#, &spec(), Client::Cursor).is_err());
        assert!(Client::parse("emacs").is_err());
    }

    #[test]
    fn run_writes_the_file_once_and_backs_up_what_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("mcp.json");
        run("cursor", false, Some(path.clone())).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("ferryman"));
        run("cursor", false, Some(path.clone())).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        let other = dir.path().join("codex.toml");
        std::fs::write(&other, "[mcp_servers.keep]\ncommand = \"x\"\n").unwrap();
        run("codex", false, Some(other.clone())).unwrap();
        let text = std::fs::read_to_string(&other).unwrap();
        assert!(text.contains("keep") && text.contains("ferryman"));
        assert!(other.with_extension("ferryman-backup").is_file());
    }
}

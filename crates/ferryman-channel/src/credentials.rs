//! Operator-local credentials, injected into the sandboxed agent CLI so secrets
//! reach the agent without being baked into images or prompts.
//!
//! The agent CLI is scrubbed of every secret-looking environment variable by
//! default; these are the *only* ones put back, and only because the operator
//! explicitly listed them in `credentials.json`.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

/// Read `credentials.json` — a flat `{"ENV_VAR": "secret"}` map — from the
/// attachment. A missing file means no credentials (the agent runs scrubbed).
pub fn load_credentials(attachment: &Path) -> Result<HashMap<String, String>> {
    let path = attachment.join("credentials.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

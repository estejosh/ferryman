//! Append-only, signed attribution ledger.
//!
//! Every order, claim, result, review, and demand that matters is recorded here
//! with the actor's name and key, hash-chained to the previous record. The file
//! is writeable (anyone appends) but never deletable in a way that goes
//! unnoticed: editing or removing any record breaks the chain.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature};

/// One signed, hash-chained record of something that happened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEntry {
    /// What kind of event: `order`, `claim`, `result`, `review`, `demand`, ...
    pub kind: String,
    /// Who did it, human-readable (an agent or operator name).
    pub actor: String,
    /// Human-readable account of what happened.
    pub summary: String,
    /// Optional referenced id (order id, message id, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Hex SHA-256 of the previous entry's exact line; empty for the first entry.
    pub prev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The whole ledger, read back with its integrity checked.
#[derive(Debug, Clone)]
pub struct LedgerLog {
    pub entries: Vec<LedgerEntry>,
    /// True when every entry parses, chains, and verifies.
    pub intact: bool,
    /// The index of the first entry that failed to parse, chain, or verify.
    pub broken_at: Option<usize>,
}

fn ledger_path(route: &ProjectRoute) -> PathBuf {
    route.communications.join("ledger.jsonl")
}

/// Exactly what a ledger signature covers, and nothing else.
fn ledger_payload(entry: &LedgerEntry) -> String {
    format!(
        "ferryman-ledger-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        entry.kind,
        entry.actor,
        entry.summary,
        entry.reference.as_deref().unwrap_or(""),
        entry.created_at.to_rfc3339(),
        entry.prev,
    )
}

fn acquire_ledger_lock(route: &ProjectRoute) -> Result<fs::File> {
    let path = route.attachment.join("runtime/locks/ledger.lock");
    fs::create_dir_all(path.parent().context("ledger lock path has no parent")?)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    file.lock_exclusive()
        .with_context(|| format!("project ledger lock is held: {}", path.display()))?;
    Ok(file)
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Append a signed entry to the channel ledger.
///
/// The entry is signed by `identity` and hash-chained to the previous line, so
/// removing or altering any earlier entry breaks the chain and is detectable.
/// Appending is the only operation; the ledger is writeable but not deletable
/// without leaving a visible gap.
pub fn append_ledger_entry(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    kind: &str,
    actor: &str,
    summary: &str,
    reference: Option<&str>,
) -> Result<LedgerEntry> {
    if !crate::is_safe_component(actor) {
        bail!("ledger actor must be a path-safe identifier");
    }
    let path = ledger_path(route);
    let _lock = acquire_ledger_lock(route)?;
    let lines = read_lines(&path)?;
    let prev = lines
        .last()
        .map(|line| hex::encode(Sha256::digest(line.as_bytes())))
        .unwrap_or_default();

    let mut entry = LedgerEntry {
        kind: kind.to_owned(),
        actor: actor.to_owned(),
        summary: summary.to_owned(),
        reference: reference.map(str::to_owned),
        created_at: Utc::now(),
        prev,
        signed_by: None,
        signature: None,
    };
    let signature = identity.signing.sign(ledger_payload(&entry).as_bytes());
    entry.signed_by = Some(identity.name().to_owned());
    entry.signature = Some(hex::encode(signature.to_bytes()));

    let line = serde_json::to_string(&entry)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{line}")?;
    drop(file);
    // Backstop the ledger (and any task files written just before it) in the
    // private-Git recovery repo, so a Syncthing deletion is recoverable. Best
    // effort: a git outage must never block the recorded event itself.
    let _ = crate::snapshot_channel_to_git(route);
    Ok(entry)
}

/// Read the ledger and report whether its chain and signatures are intact.
pub fn read_ledger(route: &ProjectRoute) -> Result<LedgerLog> {
    let lines = read_lines(&ledger_path(route))?;
    let mut entries = Vec::new();
    let mut intact = true;
    let mut broken_at = None;
    let mut previous_line: Option<&str> = None;

    for (index, line) in lines.iter().enumerate() {
        let entry: LedgerEntry = match serde_json::from_str(line) {
            Ok(entry) => entry,
            Err(_) => {
                intact = false;
                broken_at.get_or_insert(index);
                break;
            }
        };
        let expected_prev = previous_line
            .map(|previous| hex::encode(Sha256::digest(previous.as_bytes())))
            .unwrap_or_default();
        if entry.prev != expected_prev {
            intact = false;
            broken_at.get_or_insert(index);
        }
        if check_signature(
            entry.signed_by.as_ref(),
            entry.signature.as_ref(),
            &ledger_payload(&entry),
            &route.agents,
        ) != SignatureCheck::Valid
        {
            intact = false;
            broken_at.get_or_insert(index);
        }
        entries.push(entry);
        previous_line = Some(line);
    }

    Ok(LedgerLog {
        entries,
        intact,
        broken_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    fn test_route(dir: &Path) -> ProjectRoute {
        let workspace = dir.join("project");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment,
            communications,
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    fn route_with_alice(dir: &Path) -> (ProjectRoute, AgentIdentity) {
        let mut route = test_route(dir);
        fs::create_dir_all(&route.attachment).unwrap();
        let identity = AgentIdentity::load_or_create_in("alice", &route.attachment, None).unwrap();
        route.agents = vec![AgentRoute {
            name: "alice".into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(identity.public_key_hex()),
        }];
        (route, identity)
    }

    #[test]
    fn entries_append_chain_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (route, identity) = route_with_alice(dir.path());

        append_ledger_entry(
            &route,
            &identity,
            "order",
            "alice",
            "issued order t-1",
            Some("t-1"),
        )
        .unwrap();
        append_ledger_entry(
            &route,
            &identity,
            "claim",
            "alice",
            "claimed order t-1",
            Some("t-1"),
        )
        .unwrap();

        let log = read_ledger(&route).unwrap();
        assert!(log.intact);
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].prev, "");
        // The second entry chains to the first line's exact bytes.
        let first_line = serde_json::to_string(&log.entries[0]).unwrap();
        assert_eq!(
            log.entries[1].prev,
            hex::encode(Sha256::digest(first_line.as_bytes()))
        );
    }

    #[test]
    fn a_tampered_entry_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (route, identity) = route_with_alice(dir.path());

        append_ledger_entry(
            &route,
            &identity,
            "order",
            "alice",
            "issued order t-1",
            Some("t-1"),
        )
        .unwrap();
        append_ledger_entry(
            &route,
            &identity,
            "claim",
            "alice",
            "claimed order t-1",
            Some("t-1"),
        )
        .unwrap();

        let path = route.communications.join("ledger.jsonl");
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines[0] = lines[0].replace("issued order t-1", "issued order t-9");
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let log = read_ledger(&route).unwrap();
        assert!(!log.intact);
        assert_eq!(log.broken_at, Some(0));
    }

    #[test]
    fn an_entry_by_an_unknown_signer_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let route = test_route(dir.path());
        fs::create_dir_all(&route.attachment).unwrap();
        let identity = AgentIdentity::load_or_create_in("alice", &route.attachment, None).unwrap();
        // The roster is empty, so alice is not a known signer.

        append_ledger_entry(
            &route,
            &identity,
            "order",
            "alice",
            "issued order t-1",
            Some("t-1"),
        )
        .unwrap();

        let log = read_ledger(&route).unwrap();
        assert!(!log.intact);
        assert_eq!(log.broken_at, Some(0));
    }
}

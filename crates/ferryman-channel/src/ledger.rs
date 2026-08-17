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

/// One agent's ledger file. **One writer per path**, like every other channel artifact.
///
/// # Why this is per-agent and not one file
///
/// It was one `ledger.jsonl` in the synced directory, appended by every machine. The lock
/// guarding it is at `attachment/runtime/locks/`, which is machine-local and invisible to the
/// fleet - it serialises this machine's own writers and nothing else.
///
/// So two machines recording in one sync window is not an attack, it is ordinary use, and the
/// result was: Syncthing renames one copy to `ledger.sync-conflict-…`, those attribution
/// records leave the ledger entirely, and - because both machines computed `prev` from the
/// same last line - the chain no longer lines up. `read_ledger` then reports
/// `intact = false` **permanently**, with no repair possible because the file is append-only.
///
/// A tamper-evident audit log that reports tampering within hours of normal two-machine use is
/// worse than no audit log, because it trains the operator to ignore the one signal it exists
/// to give.
///
/// Every other artifact in this crate already carries its writer's name -
/// `claim.{agent}.json`, `result.{agent}.{rev}.json`, `interrupt.{issued_by}.json`. The ledger
/// was the exception.
///
/// # The chain is per-file, and that is the right granularity
///
/// Each agent chains only to its own previous line, so each file is independently verifiable
/// and no machine's chain depends on another machine's sync timing. A global order across
/// machines was never real anyway: it was an artifact of whoever's write landed first.
/// Reading merges the files by timestamp, exactly as `read_agent_roster` merges rosters.
fn ledger_path(route: &ProjectRoute, signer: &str) -> PathBuf {
    route.communications.join(format!("ledger.{signer}.jsonl"))
}

/// The single-file ledger this project may still carry from before per-agent files.
///
/// Read, never written. Its history is real and stays visible; new entries go to the writer's
/// own file. Nothing needs migrating, which is the point of reading it rather than moving it.
fn legacy_ledger_path(route: &ProjectRoute) -> PathBuf {
    route.communications.join("ledger.jsonl")
}

/// Every ledger file in the channel, oldest-named first, plus the legacy file if present.
fn ledger_files(route: &ProjectRoute) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let legacy = legacy_ledger_path(route);
    if legacy.is_file() {
        files.push(legacy);
    }
    if let Ok(entries) = fs::read_dir(&route.communications) {
        let mut per_agent: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    return false;
                };
                // `ledger.<agent>.jsonl`, and not a Syncthing conflict copy of one - those
                // are duplicates of records already counted, and reading them would report
                // a broken chain for a file that is merely a copy.
                name.starts_with("ledger.")
                    && name.ends_with(".jsonl")
                    && !name.contains(".sync-conflict-")
            })
            .collect();
        per_agent.sort();
        files.extend(per_agent);
    }
    files
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
    // Keyed by the SIGNER, not the actor. The signer is the identity whose key writes the
    // line, so keying by it is what makes this one-writer-per-path; `actor` is a separate
    // field precisely because it can name someone else (an operator's decision recorded by a
    // worker, for instance).
    let signer = identity.name();
    if !crate::is_safe_component(signer) {
        bail!("ledger signer must be a path-safe identifier");
    }
    let path = ledger_path(route, signer);
    // Now a correct lock rather than a decorative one: this file has exactly one writing
    // machine, so a machine-local lock is the whole of the contention.
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

/// Read every agent's ledger and report whether the chains and signatures are intact.
///
/// Each file is verified as its own chain, then all entries are merged by time. One machine's
/// broken chain does not make another machine's records unverifiable, which is the property the
/// single shared file could not have: there, one sync conflict broke the chain for everybody,
/// forever.
pub fn read_ledger(route: &ProjectRoute) -> Result<LedgerLog> {
    let mut entries: Vec<LedgerEntry> = Vec::new();
    let mut intact = true;
    let mut broken_at = None;

    for path in ledger_files(route) {
        let lines = read_lines(&path)?;
        let mut previous_line: Option<&str> = None;
        for line in &lines {
            // The index reported is into the MERGED list, so it points at the entry an
            // operator will actually see when they print the ledger.
            let index = entries.len();
            let entry: LedgerEntry = match serde_json::from_str(line) {
                Ok(entry) => entry,
                Err(_) => {
                    intact = false;
                    broken_at.get_or_insert(index);
                    // Stop reading THIS file - the rest of its chain is unanchored - but keep
                    // reading the others. One machine writing a bad line must not erase every
                    // other machine's history from the report.
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
    }

    // Merged by time, stably, so entries recorded in the same instant keep the order their
    // own file had. Sorting is what replaces the old global chain: an ordering across machines
    // was never truly established by it either - it recorded whichever write landed first.
    entries.sort_by_key(|entry| entry.created_at);

    Ok(LedgerLog {
        entries,
        intact,
        broken_at,
    })
}

/// One entry of an exported audit report, with its verification status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportedEntry {
    pub kind: String,
    pub actor: String,
    pub summary: String,
    pub reference: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Whether this entry's signature verified against the roster.
    pub signature_ok: bool,
}

/// A signed, standalone export of the attribution ledger, for a third party to
/// verify without running Ferryman: it carries the whole history plus a
/// signature over it, so "who did what and when" is provable off-channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub project_id: String,
    pub generated_at: DateTime<Utc>,
    /// Who exported it.
    pub generated_by: String,
    /// Whether the ledger's hash chain and signatures verified at export time.
    pub ledger_intact: bool,
    pub broken_at: Option<usize>,
    pub entries: Vec<ReportedEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn audit_report_payload(report: &AuditReport) -> String {
    let entries_digest = hex::encode(Sha256::digest(
        serde_json::to_string(&report.entries)
            .unwrap_or_default()
            .as_bytes(),
    ));
    format!(
        "ferryman-audit-report-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        report.project_id,
        report.generated_at.to_rfc3339(),
        report.generated_by,
        report.ledger_intact,
        report.broken_at.map(|i| i.to_string()).unwrap_or_default(),
        entries_digest,
    )
}

/// Build a signed audit report of the ledger, each entry carrying its own
/// verification status and the whole report signed by `identity`.
pub fn build_report(route: &ProjectRoute, identity: &AgentIdentity) -> Result<AuditReport> {
    let log = read_ledger(route)?;
    let mut entries = Vec::with_capacity(log.entries.len());
    for entry in &log.entries {
        let signature_ok = check_signature(
            entry.signed_by.as_ref(),
            entry.signature.as_ref(),
            &ledger_payload(entry),
            &route.agents,
        ) == SignatureCheck::Valid;
        entries.push(ReportedEntry {
            kind: entry.kind.clone(),
            actor: entry.actor.clone(),
            summary: entry.summary.clone(),
            reference: entry.reference.clone(),
            created_at: entry.created_at,
            signature_ok,
        });
    }

    let mut report = AuditReport {
        project_id: route.project_id.clone(),
        generated_at: Utc::now(),
        generated_by: identity.name().to_owned(),
        ledger_intact: log.intact,
        broken_at: log.broken_at,
        entries,
        signed_by: None,
        signature: None,
    };
    let signature = identity
        .signing
        .sign(audit_report_payload(&report).as_bytes());
    report.signed_by = Some(identity.name().to_owned());
    report.signature = Some(hex::encode(signature.to_bytes()));
    Ok(report)
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

    /// Two machines recording in the same window must both keep their records.
    ///
    /// This is the case the single shared file could not survive, and it needs no attacker:
    /// both machines computed `prev` from the same last line, Syncthing conflict-renamed one
    /// copy, and the chain never lined up again - `intact = false` permanently, unrepairable
    /// because the file is append-only. A tamper-evident log that cries tamper on Tuesday
    /// teaches its operator to ignore it.
    #[test]
    fn two_machines_recording_at_once_keep_both_histories_intact() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let alice = AgentIdentity::from_seed("alice", [1u8; 32]);
        let bob = AgentIdentity::from_seed("bob", [2u8; 32]);
        route.agents = vec![
            crate::AgentRoute {
                name: "alice".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(alice.public_key_hex()),
            },
            crate::AgentRoute {
                name: "bob".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(bob.public_key_hex()),
            },
        ];

        // Interleaved, as two machines syncing a folder actually are.
        append_ledger_entry(&route, &alice, "order", "alice", "issued t-1", Some("t-1")).unwrap();
        append_ledger_entry(&route, &bob, "claim", "bob", "claimed t-1", Some("t-1")).unwrap();
        append_ledger_entry(&route, &alice, "order", "alice", "issued t-2", Some("t-2")).unwrap();
        append_ledger_entry(&route, &bob, "result", "bob", "submitted t-1", Some("t-1")).unwrap();

        // Separate files, one writer each - which is what makes the above safe.
        assert!(route.communications.join("ledger.alice.jsonl").is_file());
        assert!(route.communications.join("ledger.bob.jsonl").is_file());

        let log = read_ledger(&route).unwrap();
        assert!(
            log.intact,
            "two machines recording concurrently is ordinary use, not tampering: {:?}",
            log.broken_at
        );
        assert_eq!(log.entries.len(), 4, "nobody's records may go missing");
        // Merged by time, so the operator reads one history rather than two.
        let summaries: Vec<&str> = log.entries.iter().map(|e| e.summary.as_str()).collect();
        assert_eq!(
            summaries,
            vec!["issued t-1", "claimed t-1", "issued t-2", "submitted t-1"]
        );
    }

    /// One machine writing a bad line must not erase everyone else's history from the report.
    #[test]
    fn one_broken_file_does_not_invalidate_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = test_route(dir.path());
        let alice = AgentIdentity::from_seed("alice", [1u8; 32]);
        let bob = AgentIdentity::from_seed("bob", [2u8; 32]);
        route.agents = vec![
            crate::AgentRoute {
                name: "alice".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(alice.public_key_hex()),
            },
            crate::AgentRoute {
                name: "bob".into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(bob.public_key_hex()),
            },
        ];
        append_ledger_entry(&route, &alice, "order", "alice", "issued t-1", Some("t-1")).unwrap();
        append_ledger_entry(&route, &bob, "claim", "bob", "claimed t-1", Some("t-1")).unwrap();

        // Corrupt only bob's file.
        fs::write(
            route.communications.join("ledger.bob.jsonl"),
            "this is not json\n",
        )
        .unwrap();

        let log = read_ledger(&route).unwrap();
        assert!(!log.intact, "the corruption must still be reported");
        // Alice's record survives into the report, which the shared-file version could not do.
        assert!(
            log.entries.iter().any(|e| e.summary == "issued t-1"),
            "another machine's history must not vanish because bob's file broke"
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

        // The agent's OWN file, which is where appends go now.
        let path = route.communications.join("ledger.alice.jsonl");
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

    #[test]
    fn an_audit_report_is_signed_and_carries_per_entry_status() {
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

        let report = build_report(&route, &identity).unwrap();
        assert!(report.ledger_intact);
        assert_eq!(report.entries.len(), 2);
        assert!(report.entries.iter().all(|e| e.signature_ok));
        assert_eq!(report.signed_by.as_deref(), Some("alice"));
        assert!(report.signature.is_some());
    }
}

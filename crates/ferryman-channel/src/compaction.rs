//! Channel compaction: old, acknowledged messages move into one archive file per month
//! per thread, and the channel stops carrying them as thousands of small files.
//!
//! What is promised, and how:
//!
//! - **Nothing is lost.** The archive keeps each message's (and its acknowledgement's)
//!   original file text, byte for byte, with its SHA-256. Signatures cover the fields in
//!   the file, so they verify exactly as they did, and every reader checks the digest
//!   before it trusts a line.
//! - **Nothing is deleted without a signed record first.** A pass writes the archive
//!   lines, then a record under `archive/records/` signed by the compactor naming every
//!   id and digest. Originals are removed only by a pass that finds a record whose grace
//!   has run out, re-reads the archive, and finds each entry there and intact. A file
//!   that changed since it was archived is left alone.
//! - **One writer.** Only the channel's head agent compacts, or its master when it has
//!   none. Anyone else is refused. Should two machines run as that same agent anyway, the
//!   archive is merged as a union and written by rename, and a second pass over what the
//!   first did finds nothing to do - so the worst case is repeated work, not a lost line.
//! - **Readers still find them.** [`find`], [`archived_v1`], [`archived_v2`] and the
//!   fallbacks in `read_message`, `is_acknowledged` and `find_message_by_idempotency_key`
//!   read the archive when the live folder no longer has the file.
//!
//! The age is the master's: `files.archive_after_days` in the signed engine policy (30
//! when unset). Only messages in the channel's own `messages/<project>/` folder with an
//! acknowledgement are compacted; a worker's hand-in folder is left as it is. There is no
//! separate "read" marker in a channel, so acknowledged is the one signal used.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AgentIdentity, Message, MessageV2, ProjectRoute, SignatureCheck, canonical_agent_name,
};

/// Days after which an acknowledged message is archived, when the master set none.
pub const DEFAULT_ARCHIVE_AFTER_DAYS: u32 = 30;

const FORMAT: &str = "ferryman-compaction/v1";

/// One archived message, with its acknowledgement, as stored on a line of a monthly file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Archived {
    pub id: String,
    pub thread: String,
    /// `YYYY-MM` of the message's `created_at`, UTC.
    pub month: String,
    pub created_at: DateTime<Utc>,
    /// SHA-256 of `raw`, hex.
    pub sha256: String,
    /// The message file exactly as it was.
    pub raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_sha256: Option<String>,
    /// The acknowledgement file exactly as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_raw: Option<String>,
}

impl Archived {
    /// Whether the text still hashes to what was recorded for it.
    #[must_use]
    pub fn intact(&self) -> bool {
        digest(self.raw.as_bytes()) == self.sha256
            && match (&self.ack_raw, &self.ack_sha256) {
                (Some(raw), Some(sha)) => digest(raw.as_bytes()) == *sha,
                (None, None) => true,
                _ => false,
            }
    }

    /// Whether the acknowledgement was archived with the message.
    #[must_use]
    pub fn acknowledged(&self) -> bool {
        self.ack_raw.is_some()
    }
}

/// What a compactor signed before anything was removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub format: String,
    pub project_id: String,
    pub compactor: String,
    pub created_at: DateTime<Utc>,
    /// Messages created before this were eligible.
    pub cutoff: DateTime<Utc>,
    pub entries: Vec<RecordEntry>,
    pub signed_by: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEntry {
    pub id: String,
    pub month: String,
    pub thread: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_sha256: Option<String>,
}

fn record_payload(record: &Record) -> String {
    let entries = serde_jcs::to_string(&record.entries).unwrap_or_default();
    format!(
        "{FORMAT}\n{}\n{}\n{}\n{}\n{}",
        record.project_id,
        record.compactor,
        record.created_at.to_rfc3339(),
        record.cutoff.to_rfc3339(),
        digest(entries.as_bytes()),
    )
}

/// What a pass did, or with `dry_run` would do.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub cutoff: Option<DateTime<Utc>>,
    /// Ids newly written to the archive.
    pub archived: Vec<String>,
    /// Ids whose originals were removed.
    pub removed: Vec<String>,
    /// Ids left alone, and why.
    pub kept: Vec<(String, String)>,
    /// The signed record this pass wrote.
    pub record: Option<PathBuf>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The folder a channel keeps its archive in.
#[must_use]
pub fn archive_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("archive")
}

/// Days an acknowledged message stays live, from the master's signed policy.
#[must_use]
pub fn archive_after_days(route: &ProjectRoute) -> u32 {
    let (policy, _) = crate::policy::effective(&route.communications, &route.project_id);
    policy
        .files
        .archive_after_days
        .unwrap_or(DEFAULT_ARCHIVE_AFTER_DAYS)
}

/// Who compacts this channel: its head agent, or its master when it has none.
pub fn compactor(route: &ProjectRoute) -> Result<Option<String>> {
    if let Some(head) = crate::head::current(&route.communications, &route.project_id)? {
        return Ok(Some(head.agent));
    }
    Ok(crate::master::read_master(route)?.map(|master| master.master))
}

/// The thread two names share: the same whichever way a message went.
#[must_use]
pub fn thread_of(sender: &str, recipient: &str) -> String {
    let clean = |name: &str| -> String {
        canonical_agent_name(name)
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let (a, b) = (clean(sender), clean(recipient));
    if a <= b {
        format!("{a}--{b}")
    } else {
        format!("{b}--{a}")
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn archive_file(route: &ProjectRoute, month: &str, thread: &str) -> PathBuf {
    archive_dir(route)
        .join(month)
        .join(format!("{thread}.jsonl"))
}

/// Every line of one archive file, or `None` when any line does not parse and verify -
/// an archive that is not whole is never rewritten.
fn read_archive_file(path: &Path) -> Option<Vec<Archived>> {
    let text = fs::read_to_string(path).ok()?;
    let mut entries = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let entry: Archived = serde_json::from_str(line).ok()?;
        if !entry.intact() {
            return None;
        }
        entries.push(entry);
    }
    Some(entries)
}

fn archive_files(route: &ProjectRoute) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(months) = fs::read_dir(archive_dir(route)) else {
        return files;
    };
    for month in months.flatten() {
        let path = month.path();
        if !path.is_dir() || path.file_name().is_some_and(|n| n == "records") {
            continue;
        }
        if let Ok(inside) = fs::read_dir(&path) {
            files.extend(
                inside
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "jsonl")),
            );
        }
    }
    files.sort();
    files
}

/// Every archived message whose line is intact, oldest first. A line that fails its digest
/// is skipped, never trusted.
#[must_use]
pub fn archived_messages(route: &ProjectRoute) -> Vec<Archived> {
    let mut all = Vec::new();
    for path in archive_files(route) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            if let Ok(entry) = serde_json::from_str::<Archived>(line)
                && entry.intact()
            {
                all.push(entry);
            }
        }
    }
    all.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    all.dedup_by(|a, b| a.id == b.id);
    all
}

/// One archived message by id.
#[must_use]
pub fn find(route: &ProjectRoute, message_id: &str) -> Option<Archived> {
    if !archive_dir(route).is_dir() || uuid::Uuid::parse_str(message_id).is_err() {
        return None;
    }
    archived_messages(route)
        .into_iter()
        .find(|entry| entry.id == message_id)
}

/// The archived v1 messages, parsed and checked the way a live one is.
#[must_use]
pub fn archived_v1(route: &ProjectRoute) -> Vec<Message> {
    archived_messages(route)
        .iter()
        .filter_map(|entry| serde_json::from_str::<Message>(&entry.raw).ok())
        .filter(|message| message.validate().is_ok() && message.project_id == route.project_id)
        .collect()
}

/// The archived v2 messages, parsed and verified the way a live one is.
#[must_use]
pub fn archived_v2(route: &ProjectRoute) -> Vec<MessageV2> {
    archived_messages(route)
        .iter()
        .filter_map(|entry| serde_json::from_str::<MessageV2>(&entry.raw).ok())
        .filter(|message| {
            message.project_id == route.project_id
                && crate::verify_v2_message(route, message).is_ok()
        })
        .collect()
}

fn candidates(route: &ProjectRoute, cutoff: DateTime<Utc>, report: &mut Report) -> Vec<Archived> {
    let live = route
        .communications
        .join("messages")
        .join(&route.project_id);
    let Ok(entries) = fs::read_dir(&live) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let mut found = Vec::new();
    for path in paths {
        let Some(id) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
            continue;
        };
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let text = |key: &str| value.get(key).and_then(Value::as_str);
        let (Some(file_id), Some(project), Some(sender), Some(recipient), Some(created)) = (
            text("id"),
            text("project_id"),
            text("sender"),
            text("recipient"),
            text("created_at").and_then(|c| c.parse::<DateTime<Utc>>().ok()),
        ) else {
            continue;
        };
        if file_id != id || project != route.project_id || created >= cutoff {
            continue;
        }
        let ack_path = route
            .communications
            .join("acknowledgements")
            .join(&route.project_id)
            .join(format!("{id}.json"));
        let Ok(ack_raw) = fs::read_to_string(&ack_path) else {
            continue; // not acknowledged: it is still live work
        };
        let ack_matches = serde_json::from_str::<Value>(&ack_raw)
            .ok()
            .and_then(|ack| {
                ack.get("message_id")
                    .and_then(Value::as_str)
                    .map(|m| m == id)
            })
            .unwrap_or(false);
        if !ack_matches {
            report
                .kept
                .push((id, "its acknowledgement file names another message".into()));
            continue;
        }
        found.push(Archived {
            thread: thread_of(sender, recipient),
            month: created.format("%Y-%m").to_string(),
            created_at: created,
            sha256: digest(raw.as_bytes()),
            ack_sha256: Some(digest(ack_raw.as_bytes())),
            ack_raw: Some(ack_raw),
            raw,
            id,
        });
    }
    found
}

/// The records on disk whose signature holds and whose signer had the right to compact.
fn valid_records(route: &ProjectRoute) -> Vec<Record> {
    let dir = archive_dir(route).join("records");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let master = crate::master::read_master(route).ok().flatten();
    let mut records = Vec::new();
    for path in entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
    {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<Record>(&bytes) else {
            continue;
        };
        let signed = crate::check_signature(
            Some(&record.signed_by),
            Some(&record.signature),
            &record_payload(&record),
            &route.agents,
        ) == SignatureCheck::Valid;
        let may = master
            .as_ref()
            .is_some_and(|m| m.master.eq_ignore_ascii_case(&record.compactor))
            || crate::head::held_at(
                &route.communications,
                &route.project_id,
                &record.compactor,
                record.created_at,
            );
        if record.format == FORMAT
            && record.project_id == route.project_id
            && record.signed_by.eq_ignore_ascii_case(&record.compactor)
            && signed
            && may
        {
            records.push(record);
        }
    }
    records.sort_by_key(|r| r.created_at);
    records
}

/// Run one compaction pass as `identity`, which must be the channel's compactor.
///
/// Archives what has aged out, signs a record of it, and removes originals whose record is
/// at least `grace` old and whose archive lines verify. With `dry_run` nothing is written
/// or removed and the report says what would be.
pub fn compact(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    now: DateTime<Utc>,
    grace: Duration,
    dry_run: bool,
) -> Result<Report> {
    route.validate()?;
    match compactor(route)? {
        Some(who) if who.eq_ignore_ascii_case(identity.name()) => {}
        Some(who) => bail!(
            "only {who} compacts {}'s channel (its head agent, or its master when it has none), not {}",
            route.project_id,
            identity.name()
        ),
        None => bail!(
            "{} has no master, so nobody compacts its channel",
            route.project_id
        ),
    }
    let cutoff = now - Duration::days(i64::from(archive_after_days(route)));
    let mut report = Report {
        cutoff: Some(cutoff),
        ..Report::default()
    };

    // 1. Archive what has aged out.
    let covered: BTreeSet<(String, String)> = valid_records(route)
        .into_iter()
        .flat_map(|r| r.entries)
        .map(|e| (e.id, e.sha256))
        .collect();
    let mut groups: BTreeMap<(String, String), Vec<Archived>> = BTreeMap::new();
    for entry in candidates(route, cutoff, &mut report) {
        groups
            .entry((entry.month.clone(), entry.thread.clone()))
            .or_default()
            .push(entry);
    }
    let mut newly: Vec<RecordEntry> = Vec::new();
    for ((month, thread), group) in groups {
        let path = archive_file(route, &month, &thread);
        let mut existing = if path.is_file() {
            if let Some(entries) = read_archive_file(&path) {
                entries
            } else {
                for entry in group {
                    report.kept.push((
                        entry.id,
                        format!(
                            "{} has a line that does not verify, so it was left alone",
                            path.display()
                        ),
                    ));
                }
                continue;
            }
        } else {
            Vec::new()
        };
        let mut added = false;
        for entry in group {
            match existing.iter().find(|have| have.id == entry.id) {
                Some(have)
                    if have.sha256 == entry.sha256 && have.ack_sha256 == entry.ack_sha256 => {}
                Some(_) => {
                    report.kept.push((
                        entry.id,
                        "the archive holds a different message under this id".into(),
                    ));
                    continue;
                }
                None => {
                    added = true;
                    report.archived.push(entry.id.clone());
                    existing.push(entry.clone());
                }
            }
            if !covered.contains(&(entry.id.clone(), entry.sha256.clone())) {
                newly.push(RecordEntry {
                    id: entry.id,
                    month: entry.month,
                    thread: entry.thread,
                    sha256: entry.sha256,
                    ack_sha256: entry.ack_sha256,
                });
            }
        }
        if added && !dry_run {
            existing.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
            let mut text = String::new();
            for entry in &existing {
                text.push_str(&serde_json::to_string(entry)?);
                text.push('\n');
            }
            atomic_write(&path, text.as_bytes())?;
        }
    }

    // 2. Sign the record before anything is removed.
    if !newly.is_empty() && !dry_run {
        let mut record = Record {
            format: FORMAT.into(),
            project_id: route.project_id.clone(),
            compactor: identity.name().to_owned(),
            created_at: now,
            cutoff,
            entries: newly,
            signed_by: identity.name().to_owned(),
            signature: String::new(),
        };
        record.signature = identity.sign_bytes(record_payload(&record).as_bytes());
        let path = archive_dir(route).join("records").join(format!(
            "{}-{}.json",
            now.format("%Y%m%dT%H%M%S"),
            canonical_agent_name(identity.name())
        ));
        atomic_write(&path, &serde_json::to_vec_pretty(&record)?)?;
        report.record = Some(path);
    }

    // 3. Remove originals a record covers, once its grace has run out and the archive
    //    is seen to hold them.
    sweep(route, now, grace, dry_run, &mut report);
    Ok(report)
}

fn sweep(
    route: &ProjectRoute,
    now: DateTime<Utc>,
    grace: Duration,
    dry_run: bool,
    report: &mut Report,
) {
    let live = route
        .communications
        .join("messages")
        .join(&route.project_id);
    let acks = route
        .communications
        .join("acknowledgements")
        .join(&route.project_id);
    let mut files: BTreeMap<PathBuf, Vec<Archived>> = BTreeMap::new();
    for record in valid_records(route) {
        if record.created_at + grace > now {
            continue;
        }
        for entry in record.entries {
            let message_path = live.join(format!("{}.json", entry.id));
            if !message_path.is_file() {
                continue;
            }
            let path = archive_file(route, &entry.month, &entry.thread);
            let archive = files
                .entry(path.clone())
                .or_insert_with(|| read_archive_file(&path).unwrap_or_default());
            let held = archive.iter().any(|have| {
                have.id == entry.id
                    && have.sha256 == entry.sha256
                    && have.ack_sha256 == entry.ack_sha256
            });
            if !held {
                report.kept.push((
                    entry.id,
                    "the archive does not hold it intact, so the original stays".into(),
                ));
                continue;
            }
            let unchanged = fs::read(&message_path).is_ok_and(|b| digest(&b) == entry.sha256);
            let ack_path = acks.join(format!("{}.json", entry.id));
            let ack_unchanged = match (&entry.ack_sha256, ack_path.is_file()) {
                (Some(sha), true) => fs::read(&ack_path).is_ok_and(|b| digest(&b) == *sha),
                (_, false) => true,
                (None, true) => false,
            };
            if !unchanged || !ack_unchanged {
                report
                    .kept
                    .push((entry.id, "changed since it was archived".into()));
                continue;
            }
            if !dry_run
                && (fs::remove_file(&message_path).is_err()
                    || (ack_path.is_file() && fs::remove_file(&ack_path).is_err()))
            {
                report.kept.push((entry.id, "could not be removed".into()));
                continue;
            }
            report.removed.push(entry.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Acknowledgement, AgentRoute, record_acknowledgement};

    struct Rig {
        _dir: tempfile::TempDir,
        route: ProjectRoute,
        josh: AgentIdentity,
        grouchly: AgentIdentity,
        beastly: AgentIdentity,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
        let grouchly = AgentIdentity::from_seed("grouchly", [8u8; 32]);
        let beastly = AgentIdentity::from_seed("beastly", [9u8; 32]);
        let mut route = ProjectRoute {
            project_id: "proj".into(),
            workspace: dir.path().join("proj"),
            attachment: dir.path().join("proj").join(".ferryman"),
            communications: dir.path().join("proj").join(".ferryman").join("ferryman"),
            shared_remote: "proj-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        fs::create_dir_all(&route.communications).unwrap();
        for member in [&josh, &grouchly, &beastly] {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        Rig {
            _dir: dir,
            route,
            josh,
            grouchly,
            beastly,
        }
    }

    /// A signed message `age_days` old from `from` to `to`; acknowledged when `acked`.
    fn message(
        rig: &Rig,
        from: &AgentIdentity,
        to: &str,
        age_days: i64,
        acked: bool,
        now: DateTime<Utc>,
    ) -> Message {
        let mut message = Message::new(
            "proj",
            from.name(),
            to,
            "inline",
            serde_json::json!({ "text": format!("hello {age_days}") }),
            false,
            None,
        );
        message.created_at = now - Duration::days(age_days);
        message.acknowledgement_deadline = message.created_at + Duration::hours(1);
        from.sign(&mut message);
        let path = rig
            .route
            .communications
            .join("messages/proj")
            .join(format!("{}.json", message.id));
        crate::atomic_json(&path, &message).unwrap();
        if acked {
            let ack = Acknowledgement {
                message_id: message.id.clone(),
                project_id: "proj".into(),
                recipient: message.recipient.clone(),
                processed_at: message.created_at + Duration::minutes(5),
                idempotency_key: message.idempotency_key.clone(),
            };
            record_acknowledgement(&rig.route, &ack).unwrap();
        }
        message
    }

    fn live(rig: &Rig, id: &str) -> bool {
        rig.route
            .communications
            .join("messages/proj")
            .join(format!("{id}.json"))
            .is_file()
    }

    fn live_ack(rig: &Rig, id: &str) -> bool {
        rig.route
            .communications
            .join("acknowledgements/proj")
            .join(format!("{id}.json"))
            .is_file()
    }

    #[test]
    fn an_old_acknowledged_message_is_archived_signed_for_and_still_readable() {
        let rig = rig();
        let now = Utc::now();
        let old = message(&rig, &rig.grouchly, "beastly", 45, true, now);
        let fresh = message(&rig, &rig.grouchly, "beastly", 3, true, now);
        let unanswered = message(&rig, &rig.grouchly, "beastly", 90, false, now);
        let original = fs::read_to_string(
            rig.route
                .communications
                .join("messages/proj")
                .join(format!("{}.json", old.id)),
        )
        .unwrap();

        let report = compact(&rig.route, &rig.josh, now, Duration::zero(), false).unwrap();
        assert_eq!(report.archived, vec![old.id.clone()]);
        assert_eq!(report.removed, vec![old.id.clone()]);

        // The old one left the live folder; the fresh and the unanswered did not.
        assert!(!live(&rig, &old.id) && !live_ack(&rig, &old.id));
        assert!(live(&rig, &fresh.id) && live(&rig, &unanswered.id));

        // It is in the archive, byte for byte, and its signature still verifies.
        let entry = find(&rig.route, &old.id).expect("archived");
        assert_eq!(entry.raw, original);
        assert!(entry.acknowledged());
        let read = crate::read_message(&rig.route, &old.id).unwrap();
        assert_eq!(read, old);
        assert_eq!(
            crate::verify_message(&read, &rig.route.agents),
            SignatureCheck::Valid
        );
        assert!(crate::is_acknowledged(&rig.route, &old.id));
        assert!(!crate::is_acknowledged(&rig.route, &unanswered.id));
        let listed: Vec<String> = crate::list_messages_with_archive(&rig.route)
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert!(
            listed.contains(&old.id)
                && listed.contains(&fresh.id)
                && listed.contains(&unanswered.id)
        );
        // A retried send with the same key still finds it.
        let again = crate::find_message_by_idempotency_key(&rig.route, &old.idempotency_key)
            .unwrap()
            .expect("found");
        assert_eq!(again.id, old.id);
    }

    #[test]
    fn a_signed_record_is_written_first_and_the_originals_wait_out_the_grace() {
        let rig = rig();
        let now = Utc::now();
        let old = message(&rig, &rig.grouchly, "beastly", 45, true, now);

        // First pass, with a day's grace: archived and recorded, nothing removed.
        let first = compact(&rig.route, &rig.josh, now, Duration::days(1), false).unwrap();
        assert_eq!(first.archived, vec![old.id.clone()]);
        assert!(first.removed.is_empty());
        assert!(live(&rig, &old.id), "the original stays through the grace");
        let record_path = first.record.clone().expect("a record");
        let record: Record = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(record.entries.len(), 1);
        assert_eq!(
            crate::check_signature(
                Some(&record.signed_by),
                Some(&record.signature),
                &record_payload(&record),
                &rig.route.agents
            ),
            SignatureCheck::Valid
        );

        // A second pass inside the grace writes no second record and removes nothing.
        let second = compact(
            &rig.route,
            &rig.josh,
            now + Duration::hours(2),
            Duration::days(1),
            false,
        )
        .unwrap();
        assert!(second.record.is_none() && second.removed.is_empty());
        assert!(live(&rig, &old.id));

        // After the grace the original goes, and only because the archive still holds it.
        let third = compact(
            &rig.route,
            &rig.josh,
            now + Duration::days(2),
            Duration::days(1),
            false,
        )
        .unwrap();
        assert_eq!(third.removed, vec![old.id.clone()]);
        assert!(!live(&rig, &old.id));
        // And a fourth finds nothing to do.
        let fourth = compact(
            &rig.route,
            &rig.josh,
            now + Duration::days(3),
            Duration::days(1),
            false,
        )
        .unwrap();
        assert!(fourth.archived.is_empty() && fourth.removed.is_empty());
    }

    #[test]
    fn nothing_is_removed_when_the_archive_does_not_hold_it_intact() {
        let rig = rig();
        let now = Utc::now();
        let old = message(&rig, &rig.grouchly, "beastly", 45, true, now);
        let first = compact(&rig.route, &rig.josh, now, Duration::days(1), false).unwrap();
        assert!(first.record.is_some());

        // The archive line is damaged.
        let file = archive_files(&rig.route).pop().unwrap();
        let good = fs::read_to_string(&file).unwrap();
        fs::write(&file, good.replace("hello 45", "hello 46")).unwrap();
        let after = compact(
            &rig.route,
            &rig.josh,
            now + Duration::days(2),
            Duration::days(1),
            false,
        )
        .unwrap();
        assert!(after.removed.is_empty());
        assert!(live(&rig, &old.id), "the original is the only good copy");
        // The damaged line is never served to a reader either.
        assert!(find(&rig.route, &old.id).is_none());

        // An original that changed after it was archived stays too.
        fs::write(&file, good).unwrap();
        let path = rig
            .route
            .communications
            .join("messages/proj")
            .join(format!("{}.json", old.id));
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("hello 45", "hello 99")).unwrap();
        let changed = compact(
            &rig.route,
            &rig.josh,
            now + Duration::days(2),
            Duration::days(1),
            false,
        )
        .unwrap();
        assert!(changed.removed.is_empty());
        assert!(
            changed
                .kept
                .iter()
                .any(|(id, why)| id == &old.id && why.contains("changed"))
        );
    }

    #[test]
    fn a_record_signed_by_someone_who_may_not_compact_removes_nothing() {
        let rig = rig();
        let now = Utc::now();
        let old = message(&rig, &rig.grouchly, "beastly", 45, true, now);
        let first = compact(&rig.route, &rig.josh, now, Duration::days(1), false).unwrap();
        let path = first.record.unwrap();
        let mut record: Record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record.compactor = "beastly".into();
        record.signed_by = "beastly".into();
        record.signature = rig.beastly.sign_bytes(record_payload(&record).as_bytes());
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(valid_records(&rig.route).is_empty());
        let mut report = Report::default();
        sweep(
            &rig.route,
            now + Duration::days(5),
            Duration::days(1),
            false,
            &mut report,
        );
        assert!(report.removed.is_empty());
        assert!(live(&rig, &old.id));
    }

    #[test]
    fn only_the_master_or_the_head_compacts() {
        let rig = rig();
        let now = Utc::now();
        message(&rig, &rig.grouchly, "beastly", 45, true, now);

        // A worker is refused, and nothing moved.
        let refused = compact(&rig.route, &rig.grouchly, now, Duration::zero(), false).unwrap_err();
        assert!(
            refused.to_string().contains("only josh compacts"),
            "{refused}"
        );
        assert!(archive_files(&rig.route).is_empty());

        // Once the master names a head, the head compacts and the master no longer does.
        crate::head::record_said(
            &rig.route.communications,
            "proj",
            &rig.josh,
            "grouchly is head",
        )
        .unwrap();
        crate::head::claim(&rig.route.communications, "proj", &rig.grouchly, None).unwrap();
        assert_eq!(compactor(&rig.route).unwrap().as_deref(), Some("grouchly"));
        assert!(compact(&rig.route, &rig.josh, now, Duration::zero(), false).is_err());
        let done = compact(&rig.route, &rig.grouchly, now, Duration::zero(), false).unwrap();
        assert_eq!(done.archived.len(), 1);
    }

    #[test]
    fn a_second_pass_merges_with_the_first_and_loses_nothing() {
        let rig = rig();
        let now = Utc::now();
        let a = message(&rig, &rig.grouchly, "beastly", 45, true, now);
        let b = message(&rig, &rig.beastly, "grouchly", 44, true, now);
        compact(&rig.route, &rig.josh, now, Duration::days(1), false).unwrap();
        let c = message(&rig, &rig.grouchly, "beastly", 46, true, now);
        compact(&rig.route, &rig.josh, now, Duration::days(1), false).unwrap();
        for id in [&a.id, &b.id, &c.id] {
            assert!(find(&rig.route, id).is_some(), "{id}");
        }
        // The thread is the pair, whichever way it went: one file for all three.
        let files = archive_files(&rig.route);
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(read_archive_file(&files[0]).unwrap().len(), 3);
    }

    #[test]
    fn archives_are_one_file_per_month_per_thread() {
        let rig = rig();
        let now = Utc::now();
        message(&rig, &rig.grouchly, "beastly", 100, true, now);
        message(&rig, &rig.beastly, "grouchly", 101, true, now);
        message(&rig, &rig.grouchly, "josh", 100, true, now);
        message(&rig, &rig.grouchly, "beastly", 160, true, now);
        compact(&rig.route, &rig.josh, now, Duration::zero(), false).unwrap();
        let names: Vec<String> = archive_files(&rig.route)
            .iter()
            .map(|p| {
                p.strip_prefix(archive_dir(&rig.route))
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.ends_with("/beastly--grouchly.jsonl"))
        );
        assert!(names.iter().any(|n| n.ends_with("/grouchly--josh.jsonl")));
        assert!(names.len() >= 3, "{names:?}");
        assert_eq!(
            thread_of("Grouchly", "beastly"),
            thread_of("beastly", "grouchly")
        );
    }

    #[test]
    fn a_dry_run_changes_nothing() {
        let rig = rig();
        let now = Utc::now();
        let old = message(&rig, &rig.grouchly, "beastly", 45, true, now);
        let report = compact(&rig.route, &rig.josh, now, Duration::zero(), true).unwrap();
        assert_eq!(report.archived, vec![old.id.clone()]);
        assert!(!archive_dir(&rig.route).exists());
        assert!(live(&rig, &old.id));
    }

    #[test]
    fn the_masters_policy_sets_the_age() {
        let rig = rig();
        assert_eq!(archive_after_days(&rig.route), DEFAULT_ARCHIVE_AFTER_DAYS);
        let now = Utc::now();
        let old = message(&rig, &rig.grouchly, "beastly", 10, true, now);
        assert!(
            compact(&rig.route, &rig.josh, now, Duration::zero(), true)
                .unwrap()
                .archived
                .is_empty()
        );
        let (mut policy, _) = crate::policy::effective(&rig.route.communications, "proj");
        policy.files.archive_after_days = Some(7);
        crate::policy::set_policy(&rig.route.communications, "proj", Some(policy), &rig.josh)
            .unwrap();
        assert_eq!(archive_after_days(&rig.route), 7);
        let report = compact(&rig.route, &rig.josh, now, Duration::zero(), false).unwrap();
        assert_eq!(report.archived, vec![old.id]);
    }
}

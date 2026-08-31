//! The orchestrator's brief: what only the orchestrator knows.
//!
//! ADR 0017. A worker that dies is recovered by ADR 0011, because everything a worker
//! needs is in the order. The orchestrator has no such story: it is the agent that
//! decides what the orders should be, and when it stops the project does not continue
//! with a different orchestrator - it restarts, badly.
//!
//! `ferry loadmem` prints what the *project* knows. This is what the orchestrator knows
//! and nothing else does: the objective, what is in flight and why, decisions that never
//! became ADRs, the human's standing constraints, what is waiting on the human, and what
//! was already tried and rejected.
//!
//! Written continuously rather than at handoff, for the same reason `ferry-deadman`
//! exists: running out of context is never a graceful event, so the handoff cannot be an
//! event. When updates stop, the last one is already current - and its age is always
//! shown, so a stale brief announces itself rather than lying quietly.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck};

/// One orchestrator's picture of the work, as of its last update.
///
/// The sections are free text on purpose. The value in a handoff is the reasoning, and a
/// schema that forced the reasoning into fields would keep the fields and lose the
/// reasons.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Brief {
    /// The orchestrator this belongs to, and its only writer.
    pub agent: String,
    /// One line. What this is all for right now.
    pub objective: String,
    /// When it has to be true by, if that is a real thing rather than a wish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<String>,
    /// What the human has said that still binds. Learned by being corrected, and lost
    /// completely when a context window ends.
    #[serde(default)]
    pub constraints: String,
    /// What is moving, and why each thing sits where it does.
    #[serde(default)]
    pub in_flight: String,
    /// Decisions that were load-bearing but never worth an ADR, with the reason. The
    /// reason is the part a successor cannot reconstruct.
    #[serde(default)]
    pub decided: String,
    /// Tried, and not taken. So the next orchestrator does not spend its first hour
    /// rediscovering it.
    #[serde(default)]
    pub rejected: String,
    /// Waiting on the human, not on a machine. Nothing else in the channel distinguishes
    /// these, and they are the ones that stall silently.
    #[serde(default)]
    pub waiting_on_human: String,
    /// What to do next, in the order to do it.
    #[serde(default)]
    pub next: String,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Brief {
    /// A new brief with only the objective set. Everything else is filled in as the
    /// orchestrator learns it, which is most of the point.
    #[must_use]
    pub fn new(agent: &str, objective: &str) -> Self {
        Self {
            agent: crate::canonical_agent_name(agent),
            objective: objective.to_string(),
            deadline: None,
            constraints: String::new(),
            in_flight: String::new(),
            decided: String::new(),
            rejected: String::new(),
            waiting_on_human: String::new(),
            next: String::new(),
            updated_at: Utc::now(),
            signed_by: None,
            signature: None,
        }
    }

    /// How old this brief is, in whole minutes.
    ///
    /// Always shown beside it. A successor reasoning about a four-hour-old brief behaves
    /// differently from one trusting it as current, and only one of those is safe.
    #[must_use]
    pub fn age_minutes(&self, now: DateTime<Utc>) -> i64 {
        (now - self.updated_at).num_minutes().max(0)
    }
}

/// Where one orchestrator's brief lives. Named after its only writer, so two
/// orchestrators can never produce a conflicting edit of the same file.
#[must_use]
pub fn brief_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    route
        .communications
        .join("orchestrator")
        .join(format!("{}.json", crate::canonical_agent_name(agent)))
}

/// The bytes a signature covers. Everything that carries meaning, and nothing that does
/// not - the signature fields themselves are excluded so signing is idempotent.
fn signing_payload(brief: &Brief) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        brief.agent,
        brief.objective,
        brief.deadline.as_deref().unwrap_or(""),
        brief.constraints,
        brief.in_flight,
        brief.decided,
        brief.rejected,
        brief.waiting_on_human,
        brief.next,
        brief.updated_at.to_rfc3339(),
    )
}

/// Sign and write a brief. The timestamp is set here, not by the caller, so the age
/// shown to a successor is the age of the write rather than of the intention.
pub fn write_brief(
    route: &ProjectRoute,
    brief: &Brief,
    identity: &AgentIdentity,
) -> Result<PathBuf> {
    let mut brief = brief.clone();
    brief.agent = crate::canonical_agent_name(&brief.agent);
    brief.updated_at = Utc::now();
    brief.signed_by = Some(identity.name().to_string());
    brief.signature = Some(identity.sign_bytes(signing_payload(&brief).as_bytes()));

    let path = brief_path(route, &brief.agent);
    crate::atomic_json(&path, &brief).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Read one orchestrator's brief, if it has written one.
pub fn read_brief(route: &ProjectRoute, agent: &str) -> Result<Option<Brief>> {
    let path = brief_path(route, agent);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(serde_json::from_str(&text).with_context(|| {
        format!("{} is not a readable brief", path.display())
    })?))
}

/// Whether a brief is what its author signed, checked the same way every other record in
/// the channel is checked.
#[must_use]
pub fn verify_brief(brief: &Brief, roster: &[AgentRoute]) -> SignatureCheck {
    crate::check_signature(
        brief.signed_by.as_ref(),
        brief.signature.as_ref(),
        &signing_payload(brief),
        roster,
    )
}

/// Every brief in the channel, newest first.
///
/// More than one is normal and not a conflict: an orchestrator that has handed over
/// leaves its brief behind, and reading the previous one is often how a successor learns
/// what it was not told.
pub fn list_briefs(route: &ProjectRoute) -> Result<Vec<Brief>> {
    let dir = route.communications.join("orchestrator");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(brief) = serde_json::from_str::<Brief>(&text)
        {
            out.push(brief);
        }
    }
    out.sort_by_key(|brief| std::cmp::Reverse(brief.updated_at));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
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

    fn signer(name: &str) -> (AgentIdentity, AgentRoute) {
        let mut seed = [0u8; 32];
        for (slot, byte) in seed.iter_mut().zip(name.bytes().cycle()) {
            *slot = byte;
        }
        let identity = AgentIdentity::from_seed(name, seed);
        let route = AgentRoute {
            name: name.to_string(),
            role: "orchestrator".to_string(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        };
        (identity, route)
    }

    #[test]
    fn a_brief_survives_the_round_trip_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, roster_entry) = signer("claude");

        let mut brief = Brief::new("claude", "ship 0.5.4");
        brief.constraints = "no secrets over telegram".into();
        brief.next = "land ADR 0017".into();
        write_brief(&route, &brief, &identity).unwrap();

        let read = read_brief(&route, "claude").unwrap().unwrap();
        assert_eq!(read.objective, "ship 0.5.4");
        assert_eq!(read.constraints, "no secrets over telegram");
        assert_eq!(
            verify_brief(&read, std::slice::from_ref(&roster_entry)),
            SignatureCheck::Valid
        );
    }

    #[test]
    fn a_brief_edited_after_signing_no_longer_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, roster_entry) = signer("claude");

        write_brief(&route, &Brief::new("claude", "ship 0.5.4"), &identity).unwrap();
        let mut tampered = read_brief(&route, "claude").unwrap().unwrap();
        tampered.next = "rm -rf the workspace".into();

        assert_eq!(
            verify_brief(&tampered, std::slice::from_ref(&roster_entry)),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn a_brief_from_a_name_with_no_key_concludes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, _) = signer("claude");

        write_brief(&route, &Brief::new("claude", "ship 0.5.4"), &identity).unwrap();
        let brief = read_brief(&route, "claude").unwrap().unwrap();

        assert_eq!(verify_brief(&brief, &[]), SignatureCheck::UnknownSigner);
    }

    #[test]
    fn one_writer_per_path_so_two_orchestrators_cannot_collide() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (first, _) = signer("claude");
        let (second, _) = signer("grouchly");

        let a = write_brief(&route, &Brief::new("claude", "ship 0.5.4"), &first).unwrap();
        let b = write_brief(&route, &Brief::new("grouchly", "review the queue"), &second).unwrap();

        assert_ne!(a, b);
        assert_eq!(list_briefs(&route).unwrap().len(), 2);
    }

    #[test]
    fn briefs_are_listed_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (older, _) = signer("claude");
        let (newer, _) = signer("grouchly");

        write_brief(&route, &Brief::new("claude", "older"), &older).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_brief(&route, &Brief::new("grouchly", "newer"), &newer).unwrap();

        let briefs = list_briefs(&route).unwrap();
        assert_eq!(briefs[0].objective, "newer");
        assert_eq!(briefs[1].objective, "older");
    }

    #[test]
    fn a_channel_with_no_briefs_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        assert!(list_briefs(&route).unwrap().is_empty());
        assert!(read_brief(&route, "nobody").unwrap().is_none());
    }

    #[test]
    fn the_name_is_folded_so_one_orchestrator_writes_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        assert_eq!(brief_path(&route, "Claude"), brief_path(&route, "claude"));
    }

    #[test]
    fn age_is_reported_in_whole_minutes_and_never_negative() {
        let mut brief = Brief::new("claude", "ship 0.5.4");
        let now = brief.updated_at;
        brief.updated_at = now - chrono::Duration::minutes(90);
        assert_eq!(brief.age_minutes(now), 90);

        brief.updated_at = now + chrono::Duration::minutes(5);
        assert_eq!(brief.age_minutes(now), 0);
    }
}

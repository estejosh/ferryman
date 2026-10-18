//! Where else an agent can be reached: its signed TRANSPORTS record.
//!
//! Syncthing carries a channel between machines that already trust each other's device
//! ids. The iroh lane (`ferryman-iroh`) carries the same channel over QUIC, and needs to
//! answer the same question in its own terms: which endpoint ids may connect to this
//! machine and be handed this channel's files? The answer is written into the channel
//! itself, by the agents who are in it, signed with the key the roster already knows:
//!
//! ```text
//! <channel>/transports/<agent>.json   agent's iroh endpoint id (+ relay), signed by agent
//! ```
//!
//! # Bootstrap
//!
//! The record is an ordinary channel file, so it travels like one: over Syncthing while
//! that still runs, and over iroh itself once two machines have each other's record.
//! Nothing is configured by hand on the other side; publishing is the whole handshake.
//!
//! # Trust
//!
//! A record is honoured only when all of these hold, and it is checked every time it is
//! read - nothing on disk is trusted for having been there yesterday:
//!
//! - its file is named after the agent it describes, and that agent signed it, so one
//!   member cannot publish an endpoint in another member's name;
//! - the signature verifies against the key the roster pins for that agent;
//! - the agent has its own roster entry in THIS channel (`agents/<agent>.json`), not only
//!   in the fleet folder, so leaving a project ends its reach there;
//! - the project's master has not revoked the agent;
//! - the project id is in the signed payload, so a record cannot be lifted from one
//!   channel into another the agent is not in;
//! - it is not dated in the future beyond [`CLOCK_SKEW`].
//!
//! An endpoint id is a public key. Publishing it gives nothing away; what it grants is
//! the right to connect, and that is exactly what the signature controls.

use std::fs;
use std::path::PathBuf;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, canonical_agent_name, is_safe_component};

/// The directory inside the channel.
pub const DIR: &str = "transports";

/// The record format. Bumped only if the signed payload changes shape.
pub const VERSION: u32 = 1;

/// How far ahead of this machine's clock a record may be dated and still be read. A
/// record's date is its signer's word, and only shown, but one from the future is a
/// clock that is wrong or a record that was made to look fresh.
pub const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(10);

/// One agent's signed statement of how it can be reached over iroh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transports {
    pub version: u32,
    /// The project whose channel this is in. Signed, so the record means "in this
    /// project", not "anywhere this file is copied to".
    pub project_id: String,
    pub agent: String,
    /// The iroh endpoint id: the machine's iroh public key, hex.
    pub endpoint_id: String,
    /// The relay the endpoint keeps a home connection to, if any. A hint for dialing; the
    /// endpoint id is what is checked on every connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    pub at: DateTime<Utc>,
    pub signed_by: String,
    pub signature: String,
}

fn payload(record: &Transports) -> String {
    format!(
        "ferryman-transports-v{}\n{}\n{}\n{}\n{}\n{}",
        record.version,
        record.project_id,
        record.agent,
        record.endpoint_id,
        record.relay_url.as_deref().unwrap_or(""),
        record.at.to_rfc3339(),
    )
}

/// Where an agent's own record lives: the channel's `transports/`, or for a Worker-level
/// agent (which never writes the channel) `handins/<agent>/transports/`.
fn path(route: &ProjectRoute, agent: &str) -> PathBuf {
    crate::access::out_path(
        route,
        agent,
        &std::path::Path::new(DIR).join(format!("{}.json", canonical_agent_name(agent))),
    )
}

/// Write `identity`'s record into this channel: it can be reached at `endpoint_id`.
///
/// Returns whether anything was written. A record that already says the same thing and
/// still verifies is left alone, because a worker publishes on every start and a rewrite
/// each time would be a synced change on every machine for nothing.
///
/// # Errors
/// The agent name is not path-safe, the endpoint id is not 64 hex characters, or the file
/// cannot be written.
pub fn publish(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    endpoint_id: &str,
    relay_url: Option<&str>,
) -> Result<bool> {
    let agent = canonical_agent_name(identity.name());
    if !is_safe_component(&agent) {
        bail!("agent name must be a path-safe identifier");
    }
    if endpoint_id.len() != 64 || !endpoint_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("an endpoint id is 64 hex characters");
    }
    let file = path(route, &agent);
    if let Some(existing) = read_one(&file)
        && existing.endpoint_id.eq_ignore_ascii_case(endpoint_id)
        && existing.relay_url.as_deref() == relay_url
        && honoured(route, &existing)
    {
        return Ok(false);
    }
    let mut record = Transports {
        version: VERSION,
        project_id: route.project_id.clone(),
        agent: agent.clone(),
        endpoint_id: endpoint_id.to_ascii_lowercase(),
        relay_url: relay_url.map(str::to_owned),
        at: Utc::now(),
        signed_by: agent,
        signature: String::new(),
    };
    record.signature = identity.sign_bytes(payload(&record).as_bytes());
    crate::atomic_json(&file, &record)?;
    Ok(true)
}

fn read_one(file: &std::path::Path) -> Option<Transports> {
    serde_json::from_slice(&fs::read(file).ok()?).ok()
}

/// Whether `record` is one this channel honours. See the module documentation for each
/// condition and why it is there.
fn honoured(route: &ProjectRoute, record: &Transports) -> bool {
    let agent = canonical_agent_name(&record.agent);
    if record.version != VERSION
        || record.project_id != route.project_id
        || !record.signed_by.eq_ignore_ascii_case(&agent)
        || record.at > Utc::now() + CLOCK_SKEW
        || !is_safe_component(&agent)
    {
        return false;
    }
    if !route
        .communications
        .join("agents")
        .join(format!("{agent}.json"))
        .is_file()
    {
        return false;
    }
    let roster = crate::gate::roster(route);
    if crate::check_signature(
        Some(&record.signed_by),
        Some(&record.signature),
        &payload(record),
        &roster,
    ) != SignatureCheck::Valid
    {
        return false;
    }
    !crate::master::is_revoked_in(&route.communications, &roster, &agent)
}

/// Every record in this channel that is honoured, by agent name.
///
/// Read afresh on every call: an agent revoked a second ago is not reachable now.
/// Syncthing conflict copies are not records; neither is a file named for one agent and
/// holding another's.
#[must_use]
pub fn honoured_records(route: &ProjectRoute) -> Vec<Transports> {
    // A Worker-level agent's record is taken from its own hand-ins folder, never from the
    // channel: the channel is not where a Worker writes (ADR 0024), so a Worker's record
    // found there is not its own.
    let workers = crate::access::refused_authors(&route.communications, &route.project_id);
    let mut found: Vec<Transports> = Vec::new();
    let mut take = |dir: &std::path::Path, only: Option<&str>| {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if stem.contains(".sync-conflict-") || only.is_some_and(|only| only != stem) {
                continue;
            }
            if only.is_none() && workers.contains(stem) {
                continue;
            }
            let Some(record) = read_one(&entry.path()) else {
                continue;
            };
            if canonical_agent_name(&record.agent) == stem && honoured(route, &record) {
                found.push(record);
            }
        }
    };
    take(&route.communications.join(DIR), None);
    for (worker, dir) in crate::access::overlay_dirs(&route.communications, &route.project_id) {
        take(&dir.join(DIR), Some(&worker));
    }
    found.sort_by(|a, b| a.agent.cmp(&b.agent));
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;

    struct Fixture {
        _dir: tempfile::TempDir,
        route: ProjectRoute,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("demo");
        let attachment = workspace.join(".ferryman");
        let communications = attachment.join("ferryman");
        fs::create_dir_all(&communications).unwrap();
        let route = ProjectRoute {
            project_id: "demo".into(),
            workspace,
            attachment,
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: "private".into(),
            agents: Vec::new(),
        };
        Fixture { _dir: dir, route }
    }

    fn member(route: &ProjectRoute, name: &str) -> AgentIdentity {
        let identity = AgentIdentity::load_or_create(name, &route.attachment).unwrap();
        crate::register_agent(
            route,
            &AgentRoute {
                name: name.into(),
                role: "worker".into(),
                capabilities: Vec::new(),
                public_key: Some(identity.public_key_hex()),
                encryption_key: None,
            },
        )
        .unwrap();
        identity
    }

    const ENDPOINT: &str = "aa00000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn a_member_publishes_once_and_the_record_is_honoured() {
        let f = fixture();
        let fang = member(&f.route, "fang");
        assert!(publish(&f.route, &fang, ENDPOINT, Some("https://relay.example")).unwrap());
        assert!(!publish(&f.route, &fang, ENDPOINT, Some("https://relay.example")).unwrap());
        let records = honoured_records(&f.route);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].endpoint_id, ENDPOINT);
    }

    #[test]
    fn a_record_signed_by_someone_off_the_roster_is_not_honoured() {
        let f = fixture();
        let stranger = AgentIdentity::load_or_create("mallory", &f.route.attachment).unwrap();
        publish(&f.route, &stranger, ENDPOINT, None).unwrap();
        assert!(honoured_records(&f.route).is_empty());
    }

    #[test]
    fn a_record_in_another_members_name_is_not_honoured() {
        let f = fixture();
        let _fang = member(&f.route, "fang");
        let wisp = member(&f.route, "wisp");
        publish(&f.route, &wisp, ENDPOINT, None).unwrap();
        // wisp's record, put where fang's would be.
        fs::rename(path(&f.route, "wisp"), path(&f.route, "fang")).unwrap();
        assert!(honoured_records(&f.route).is_empty());
    }

    #[test]
    fn a_record_lifted_from_another_project_is_not_honoured() {
        let f = fixture();
        let fang = member(&f.route, "fang");
        publish(&f.route, &fang, ENDPOINT, None).unwrap();
        let file = path(&f.route, "fang");
        let mut record = read_one(&file).unwrap();
        record.project_id = "elsewhere".into();
        fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(honoured_records(&f.route).is_empty());
    }

    #[test]
    fn an_edited_endpoint_no_longer_verifies() {
        let f = fixture();
        let fang = member(&f.route, "fang");
        publish(&f.route, &fang, ENDPOINT, None).unwrap();
        let file = path(&f.route, "fang");
        let mut record = read_one(&file).unwrap();
        record.endpoint_id = ENDPOINT.replace("01", "02");
        fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(honoured_records(&f.route).is_empty());
    }

    #[test]
    fn leaving_the_channel_roster_ends_the_record() {
        let f = fixture();
        let fang = member(&f.route, "fang");
        publish(&f.route, &fang, ENDPOINT, None).unwrap();
        fs::remove_file(f.route.communications.join("agents").join("fang.json")).unwrap();
        assert!(honoured_records(&f.route).is_empty());
    }
}

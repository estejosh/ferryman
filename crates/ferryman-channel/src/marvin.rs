//! Marvin: the orchestrator's memory, which outlives the machine holding it.
//!
//! ADR 0017. A worker that dies is recovered by ADR 0011, because everything a worker
//! needs is in the order. The orchestrator had no such story: it is the agent that
//! decides what the orders should be, and when it stopped the project did not continue
//! with a different orchestrator - it restarted, badly.
//!
//! # Why this is not "the orchestrator machine"
//!
//! The thing that has to survive is not a machine and not a model. It is what the
//! orchestrator knows. Machines run out of tokens, sessions end, a box goes down - and
//! the project should carry on with a different machine, or a different model, holding
//! the same memory and continuing the same thought.
//!
//! So Marvin is the memory. Exactly one machine holds it at a time, and holding is a
//! lease rather than a title: it is taken, heartbeated while it is used, and taken over
//! by somebody else once it has gone quiet. Nothing about the memory belongs to whoever
//! happens to be holding it right now.
//!
//! # One writer per path, and one memory
//!
//! Each holder writes its own file - `marvin/brief.<holder>.json` - because that is the
//! rule the whole channel is built on and two machines editing one file is the conflict
//! this project structurally does not have. Those files are not separate briefs. They
//! are pages of one memory, and `resume` reads them as one: the current holder's page
//! first, then what its predecessors left, so a successor inherits the reasoning and not
//! just the latest snapshot.
//!
//! `ferry loadmem` prints what the *project* knows. This is what the orchestrator knows
//! and nothing else does: the objective, what is in flight and why, decisions that never
//! became ADRs, the human's standing constraints, what is waiting on the human, and what
//! was already tried and rejected.
//!
//! # Written continuously, never at handoff
//!
//! The same insight as `ferry-deadman`: running out of context is never a graceful
//! event, so the handoff cannot be an event. There is no moment at which a dying
//! orchestrator reliably gets to summarise itself. When updates stop, the last one is
//! already current - and its age is always shown, so a stale memory announces itself
//! rather than lying quietly.
//!
//! Named for Douglas Adams' Marvin: a mind that carries on regardless of which body it
//! is in, and remembers everything.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck};

/// One holder's page of Marvin's memory: its picture of the work, as of its last update.
///
/// The sections are free text on purpose. The value in a handoff is the reasoning, and a
/// schema that forced the reasoning into fields would keep the fields and lose the
/// reasons.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Brief {
    /// The machine that wrote this page, and its only writer.
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

/// The directory holding everything Marvin is: the pages of the memory, and the record
/// of who is holding it.
#[must_use]
pub fn marvin_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("marvin")
}

/// One holder's page of Marvin's memory. Named after its only writer, so two machines
/// can never produce a conflicting edit of the same file - and so the succession is
/// legible afterwards rather than being overwritten by whoever spoke last.
#[must_use]
pub fn brief_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    marvin_dir(route).join(format!("brief.{}.json", crate::canonical_agent_name(agent)))
}

/// Where one machine records that it is holding Marvin.
#[must_use]
pub fn holding_path(route: &ProjectRoute, agent: &str) -> PathBuf {
    marvin_dir(route).join(format!(
        "holding.{}.json",
        crate::canonical_agent_name(agent)
    ))
}

/// How long a holding stays live without being touched.
///
/// Not a timeout on the work - an orchestrator can think for an hour. It is how long the
/// fleet waits before concluding that whoever held Marvin is not coming back, which is
/// the event this whole module exists for and the one nobody is present to announce.
pub const HOLDING_GOES_QUIET_AFTER_MINUTES: i64 = 30;

/// One machine's claim to be the live Marvin.
///
/// Signed, like everything else here, so "who is orchestrating" is an attributable fact
/// rather than whichever file appeared last.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Holding {
    /// The machine holding Marvin.
    pub agent: String,
    /// When it took the memory over.
    pub taken_at: DateTime<Utc>,
    /// Last sign of life. Refreshed every time the holder writes to the memory.
    pub touched_at: DateTime<Utc>,
    /// Why it took over, when it took over from somebody. Worth more to a person reading
    /// the succession later than the timestamps are.
    #[serde(default)]
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Holding {
    /// Minutes since this holding was last touched.
    #[must_use]
    pub fn quiet_minutes(&self, now: DateTime<Utc>) -> i64 {
        (now - self.touched_at).num_minutes().max(0)
    }

    /// Whether this holding has gone quiet long enough that somebody else may take over.
    ///
    /// Deliberately not called `is_dead`. Nothing here can tell a machine that died from
    /// one that is thinking, and the honest claim is only that it has stopped saying so.
    #[must_use]
    pub fn has_gone_quiet(&self, now: DateTime<Utc>) -> bool {
        self.quiet_minutes(now) >= HOLDING_GOES_QUIET_AFTER_MINUTES
    }
}

fn holding_payload(holding: &Holding) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        holding.agent,
        holding.taken_at.to_rfc3339(),
        holding.touched_at.to_rfc3339(),
        holding.note,
    )
}

/// Whether a holding is what its author signed.
#[must_use]
pub fn verify_holding(holding: &Holding, roster: &[AgentRoute]) -> SignatureCheck {
    crate::check_signature(
        holding.signed_by.as_ref(),
        holding.signature.as_ref(),
        &holding_payload(holding),
        roster,
    )
}

/// Every holding in the channel, most recently touched first.
pub fn list_holdings(route: &ProjectRoute) -> Result<Vec<Holding>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(marvin_dir(route)) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let is_holding = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("holding."));
        if !is_holding {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(holding) = serde_json::from_str::<Holding>(&text)
        {
            out.push(holding);
        }
    }
    out.sort_by_key(|holding| std::cmp::Reverse(holding.touched_at));
    Ok(out)
}

/// Who is holding Marvin right now, if anybody is.
///
/// The most recently touched holding wins. A holding that has gone quiet is still
/// returned - it is the truth about who last held the memory, and the caller decides
/// whether that is good enough. Hiding it would turn "nobody has spoken for six hours"
/// into "nobody was ever here", which is a different and much worse thing to tell a
/// successor.
pub fn current_holder(route: &ProjectRoute) -> Result<Option<Holding>> {
    Ok(list_holdings(route)?.into_iter().next())
}

/// Take Marvin over, or refresh a holding this machine already has.
///
/// Refuses while somebody else is still live, because two orchestrators issuing orders
/// into one channel is exactly the situation this is meant to end. `force` is for the
/// case the rule cannot see: a machine that is genuinely gone but whose last heartbeat
/// is recent, where a person knows something the channel does not.
pub fn take(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    note: &str,
    force: bool,
) -> Result<Holding> {
    let me = crate::canonical_agent_name(identity.name());
    let now = Utc::now();

    if let Some(current) = current_holder(route)?
        && crate::canonical_agent_name(&current.agent) != me
        && !current.has_gone_quiet(now)
        && !force
    {
        anyhow::bail!(
            "'{}' is holding Marvin and was heard from {} minutes ago. Only one \
             orchestrator runs at a time, so wait for it to go quiet ({} minutes), ask it \
             to release, or take it anyway with --force if you know it is gone.",
            current.agent,
            current.quiet_minutes(now),
            HOLDING_GOES_QUIET_AFTER_MINUTES,
        );
    }

    // An existing holding of our own keeps its original `taken_at`: the succession should
    // record when this machine took over, not when it last said something.
    let taken_at = match read_holding(route, &me)? {
        Some(mine) => mine.taken_at,
        None => now,
    };
    let mut holding = Holding {
        agent: me,
        taken_at,
        touched_at: now,
        note: note.to_string(),
        signed_by: None,
        signature: None,
    };
    holding.signed_by = Some(identity.name().to_string());
    holding.signature = Some(identity.sign_bytes(holding_payload(&holding).as_bytes()));

    let path = holding_path(route, &holding.agent);
    crate::atomic_json(&path, &holding).with_context(|| format!("write {}", path.display()))?;
    Ok(holding)
}

/// One machine's holding, if it has one.
pub fn read_holding(route: &ProjectRoute, agent: &str) -> Result<Option<Holding>> {
    let path = holding_path(route, agent);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(serde_json::from_str(&text).with_context(|| {
        format!("{} is not a readable holding", path.display())
    })?))
}

/// Let Marvin go, so the next machine does not have to wait out the quiet period.
///
/// The holding file is left in place with its heartbeat pushed back rather than deleted:
/// the succession is part of the memory, and a hole in it is not an improvement.
pub fn release(route: &ProjectRoute, identity: &AgentIdentity, note: &str) -> Result<()> {
    let me = crate::canonical_agent_name(identity.name());
    let Some(mut holding) = read_holding(route, &me)? else {
        anyhow::bail!("'{me}' is not holding Marvin, so there is nothing to release")
    };
    holding.touched_at = Utc::now() - chrono::Duration::minutes(HOLDING_GOES_QUIET_AFTER_MINUTES);
    holding.note = if note.is_empty() {
        "released".to_string()
    } else {
        note.to_string()
    };
    holding.signed_by = Some(identity.name().to_string());
    holding.signature = Some(identity.sign_bytes(holding_payload(&holding).as_bytes()));
    let path = holding_path(route, &me);
    crate::atomic_json(&path, &holding).with_context(|| format!("write {}", path.display()))
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

    // Writing to the memory IS the heartbeat. A separate keep-alive would be a second
    // thing to remember, and the whole design rests on the memory being updated as work
    // happens - so the act of doing that is what tells the fleet this machine is still
    // here. Best-effort: a page that landed must not be reported as failed because the
    // holding could not be refreshed.
    let _ = take(route, identity, "", true);
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

/// Every page of Marvin's memory, newest first.
///
/// More than one is the normal case and never a conflict. Each machine that has held
/// Marvin leaves its page behind, and reading the one before yours is usually how a
/// successor learns the things nobody thought to write down twice.
pub fn list_briefs(route: &ProjectRoute) -> Result<Vec<Brief>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(marvin_dir(route)) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        // Only the pages of the memory. The holdings live in the same directory and are
        // not briefs.
        let is_brief = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("brief."));
        if !is_brief {
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
    fn taking_marvin_is_refused_while_someone_else_is_still_being_heard_from() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (first, _) = signer("beastly");
        let (second, _) = signer("grouchly");

        take(&route, &first, "starting", false).unwrap();
        let refused = take(&route, &second, "taking over", false).unwrap_err();
        let text = refused.to_string();
        assert!(text.contains("beastly"), "{text}");
        assert!(
            text.contains("--force"),
            "the refusal has to say how to get past it: {text}"
        );

        // The person who knows the machine is gone can still say so.
        take(&route, &second, "beastly is off", true).unwrap();
        assert_eq!(current_holder(&route).unwrap().unwrap().agent, "grouchly");
    }

    #[test]
    fn a_holder_that_has_gone_quiet_can_be_taken_over_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (first, _) = signer("beastly");
        let (second, _) = signer("grouchly");

        take(&route, &first, "starting", false).unwrap();

        // Age the holding past the quiet period, as running out of tokens would.
        let mut stale = read_holding(&route, "beastly").unwrap().unwrap();
        stale.touched_at =
            Utc::now() - chrono::Duration::minutes(HOLDING_GOES_QUIET_AFTER_MINUTES + 1);
        crate::atomic_json(&holding_path(&route, "beastly"), &stale).unwrap();

        take(&route, &second, "beastly went quiet", false).unwrap();
        assert_eq!(current_holder(&route).unwrap().unwrap().agent, "grouchly");
    }

    #[test]
    fn releasing_hands_it_over_without_waiting_and_keeps_the_succession() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (first, _) = signer("beastly");
        let (second, _) = signer("grouchly");

        take(&route, &first, "starting", false).unwrap();
        release(&route, &first, "handing over").unwrap();

        // No wait, and no --force.
        take(&route, &second, "picking it up", false).unwrap();
        assert_eq!(current_holder(&route).unwrap().unwrap().agent, "grouchly");

        // The record of who held it is still there. A hole in the succession is not an
        // improvement on a released holding.
        assert!(read_holding(&route, "beastly").unwrap().is_some());
        assert_eq!(list_holdings(&route).unwrap().len(), 2);
    }

    #[test]
    fn a_holding_is_signed_and_a_tampered_one_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, roster_entry) = signer("beastly");

        take(&route, &identity, "starting", false).unwrap();
        let holding = read_holding(&route, "beastly").unwrap().unwrap();
        assert_eq!(
            verify_holding(&holding, std::slice::from_ref(&roster_entry)),
            SignatureCheck::Valid
        );

        let mut tampered = holding;
        tampered.agent = "grouchly".into();
        assert_eq!(
            verify_holding(&tampered, std::slice::from_ref(&roster_entry)),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn taking_it_back_keeps_when_this_machine_first_took_over() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, _) = signer("beastly");

        let first = take(&route, &identity, "starting", false).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let again = take(&route, &identity, "still here", false).unwrap();

        assert_eq!(
            again.taken_at, first.taken_at,
            "taken_at is when it took over"
        );
        assert!(
            again.touched_at > first.touched_at,
            "touched_at is a heartbeat"
        );
    }

    /// Writing to the memory IS the heartbeat: a separate keep-alive is a second thing to
    /// remember, and the design rests on the memory being updated as work happens.
    #[test]
    fn writing_a_page_keeps_the_holding_alive() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, _) = signer("beastly");

        take(&route, &identity, "starting", false).unwrap();
        let mut aged = read_holding(&route, "beastly").unwrap().unwrap();
        aged.touched_at = Utc::now() - chrono::Duration::minutes(20);
        crate::atomic_json(&holding_path(&route, "beastly"), &aged).unwrap();

        write_brief(&route, &Brief::new("beastly", "ship it"), &identity).unwrap();

        let refreshed = read_holding(&route, "beastly").unwrap().unwrap();
        assert!(refreshed.quiet_minutes(Utc::now()) < 5);
    }

    /// The holdings live beside the pages in one directory, and neither listing may pick
    /// up the other's files.
    #[test]
    fn holdings_and_pages_are_never_mistaken_for_one_another() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let (identity, _) = signer("beastly");

        take(&route, &identity, "starting", false).unwrap();
        write_brief(&route, &Brief::new("beastly", "ship it"), &identity).unwrap();

        assert_eq!(list_holdings(&route).unwrap().len(), 1);
        assert_eq!(list_briefs(&route).unwrap().len(), 1);
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

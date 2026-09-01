//! Interrupts: a signed way for an operator to pause, steer or kill a running
//! agent mid-task.
//!
//! Groundcrew's answer to the same need is a live terminal you take over;
//! Ferryman's is a signed order the worker honours between poll ticks. The
//! intervention is itself attributable and auditable - it carries a signature
//! and lands in the ledger, so "who stopped this task and why" is answerable
//! the way the rest of the channel is.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ProjectRoute;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterruptAction {
    /// Stop now and abandon the claim, so another machine can take the task.
    Kill,
    /// Stop now and release the task to be picked up again later.
    Pause,
    /// Fold the note into the next prompt and keep going.
    Steer,
}

impl InterruptAction {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "kill" => Ok(Self::Kill),
            "pause" => Ok(Self::Pause),
            "steer" => Ok(Self::Steer),
            other => bail!("interrupt action must be 'kill', 'pause' or 'steer', not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kill => "kill",
            Self::Pause => "pause",
            Self::Steer => "steer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interrupt {
    pub order_id: String,
    pub action: InterruptAction,
    pub note: String,
    pub issued_by: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The exact bytes a signature covers.
#[must_use]
pub fn payload(interrupt: &Interrupt) -> String {
    format!(
        "ferryman-interrupt-v1\n{}\n{}\n{}\n{}\n{}",
        interrupt.order_id,
        interrupt.action.as_str(),
        interrupt.note,
        interrupt.issued_by,
        interrupt.created_at.to_rfc3339(),
    )
}

fn interrupt_path(route: &ProjectRoute, order_id: &str, issued_by: &str) -> PathBuf {
    crate::task_dir(route, order_id).join(format!("interrupt.{issued_by}.json"))
}

fn ack_path(route: &ProjectRoute, order_id: &str, issued_by: &str, agent: &str) -> PathBuf {
    crate::task_dir(route, order_id).join(format!("interrupt.{issued_by}.{agent}.acked.json"))
}

/// Write a signed interrupt into the channel.
pub fn write_interrupt(route: &ProjectRoute, interrupt: &Interrupt) -> Result<PathBuf> {
    if !crate::is_safe_component(&interrupt.issued_by) {
        bail!("issuer name must be a path-safe identifier");
    }
    let path = interrupt_path(route, &interrupt.order_id, &interrupt.issued_by);
    crate::write_task_file(&path, interrupt)?;
    Ok(path)
}

/// Every interrupt on an order that this agent has not yet acknowledged.
pub fn pending_interrupts(
    route: &ProjectRoute,
    order_id: &str,
    agent: &str,
) -> Result<Vec<Interrupt>> {
    let dir = crate::task_dir(route, order_id);
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Acknowledgements live beside interrupts and share the prefix; they are
        // not interrupts themselves.
        if name.ends_with(".acked.json") {
            continue;
        }
        let Some(issued_by) = name
            .strip_prefix("interrupt.")
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        if ack_path(route, order_id, issued_by, agent).exists() {
            continue;
        }
        // Every failure from here on SKIPS this file. It must never propagate.
        //
        // Reading and parsing used to use `?`, above the signature check, so one non-JSON
        // file in one task directory made every worker pass fail identically every ten
        // seconds, forever, doing no work and quarantining nothing. That is a denial of
        // service needing no valid signature at all - it failed before signatures were
        // consulted - and any peer, or a Syncthing `.sync-conflict-….json` copy, could
        // cause it. The signature check below always got this right; the parse did not.
        let Ok(raw) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(interrupt) = serde_json::from_str::<Interrupt>(&raw) else {
            continue;
        };
        // Trust boundary: only honour interrupts whose signature verifies. A
        // peer can write to the shared folder, so an unsigned interrupt is a
        // forged steer/kill/pause and must be ignored, not acted on.
        if crate::verify_interrupt(&interrupt, &route.agents) != crate::SignatureCheck::Valid {
            continue;
        }
        // A valid signature over the WRONG order is still the wrong order.
        //
        // The signed payload contains `order_id`, and nothing compared it to the directory
        // the file was found in. So a legitimately-signed `kill` could be copied into every
        // task directory - no key required, just `cp` - and every worker would abandon the
        // claim for whichever task the directory happened to be. Binding the signature to
        // its location is what makes the signature mean "kill THIS task".
        if interrupt.order_id != order_id {
            continue;
        }
        // The name on the file must be the name in the signature.
        //
        // Without this, any roster member could sign an interrupt and file it under
        // `interrupt.orchestrator.json`, and the worker would attribute the kill - and its
        // acknowledgement - to the orchestrator. It also keeps the ack path derivable from
        // the body alone, which is what fixes the replay below.
        if interrupt.issued_by != issued_by {
            continue;
        }
        out.push(interrupt);
    }
    out.sort_by_key(|interrupt| interrupt.created_at);
    Ok(out)
}

/// Acknowledge an interrupt so it is not applied again on the next poll.
pub fn acknowledge(
    route: &ProjectRoute,
    order_id: &str,
    issued_by: &str,
    agent: &str,
) -> Result<()> {
    let path = ack_path(route, order_id, issued_by, agent);
    crate::write_task_file(
        &path,
        &serde_json::json!({
            "order_id": order_id,
            "issued_by": issued_by,
            "agent": agent,
            "acknowledged_at": Utc::now().to_rfc3339(),
        }),
    )?;
    Ok(())
}

/// Abandon this agent's claim on an order, so another machine can take it.
pub fn abandon_claim(route: &ProjectRoute, order_id: &str, agent: &str) -> Result<()> {
    let path = crate::task_dir(route, order_id).join(format!("claim.{agent}.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove the claim"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProjectRoute;

    fn route(dir: &std::path::Path) -> ProjectRoute {
        let workspace = dir.join("workspace");
        let attachment = workspace.join(".ferryman");
        ProjectRoute {
            project_id: "ferryman".into(),
            workspace,
            attachment: attachment.clone(),
            communications: attachment.join("ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        }
    }

    /// A signed interrupt must not travel between tasks.
    ///
    /// The attack needs no key: copy one legitimately-signed `kill` into every task
    /// directory. Before the binding check, every worker abandoned the claim for whichever
    /// task the directory happened to be.
    #[test]
    fn a_signed_interrupt_for_one_order_does_not_apply_to_another() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        let identity =
            crate::AgentIdentity::load_or_create("orchestrator", &route.attachment).unwrap();
        route.agents = vec![crate::AgentRoute {
            name: "orchestrator".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }];
        let mut interrupt = Interrupt {
            order_id: "t-1".into(),
            action: InterruptAction::Kill,
            note: "stop".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        identity.sign_interrupt(&mut interrupt);
        write_interrupt(&route, &interrupt).unwrap();

        // Where it belongs, it applies.
        assert_eq!(
            pending_interrupts(&route, "t-1", "claw").unwrap().len(),
            1,
            "the interrupt must work for the order it names"
        );

        // Copied verbatim into another task's directory - same bytes, same valid signature.
        let elsewhere = crate::task_dir(&route, "t-2");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::copy(
            interrupt_path(&route, "t-1", "orchestrator"),
            elsewhere.join("interrupt.orchestrator.json"),
        )
        .unwrap();
        assert!(
            pending_interrupts(&route, "t-2", "claw")
                .unwrap()
                .is_empty(),
            "a signature over t-1 must not kill t-2"
        );
    }

    /// One unparseable file must not stop the worker, and must not need a signature to be
    /// refused. This was an unauthenticated permanent denial of service: the parse used `?`
    /// above the signature check, so `work_once` failed identically every poll, forever.
    #[test]
    fn a_malformed_or_forged_interrupt_is_skipped_rather_than_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        let identity =
            crate::AgentIdentity::load_or_create("orchestrator", &route.attachment).unwrap();
        route.agents = vec![crate::AgentRoute {
            name: "orchestrator".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }];
        let task = crate::task_dir(&route, "t-1");
        std::fs::create_dir_all(&task).unwrap();

        // Not JSON at all.
        std::fs::write(task.join("interrupt.someone.json"), "{ not json").unwrap();
        // Valid JSON, wrong shape.
        std::fs::write(task.join("interrupt.other.json"), r#"{"hello":"world"}"#).unwrap();
        // A Syncthing conflict copy of a real interrupt, which passes the prefix/suffix
        // filter and whose derived issuer will not match the body.
        let mut real = Interrupt {
            order_id: "t-1".into(),
            action: InterruptAction::Kill,
            note: "stop".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        identity.sign_interrupt(&mut real);
        std::fs::write(
            task.join("interrupt.orchestrator.sync-conflict-20260817-101112.json"),
            serde_json::to_string(&real).unwrap(),
        )
        .unwrap();

        let pending = pending_interrupts(&route, "t-1", "claw")
            .expect("a malformed file must not fail the whole pass");
        assert!(
            pending.is_empty(),
            "nothing here should be honoured: {pending:?}"
        );

        // And a well-formed signed one still gets through, so the skipping is not blanket.
        write_interrupt(&route, &real).unwrap();
        assert_eq!(pending_interrupts(&route, "t-1", "claw").unwrap().len(), 1);
    }

    /// The name on the file must be the name in the signature, or a roster member could
    /// file their own signed interrupt under someone else's name and have the worker
    /// attribute the kill - and its acknowledgement - to that person.
    #[test]
    fn an_interrupt_filed_under_another_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        let mallory = crate::AgentIdentity::load_or_create("mallory", &route.attachment).unwrap();
        route.agents = vec![crate::AgentRoute {
            name: "mallory".into(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: Some(mallory.public_key_hex()),
            encryption_key: None,
        }];
        let mut interrupt = Interrupt {
            order_id: "t-1".into(),
            action: InterruptAction::Kill,
            note: "stop".into(),
            issued_by: "mallory".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        // Genuinely signed by mallory, with mallory's real key, and mallory is on the
        // roster. The only lie is the filename.
        mallory.sign_interrupt(&mut interrupt);
        let task = crate::task_dir(&route, "t-1");
        std::fs::create_dir_all(&task).unwrap();
        std::fs::write(
            task.join("interrupt.orchestrator.json"),
            serde_json::to_string(&interrupt).unwrap(),
        )
        .unwrap();

        assert!(
            pending_interrupts(&route, "t-1", "claw")
                .unwrap()
                .is_empty(),
            "a valid signature does not make the filename true"
        );
    }

    #[test]
    fn an_interrupt_round_trips_and_acks() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        let identity =
            crate::AgentIdentity::load_or_create("orchestrator", &route.attachment).unwrap();
        route.agents = vec![crate::AgentRoute {
            name: "orchestrator".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }];
        let mut interrupt = Interrupt {
            order_id: "t-1".into(),
            action: InterruptAction::Steer,
            note: "use the totals from page 2".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        identity.sign_interrupt(&mut interrupt);
        write_interrupt(&route, &interrupt).unwrap();
        let pending = pending_interrupts(&route, "t-1", "worker").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].note, "use the totals from page 2");
        acknowledge(&route, "t-1", "orchestrator", "worker").unwrap();
        assert!(
            pending_interrupts(&route, "t-1", "worker")
                .unwrap()
                .is_empty()
        );
        // An ack is per-agent; another machine still sees the interrupt.
        assert_eq!(pending_interrupts(&route, "t-1", "nebra").unwrap().len(), 1);
    }

    #[test]
    fn an_unsigned_interrupt_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let route = route(dir.path());
        let interrupt = Interrupt {
            order_id: "t-1".into(),
            action: InterruptAction::Kill,
            note: "forged".into(),
            issued_by: "attacker".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        write_interrupt(&route, &interrupt).unwrap();
        assert!(
            pending_interrupts(&route, "t-1", "worker")
                .unwrap()
                .is_empty(),
            "an unsigned interrupt must never reach the worker"
        );
    }

    #[test]
    fn actions_parse_and_reject_garbage() {
        assert_eq!(
            InterruptAction::parse("steer").unwrap(),
            InterruptAction::Steer
        );
        assert_eq!(
            InterruptAction::parse("KILL").unwrap(),
            InterruptAction::Kill
        );
        assert!(InterruptAction::parse("nuke").is_err());
    }

    #[test]
    fn a_payload_is_stable_for_signing() {
        let interrupt = Interrupt {
            order_id: "t-1".into(),
            action: InterruptAction::Kill,
            note: "wrong branch".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        assert_eq!(payload(&interrupt), payload(&interrupt));
        assert!(
            payload(&interrupt).starts_with("ferryman-interrupt-v1\nt-1\nkill\nwrong branch\n")
        );
    }

    /// Set up a route with one signing operator and one order on disk.
    fn route_with_order(dir: &std::path::Path, order_id: &str) -> (ProjectRoute, crate::AgentIdentity) {
        let mut route = route(dir);
        let identity =
            crate::AgentIdentity::load_or_create("orchestrator", &route.attachment).unwrap();
        route.agents = vec![crate::AgentRoute {
            name: "orchestrator".into(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: Some(identity.public_key_hex()),
            encryption_key: None,
        }];
        let task = crate::task_dir(&route, order_id);
        std::fs::create_dir_all(&task).unwrap();
        let mut order = crate::Order {
            id: order_id.into(),
            project_id: "ferryman".into(),
            issued_by: "orchestrator".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: serde_json::json!({ "task": "do the thing" }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            result_contract: None,
            signed_by: None,
            signature: None,
        };
        identity.sign_order(&mut order);
        crate::write_task_file(&task.join("order.json"), &order).unwrap();
        (route, identity)
    }

    fn kill(route: &ProjectRoute, identity: &crate::AgentIdentity, order_id: &str) {
        let mut interrupt = Interrupt {
            order_id: order_id.into(),
            action: InterruptAction::Kill,
            note: "superseded".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        identity.sign_interrupt(&mut interrupt);
        write_interrupt(route, &interrupt).unwrap();
    }

    /// The bug this exists to prevent, exactly as it happened.
    ///
    /// An order killed at 20:11 was acknowledged at 23:13 and re-claimed by the same
    /// worker at 23:45, because the ack made the interrupt stop being pending and the
    /// order read as plainly open. It ran work the operator had stopped, and starved
    /// live work queued behind it.
    #[test]
    fn acknowledging_a_kill_does_not_bring_the_order_back_to_life() {
        let dir = tempfile::tempdir().unwrap();
        let (route, identity) = route_with_order(dir.path(), "t-dead");
        kill(&route, &identity, "t-dead");

        // The worker sees the kill once and acknowledges it, as it always did.
        assert_eq!(pending_interrupts(&route, "t-dead", "claw").unwrap().len(), 1);
        acknowledge(&route, "t-dead", "orchestrator", "claw").unwrap();
        assert!(
            pending_interrupts(&route, "t-dead", "claw")
                .unwrap()
                .is_empty(),
            "an acknowledged interrupt is no longer pending - that part was always right"
        );

        // What must not happen: the order reading as claimable again.
        let task = crate::read_task(&route, "t-dead").unwrap();
        assert!(
            matches!(task.state(), crate::TaskState::Killed { .. }),
            "an acknowledged kill still leaves the order dead, not open"
        );
        assert!(
            crate::work_for(&route, "claw").unwrap().is_empty(),
            "no machine may be offered a killed order it does not hold"
        );
    }

    /// A kill that lands before anyone claims is just as final as one that interrupts a run.
    #[test]
    fn a_kill_on_an_unclaimed_order_is_final_too() {
        let dir = tempfile::tempdir().unwrap();
        let (route, identity) = route_with_order(dir.path(), "t-open");
        assert_eq!(
            crate::work_for(&route, "claw").unwrap().len(),
            1,
            "before the kill it is ordinary open work"
        );
        kill(&route, &identity, "t-open");
        assert!(crate::work_for(&route, "claw").unwrap().is_empty());
    }

    /// Killing is destructive and irreversible, so it takes a valid signature. Any peer
    /// can write into the synced folder; an unsigned kill is a forged one.
    #[test]
    fn an_unsigned_kill_does_not_end_an_order() {
        let dir = tempfile::tempdir().unwrap();
        let (route, _identity) = route_with_order(dir.path(), "t-live");
        let forged = Interrupt {
            order_id: "t-live".into(),
            action: InterruptAction::Kill,
            note: "stop".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        write_interrupt(&route, &forged).unwrap();
        let task = crate::read_task(&route, "t-live").unwrap();
        assert!(
            !matches!(task.state(), crate::TaskState::Killed { .. }),
            "an unsigned kill must not end an order"
        );
    }

    /// Pause and kill are different promises. Pause says come back to this; kill says
    /// never. They used to do the same thing, which meant kill was only ever a pause.
    #[test]
    fn a_pause_leaves_the_order_claimable_and_a_kill_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (route, identity) = route_with_order(dir.path(), "t-paused");
        let mut interrupt = Interrupt {
            order_id: "t-paused".into(),
            action: InterruptAction::Pause,
            note: "later".into(),
            issued_by: "orchestrator".into(),
            created_at: Utc::now(),
            signed_by: None,
            signature: None,
        };
        identity.sign_interrupt(&mut interrupt);
        write_interrupt(&route, &interrupt).unwrap();
        assert_eq!(
            crate::work_for(&route, "claw").unwrap().len(),
            1,
            "a paused order is meant to be picked up again"
        );
    }

    /// The one machine still holding a killed order is offered it once, so that it can
    /// let go. Nobody else sees it, and it sees nothing after the claim is gone.
    #[test]
    fn the_holder_of_a_killed_order_is_offered_it_only_to_release_it() {
        let dir = tempfile::tempdir().unwrap();
        let (route, identity) = route_with_order(dir.path(), "t-held");
        crate::claim_order(&route, "t-held", "claw").unwrap();
        kill(&route, &identity, "t-held");

        assert_eq!(
            crate::work_for(&route, "claw").unwrap().len(),
            1,
            "the holder must be told, or its claim sits on the order forever"
        );
        assert!(
            crate::work_for(&route, "someone-else").unwrap().is_empty(),
            "nobody else is offered a killed order"
        );

        abandon_claim(&route, "t-held", "claw").unwrap();
        assert!(
            crate::work_for(&route, "claw").unwrap().is_empty(),
            "once it has let go, the killed order is gone for everyone"
        );
    }
}

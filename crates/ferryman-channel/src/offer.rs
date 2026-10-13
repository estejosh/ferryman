//! Re-offering an order, without editing the signed order.
//!
//! # What was missing
//!
//! An order addressed to an identity (`assigned_to`) belongs to it and to nobody else, and
//! the address is signed into the order. When that identity is retired, replaced or revoked
//! (a machine moves to one worker identity, the old one is revoked), every order addressed
//! to it sits `Offered` to a name that will never claim it. The signed order cannot be
//! edited, and should not be: its signature is the record of what the issuer asked for.
//!
//! # What this does
//!
//! A new, signed record beside the order: `offer.<signer>.<time>.json`. It says who the
//! order is offered to now (or `None`: to whoever picks it up first), who said so, and why.
//! The order, its claims and every earlier offer stay where they are, so the history keeps
//! each hand-over. The newest valid offer decides the assignee ([`crate::Task::assignee`]);
//! with none, the order's own address stands.
//!
//! # Who may
//!
//! The order's issuer, or the project's master. An offer from anyone else, or one whose
//! signature does not verify, is not read at all: a peer that can write the channel
//! can write the file, and cannot make anyone act on it.

use std::path::PathBuf;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck};

/// A signed statement of who an order is offered to from now on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Offer {
    /// The project the order is in. Signed, so an offer the master wrote for one project's
    /// order cannot be copied into another project's channel that has an order with the
    /// same id.
    #[serde(default)]
    pub project_id: String,
    pub order_id: String,
    /// Who it is offered to: an identity or a machine, as `assigned_to` is. `None` is the
    /// queue: whoever picks it up first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Who signed this offer (the order's issuer, or the project's master).
    pub offered_by: String,
    /// Who the order was addressed to before this offer, for the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub reason: String,
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn payload(offer: &Offer) -> String {
    format!(
        "ferryman-offer-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        offer.project_id,
        offer.order_id,
        offer.to.as_deref().unwrap_or(""),
        offer.offered_by,
        offer.from.as_deref().unwrap_or(""),
        offer.reason,
        offer.at.to_rfc3339(),
    )
}

/// How far ahead of this machine's clock an offer may be dated and still be read. The
/// newest offer decides, and a date is the signer's own word: an issuer who signs an offer
/// dated years ahead would otherwise be the newest for good, and the master could never
/// offer the order to anyone else.
pub const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(10);

/// The longest reason that is written (it goes into the ledger too).
pub const REASON_CAP: usize = 500;

/// Whether the offer's signature verifies against the roster.
#[must_use]
pub fn verify(offer: &Offer, roster: &[AgentRoute]) -> SignatureCheck {
    if offer.signed_by.as_deref() != Some(offer.offered_by.as_str()) {
        return SignatureCheck::Invalid;
    }
    if offer.at > Utc::now() + CLOCK_SKEW {
        return SignatureCheck::Invalid;
    }
    crate::check_signature(
        offer.signed_by.as_ref(),
        offer.signature.as_ref(),
        &payload(offer),
        roster,
    )
}

/// Whether `signer` may re-offer an order that `issuer` issued in this project.
#[must_use]
pub fn may_offer(route: &ProjectRoute, issuer: &str, signer: &str) -> bool {
    if signer.eq_ignore_ascii_case(issuer) {
        return true;
    }
    crate::master::read_master(route)
        .ok()
        .flatten()
        .is_some_and(|declared| declared.master.eq_ignore_ascii_case(signer))
}

fn file_for(route: &ProjectRoute, order_id: &str, offer: &Offer) -> PathBuf {
    crate::task_dir(route, order_id).join(format!(
        "offer.{}.{}.json",
        offer.offered_by,
        offer.at.timestamp_millis()
    ))
}

/// Write a signed offer for `order_id`, naming `to` (or the queue), as `signer`.
///
/// The order and everything already in its directory are untouched; the new file is the
/// only thing written, and the ledger gets a line saying who handed the order over.
///
/// # Errors
/// The order is unreadable or already finished or killed, `signer` is neither its issuer
/// nor the project's master, or `to` is not a path-safe name.
pub fn reoffer(
    route: &ProjectRoute,
    order_id: &str,
    to: Option<&str>,
    reason: &str,
    signer: &AgentIdentity,
) -> Result<Offer> {
    let task = crate::read_task(route, order_id)?;
    if let Some(name) = to
        && !crate::is_safe_component(name)
    {
        bail!("'{name}' is not a name: use letters, digits, '.', '-' and '_'");
    }
    if !may_offer(route, &task.order.issued_by, signer.name()) {
        bail!(
            "only {} (who issued {order_id}) or the project's master can re-offer it - not {}",
            task.order.issued_by,
            signer.name()
        );
    }
    match task.state() {
        crate::TaskState::Killed { .. } => {
            bail!("{order_id} was killed, and a killed order is not offered to anyone")
        }
        crate::TaskState::Accepted | crate::TaskState::Done => {
            bail!("{order_id} is finished; there is nothing to offer")
        }
        _ => {}
    }
    let reason: String = reason
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(REASON_CAP)
        .collect();
    let mut offer = Offer {
        project_id: route.project_id.clone(),
        order_id: order_id.to_owned(),
        to: to.map(str::to_owned),
        offered_by: signer.name().to_owned(),
        from: task.assignee().map(str::to_owned),
        reason: reason.clone(),
        at: Utc::now(),
        signed_by: None,
        signature: None,
    };
    offer.signed_by = Some(signer.name().to_owned());
    offer.signature = Some(signer.sign_bytes(payload(&offer).as_bytes()));
    crate::write_task_file(&file_for(route, order_id, &offer), &offer)?;
    crate::ledger::append_ledger_entry(
        route,
        signer,
        "offer",
        signer.name(),
        &format!(
            "re-offered {order_id} from {} to {} ({reason})",
            offer.from.as_deref().unwrap_or("the queue"),
            to.unwrap_or("the queue")
        ),
        Some(order_id),
    )?;
    Ok(offer)
}

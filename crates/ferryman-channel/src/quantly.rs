//! Quantly's paper-research protocol carried by a Ferryman channel.
//!
//! This module deliberately models research, replay, and paper-market events only.
//! It contains no broker configuration, credential fields, or live-order variant.
//! A Quantly process should reject a message that cannot pass these checks before it
//! touches a strategy or paper ledger.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AgentRoute, Message};

/// Stable identity used by the Quantly Rust services on a Ferryman channel.
pub const QUANTLY_AGENT: &str = "quantly";
/// Stable identity of the Grouchly machine-side peer.
pub const GROUCHLY_AGENT: &str = "grouchly";
/// The only protocol version accepted by this adapter.
pub const QUANTLY_MESSAGE_FORMAT: &str = "quantly.ferryman/v1";

/// Capabilities intentionally exclude any live trading or account-operation action.
pub const QUANTLY_CAPABILITIES: &[&str] = &[
    "quantly.research.receive",
    "quantly.research.publish",
    "quantly.paper.replay",
    "quantly.paper.ledger",
    "quantly.paper.market",
];

/// A channel participant declaration for Quantly. Publish it through normal roster
/// registration; the private key is still created and retained on Quantly's machine.
#[must_use]
pub fn quantly_service() -> AgentRoute {
    AgentRoute {
        name: QUANTLY_AGENT.to_owned(),
        role: "research-service".to_owned(),
        capabilities: QUANTLY_CAPABILITIES
            .iter()
            .map(ToString::to_string)
            .collect(),
        public_key: None,
        encryption_key: None,
    }
}

/// A minimal, explicit configuration for the machine that runs Grouchly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrouchlyPeerConfig {
    pub agent: String,
    pub role: String,
    pub capabilities: Vec<String>,
}

impl Default for GrouchlyPeerConfig {
    fn default() -> Self {
        Self {
            agent: GROUCHLY_AGENT.to_owned(),
            role: "research-peer".to_owned(),
            capabilities: vec![
                "quantly.research.receive".to_owned(),
                "quantly.research.publish".to_owned(),
                "quantly.paper.replay".to_owned(),
            ],
        }
    }
}

impl GrouchlyPeerConfig {
    #[must_use]
    pub fn agent_route(&self) -> AgentRoute {
        AgentRoute {
            name: self.agent.clone(),
            role: self.role.clone(),
            capabilities: self.capabilities.clone(),
            public_key: None,
            encryption_key: None,
        }
    }
}

/// The only event families that may cross the Quantly channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuantlyMessageKind {
    ResearchRequest,
    ResearchResult,
    PaperMarketSnapshot,
    PaperOrderIntent,
    PaperFill,
    ReplayRequest,
    ReplayResult,
    Health,
}

/// Typed payload wrapped inside a standard signed Ferryman [`Message`].
///
/// `paper_only` is present in every record so a receiver can fail closed even when
/// messages are forwarded through a generic queue. `data` must remain non-secret;
/// Ferryman's outer envelope also rejects sensitive-looking JSON keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuantlyEnvelope {
    pub format: String,
    pub kind: QuantlyMessageKind,
    pub run_id: String,
    pub paper_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_reference: Option<String>,
    pub data: Value,
}

impl QuantlyEnvelope {
    #[must_use]
    pub fn new(kind: QuantlyMessageKind, run_id: impl Into<String>, data: Value) -> Self {
        Self {
            format: QUANTLY_MESSAGE_FORMAT.to_owned(),
            kind,
            run_id: run_id.into(),
            paper_only: true,
            source_reference: None,
            data,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != QUANTLY_MESSAGE_FORMAT {
            bail!("unsupported Quantly message format")
        }
        if self.run_id.trim().is_empty() || self.run_id.len() > 128 {
            bail!("Quantly run_id is required and must be at most 128 bytes")
        }
        if !self.paper_only {
            bail!("Quantly transport is paper-only; live trading is not permitted")
        }
        if let Some(reference) = &self.source_reference
            && (reference.trim().is_empty() || reference.len() > 2_048)
        {
            bail!("Quantly source_reference is empty or exceeds 2048 bytes")
        }
        if !self.data.is_object() {
            bail!("Quantly data must be a JSON object")
        }
        Ok(())
    }

    /// Build the standard Ferryman envelope; use the regular channel delivery and
    /// acknowledgement APIs after this point.
    pub fn into_message(
        self,
        project_id: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        reply_required: bool,
        idempotency_key: Option<String>,
    ) -> Result<Message> {
        self.validate()?;
        let payload = serde_json::to_value(&self)?;
        let run_id = self.run_id.clone();
        let message = Message::new(
            project_id,
            sender,
            recipient,
            format!("quantly://paper/{run_id}"),
            payload,
            reply_required,
            idempotency_key,
        );
        message.validate()?;
        Ok(message)
    }

    /// Decode only a Ferryman message carrying this protocol, then apply the
    /// paper-only safety checks before a consumer acts on it.
    pub fn from_message(message: &Message) -> Result<Self> {
        message.validate()?;
        let envelope: Self = serde_json::from_value(message.payload.clone())?;
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn service_capabilities_are_paper_research_only() {
        let service = quantly_service();
        assert_eq!(service.name, QUANTLY_AGENT);
        assert!(service.capabilities.iter().all(|cap| !cap.contains("live")));
        assert!(
            service
                .capabilities
                .iter()
                .all(|cap| !cap.contains("order.submit"))
        );
    }

    #[test]
    fn round_trip_is_a_standard_ferryman_message() {
        let envelope = QuantlyEnvelope::new(
            QuantlyMessageKind::PaperOrderIntent,
            "replay-20260920-001",
            json!({"symbol": "SPY", "side": "buy", "quantity": 1}),
        );
        let message = envelope
            .into_message("quantly", QUANTLY_AGENT, GROUCHLY_AGENT, true, None)
            .expect("valid paper envelope");
        assert_eq!(
            message.payload_reference,
            "quantly://paper/replay-20260920-001"
        );
        assert_eq!(
            QuantlyEnvelope::from_message(&message).unwrap().kind,
            QuantlyMessageKind::PaperOrderIntent
        );
    }

    #[test]
    fn live_mode_is_refused_before_delivery() {
        let mut envelope = QuantlyEnvelope::new(
            QuantlyMessageKind::PaperFill,
            "replay-1",
            json!({"symbol": "SPY"}),
        );
        envelope.paper_only = false;
        assert!(
            envelope
                .validate()
                .unwrap_err()
                .to_string()
                .contains("paper-only")
        );
    }

    #[test]
    fn generic_ferryman_secret_defence_still_applies() {
        let envelope = QuantlyEnvelope::new(
            QuantlyMessageKind::ResearchRequest,
            "research-1",
            json!({"api_key": "never-portable"}),
        );
        assert!(
            envelope
                .into_message("quantly", QUANTLY_AGENT, GROUCHLY_AGENT, false, None)
                .is_err()
        );
    }
}

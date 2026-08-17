//! Fleet discovery: who is in the channel, what they are practiced at, and which
//! single agent (if any) speaks MCP for the fleet.
//!
//! Everything here is *derived* — from the roster, the per-agent memory-bank
//! profiles, and the operator's skills — never a new source of truth. That keeps
//! discovery free of the "shared mutable aggregate" problem: any machine can
//! recompute the same manifest from files that already have clear owners.

use anyhow::Result;
use serde_json::{Value, json};

use crate::{AgentRoute, ProjectRoute};

/// The capability an agent carries to mark itself as the fleet's MCP gateway.
/// Exactly one agent should carry it; the manifest reports when more do.
pub const MCP_CAPABILITY: &str = "mcp";

/// Whether an agent carries the MCP capability.
#[must_use]
pub fn is_mcp(agent: &AgentRoute) -> bool {
    agent.capabilities.iter().any(|c| c == MCP_CAPABILITY)
}

/// Every agent claiming to be the MCP gateway, in roster order.
#[must_use]
pub fn mcp_agents(route: &ProjectRoute) -> Vec<&AgentRoute> {
    route.agents.iter().filter(|a| is_mcp(a)).collect()
}

/// The fleet's MCP agent. When more than one claims it the lexicographically
/// smallest name wins, so every machine answers the question identically.
#[must_use]
pub fn mcp_agent(route: &ProjectRoute) -> Option<&AgentRoute> {
    route
        .agents
        .iter()
        .filter(|a| is_mcp(a))
        .min_by_key(|a| &a.name)
}

/// The machine-readable discovery manifest: every agent with role, capabilities,
/// specialization summary and public key; the MCP agent and any conflict; and
/// the operator's skills. Recomputed on demand.
pub fn manifest(route: &ProjectRoute) -> Result<Value> {
    let bank = crate::memory::memory_bank_dir(route);
    let skills = crate::skills::load_skills(route)?;
    let claimants = mcp_agents(route);
    let agents: Vec<Value> = route
        .agents
        .iter()
        .map(|agent| {
            json!({
                "name": agent.name,
                "role": agent.role,
                "capabilities": agent.capabilities,
                "mcp": is_mcp(agent),
                "key": agent.public_key,
                "summary": crate::memory::agent_summary(&bank, &agent.name).unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({
        "project": route.project_id,
        "mcp_agent": mcp_agent(route).map(|a| &a.name),
        "mcp_conflict": (claimants.len() > 1)
            .then(|| claimants.iter().map(|a| &a.name).collect::<Vec<_>>()),
        "agents": agents,
        "skills": skills
            .iter()
            .map(|s| json!({ "name": s.name, "description": s.description }))
            .collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn agent(name: &str, caps: &[&str]) -> AgentRoute {
        AgentRoute {
            name: name.into(),
            role: "worker".into(),
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            public_key: None,
        }
    }

    #[test]
    fn mcp_is_detected_and_picked_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        route.agents = vec![
            agent("alice", &["messages.receive"]),
            agent("bob", &["mcp", "code"]),
        ];
        assert!(is_mcp(&route.agents[1]));
        assert!(!is_mcp(&route.agents[0]));
        assert_eq!(mcp_agent(&route).unwrap().name, "bob");
    }

    #[test]
    fn manifest_reports_a_conflict_when_two_claim_mcp() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        route.agents = vec![agent("b", &["mcp"]), agent("a", &["mcp"])];
        let manifest = manifest(&route).unwrap();
        // Deterministic winner: lexicographically smallest name.
        assert_eq!(manifest["mcp_agent"], "a");
        assert_eq!(manifest["mcp_conflict"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn manifest_folds_in_profiles_and_skills() {
        let dir = tempfile::tempdir().unwrap();
        let mut route = route(dir.path());
        route.agents = vec![agent("alice", &["code"])];
        let bank = crate::memory::memory_bank_dir(&route);
        let identity = crate::AgentIdentity::from_seed("alice", [7u8; 32]);
        crate::memory::append_agent_profile(&bank, "alice", "Rust services", &identity).unwrap();
        std::fs::create_dir_all(route.attachment.join("skills/db")).unwrap();
        std::fs::write(
            route.attachment.join("skills/db/SKILL.md"),
            "---\nname: db\ndescription: Create databases\n---\n# DB\n",
        )
        .unwrap();
        let manifest = manifest(&route).unwrap();
        assert_eq!(manifest["agents"][0]["summary"], "Rust services");
        assert_eq!(manifest["skills"][0]["name"], "db");
        assert_eq!(manifest["mcp_agent"], serde_json::Value::Null);
    }
}

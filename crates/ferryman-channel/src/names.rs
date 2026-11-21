//! Agent names, aliases, charters and retirement: `fleet/names.toml` in the ferry root.
//!
//! A missing file changes nothing. Retired identities still verify old signatures (their
//! keys stay on the roster); they just take no orders and are hidden from pickers.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::Deserialize;

use crate::{Order, ProjectRoute, is_safe_component};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Agent {
    pub alias: String,
    pub system: String,
    #[serde(default)]
    pub identities: Vec<String>,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub charter: Option<String>,
    #[serde(default)]
    pub never: Vec<String>,
    #[serde(default)]
    pub limits: Option<toml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Retired {
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub identities: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Names {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, rename = "agent")]
    pub agents: Vec<Agent>,
    #[serde(default)]
    pub retired: Retired,
}

/// Kinds a worker-level agent may not take: planning is the orchestrator's job.
const WORKER_REFUSED_KINDS: [&str; 1] = ["plan"];
/// Order titles that are never worker work: questions for the head, and VPS root changes.
const WORKER_REFUSED_PREFIXES: [&str; 2] = ["ask:", "vps:"];

fn same(a: &str, b: &str) -> bool {
    crate::canonical_agent_name(a) == crate::canonical_agent_name(b)
}

impl Names {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }

    /// The ferry root's `fleet/names.toml`; `None` when there is none (today's behaviour).
    #[must_use]
    pub fn here() -> Option<Self> {
        let path = crate::ferry::find_root()?
            .path
            .join("fleet")
            .join("names.toml");
        path.is_file().then(|| Self::load(&path).ok()).flatten()
    }

    /// Every agent that lists `identity`.
    pub fn agents_for<'a>(&'a self, identity: &str) -> impl Iterator<Item = &'a Agent> + use<'a> {
        let identity = identity.to_string();
        self.agents
            .iter()
            .filter(move |a| a.identities.iter().any(|i| same(i, &identity)))
    }

    /// The agent an identity is when it is working an order: an identity shared with the
    /// orchestrator (ichabod-beastly-swarm) is the worker, not Ash.
    #[must_use]
    pub fn agent_for(&self, identity: &str) -> Option<&Agent> {
        let first = self.agents_for(identity).next()?;
        Some(if first.level == "orchestrator" {
            self.agents_for(identity)
                .find(|a| a.level != "orchestrator")
                .unwrap_or(first)
        } else {
            first
        })
    }

    /// `Alias (system.name)`, or the identity itself when it has no entry.
    #[must_use]
    pub fn label(&self, identity: &str) -> String {
        match self.agent_for(identity) {
            Some(a) => format!("{} ({})", a.alias, a.system),
            None => identity.to_string(),
        }
    }

    #[must_use]
    pub fn is_retired(&self, identity: &str) -> bool {
        self.retired.identities.iter().any(|i| same(i, identity))
    }

    /// Why a worker must not start this order, from its charter alone: no model involved.
    #[must_use]
    pub fn charter_refusal(&self, identity: &str, order: &Order) -> Option<String> {
        let agent = self.agent_for(identity).filter(|a| a.level == "worker")?;
        let title = order
            .payload
            .get("task")
            .and_then(|t| t.as_str())
            .and_then(|t| t.lines().map(str::trim).find(|l| !l.is_empty()))
            .unwrap_or("");
        let lower = title.to_ascii_lowercase();
        let who = format!("{} ({})", agent.alias, agent.system);
        if let Some(p) = WORKER_REFUSED_PREFIXES
            .iter()
            .find(|p| lower.starts_with(*p))
        {
            return Some(format!("{who}: '{p}' orders are not worker work"));
        }
        let kind = order
            .needs
            .as_ref()
            .and_then(|n| n.kind)
            .and_then(|k| serde_json::to_value(k).ok())
            .and_then(|v| v.as_str().map(str::to_string))?;
        WORKER_REFUSED_KINDS
            .contains(&kind.as_str())
            .then(|| format!("{who}: kind '{kind}' is not allowed for a worker"))
    }
}

impl Agent {
    /// The top of every worker prompt: who you are, what you do, and the refusal rule.
    #[must_use]
    pub fn charter_block(&self) -> String {
        let mut s = format!(
            "You are {} ({}). Your charter: {}\n",
            self.alias,
            self.system,
            self.charter.as_deref().unwrap_or("(none written)")
        );
        if !self.never.is_empty() {
            s.push_str(&format!("You never: {}.\n", self.never.join("; ")));
        }
        s.push_str(
            "If this order is outside your charter, do not start it. Refuse in one line saying \
             why: `ferry agent refuse <order> --why \"<one line>\"` sends it back to Charon. \
             Then take your next order.",
        );
        s
    }
}

fn fleet_file(name: &str) -> Option<PathBuf> {
    Some(crate::ferry::find_root()?.path.join("fleet").join(name))
}

/// Refuse to claim as a retired, or not yet approved, identity.
pub fn check_may_claim(agent: &str) -> Result<()> {
    let Some(names) = Names::here() else {
        return Ok(());
    };
    let pending = fleet_file("pending")
        .map(|d| d.join(format!("{}.toml", crate::canonical_agent_name(agent))));
    may_claim(&names, pending.as_deref(), agent)
}

/// The rule behind `check_may_claim`, with the names and the pending file given.
pub fn may_claim(names: &Names, pending: Option<&Path>, agent: &str) -> Result<()> {
    if names.is_retired(agent) {
        bail!(
            "{agent} is retired on {} (AGENTS.md) and takes no orders",
            names.retired.date.as_deref().unwrap_or("an earlier date")
        )
    }
    if pending.is_some_and(Path::is_file) {
        bail!("{agent} is enrolled but Josh has not approved it yet")
    }
    Ok(())
}

/// Send an order back to Charon: record the refusal on the order and issue
/// `refused: <id>` (kind chore) to the `ferryman` project. Returns whether it was new.
pub fn refuse(
    route: &ProjectRoute,
    identity: &crate::AgentIdentity,
    order_id: &str,
    why: &str,
) -> Result<bool> {
    if !crate::hold::record(route, identity, order_id, &format!("refused: {why}"))? {
        return Ok(false);
    }
    let root = crate::ferry::find_root().context("no ferry root to send the refusal to")?;
    let projects = root.read().projects;
    let entry = projects
        .iter()
        .find(|p| p.project_id == "ferryman")
        .context("no `ferryman` project in the ferry root")?;
    let (target, _) = entry.route(&root)?;
    let mut order = Order {
        id: format!("refused-{order_id}-{}", identity.name()),
        project_id: target.project_id.clone(),
        issued_by: identity.name().to_string(),
        assigned_to: None,
        created_at: Utc::now(),
        payload: serde_json::json!({
            "task": format!(
                "refused: {order_id}\n\n{} refused {} order {order_id}: {why}\n\
                 Route it to an agent whose charter allows it.",
                identity.name(),
                route.project_id
            )
        }),
        requires_review: false,
        requires_approval: false,
        depends_on: Vec::new(),
        signed_by: None,
        signature: None,
        result_contract: None,
        interface: None,
        touches: Vec::new(),
        needs: Some(crate::work::ExplicitNeeds {
            kind: Some(crate::work::WorkKind::Chore),
            ..Default::default()
        }),
        allow_overlap: false,
        priority: None,
    };
    identity.sign_order(&mut order);
    // Written once: a repeat refusal of the same order by the same agent is a no-op.
    let _ = crate::issue_order(&target, &order);
    Ok(true)
}

/// A new agent's name must be `<role>.<place>` from the role list, with a unique alias.
pub fn check_enrollment(names: &Names, alias: &str, system: &str, identity: &str) -> Result<()> {
    let (role, place) = system
        .split_once('.')
        .context("system name is role.place")?;
    if !names.roles.iter().any(|r| r == role) {
        bail!(
            "role '{role}' is not on the role list: {}",
            names.roles.join(", ")
        )
    }
    if !is_safe_component(place) || !is_safe_component(alias) {
        bail!("alias and place must be path-safe words")
    }
    let taken = names
        .agents
        .iter()
        .any(|x| x.alias.eq_ignore_ascii_case(alias))
        || names
            .retired
            .identities
            .iter()
            .any(|i| i.eq_ignore_ascii_case(alias));
    if taken {
        bail!("alias '{alias}' is already used (aliases are never reused, retired ones included)")
    }
    if names.is_retired(identity) || names.agents_for(identity).next().is_some() {
        bail!("identity '{identity}' is already named or retired")
    }
    Ok(())
}

/// Record an enrolment as pending: the agent cannot claim until Josh approves it.
pub fn enroll(
    alias: &str,
    system: &str,
    identity: &str,
    level: &str,
    charter: &str,
    limits: Option<&str>,
) -> Result<PathBuf> {
    let names = Names::here().context("no fleet/names.toml in the ferry root")?;
    check_enrollment(&names, alias, system, identity)?;
    let dir = fleet_file("pending").context("no ferry root")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.toml", crate::canonical_agent_name(identity)));
    let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let mut text = format!(
        "[[agent]]\nalias = {}\nsystem = {}\nidentities = [{}]\nlevel = {}\ncharter = {}\n",
        q(alias),
        q(system),
        q(identity),
        q(level),
        q(charter)
    );
    if let Some(l) = limits {
        text.push_str(&format!("# limits: {l}\n"));
    }
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Josh's approval: append the pending entry to names.toml and clear the pending file.
pub fn approve(identity: &str) -> Result<()> {
    let pending = fleet_file("pending")
        .context("no ferry root")?
        .join(format!("{}.toml", crate::canonical_agent_name(identity)));
    let text = std::fs::read_to_string(&pending)
        .with_context(|| format!("no pending enrolment for {identity}"))?;
    let names_path = fleet_file("names.toml").context("no ferry root")?;
    let mut all = std::fs::read_to_string(&names_path)?;
    all.push_str(&format!("\n{text}"));
    std::fs::write(&names_path, all)?;
    std::fs::remove_file(pending)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Names {
        toml::from_str(
            r#"
roles = ["master", "worker", "head"]
[[agent]]
alias = "Ash"
system = "head.chat"
identities = ["ichabod-beastly-swarm"]
level = "orchestrator"
[[agent]]
alias = "Ichabod"
system = "worker.beastly"
identities = ["ichabod-beastly-swarm"]
level = "worker"
charter = "Build."
never = ["commit to main"]
[retired]
date = "2026-11-21"
identities = ["codex-grouchly", "quantly"]
"#,
        )
        .unwrap()
    }

    fn order(task: &str, kind: Option<crate::work::WorkKind>) -> Order {
        let mut o: Order = serde_json::from_value(serde_json::json!({
            "id": "o1", "project_id": "p", "issued_by": "josh",
            "created_at": "2026-11-21T00:00:00Z", "payload": {"task": task}
        }))
        .unwrap();
        o.needs = kind.map(|k| crate::work::ExplicitNeeds {
            kind: Some(k),
            ..Default::default()
        });
        o
    }

    #[test]
    fn labels_use_alias_and_the_worker_wins_a_shared_identity() {
        let n = names();
        assert_eq!(n.label("ichabod-beastly-swarm"), "Ichabod (worker.beastly)");
        assert_eq!(n.label("stranger"), "stranger");
    }

    #[test]
    fn retired_identities_are_flagged() {
        let n = names();
        assert!(n.is_retired("codex-grouchly") && !n.is_retired("ichabod-beastly-swarm"));
    }

    #[test]
    fn a_retired_identity_cannot_claim_and_the_message_gives_the_date() {
        let n = names();
        let err = may_claim(&n, None, "codex-grouchly")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "codex-grouchly is retired on 2026-11-21 (AGENTS.md) and takes no orders"
        );
        assert!(may_claim(&n, None, "ichabod-beastly-swarm").is_ok());
        assert!(may_claim(&n, None, "stranger").is_ok());
    }

    #[test]
    fn an_enrolled_but_unapproved_identity_cannot_claim() {
        let n = names();
        let missing = Path::new("no-such-pending-file.toml");
        assert!(may_claim(&n, Some(missing), "newcomer").is_ok());
        // A pending file that exists blocks; a file that is always there serves as one.
        let present = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let err = may_claim(&n, Some(&present), "newcomer").unwrap_err();
        assert!(err.to_string().contains("not approved"));
    }

    #[test]
    fn a_worker_refuses_ask_vps_and_plan_but_takes_build_work() {
        let n = names();
        let me = "ichabod-beastly-swarm";
        assert!(
            n.charter_refusal(me, &order("ask: where is x?", None))
                .is_some()
        );
        assert!(
            n.charter_refusal(me, &order("VPS: restart", None))
                .is_some()
        );
        let plan = order("build it", Some(crate::work::WorkKind::Plan));
        assert!(n.charter_refusal(me, &plan).is_some());
        let code = order("build it", Some(crate::work::WorkKind::CodeChange));
        assert!(n.charter_refusal(me, &code).is_none());
        assert!(
            n.charter_refusal("stranger", &order("ask: x", None))
                .is_none()
        );
    }

    #[test]
    fn enrolment_checks_role_and_alias_including_retired() {
        let n = names();
        assert!(check_enrollment(&n, "Wren", "worker.pi", "wren-pi").is_ok());
        assert!(check_enrollment(&n, "Wren", "boss.pi", "wren-pi").is_err());
        assert!(check_enrollment(&n, "ash", "worker.pi", "x").is_err());
        assert!(check_enrollment(&n, "Quantly", "worker.pi", "x").is_err());
        assert!(check_enrollment(&n, "Wren", "worker.pi", "codex-grouchly").is_err());
    }

    #[test]
    fn the_charter_block_carries_the_refusal_rule() {
        let n = names();
        let b = n
            .agent_for("ichabod-beastly-swarm")
            .unwrap()
            .charter_block();
        assert!(b.contains("Ichabod (worker.beastly)") && b.contains("ferry agent refuse"));
    }
}

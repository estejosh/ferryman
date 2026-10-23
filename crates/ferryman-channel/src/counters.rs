//! Shared counters: sequential ids (decision numbers, asset ids) handed out through the
//! channel so that two agents never take the same one (ADR 0028).
//!
//! A claim is a signed file `counters/<name>/<n>.<agent>.json`. The number `n` belongs to
//! the claim with the lowest `(claimed_at, agent, machine)` among the validly signed
//! claims for it; anyone who finds a better claim for their number has lost and takes the
//! next one. A claim that does not verify against the roster counts for nothing.
//!
//! # The guarantee, honestly
//!
//! * **Agents on one machine** are serialized by an OS lock on the machine, and read the
//!   claims of every earlier allocation off the same disk. They cannot collide.
//! * **Agents on different machines** can each claim the same `n` before either has seen
//!   the other's file. Both claims then exist, the rule above picks one winner everywhere,
//!   and the loser finds out when the other claim arrives. A number is therefore **final
//!   only after the settle window** (`--settle`, default long enough for Syncthing or iroh
//!   to deliver) **and only if every peer has been seen**. `ferry counter check` lists any
//!   number with more than one claim and who won, so a late loser is found, not silent.
//! * To make the safe thing the default where it matters, a project's master can write a
//!   signed **policy**: name an `allocator` (only that agent allocates; others are refused
//!   unless they ask for a `--provisional` number) and/or give agents disjoint `ranges`
//!   (an agent allocates only inside its own range, which cannot collide with anyone's).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::{AgentIdentity, ProjectRoute, SignatureCheck, check_signature, is_safe_component};

/// One signed claim on one number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub project_id: String,
    pub name: String,
    pub n: u64,
    pub agent: String,
    pub machine: String,
    pub claimed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Claim {
    fn payload(&self) -> String {
        format!(
            "ferryman-counter-claim-v1\n{}\n{}\n{}\n{}\n{}\n{}",
            self.project_id,
            self.name,
            self.n,
            self.agent,
            self.machine,
            self.claimed_at.to_rfc3339()
        )
    }

    fn rank(&self) -> (DateTime<Utc>, &str, &str) {
        (self.claimed_at, self.agent.as_str(), self.machine.as_str())
    }
}

fn dir(route: &ProjectRoute, name: &str) -> PathBuf {
    route.communications.join("counters").join(name)
}

fn claim_file(route: &ProjectRoute, name: &str, n: u64, agent: &str) -> PathBuf {
    dir(route, name).join(format!("{n}.{agent}.json"))
}

fn safe_name(name: &str) -> Result<()> {
    if !is_safe_component(name) || name.starts_with('.') {
        bail!("a counter name is letters, digits, '-', '_' and '.': '{name}'");
    }
    Ok(())
}

/// Write a signed claim for `n`. Public so a test can stand in for another machine.
pub fn claim_at(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    name: &str,
    n: u64,
    machine: &str,
    at: DateTime<Utc>,
) -> Result<Claim> {
    safe_name(name)?;
    let mut claim = Claim {
        project_id: route.project_id.clone(),
        name: name.to_owned(),
        n,
        agent: identity.name().to_owned(),
        machine: machine.to_owned(),
        claimed_at: at,
        signed_by: None,
        signature: None,
    };
    let signature = identity.signing.sign(claim.payload().as_bytes());
    claim.signed_by = Some(identity.name().to_owned());
    claim.signature = Some(hex::encode(signature.to_bytes()));
    crate::atomic_json(&claim_file(route, name, n, &claim.agent), &claim)?;
    Ok(claim)
}

/// Every validly signed claim on `name`, by number.
pub fn claims(route: &ProjectRoute, name: &str) -> Result<BTreeMap<u64, Vec<Claim>>> {
    safe_name(name)?;
    let roster = crate::read_agent_roster(&route.communications)?;
    let mut out: BTreeMap<u64, Vec<Claim>> = BTreeMap::new();
    let Ok(entries) = fs::read_dir(dir(route, name)) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json")
            || path.file_name().is_some_and(|n| n == "policy.json")
        {
            continue;
        }
        let Some(claim) = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Claim>(&b).ok())
        else {
            continue;
        };
        let expected = format!("{}.{}.json", claim.n, claim.agent);
        if claim.project_id != route.project_id
            || claim.name != name
            || path
                .file_name()
                .is_none_or(|f| f.to_string_lossy() != expected)
            || check_signature(
                claim.signed_by.as_ref(),
                claim.signature.as_ref(),
                &claim.payload(),
                &roster,
            ) != SignatureCheck::Valid
            || claim.signed_by.as_deref() != Some(claim.agent.as_str())
        {
            continue;
        }
        out.entry(claim.n).or_default().push(claim);
    }
    for list in out.values_mut() {
        list.sort_by(|a, b| a.rank().cmp(&b.rank()));
    }
    Ok(out)
}

/// A number and who holds it.
#[derive(Debug, Clone, Serialize)]
pub struct Held {
    pub n: u64,
    pub winner: Claim,
    pub losers: Vec<Claim>,
}

/// Every number taken, with the winner of each and any claim that lost it.
pub fn held(route: &ProjectRoute, name: &str) -> Result<Vec<Held>> {
    Ok(claims(route, name)?
        .into_iter()
        .map(|(n, mut list)| {
            let winner = list.remove(0);
            Held {
                n,
                winner,
                losers: list,
            }
        })
        .collect())
}

/// A master-signed rule for one counter.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub project_id: String,
    pub name: String,
    /// The one agent that allocates; others need `--provisional`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocator: Option<String>,
    /// Disjoint ranges, inclusive: an agent allocates only inside its own.
    #[serde(default)]
    pub ranges: BTreeMap<String, (u64, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Policy {
    fn payload(&self) -> String {
        let ranges: Vec<String> = self
            .ranges
            .iter()
            .map(|(a, (s, e))| format!("{a}={s}-{e}"))
            .collect();
        format!(
            "ferryman-counter-policy-v1\n{}\n{}\n{}\n{}",
            self.project_id,
            self.name,
            self.allocator.clone().unwrap_or_default(),
            ranges.join(",")
        )
    }
}

fn policy_path(route: &ProjectRoute, name: &str) -> PathBuf {
    dir(route, name).join("policy.json")
}

/// Set the policy for a counter. Only the project's master may.
pub fn set_policy(
    route: &ProjectRoute,
    master: &AgentIdentity,
    name: &str,
    allocator: Option<String>,
    ranges: BTreeMap<String, (u64, u64)>,
) -> Result<Policy> {
    safe_name(name)?;
    let Some(declaration) = crate::master::read_master(route)? else {
        bail!("this project has no master; only a master sets a counter policy");
    };
    if declaration.master != master.name() {
        bail!(
            "only the master ({}) sets a counter policy",
            declaration.master
        );
    }
    let mut spans: Vec<(u64, u64)> = ranges.values().copied().collect();
    spans.sort_unstable();
    if spans.iter().any(|(s, e)| s > e) || spans.windows(2).any(|w| w[0].1 >= w[1].0) {
        bail!("ranges must be well-formed and must not overlap");
    }
    let mut policy = Policy {
        project_id: route.project_id.clone(),
        name: name.to_owned(),
        allocator,
        ranges,
        signed_by: None,
        signature: None,
    };
    let signature = master.signing.sign(policy.payload().as_bytes());
    policy.signed_by = Some(master.name().to_owned());
    policy.signature = Some(hex::encode(signature.to_bytes()));
    crate::atomic_json(&policy_path(route, name), &policy)?;
    Ok(policy)
}

/// The policy, if one is there and the master signed it. One that does not verify is
/// ignored loudly by the caller, never obeyed.
pub fn policy(route: &ProjectRoute, name: &str) -> Result<Option<Policy>> {
    let Ok(bytes) = fs::read(policy_path(route, name)) else {
        return Ok(None);
    };
    let policy: Policy = serde_json::from_slice(&bytes).context("read counter policy")?;
    let roster = crate::read_agent_roster(&route.communications)?;
    let master = crate::master::read_master(route)?.map(|d| d.master);
    let valid = check_signature(
        policy.signed_by.as_ref(),
        policy.signature.as_ref(),
        &policy.payload(),
        &roster,
    ) == SignatureCheck::Valid
        && policy.signed_by == master
        && policy.project_id == route.project_id
        && policy.name == name;
    if !valid {
        bail!(
            "the policy for counter '{name}' is not signed by the master; refusing to allocate until it is fixed"
        );
    }
    Ok(Some(policy))
}

/// How to take the next number.
#[derive(Debug, Clone)]
pub struct NextOptions {
    /// The first number of a counter that has none yet (and a floor for later ones).
    pub start: u64,
    /// Wait this long after claiming, then check no better claim has arrived.
    pub settle: StdDuration,
    /// Take a number even though the policy names a different allocator.
    pub provisional: bool,
    /// The machine written into the claim.
    pub machine: String,
}

impl Default for NextOptions {
    fn default() -> Self {
        Self {
            start: 1,
            settle: StdDuration::ZERO,
            provisional: false,
            machine: crate::lanes::this_machine(),
        }
    }
}

fn local_lock(route: &ProjectRoute, name: &str) -> Result<fs::File> {
    let dir = route.attachment.join("runtime");
    fs::create_dir_all(&dir)?;
    let deadline = Instant::now() + StdDuration::from_secs(15);
    loop {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(format!("counter-{name}.lock")))?;
        if file.try_lock_exclusive().is_ok() {
            return Ok(file);
        }
        if Instant::now() >= deadline {
            bail!("another allocation of '{name}' has held the lock for 15s");
        }
        std::thread::sleep(StdDuration::from_millis(20));
    }
}

/// Take the next number of counter `name`.
pub fn next(
    route: &ProjectRoute,
    identity: &AgentIdentity,
    name: &str,
    opts: &NextOptions,
) -> Result<u64> {
    safe_name(name)?;
    let policy = policy(route, name)?;
    let me = identity.name();
    let mut range = None;
    if let Some(policy) = &policy {
        if let Some(r) = policy.ranges.get(me) {
            range = Some(*r);
        } else if let Some(allocator) = &policy.allocator
            && allocator != me
            && !opts.provisional
        {
            bail!(
                "counter '{name}' is allocated by '{allocator}'. Run this where that agent runs, or pass \
                 --provisional to take a number that is final only once `ferry counter check` shows you won it"
            );
        }
    }
    let _lock = local_lock(route, name)?;
    for _ in 0..100 {
        let all = claims(route, name)?;
        let (floor, ceiling) =
            range.map_or((opts.start, u64::MAX), |(s, e)| (s.max(opts.start), e));
        let highest = all
            .keys()
            .copied()
            .filter(|n| *n >= floor && *n <= ceiling)
            .max();
        let candidate = highest.map_or(floor, |h| h + 1);
        if candidate > ceiling {
            bail!("agent '{me}' has used its whole range for counter '{name}'");
        }
        let mine = claim_at(route, identity, name, candidate, &opts.machine, Utc::now())?;
        if !opts.settle.is_zero() {
            std::thread::sleep(opts.settle);
        }
        let now = claims(route, name)?;
        let won = now
            .get(&candidate)
            .and_then(|list| list.first())
            .is_some_and(|w| {
                w.agent == mine.agent
                    && w.machine == mine.machine
                    && w.claimed_at == mine.claimed_at
            });
        if won {
            return Ok(candidate);
        }
        // Lost to a claim that arrived first: step aside and take the next one.
        let _ = fs::remove_file(claim_file(route, name, candidate, me));
    }
    bail!("could not settle a number for '{name}' after 100 tries")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;
    use chrono::Duration;

    pub(crate) fn route_with(dir: &std::path::Path, who: &[&AgentIdentity]) -> ProjectRoute {
        let workspace = dir.join("repo");
        let attachment = workspace.join(".ferryman");
        let communications = dir.join("channel");
        fs::create_dir_all(&attachment).unwrap();
        fs::create_dir_all(&communications).unwrap();
        let route = ProjectRoute {
            project_id: "demo".into(),
            workspace,
            attachment,
            communications: communications.clone(),
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for i in who {
            crate::register_agent(
                &route,
                &AgentRoute {
                    name: i.name().into(),
                    role: "worker".into(),
                    capabilities: Vec::new(),
                    public_key: Some(i.public_key_hex()),
                    encryption_key: None,
                },
            )
            .unwrap();
        }
        ProjectRoute {
            agents: crate::read_agent_roster(&communications).unwrap(),
            ..route
        }
    }

    #[test]
    fn concurrent_allocations_on_one_machine_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let a = AgentIdentity::from_seed("ash", [1; 32]);
        let b = AgentIdentity::from_seed("rf", [2; 32]);
        let route = route_with(dir.path(), &[&a, &b]);
        let mut handles = Vec::new();
        for (i, (nm, seed)) in [("ash", 1u8), ("rf", 2u8)].into_iter().enumerate() {
            let route = route.clone();
            handles.push(std::thread::spawn(move || {
                let who = AgentIdentity::from_seed(nm, [seed; 32]);
                (0..15)
                    .map(|_| {
                        next(
                            &route,
                            &who,
                            "decision",
                            &NextOptions {
                                start: 30,
                                ..NextOptions::default()
                            },
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|n| (i, n))
                    .collect::<Vec<_>>()
            }));
        }
        let mut got: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .map(|(_, n)| n)
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            (30..60).collect::<Vec<u64>>(),
            "every number exactly once, none skipped"
        );
    }

    #[test]
    fn the_earlier_claim_wins_and_the_loser_takes_the_next_number() {
        let dir = tempfile::tempdir().unwrap();
        let a = AgentIdentity::from_seed("ash", [1; 32]);
        let b = AgentIdentity::from_seed("rf", [2; 32]);
        let route = route_with(dir.path(), &[&a, &b]);
        // Another machine claimed 30 a moment ago and its file has just arrived.
        let early = Utc::now() - Duration::seconds(5);
        claim_at(&route, &b, "decision", 30, "grouchly", early).unwrap();
        assert_eq!(
            next(
                &route,
                &a,
                "decision",
                &NextOptions {
                    start: 30,
                    ..NextOptions::default()
                }
            )
            .unwrap(),
            31
        );

        // Both machines claimed 31 before seeing each other: the earlier stamp wins
        // everywhere, and the tie-break on equal stamps is the agent name.
        let t = Utc::now() - Duration::seconds(1);
        claim_at(&route, &a, "decision", 40, "beastly", t).unwrap();
        claim_at(&route, &b, "decision", 40, "grouchly", t).unwrap();
        let held = held(&route, "decision").unwrap();
        let forty = held.iter().find(|h| h.n == 40).unwrap();
        assert_eq!(forty.winner.agent, "ash");
        assert_eq!(forty.losers.len(), 1);
        assert_eq!(forty.losers[0].agent, "rf");
    }

    #[test]
    fn a_claim_that_does_not_verify_counts_for_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let a = AgentIdentity::from_seed("ash", [1; 32]);
        let route = route_with(dir.path(), &[&a]);
        let stranger = AgentIdentity::from_seed("ash", [9; 32]); // same name, other key
        claim_at(
            &route,
            &stranger,
            "decision",
            30,
            "evil",
            Utc::now() - Duration::seconds(60),
        )
        .unwrap();
        assert!(claims(&route, "decision").unwrap().is_empty());
        assert_eq!(
            next(
                &route,
                &a,
                "decision",
                &NextOptions {
                    start: 30,
                    ..NextOptions::default()
                }
            )
            .unwrap(),
            30
        );
    }

    #[test]
    fn ranges_and_an_allocator_come_only_from_the_master() {
        let dir = tempfile::tempdir().unwrap();
        let master = AgentIdentity::from_seed("josh", [3; 32]);
        let a = AgentIdentity::from_seed("ash", [1; 32]);
        let b = AgentIdentity::from_seed("rf", [2; 32]);
        let route = route_with(dir.path(), &[&master, &a, &b]);
        crate::master::initialize_master(&route, &master, "josh").unwrap();
        assert!(set_policy(&route, &a, "asset", None, BTreeMap::new()).is_err());
        let ranges = BTreeMap::from([
            ("ash".to_string(), (1000, 1999)),
            ("rf".to_string(), (2000, 2999)),
        ]);
        set_policy(&route, &master, "asset", None, ranges).unwrap();
        assert_eq!(
            next(&route, &a, "asset", &NextOptions::default()).unwrap(),
            1000
        );
        assert_eq!(
            next(&route, &b, "asset", &NextOptions::default()).unwrap(),
            2000
        );
        assert_eq!(
            next(&route, &a, "asset", &NextOptions::default()).unwrap(),
            1001
        );

        set_policy(
            &route,
            &master,
            "decision",
            Some("josh".into()),
            BTreeMap::new(),
        )
        .unwrap();
        assert!(next(&route, &a, "decision", &NextOptions::default()).is_err());
        assert_eq!(
            next(
                &route,
                &a,
                "decision",
                &NextOptions {
                    provisional: true,
                    ..NextOptions::default()
                }
            )
            .unwrap(),
            1
        );
    }
}

//! One lane of the machine scheduler (ADR 0033): a single line of requests, a width, a
//! budget, leases, and tenant servers started on demand and stopped when idle.
//!
//! The lane is plain state. Every method takes `now` in seconds and nothing here reads a
//! clock, a process table or a disk, so it is deterministic and the state can be saved
//! between calls (it is `serde`). The `gpu` lane is this engine with the card's memory as
//! the budget; see [`crate::gpu`].
//!
//! # Rules
//!
//! - **One line.** Requests are ordered by effective priority, then by who asked first.
//! - **Aging.** Effective priority is the priority plus one point per `age_secs` waited, so
//!   a request that keeps losing eventually leads the line.
//! - **The head blocks.** If the first request in the line does not fit the budget, nothing
//!   behind it is granted until it does. A large request cannot be skipped forever by a
//!   stream of small ones. Ponytail: some budget idles while the head waits; backfill
//!   only if that is measured to matter.
//! - **Nothing is killed.** A grant ends when its holder releases it, or when its process
//!   is gone. A lapsed lease with a live process keeps the grant.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The knobs of one lane. Config, not state: callers set them on every load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// How many grants run at once.
    pub width: usize,
    /// The most `cost` held at once. 0 means no budget, only the width.
    pub budget: u64,
    /// How long a grant lasts without renewal.
    pub lease_secs: u64,
    /// How long a tenant stays up after its last grant or queued request.
    pub idle_secs: u64,
    /// Seconds waited per point of priority gained. 0 turns aging off.
    pub age_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            width: 1,
            budget: 0,
            lease_secs: 120,
            idle_secs: 300,
            age_secs: 60,
        }
    }
}

/// Someone waiting for a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    /// What it takes from the budget (for the gpu lane, megabytes of video memory).
    pub cost: u64,
    /// Higher goes first.
    pub priority: i64,
    /// A managed server this request needs. Started with the grant, stopped when idle.
    pub tenant: Option<String>,
    /// The process that will hold the grant, when known.
    pub pid: Option<u32>,
    pub queued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub cost: u64,
    pub tenant: Option<String>,
    pub pid: Option<u32>,
    pub priority: i64,
    pub waited_secs: u64,
    pub granted_at: u64,
    pub lease_until: u64,
}

/// What the lane wants done to a tenant server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantAction {
    Start(String),
    Stop(String),
}

/// One row of the line as a person sees it: holders first, then the queue in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub id: String,
    pub holder: bool,
    /// 1 is next. None for a holder.
    pub position: Option<usize>,
    /// How long it waited (so far, or before it was granted).
    pub wait_secs: u64,
    /// The priority it was given.
    pub priority: i64,
    /// The priority it counts with now, aging included.
    pub effective: i64,
    pub cost: u64,
    pub tenant: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lane {
    pub limits: Limits,
    queue: Vec<Request>,
    grants: Vec<Grant>,
    /// Tenant name -> the last second it was granted or still had work.
    tenants: BTreeMap<String, u64>,
}

impl Lane {
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    fn effective(&self, request: &Request, now: u64) -> i64 {
        let waited = now.saturating_sub(request.queued_at);
        let aged = waited.checked_div(self.limits.age_secs).unwrap_or(0);
        request
            .priority
            .saturating_add(i64::try_from(aged).unwrap_or(i64::MAX))
    }

    fn sort(&mut self, now: u64) {
        let mut keyed: Vec<(i64, Request)> = std::mem::take(&mut self.queue)
            .into_iter()
            .map(|r| (self.effective(&r, now), r))
            .collect();
        keyed.sort_by(|(ea, a), (eb, b)| {
            eb.cmp(ea)
                .then(a.queued_at.cmp(&b.queued_at))
                .then(a.id.cmp(&b.id))
        });
        self.queue = keyed.into_iter().map(|(_, r)| r).collect();
    }

    /// Join the line.
    ///
    /// # Errors
    /// The id is already queued or granted, or the request could never fit the budget.
    pub fn enqueue(&mut self, request: Request) -> Result<(), String> {
        if self.knows(&request.id) {
            return Err(format!("'{}' is already in the line", request.id));
        }
        if self.limits.budget > 0 && request.cost > self.limits.budget {
            return Err(format!(
                "'{}' needs {} but the lane's budget is {}",
                request.id, request.cost, self.limits.budget
            ));
        }
        self.queue.push(request);
        Ok(())
    }

    fn knows(&self, id: &str) -> bool {
        self.queue.iter().any(|r| r.id == id) || self.grants.iter().any(|g| g.id == id)
    }

    /// Leave the line without ever having been granted. True when it was waiting.
    pub fn cancel(&mut self, id: &str) -> bool {
        let before = self.queue.len();
        self.queue.retain(|r| r.id != id);
        self.queue.len() != before
    }

    /// Change a waiting request's priority.
    pub fn set_priority(&mut self, id: &str, priority: i64) -> bool {
        self.queue
            .iter_mut()
            .find(|r| r.id == id)
            .map(|r| r.priority = priority)
            .is_some()
    }

    /// Put a waiting request first in line, for the master. Nothing else jumps the line.
    pub fn bump(&mut self, id: &str, now: u64) -> bool {
        let top = self
            .queue
            .iter()
            .filter(|r| r.id != id)
            .map(|r| self.effective(r, now))
            .max();
        let Some(request) = self.queue.iter().find(|r| r.id == id) else {
            return false;
        };
        let aged = self.effective(request, now) - request.priority;
        let wanted = top.map_or(request.priority, |top| top + 1 - aged);
        self.set_priority(id, wanted.max(request.priority))
    }

    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    #[must_use]
    pub fn queued(&self) -> &[Request] {
        &self.queue
    }

    #[must_use]
    pub fn holds(&self, id: &str) -> bool {
        self.grants.iter().any(|g| g.id == id)
    }

    /// The line: holders, then the queue in the order it will be served.
    #[must_use]
    pub fn snapshot(&self, now: u64) -> Vec<Row> {
        let held = self.grants.iter().map(|g| Row {
            id: g.id.clone(),
            holder: true,
            position: None,
            wait_secs: g.waited_secs,
            priority: g.priority,
            effective: g.priority,
            cost: g.cost,
            tenant: g.tenant.clone(),
            pid: g.pid,
        });
        let mut waiting: Vec<(i64, &Request)> = self
            .queue
            .iter()
            .map(|r| (self.effective(r, now), r))
            .collect();
        waiting.sort_by(|(ea, a), (eb, b)| {
            eb.cmp(ea)
                .then(a.queued_at.cmp(&b.queued_at))
                .then(a.id.cmp(&b.id))
        });
        let queued = waiting.into_iter().enumerate().map(|(i, (eff, r))| Row {
            id: r.id.clone(),
            holder: false,
            position: Some(i + 1),
            wait_secs: now.saturating_sub(r.queued_at),
            priority: r.priority,
            effective: eff,
            cost: r.cost,
            tenant: r.tenant.clone(),
            pid: r.pid,
        });
        held.chain(queued).collect()
    }

    /// Hand out every grant that fits, first in line first, and start any tenant those need.
    pub fn schedule(&mut self, now: u64) -> Vec<TenantAction> {
        self.sort(now);
        let mut actions = Vec::new();
        while !self.queue.is_empty() && self.grants.len() < self.limits.width {
            let used: u64 = self.grants.iter().map(|g| g.cost).sum();
            let head = &self.queue[0];
            if self.limits.budget > 0 && used + head.cost > self.limits.budget {
                break;
            }
            let priority = head.priority;
            let req = self.queue.remove(0);
            if let Some(tenant) = &req.tenant
                && self.tenants.insert(tenant.clone(), now).is_none()
            {
                actions.push(TenantAction::Start(tenant.clone()));
            }
            self.grants.push(Grant {
                waited_secs: now.saturating_sub(req.queued_at),
                id: req.id,
                cost: req.cost,
                tenant: req.tenant,
                pid: req.pid,
                priority,
                granted_at: now,
                lease_until: now + self.limits.lease_secs,
            });
        }
        actions
    }

    /// The holder renews its lease. False when there is no such grant (it was taken back).
    pub fn renew(&mut self, id: &str, now: u64) -> bool {
        let Some(grant) = self.grants.iter_mut().find(|g| g.id == id) else {
            return false;
        };
        grant.lease_until = now + self.limits.lease_secs;
        // Only a tenant believed up has a last-used time; one that failed to start has none.
        if let Some(seen) = grant.tenant.as_ref().and_then(|t| self.tenants.get_mut(t)) {
            *seen = now;
        }
        true
    }

    /// The holder is done. Frees its grant.
    pub fn release(&mut self, id: &str, now: u64) {
        if let Some(pos) = self.grants.iter().position(|g| g.id == id) {
            let grant = self.grants.remove(pos);
            if let Some(seen) = grant.tenant.and_then(|t| self.tenants.get_mut(&t)) {
                *seen = now;
            }
        }
    }

    /// Take back the grants whose holder is gone. Returns the ids taken back.
    ///
    /// A grant whose process is not running is taken back at once. A grant whose lease
    /// lapsed is taken back only if no live process holds it: the card is never given to
    /// another job while the holder is still running, so a holder that forgot to renew
    /// keeps what it has.
    pub fn reap(&mut self, now: u64, alive: impl Fn(u32) -> bool) -> Vec<String> {
        let mut taken = Vec::new();
        self.grants.retain(|g| {
            let gone = match g.pid {
                Some(pid) => !alive(pid),
                None => g.lease_until <= now,
            };
            if gone {
                taken.push(g.id.clone());
            }
            !gone
        });
        taken
    }

    /// Stop every tenant that has had no grant or queued work for `idle_secs`.
    pub fn stop_idle_tenants(&mut self, now: u64) -> Vec<TenantAction> {
        let busy: Vec<String> = self
            .grants
            .iter()
            .filter_map(|g| g.tenant.clone())
            .chain(self.queue.iter().filter_map(|r| r.tenant.clone()))
            .collect();
        let idle_secs = self.limits.idle_secs;
        let mut stopped = Vec::new();
        self.tenants.retain(|name, last_used| {
            if busy.contains(name) {
                *last_used = now;
                return true;
            }
            if now.saturating_sub(*last_used) >= idle_secs {
                stopped.push(TenantAction::Stop(name.clone()));
                false
            } else {
                true
            }
        });
        stopped
    }

    /// A tenant that could not be started is not up: the next request starts it again.
    pub fn forget_tenant(&mut self, name: &str) {
        self.tenants.remove(name);
    }

    /// The tenants the lane believes are running.
    pub fn tenants(&self) -> impl Iterator<Item = &str> {
        self.tenants.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(width: usize, budget: u64) -> Lane {
        Lane::new(Limits {
            width,
            budget,
            lease_secs: 60,
            idle_secs: 300,
            age_secs: 60,
        })
    }

    fn req(id: &str, priority: i64, queued_at: u64) -> Request {
        Request {
            id: id.into(),
            cost: 1000,
            priority,
            tenant: None,
            pid: None,
            queued_at,
        }
    }

    fn held(lane: &Lane) -> Vec<&str> {
        lane.grants().iter().map(|g| g.id.as_str()).collect()
    }

    #[test]
    fn grants_one_at_a_time_in_priority_order() {
        let mut lane = lane(1, 24_000);
        for r in [req("low", 1, 0), req("high", 9, 0), req("mid", 5, 0)] {
            lane.enqueue(r).unwrap();
        }
        lane.schedule(10);
        assert_eq!(held(&lane), ["high"]);
        lane.release("high", 11);
        lane.schedule(11);
        assert_eq!(held(&lane), ["mid"]);
        lane.release("mid", 12);
        lane.schedule(12);
        assert_eq!(held(&lane), ["low"]);
    }

    #[test]
    fn aging_lets_a_large_job_lead_instead_of_being_skipped_forever() {
        let mut lane = lane(2, 10_000);
        lane.enqueue(Request {
            cost: 9_000,
            ..req("big", 0, 0)
        })
        .unwrap();
        lane.enqueue(Request {
            cost: 2_000,
            ..req("small-0", 5, 0)
        })
        .unwrap();
        lane.schedule(0);
        // The small job leads on priority; the big one does not fit beside it and waits.
        assert_eq!(held(&lane), ["small-0"]);
        // A stream of small, higher-priority jobs arrives and each is served in its turn
        // while the big one ages, one point a minute, until it leads them.
        let mut now = 0;
        for n in 1..=10 {
            now = n * 60;
            let id = lane.grants()[0].id.clone();
            lane.release(&id, now);
            lane.enqueue(Request {
                cost: 2_000,
                ..req(&format!("small-{n}"), 5, now)
            })
            .unwrap();
            lane.schedule(now);
            if lane.holds("big") {
                break;
            }
        }
        assert_eq!(held(&lane), ["big"]);
        assert_eq!(
            now, 300,
            "it leads once its aged priority reaches the others'"
        );
    }

    #[test]
    fn the_head_blocks_so_small_jobs_cannot_jump_a_job_that_does_not_fit_yet() {
        let mut lane = lane(3, 10_000);
        lane.enqueue(Request {
            cost: 6_000,
            ..req("a", 9, 0)
        })
        .unwrap();
        lane.enqueue(Request {
            cost: 8_000,
            ..req("big", 8, 0)
        })
        .unwrap();
        lane.enqueue(Request {
            cost: 1_000,
            ..req("small", 1, 0)
        })
        .unwrap();
        lane.schedule(0);
        assert_eq!(held(&lane), ["a"]);
        assert_eq!(lane.queued().len(), 2);
    }

    #[test]
    fn a_request_that_can_never_fit_is_refused() {
        let mut lane = lane(1, 10_000);
        let err = lane
            .enqueue(Request {
                cost: 20_000,
                ..req("huge", 0, 0)
            })
            .unwrap_err();
        assert!(err.contains("budget"), "{err}");
        assert!(lane.enqueue(req("a", 0, 0)).is_ok());
        assert!(lane.enqueue(req("a", 0, 0)).is_err(), "duplicate id");
    }

    #[test]
    fn bump_puts_a_request_first_and_priority_can_be_set() {
        let mut lane = lane(1, 0);
        lane.enqueue(req("a", 9, 0)).unwrap();
        lane.enqueue(req("b", 1, 0)).unwrap();
        lane.enqueue(req("c", 5, 0)).unwrap();
        assert!(lane.bump("b", 0));
        assert!(!lane.bump("nobody", 0));
        assert_eq!(lane.snapshot(0)[0].id, "b");
        assert!(lane.set_priority("c", 100));
        let ids: Vec<_> = lane.snapshot(0).into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["c", "b", "a"]);
    }

    #[test]
    fn the_snapshot_shows_holder_position_wait_and_priority() {
        let mut lane = lane(1, 0);
        lane.enqueue(req("a", 2, 0)).unwrap();
        lane.enqueue(req("b", 1, 30)).unwrap();
        lane.schedule(40);
        let rows = lane.snapshot(100);
        assert!(rows[0].holder && rows[0].id == "a" && rows[0].wait_secs == 40);
        assert_eq!(rows[1].position, Some(1));
        assert_eq!(rows[1].wait_secs, 70);
        assert_eq!(rows[1].priority, 1);
        assert_eq!(rows[1].effective, 2, "one point gained for the 60s waited");
    }

    #[test]
    fn a_lease_nobody_holds_is_taken_back_but_a_live_holder_keeps_its_grant() {
        let mut lane = lane(2, 0);
        lane.enqueue(req("no-process", 1, 0)).unwrap();
        lane.enqueue(Request {
            pid: Some(42),
            ..req("running", 1, 0)
        })
        .unwrap();
        lane.schedule(0);
        assert!(lane.renew("no-process", 50));
        assert!(lane.reap(100, |_| true).is_empty());
        // Both leases have lapsed at 200. The one with a live process is kept, so the
        // card is not given to someone else underneath it.
        assert_eq!(lane.reap(200, |_| true), ["no-process"]);
        assert_eq!(held(&lane), ["running"]);
        // Its process exits: taken back at once, lease or not.
        assert_eq!(lane.reap(201, |_| false), ["running"]);
        assert!(!lane.renew("running", 202));
    }

    #[test]
    fn a_tenant_starts_with_its_first_grant_and_stops_after_idle_time() {
        let mut lane = lane(1, 0);
        lane.enqueue(Request {
            tenant: Some("server".into()),
            ..req("a", 1, 0)
        })
        .unwrap();
        assert_eq!(lane.schedule(0), [TenantAction::Start("server".into())]);
        lane.release("a", 10);
        assert!(lane.stop_idle_tenants(100).is_empty());
        assert_eq!(
            lane.stop_idle_tenants(310),
            [TenantAction::Stop("server".into())]
        );
        assert_eq!(lane.tenants().count(), 0);
    }

    #[test]
    fn a_tenant_with_queued_work_is_not_stopped() {
        let mut lane = lane(1, 0);
        for id in ["a", "b"] {
            lane.enqueue(Request {
                tenant: Some("server".into()),
                ..req(id, 1, 0)
            })
            .unwrap();
        }
        lane.schedule(0);
        lane.release("a", 1);
        assert!(lane.stop_idle_tenants(10_000).is_empty());
    }

    #[test]
    fn state_survives_a_round_trip_through_json() {
        let mut lane = lane(1, 0);
        lane.enqueue(req("a", 1, 0)).unwrap();
        lane.enqueue(req("b", 1, 1)).unwrap();
        lane.schedule(2);
        let back: Lane = serde_json::from_str(&serde_json::to_string(&lane).unwrap()).unwrap();
        assert_eq!(back, lane);
    }
}

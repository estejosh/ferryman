//! The GPU lane: who may use the card, for how long, and what holds VRAM without a grant.
//!
//! Pure state. Every method takes `now` in seconds, so nothing here reads a clock and the
//! tests are deterministic. See `docs/GPU_SCHEDULER.md`.

use std::collections::BTreeMap;

/// A job that needs the GPU, waiting for a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRequest {
    pub id: String,
    pub vram_mb: u64,
    /// The dispatcher score (focus, unblocks, age, priority). Higher runs first.
    pub score: i64,
    /// A long-lived server this job needs, if any. Started with the grant, stopped when idle.
    pub tenant: Option<String>,
    pub queued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub vram_mb: u64,
    pub tenant: Option<String>,
    pub lease_until: u64,
}

/// What the lane wants done to a tenant server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantAction {
    Start(String),
    Stop(String),
}

/// A process seen holding VRAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuProc {
    pub pid: u32,
    pub name: String,
    pub vram_mb: u64,
    /// Marked `keep` by the master (desktop, games). Never reported as a problem.
    pub keep: bool,
}

#[derive(Debug)]
pub struct GpuLane {
    width: usize,
    vram_budget_mb: u64,
    lease_secs: u64,
    idle_secs: u64,
    queue: Vec<GpuRequest>,
    grants: Vec<Grant>,
    /// Tenant name -> the last second it was granted or still had work.
    tenants: BTreeMap<String, u64>,
}

impl GpuLane {
    /// `width` is how many grants run at once (1 on a single card). `lease_secs` is how long
    /// a grant lasts without renewal; `idle_secs` is how long a tenant stays up after its last job.
    #[must_use]
    pub fn new(width: usize, vram_budget_mb: u64, lease_secs: u64, idle_secs: u64) -> Self {
        Self {
            width,
            vram_budget_mb,
            lease_secs,
            idle_secs,
            queue: Vec::new(),
            grants: Vec::new(),
            tenants: BTreeMap::new(),
        }
    }

    pub fn enqueue(&mut self, request: GpuRequest) {
        self.queue.push(request);
    }

    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    #[must_use]
    pub fn queued(&self) -> &[GpuRequest] {
        &self.queue
    }

    /// Hand out every grant that fits, best score first, and start any tenant those need.
    pub fn schedule(&mut self, now: u64) -> Vec<TenantAction> {
        let mut actions = Vec::new();
        self.queue.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then(a.queued_at.cmp(&b.queued_at))
                .then(a.id.cmp(&b.id))
        });
        let mut i = 0;
        while i < self.queue.len() && self.grants.len() < self.width {
            let used: u64 = self.grants.iter().map(|g| g.vram_mb).sum();
            if used + self.queue[i].vram_mb > self.vram_budget_mb {
                i += 1;
                continue;
            }
            let req = self.queue.remove(i);
            if let Some(tenant) = &req.tenant
                && self.tenants.insert(tenant.clone(), now).is_none()
            {
                actions.push(TenantAction::Start(tenant.clone()));
            }
            self.grants.push(Grant {
                id: req.id,
                vram_mb: req.vram_mb,
                tenant: req.tenant,
                lease_until: now + self.lease_secs,
            });
        }
        actions
    }

    /// The running job renews its lease. False when there is no such grant (it was taken back).
    pub fn renew(&mut self, id: &str, now: u64) -> bool {
        let Some(grant) = self.grants.iter_mut().find(|g| g.id == id) else {
            return false;
        };
        grant.lease_until = now + self.lease_secs;
        if let Some(tenant) = &grant.tenant {
            self.tenants.insert(tenant.clone(), now);
        }
        true
    }

    /// The job is done. Frees its grant.
    pub fn release(&mut self, id: &str, now: u64) {
        if let Some(pos) = self.grants.iter().position(|g| g.id == id) {
            let grant = self.grants.remove(pos);
            if let Some(tenant) = grant.tenant {
                self.tenants.insert(tenant, now);
            }
        }
    }

    /// Take back every grant whose lease ran out. Returns the ids taken back.
    pub fn reap(&mut self, now: u64) -> Vec<String> {
        let mut taken = Vec::new();
        self.grants.retain(|g| {
            if g.lease_until <= now {
                taken.push(g.id.clone());
                false
            } else {
                true
            }
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
        let idle_secs = self.idle_secs;
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

    /// VRAM held by processes that are neither a running tenant nor marked `keep`.
    #[must_use]
    pub fn unmanaged_holders<'a>(
        &self,
        procs: &'a [GpuProc],
        tenant_pids: &[u32],
    ) -> Vec<&'a GpuProc> {
        procs
            .iter()
            .filter(|p| !p.keep && p.vram_mb > 0 && !tenant_pids.contains(&p.pid))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str, score: i64, queued_at: u64) -> GpuRequest {
        GpuRequest {
            id: id.into(),
            vram_mb: 1000,
            score,
            tenant: None,
            queued_at,
        }
    }

    #[test]
    fn grants_one_at_a_time_in_score_order() {
        let mut lane = GpuLane::new(1, 24_000, 60, 300);
        lane.enqueue(req("low", 1, 0));
        lane.enqueue(req("high", 9, 5));
        lane.enqueue(req("mid", 5, 2));
        lane.schedule(10);
        assert_eq!(
            lane.grants()
                .iter()
                .map(|g| g.id.as_str())
                .collect::<Vec<_>>(),
            ["high"]
        );
        lane.release("high", 11);
        lane.schedule(11);
        assert_eq!(lane.grants()[0].id, "mid");
        lane.release("mid", 12);
        lane.schedule(12);
        assert_eq!(lane.grants()[0].id, "low");
    }

    #[test]
    fn unrenewed_lease_is_taken_back() {
        let mut lane = GpuLane::new(1, 24_000, 60, 300);
        lane.enqueue(req("a", 1, 0));
        lane.schedule(0);
        assert!(lane.renew("a", 50));
        assert!(lane.reap(100).is_empty());
        assert_eq!(lane.reap(110), ["a"]);
        assert!(!lane.renew("a", 111));
    }

    #[test]
    fn idle_tenant_is_stopped_after_idle_time() {
        let mut lane = GpuLane::new(1, 24_000, 60, 300);
        lane.enqueue(GpuRequest {
            tenant: Some("llm".into()),
            ..req("a", 1, 0)
        });
        assert_eq!(lane.schedule(0), [TenantAction::Start("llm".into())]);
        lane.release("a", 10);
        assert!(lane.stop_idle_tenants(100).is_empty());
        assert_eq!(
            lane.stop_idle_tenants(310),
            [TenantAction::Stop("llm".into())]
        );
    }

    #[test]
    fn vram_holder_without_grant_is_reported_unless_kept() {
        let lane = GpuLane::new(1, 24_000, 60, 300);
        let procs = [
            GpuProc {
                pid: 1,
                name: "llama-server".into(),
                vram_mb: 13_000,
                keep: false,
            },
            GpuProc {
                pid: 2,
                name: "dwm".into(),
                vram_mb: 300,
                keep: true,
            },
            GpuProc {
                pid: 3,
                name: "comfy".into(),
                vram_mb: 5_000,
                keep: false,
            },
        ];
        let held = lane.unmanaged_holders(&procs, &[3]);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].name, "llama-server");
    }

    #[test]
    fn vram_budget_skips_a_job_that_does_not_fit() {
        let mut lane = GpuLane::new(2, 10_000, 60, 300);
        lane.enqueue(GpuRequest {
            vram_mb: 8_000,
            ..req("big", 9, 0)
        });
        lane.enqueue(GpuRequest {
            vram_mb: 8_000,
            ..req("big2", 8, 1)
        });
        lane.enqueue(GpuRequest {
            vram_mb: 1_000,
            ..req("small", 1, 2)
        });
        lane.schedule(0);
        let ids: Vec<&str> = lane.grants().iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, ["big", "small"]);
    }
}

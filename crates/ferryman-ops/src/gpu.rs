//! The `gpu` lane of the machine scheduler (ADR 0033): who may use the card, in one line.
//!
//! [`crate::sched::Lane`] is the engine; this is the card-shaped part around it:
//!
//! - the `[gpu]` config from `<root>/ferry.toml` (width, memory budget, tenants);
//! - the lane's state, kept on disk under a file lock so that the worker, `ferry gpu run`,
//!   `ferry gpu acquire` and `ferry gpu status` in different processes see one line;
//! - the executor for tenant servers (start when a grant needs one, stop when idle);
//! - a lease that the holder renews ([`Hold`]);
//! - what is holding video memory without a grant.
//!
//! No daemon: whoever touches the lane drives it ([`Gpu::step`]). The worker steps it once
//! per pass, so idle tenants are stopped even when nobody is asking.
//!
//! Nothing here is specific to a machine, a vendor tool or a project. Tenants, their
//! start and stop commands and the memory budget all come from config. See
//! `docs/GPU_SCHEDULER.md`.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::Deserialize;

use crate::sched::{Lane, Limits, Request, Row, TenantAction};

/// A managed server. Started with the first grant that names it, stopped when idle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Tenant {
    /// Shell command that launches the server and returns. Safe to run when it is up.
    pub start: String,
    /// Shell command that stops it. Empty means Ferryman cannot stop it and says so.
    pub stop: String,
    /// Part of the server's process name, so its memory is not reported as unmanaged.
    pub process: String,
}

/// `[gpu]` in `<root>/ferry.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct GpuConfig {
    /// Grants at once. 1 on a single card.
    pub width: usize,
    /// Megabytes of video memory Ferryman may hand out at once. 0 means no budget.
    pub vram_mb: u64,
    pub lease_secs: u64,
    pub idle_secs: u64,
    /// Seconds waited per point of priority gained.
    pub age_secs: u64,
    /// Process names (a part is enough) that are never reported: the desktop, games.
    pub keep: Vec<String>,
    pub tenants: BTreeMap<String, Tenant>,
}

impl Default for GpuConfig {
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            width: limits.width,
            vram_mb: limits.budget,
            lease_secs: limits.lease_secs,
            idle_secs: limits.idle_secs,
            age_secs: limits.age_secs,
            keep: Vec::new(),
            tenants: BTreeMap::new(),
        }
    }
}

impl GpuConfig {
    /// `[gpu]` from `<root>/ferry.toml`; the defaults when there is none.
    ///
    /// # Errors
    /// The file exists and its `[gpu]` table is not valid. A lane that guessed would hand
    /// out the card on a width nobody chose.
    pub fn load(root: &Path) -> Result<Self> {
        #[derive(Deserialize, Default)]
        struct Doc {
            #[serde(default)]
            gpu: Option<GpuConfig>,
        }
        let path = root.join("ferry.toml");
        let Ok(text) = fs::read_to_string(&path) else {
            return Ok(Self::default());
        };
        let doc: Doc =
            toml::from_str(&text).with_context(|| format!("[gpu] in {}", path.display()))?;
        let config = doc.gpu.unwrap_or_default();
        if config.width == 0 {
            bail!(
                "[gpu] width is 0 in {}: nothing could ever run",
                path.display()
            );
        }
        Ok(config)
    }

    #[must_use]
    pub fn limits(&self) -> Limits {
        Limits {
            width: self.width,
            budget: self.vram_mb,
            lease_secs: self.lease_secs,
            idle_secs: self.idle_secs,
            age_secs: self.age_secs,
        }
    }
}

/// Seconds since the epoch.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Where the lane's state lives: `<machine state>/gpu`.
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("gpu"))
}

/// What someone asking for the card says.
#[derive(Debug, Clone)]
pub struct Ask {
    /// Unique in the lane. See [`Gpu::new_id`].
    pub id: String,
    /// Who is asking. A configured tenant name makes the server start with the grant.
    pub who: String,
    pub vram_mb: u64,
    pub priority: i64,
    /// The process that holds the grant. While it runs the grant is kept.
    pub pid: Option<u32>,
}

/// How long to wait for a grant, and how to stop waiting.
#[derive(Debug, Clone)]
pub struct Wait {
    pub timeout: Option<Duration>,
    pub poll: Duration,
    /// Set by the caller to give up (the order was dropped).
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for Wait {
    fn default() -> Self {
        Self {
            timeout: None,
            poll: Duration::from_secs(1),
            cancel: None,
        }
    }
}

/// The lane on this machine.
#[derive(Debug, Clone)]
pub struct Gpu {
    dir: PathBuf,
    pub config: GpuConfig,
}

impl Gpu {
    #[must_use]
    pub fn new(dir: PathBuf, config: GpuConfig) -> Self {
        Self { dir, config }
    }

    /// A lane id that no other asker has: `<who>-<pid>-<n>`.
    #[must_use]
    pub fn new_id(who: &str) -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            "{who}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Run `f` on the lane with the file lock held; save what it did.
    fn with<T>(&self, f: impl FnOnce(&mut Lane) -> T) -> Result<T> {
        fs::create_dir_all(&self.dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("lane.lock"))?;
        lock.lock_exclusive()?;
        let path = self.dir.join("lane.json");
        let mut lane: Lane = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        lane.limits = self.config.limits();
        let out = f(&mut lane);
        let tmp = self.dir.join("lane.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&lane)?)?;
        fs::rename(&tmp, &path)?;
        File::unlock(&lock)?;
        Ok(out)
    }

    /// Take back what is gone, hand out what fits, stop what is idle. Returns what the
    /// lane wants done to tenant servers; [`Gpu::apply`] does it.
    ///
    /// # Errors
    /// The lane's state could not be read or written.
    pub fn tick(&self, now: u64, alive: impl Fn(u32) -> bool) -> Result<Vec<TenantAction>> {
        self.with(|lane| {
            lane.reap(now, alive);
            let mut actions = lane.schedule(now);
            actions.extend(lane.stop_idle_tenants(now));
            actions
        })
    }

    /// Carry out tenant actions, outside the lock. A start that fails is forgotten, so the
    /// next request starts it again. Returns what went wrong, for the caller to say.
    pub fn apply(
        &self,
        actions: &[TenantAction],
        run: &mut dyn FnMut(&str) -> bool,
    ) -> Vec<String> {
        let mut problems = Vec::new();
        for action in actions {
            match action {
                TenantAction::Start(name) => {
                    let command = self.config.tenants.get(name).map_or("", |t| &t.start);
                    if command.is_empty() || !run(command) {
                        problems.push(format!("tenant '{name}' did not start"));
                        let _ = self.with(|lane| lane.forget_tenant(name));
                    }
                }
                TenantAction::Stop(name) => {
                    let command = self.config.tenants.get(name).map_or("", |t| &t.stop);
                    if command.is_empty() {
                        problems.push(format!("tenant '{name}' has no stop command"));
                    } else if !run(command) {
                        problems.push(format!("tenant '{name}' did not stop"));
                    }
                }
            }
        }
        problems
    }

    /// One turn of the lane: [`Gpu::tick`] then [`Gpu::apply`], with the real process table
    /// and a real shell.
    ///
    /// # Errors
    /// The lane's state could not be read or written.
    pub fn step(&self) -> Result<Vec<String>> {
        let actions = self.tick(now(), crate::agent::process_alive)?;
        Ok(self.apply(&actions, &mut shell))
    }

    /// Join the line.
    ///
    /// # Errors
    /// The id is taken, the request can never fit the budget, or the state is unwritable.
    pub fn enqueue(&self, ask: &Ask, now: u64) -> Result<()> {
        let tenant = self
            .config
            .tenants
            .contains_key(&ask.who)
            .then(|| ask.who.clone());
        let request = Request {
            id: ask.id.clone(),
            cost: ask.vram_mb,
            priority: ask.priority,
            tenant,
            pid: ask.pid,
            queued_at: now,
        };
        self.with(|lane| lane.enqueue(request))?
            .map_err(anyhow::Error::msg)
    }

    /// Join the line and wait for the card. Returns the id to renew and release.
    ///
    /// Gives up (and leaves the line) at the timeout or when `wait.cancel` is set.
    ///
    /// # Errors
    /// Refused at enqueue, timed out, cancelled, or the state is unwritable.
    pub fn acquire(&self, ask: &Ask, wait: &Wait) -> Result<String> {
        self.enqueue(ask, now())?;
        let start = Instant::now();
        loop {
            self.step()?;
            if self.with(|lane| lane.holds(&ask.id))? {
                return Ok(ask.id.clone());
            }
            let cancelled = wait
                .cancel
                .as_ref()
                .is_some_and(|c| c.load(Ordering::Relaxed));
            let timed_out = wait.timeout.is_some_and(|t| start.elapsed() >= t);
            if cancelled || timed_out {
                self.with(|lane| lane.cancel(&ask.id))?;
                bail!(
                    "{} for the gpu lane: '{}' gave up its place in the line",
                    if cancelled {
                        "cancelled"
                    } else {
                        "timed out waiting"
                    },
                    ask.id
                );
            }
            std::thread::sleep(wait.poll);
        }
    }

    /// Give the card back (or leave the line), then let the next in line have it.
    ///
    /// # Errors
    /// The state could not be read or written.
    pub fn release(&self, id: &str) -> Result<()> {
        self.with(|lane| {
            if !lane.cancel(id) {
                lane.release(id, now());
            }
        })?;
        self.step().map(|_| ())
    }

    /// Renew a lease. False when the grant was taken back.
    ///
    /// # Errors
    /// The state could not be read or written.
    pub fn renew(&self, id: &str) -> Result<bool> {
        self.with(|lane| lane.renew(id, now()))
    }

    /// The master puts a waiting request first, or gives it a priority.
    ///
    /// # Errors
    /// The state could not be read or written.
    pub fn bump(&self, id: &str, priority: Option<i64>) -> Result<bool> {
        self.with(|lane| match priority {
            Some(p) => lane.set_priority(id, p),
            None => lane.bump(id, now()),
        })
    }

    /// The line and the tenants the lane believes are up.
    ///
    /// # Errors
    /// The state could not be read or written.
    pub fn snapshot(&self, now: u64) -> Result<(Vec<Row>, Vec<String>)> {
        self.with(|lane| {
            (
                lane.snapshot(now),
                lane.tenants().map(str::to_string).collect(),
            )
        })
    }

    /// Whatever holds video memory with no grant behind it, from the real card and the
    /// real process table. Empty when there is no `nvidia-smi` to ask.
    ///
    /// # Errors
    /// The state could not be read or written.
    pub fn unmanaged_now(&self) -> Result<Vec<GpuProc>> {
        let Some(procs) = sample_procs() else {
            return Ok(Vec::new());
        };
        let (rows, tenants) = self.snapshot(now())?;
        let granted: Vec<u32> = rows
            .iter()
            .filter(|r| r.holder)
            .filter_map(|r| r.pid)
            .collect();
        let parents = parent_map();
        Ok(unmanaged_holders(
            &self.config,
            &procs,
            &granted,
            &tenants,
            &|pid| parents.get(&pid).copied(),
        ))
    }
}

/// A grant being held: the lease is renewed until this drops, then the card is released.
/// Nothing is killed if the lease was taken back; the job just no longer owns the line.
pub struct Hold {
    gpu: Gpu,
    id: String,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Hold {
    #[must_use]
    pub fn new(gpu: &Gpu, id: String) -> Self {
        let (stop, rx) = mpsc::channel::<()>();
        let every = Duration::from_secs((gpu.config.lease_secs / 3).max(1));
        let (renewer, renew_id) = (gpu.clone(), id.clone());
        let thread = std::thread::spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(every) {
                let _ = renewer.renew(&renew_id);
            }
        });
        Self {
            gpu: gpu.clone(),
            id,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = self.gpu.release(&self.id);
    }
}

/// Run a command through the platform shell, waiting for it. True when it succeeded.
fn shell(command: &str) -> bool {
    let (program, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    Command::new(program)
        .args([flag, command])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A process holding video memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuProc {
    pub pid: u32,
    pub name: String,
    pub vram_mb: u64,
}

/// `nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits`.
#[must_use]
pub fn parse_smi(csv: &str) -> Vec<GpuProc> {
    csv.lines()
        .filter_map(|line| {
            let mut parts = line.split(',').map(str::trim);
            let pid = parts.next()?.parse().ok()?;
            let name = parts.next()?.to_string();
            let vram_mb = parts.next()?.parse().ok()?;
            Some(GpuProc { pid, name, vram_mb })
        })
        .collect()
}

/// The card's compute processes, or None when there is nothing to ask.
#[must_use]
pub fn sample_procs() -> Option<Vec<GpuProc>> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,process_name,used_memory",
            "--format=csv,noheader,nounits",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_smi(&String::from_utf8_lossy(&out.stdout)))
}

/// Every running process's parent, from the real process table.
#[must_use]
pub fn parent_map() -> BTreeMap<u32, u32> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    system
        .processes()
        .iter()
        .filter_map(|(pid, p)| Some((pid.as_u32(), p.parent()?.as_u32())))
        .collect()
}

/// Processes holding memory that no grant, no running tenant and no `keep` entry explains.
///
/// A process is a grant's if it, or any process above it, is the pid a grant names: the job
/// `ferry gpu run` starts is a child of the holder.
#[must_use]
pub fn unmanaged_holders(
    config: &GpuConfig,
    procs: &[GpuProc],
    granted_pids: &[u32],
    running_tenants: &[String],
    parent_of: &dyn Fn(u32) -> Option<u32>,
) -> Vec<GpuProc> {
    let tenant_names: Vec<String> = running_tenants
        .iter()
        .filter_map(|name| config.tenants.get(name))
        .filter(|t| !t.process.is_empty())
        .map(|t| t.process.to_ascii_lowercase())
        .collect();
    let named = |name: &str, parts: &[String]| {
        let name = name.to_ascii_lowercase();
        parts.iter().any(|p| !p.is_empty() && name.contains(p))
    };
    let keep: Vec<String> = config.keep.iter().map(|k| k.to_ascii_lowercase()).collect();
    procs
        .iter()
        .filter(|p| p.vram_mb > 0)
        .filter(|p| !named(&p.name, &keep) && !named(&p.name, &tenant_names))
        .filter(|p| {
            let mut at = Some(p.pid);
            for _ in 0..64 {
                match at {
                    Some(pid) if granted_pids.contains(&pid) => return false,
                    Some(pid) => at = parent_of(pid),
                    None => break,
                }
            }
            true
        })
        .cloned()
        .collect()
}

/// What the worker calls before it starts an order that needs the card: the order's
/// `gpu_mem_gb` hint says it does. Waits in the line; the returned [`Hold`] keeps the
/// grant until the order's run ends. None when the order does not need the card.
///
/// # Errors
/// The lane could not be opened or the request was refused.
pub async fn hold_for_order(
    route: &ferryman_channel::ProjectRoute,
    order_id: &str,
) -> Result<Option<Hold>> {
    let Ok(task) = ferryman_channel::read_task(route, order_id) else {
        return Ok(None);
    };
    let Some(gb) = task
        .order
        .needs
        .as_ref()
        .and_then(|needs| needs.hints.as_ref())
        .and_then(|hints| hints.gpu_mem_gb)
    else {
        return Ok(None);
    };
    let root = ferryman_channel::ferry::find_root().map(|root| root.path);
    let config = match &root {
        Some(root) => GpuConfig::load(root)?,
        None => GpuConfig::default(),
    };
    let dir = state_dir().context("no per-user state directory on this machine")?;
    let gpu = Gpu::new(dir, config);
    let priority = match task.order.priority {
        Some(ferryman_channel::Priority::High) => 20,
        Some(ferryman_channel::Priority::Low) => 0,
        _ => 10,
    };
    let ask = Ask {
        id: Gpu::new_id(&format!("order-{order_id}")),
        who: format!("order-{order_id}"),
        vram_mb: u64::from(gb) * 1024,
        priority,
        pid: Some(std::process::id()),
    };
    // A dropped future cannot stop a blocking wait by itself; the flag does.
    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let cancel = Cancel(Arc::new(AtomicBool::new(false)));
    let wait = Wait {
        cancel: Some(cancel.0.clone()),
        ..Wait::default()
    };
    let waiting = gpu.clone();
    let id = tokio::task::spawn_blocking(move || waiting.acquire(&ask, &wait))
        .await
        .context("the gpu wait stopped")??;
    // Granted; the flag is only read while waiting, so dropping it now cancels nothing.
    drop(cancel);
    Ok(Some(Hold::new(&gpu, id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu(dir: &Path, extra: &str) -> Gpu {
        let toml = format!("[gpu]\nlease_secs = 60\nidle_secs = 300\n{extra}");
        fs::write(dir.join("ferry.toml"), toml).unwrap();
        Gpu::new(dir.join("state"), GpuConfig::load(dir).unwrap())
    }

    fn ask(id: &str, who: &str, priority: i64) -> Ask {
        Ask {
            id: id.into(),
            who: who.into(),
            vram_mb: 1000,
            priority,
            pid: None,
        }
    }

    fn holder_ids(gpu: &Gpu) -> Vec<String> {
        gpu.snapshot(now())
            .unwrap()
            .0
            .into_iter()
            .filter(|r| r.holder)
            .map(|r| r.id)
            .collect()
    }

    #[test]
    fn config_reads_tenants_and_refuses_a_zero_width() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(
            dir.path(),
            "width = 2\nvram_mb = 24000\nkeep = [\"desktop\"]\n[gpu.tenants.llm]\nstart = \"s\"\nstop = \"t\"\nprocess = \"server\"\n",
        );
        assert_eq!(gpu.config.width, 2);
        assert_eq!(gpu.config.tenants["llm"].stop, "t");
        fs::write(dir.path().join("ferry.toml"), "[gpu]\nwidth = 0\n").unwrap();
        assert!(GpuConfig::load(dir.path()).is_err());
        fs::remove_file(dir.path().join("ferry.toml")).unwrap();
        assert_eq!(GpuConfig::load(dir.path()).unwrap().width, 1);
    }

    #[test]
    fn two_orders_and_a_run_are_granted_one_at_a_time_in_priority_order() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(dir.path(), "");
        // Two queued orders and one `ferry gpu run`, asked in the wrong order.
        gpu.enqueue(&ask("order-1", "order-1", 10), 1_000).unwrap();
        gpu.enqueue(&ask("run-1", "tool", 20), 1_001).unwrap();
        gpu.enqueue(&ask("order-2", "order-2", 0), 1_002).unwrap();
        let mut served = Vec::new();
        for _ in 0..3 {
            let actions = gpu.tick(1_010, |_| true).unwrap();
            assert!(actions.is_empty());
            let held = holder_ids(&gpu);
            assert_eq!(held.len(), 1, "one at a time: {held:?}");
            served.push(held[0].clone());
            gpu.release(&held[0]).unwrap();
        }
        assert_eq!(served, ["run-1", "order-1", "order-2"]);
    }

    #[test]
    fn a_lapsed_lease_is_taken_back_unless_the_holder_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(dir.path(), "");
        gpu.enqueue(&ask("quiet", "x", 1), 0).unwrap();
        gpu.tick(0, |_| true).unwrap();
        gpu.tick(30, |_| true).unwrap();
        assert_eq!(holder_ids(&gpu), ["quiet"]);
        gpu.tick(100_000_000_000, |_| true).unwrap();
        assert!(
            holder_ids(&gpu).is_empty(),
            "no process, lease lapsed: taken back"
        );
    }

    #[test]
    fn an_idle_tenant_is_stopped_after_its_idle_time_and_started_again_when_needed() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(
            dir.path(),
            "[gpu.tenants.llm]\nstart = \"start-llm\"\nstop = \"stop-llm\"\n",
        );
        let ran = std::cell::RefCell::new(Vec::<String>::new());
        let mut run = |c: &str| {
            ran.borrow_mut().push(c.to_string());
            true
        };
        gpu.enqueue(&ask("a", "llm", 1), 0).unwrap();
        let actions = gpu.tick(0, |_| true).unwrap();
        assert!(gpu.apply(&actions, &mut run).is_empty());
        gpu.with(|lane| lane.release("a", 10)).unwrap();
        assert!(gpu.tick(100, |_| true).unwrap().is_empty());
        let actions = gpu.tick(310, |_| true).unwrap();
        assert!(gpu.apply(&actions, &mut run).is_empty());
        assert_eq!(*ran.borrow(), ["start-llm", "stop-llm"]);
        gpu.enqueue(&ask("b", "llm", 1), 400).unwrap();
        let actions = gpu.tick(400, |_| true).unwrap();
        gpu.apply(&actions, &mut run);
        assert_eq!(*ran.borrow(), ["start-llm", "stop-llm", "start-llm"]);
    }

    #[test]
    fn a_tenant_that_fails_to_start_is_reported_and_tried_again() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(dir.path(), "[gpu.tenants.llm]\nstart = \"x\"\n");
        gpu.enqueue(&ask("a", "llm", 1), 0).unwrap();
        let actions = gpu.tick(0, |_| true).unwrap();
        let problems = gpu.apply(&actions, &mut |_| false);
        assert_eq!(problems, ["tenant 'llm' did not start"]);
        gpu.enqueue(&ask("b", "llm", 1), 1).unwrap();
        gpu.with(|lane| lane.release("a", 1)).unwrap();
        assert_eq!(
            gpu.tick(2, |_| true).unwrap(),
            [TenantAction::Start("llm".into())]
        );
    }

    #[test]
    fn bump_and_the_snapshot_work_through_the_shared_state() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(dir.path(), "");
        gpu.enqueue(&ask("a", "x", 9), 0).unwrap();
        gpu.enqueue(&ask("b", "x", 1), 0).unwrap();
        gpu.enqueue(&ask("c", "x", 1), 0).unwrap();
        assert!(gpu.bump("c", None).unwrap());
        assert!(!gpu.bump("nobody", None).unwrap());
        let (rows, _) = gpu.snapshot(10).unwrap();
        let order: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(order, ["c", "a", "b"]);
        assert_eq!(rows[0].position, Some(1));
    }

    #[test]
    fn acquire_waits_its_turn_and_a_hold_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let gpu = gpu(dir.path(), "");
        let wait = Wait {
            poll: Duration::from_millis(10),
            ..Wait::default()
        };
        let id = gpu.acquire(&ask("first", "x", 1), &wait).unwrap();
        let hold = Hold::new(&gpu, id);
        let timed = Wait {
            timeout: Some(Duration::from_millis(100)),
            ..wait.clone()
        };
        let err = gpu.acquire(&ask("second", "x", 1), &timed).unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert_eq!(holder_ids(&gpu), ["first"]);
        assert!(
            gpu.snapshot(now())
                .unwrap()
                .0
                .iter()
                .all(|r| r.id != "second")
        );
        drop(hold);
        assert!(gpu.acquire(&ask("third", "x", 1), &wait).is_ok());
    }

    #[test]
    fn smi_output_parses_and_memory_without_a_grant_is_reported() {
        let procs = parse_smi(
            "101, /usr/bin/model-server, 13000\n202, desktop-shell, 300\n303, job, 5000\n404, child-of-job, 100\nbad line\n",
        );
        assert_eq!(procs.len(), 4);
        let config = GpuConfig {
            keep: vec!["Desktop".into()],
            tenants: BTreeMap::from([(
                "llm".to_string(),
                Tenant {
                    process: "model-server".into(),
                    ..Tenant::default()
                },
            )]),
            ..GpuConfig::default()
        };
        let parent = |pid| (pid == 404).then_some(303);
        // 101 is a running tenant, 202 is kept, 303 holds a grant, 404 is under it.
        let held = unmanaged_holders(&config, &procs, &[303], &["llm".into()], &parent);
        assert!(held.is_empty(), "{held:?}");
        // The tenant is not up and nothing is granted: only the kept process is exempt.
        let held = unmanaged_holders(&config, &procs, &[], &[], &parent);
        let pids: Vec<u32> = held.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [101, 303, 404]);
    }
}

//! What this machine remembers of reading a channel, so an idle poll does not read it again.
//!
//! A worker re-lists every task on every pass. On a channel with thousands of finished
//! tasks nearly all of that is the same answer as last time, and getting it meant opening,
//! parsing and signature-checking every file again. This keeps, per task folder, the parsed
//! task together with a fingerprint (name, size, modified time) of the files it was read
//! from, and the trust it was judged under.
//!
//! It lives in this process's memory: machine state, never written into the channel, and
//! gone when the worker restarts. Nothing in it is believed on its own:
//!
//! - A task is served from memory only if every file in its folder (and in each Worker's
//!   hand-in folder for it) has the same name, size and modified time as when it was read.
//! - And only under the same trust: the roster the signatures were checked against, the
//!   Worker-level agents whose files are refused, and the master's declaration, grants,
//!   delegations, access levels and head. A revocation, a roster change, a grant or a new
//!   master changes one of those, so every verdict is judged again.
//! - A file touched in the last couple of seconds is never remembered (the same "racy"
//!   rule git uses for its index), so a rewrite within the clock's resolution cannot be
//!   missed.
//! - A task with an offer or a delegated review is never remembered: whether those count
//!   depends on the time as well as on files.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Task;

/// How recently a file must have been written to be distrusted: inside this window a change
/// could share a timestamp with the read that remembered it.
const SETTLE: Duration = Duration::from_secs(2);

/// Name, size and modified time (ns) of each file in some folders.
pub(crate) type Stamp = Vec<(String, u64, i128)>;

/// A [`Stamp`], and whether every file in it is old enough to be believed.
#[derive(Debug, Default, Clone)]
pub(crate) struct Fingerprint {
    pub stamp: Stamp,
    unsettled: bool,
}

impl Fingerprint {
    /// Add the files directly inside `dir`, named `label` + file name. A folder that is not
    /// there is recorded as absent, so its appearing changes the fingerprint.
    pub fn add_dir(&mut self, label: &str, dir: &Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            self.stamp.push((label.to_string(), 0, -1));
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            self.push(
                format!("{label}{}", entry.file_name().to_string_lossy()),
                &meta,
                now,
            );
        }
    }

    /// Add one file (absent is recorded as absent).
    pub fn add_file(&mut self, label: &str, path: &Path) {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() => self.push(label.to_string(), &meta, SystemTime::now()),
            _ => self.stamp.push((label.to_string(), 0, -1)),
        }
    }

    fn push(&mut self, name: String, meta: &std::fs::Metadata, now: SystemTime) {
        let modified = meta.modified().unwrap_or(UNIX_EPOCH);
        let nanos = match modified.duration_since(UNIX_EPOCH) {
            Ok(after) => i128::try_from(after.as_nanos()).unwrap_or(i128::MAX),
            Err(before) => -i128::try_from(before.duration().as_nanos()).unwrap_or(i128::MAX),
        };
        // Written a moment ago, or stamped in the future: not yet to be believed.
        if now
            .duration_since(modified)
            .map_or(true, |age| age < SETTLE)
        {
            self.unsettled = true;
        }
        self.stamp.push((name, meta.len(), nanos));
    }

    /// Order-independent, so the platform's directory order does not matter.
    pub fn sorted(mut self) -> Self {
        self.stamp.sort();
        self
    }

    pub fn is_settled(&self) -> bool {
        !self.unsettled
    }
}

/// A digest of everything a task's verdicts depend on besides its own files. `None` when
/// some of it changed a moment ago, which keeps the cache out of the way.
pub(crate) fn trust_key(
    project_id: &str,
    roster: &[crate::AgentRoute],
    refused: &std::collections::BTreeSet<String>,
    overlays: &[(String, PathBuf)],
    channel: &Path,
) -> Option<u64> {
    let mut control = Fingerprint::default();
    for dir in ["agents", "grants", "delegations", "access", "head"] {
        control.add_dir(&format!("{dir}/"), &channel.join(dir));
    }
    control.add_file("master.json", &channel.join("master.json"));
    let control = control.sorted();
    if !control.is_settled() {
        return None;
    }
    let mut hasher = DefaultHasher::new();
    project_id.hash(&mut hasher);
    // The roster as the signatures are checked against it: keys included.
    serde_json::to_string(roster)
        .unwrap_or_default()
        .hash(&mut hasher);
    refused.hash(&mut hasher);
    overlays.hash(&mut hasher);
    control.stamp.hash(&mut hasher);
    Some(hasher.finish())
}

struct Entry {
    trust: u64,
    stamp: Stamp,
    task: Task,
}

static TASKS: LazyLock<Mutex<HashMap<PathBuf, Entry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The remembered task for `directory`, if nothing it depended on has changed.
pub(crate) fn lookup(directory: &Path, trust: Option<u64>, files: &Fingerprint) -> Option<Task> {
    let trust = trust?;
    let cache = TASKS.lock().ok()?;
    let entry = cache.get(directory)?;
    (entry.trust == trust && entry.stamp == files.stamp).then(|| entry.task.clone())
}

/// Remember `task`, read from `files` under `trust`. Ignored when anything was written
/// too recently to be believed.
pub(crate) fn remember(directory: &Path, trust: Option<u64>, files: Fingerprint, task: &Task) {
    let Some(trust) = trust else { return };
    if !files.is_settled() {
        return;
    }
    if let Ok(mut cache) = TASKS.lock() {
        cache.insert(
            directory.to_path_buf(),
            Entry {
                trust,
                stamp: files.stamp,
                task: task.clone(),
            },
        );
    }
}

/// Forget the folders under `root` that are not in `keep`: the tasks that have gone.
pub(crate) fn retain_under(root: &Path, keep: &std::collections::HashSet<PathBuf>) {
    if let Ok(mut cache) = TASKS.lock() {
        cache.retain(|path, _| !path.starts_with(root) || keep.contains(path));
    }
}

/// How many tasks under `root` are remembered (a test).
#[must_use]
pub fn remembered_under(root: &Path) -> usize {
    TASKS.lock().map_or(0, |cache| {
        cache.keys().filter(|path| path.starts_with(root)).count()
    })
}

//! What is in a channel folder, what differs between two of them, and how a file that
//! arrives is let in.
//!
//! # The rules, and why each one
//!
//! - **The channel's own exclusions.** The same `.stignore` Syncthing obeys (keys, seeds,
//!   executables, scripts, `local`), plus that list built in, so a channel whose
//!   `.stignore` was lost does not start handing out keys. Applied on BOTH sides: a peer
//!   that offers an `.exe` is not asked for it, and one that sends one anyway is refused.
//! - **No conflict copies, no temporary files, no Syncthing internals.** They are one
//!   machine's working state, not the channel's.
//! - **Nothing over [`MAX_FILE`].**
//! - **Never a deletion.** A file missing on one side is a file the other side has. Every
//!   writer in the channel is built so that nothing needs deleting to make progress, and a
//!   lane that could delete could be told to empty a channel.
//! - **Never outside the folder.** A path is relative, `/`-separated, and every component
//!   is an ordinary name: no `..`, no root, no drive, no backslash, no Windows device
//!   name. On the way in, no directory on the path and no file at the end may be a
//!   symlink, so an existing link cannot carry a write somewhere else. Symlinks are
//!   never offered either.
//! - **The newer modification time wins** for a path whose contents differ. Equal times
//!   with different contents keep the local copy on both sides: neither has a better
//!   claim, and both still have a file. Times are carried with the file, as Syncthing
//!   carries them, so a file once synced compares equal on the next round.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::MAX_FILE;

/// One file in a channel, as the other side is told about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Relative to the channel folder, `/`-separated.
    pub path: String,
    pub size: u64,
    /// Modification time, milliseconds since the Unix epoch.
    pub mtime: i64,
    /// BLAKE3 of the contents, hex.
    pub hash: String,
}

/// Excluded whatever the channel's `.stignore` says: the list `ferry enable` writes.
const BUILT_IN: &[&str] = &[
    "keys",
    "*.tmp",
    "*.key",
    "*.seed",
    "operator.seed",
    "operator.seed.*",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
    "*.msi",
    "*.bat",
    "*.cmd",
    "*.ps1",
    "*.sh",
];

/// The suffix of the lane's own temporary files. Ends in `.tmp`, so Syncthing (and this
/// lane) never carry one that is half written.
const TEMP_SUFFIX: &str = ".iroh.tmp";

/// What a channel keeps to itself.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Lowercased: excluding a file whose name differs only in case is the safe mistake.
    patterns: Vec<String>,
    /// Worker-level agents (ADR 0024): a channel file authored by one is not carried and
    /// not let in, whoever offers it. Empty for a hand-ins folder, which is where their
    /// files belong.
    refused_authors: std::collections::BTreeSet<String>,
    /// Hand-ins folders only: `accepted.json` and `rejected.json` are the head's alone, so
    /// from a peer that is not the head they are neither wanted nor let in.
    no_verdicts: bool,
    /// Nothing is let in from the peer: it is a machine whose agents are all Workers, whose
    /// writes belong in the hand-ins folder and not in the channel (ADR 0024).
    no_incoming: bool,
    /// Roster entries and device records for names the master has not admitted (a fresh
    /// name a Worker registered): neither carried nor let in.
    refused_roster: std::collections::BTreeSet<String>,
    /// First contact: only `transports/<agent>.json` is carried, and a received one must
    /// pass the channel's own check for a record it would honour.
    transports_only: Option<Gate>,
}

/// A check on a received file: its path and bytes.
type Check = dyn Fn(&str, &[u8]) -> bool + Send + Sync;

/// What a received file must satisfy besides the path rules.
#[derive(Clone)]
struct Gate(std::sync::Arc<Check>);

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gate")
    }
}

/// Whether `lower` (lowercased, `/`-separated) is the `transports` folder or a record in it.
fn is_transports_path(lower: &str) -> bool {
    let mut parts = lower.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("transports"), None, _) => true,
        (Some("transports"), Some(name), None) => name.ends_with(".json") && name.len() > 5,
        _ => false,
    }
}

/// The head's verdict files, written beside a hand-in.
const VERDICT_FILES: [&str; 2] = ["accepted.json", "rejected.json"];

impl Rules {
    /// Refuse files authored by these Worker-level agents (a channel's rules).
    #[must_use]
    pub fn refusing_authors(mut self, workers: std::collections::BTreeSet<String>) -> Self {
        self.refused_authors = workers;
        self
    }

    /// Refuse the head's verdict files (a hand-ins folder, shared with a peer that is not
    /// the head).
    #[must_use]
    pub fn refusing_verdicts(mut self, refuse: bool) -> Self {
        self.no_verdicts = refuse;
        self
    }

    /// Also keep `pattern` (anchored at the folder, `/`-separated) where it is. For a
    /// channel in a project whose hand-ins live elsewhere: a `handins/` folder in the
    /// channel is a leftover of the old layout, and an unmigrated peer must not re-create it.
    #[must_use]
    pub fn excluding(mut self, pattern: &str) -> Self {
        self.patterns.push(pattern.to_ascii_lowercase());
        self
    }

    /// Carry only the agents' `transports/` records, and let in only one that `route` would
    /// itself honour: what a peer trusted in another channel may be given of this one before
    /// it is trusted in it.
    #[must_use]
    pub fn transports_only(mut self, route: ferryman_channel::ProjectRoute) -> Self {
        self.transports_only = Some(Gate(std::sync::Arc::new(move |path, bytes| {
            ferryman_channel::transports::acceptable(&route, path, bytes)
        })));
        self
    }

    /// Refuse the roster entries and device records of these unadmitted names.
    #[must_use]
    pub fn refusing_roster(mut self, unadmitted: std::collections::BTreeSet<String>) -> Self {
        self.refused_roster = unadmitted;
        self
    }

    /// Let nothing in from the peer (a channel shared with a Worker-only machine).
    #[must_use]
    pub fn refusing_incoming(mut self, refuse: bool) -> Self {
        self.no_incoming = refuse;
        self
    }

    /// The built-in list and the channel's `.stignore`.
    ///
    /// Only the parts of the `.stignore` syntax that exclude are used. A negation (`!`) is
    /// skipped rather than honoured, which can only make the lane carry less than
    /// Syncthing does, never more.
    #[must_use]
    pub fn for_channel(channel: &Path) -> Self {
        let mut patterns: Vec<String> = BUILT_IN.iter().map(|p| (*p).to_owned()).collect();
        if let Ok(text) = fs::read_to_string(channel.join(".stignore")) {
            for line in text.lines() {
                let mut line = line.trim();
                for prefix in ["(?d)", "(?i)"] {
                    line = line.strip_prefix(prefix).unwrap_or(line);
                }
                if line.is_empty()
                    || line.starts_with("//")
                    || line.starts_with('#')
                    || line.starts_with('!')
                {
                    continue;
                }
                patterns.push(line.trim_start_matches('/').to_ascii_lowercase());
            }
        }
        Self {
            patterns,
            refused_authors: std::collections::BTreeSet::new(),
            no_verdicts: false,
            no_incoming: false,
            refused_roster: std::collections::BTreeSet::new(),
            transports_only: None,
        }
    }

    /// Whether `path` is not let in from the peer: everything [`Rules::excludes`] keeps
    /// out, and the head's verdict files when the peer is not the head. What this side
    /// offers is not held to the second rule - its own head's verdicts must go out.
    #[must_use]
    pub fn excludes_incoming(&self, path: &str) -> bool {
        self.excludes(path)
            || self.no_incoming
            || (self.no_verdicts
                && path.rsplit('/').next().is_some_and(|name| {
                    VERDICT_FILES.contains(&name.to_ascii_lowercase().as_str())
                }))
    }

    /// Whether `path` (relative, `/`-separated) stays where it is.
    #[must_use]
    pub fn excludes(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        let components: Vec<&str> = lower.split('/').collect();
        if components.iter().any(|name| machine_local(name)) {
            return true;
        }
        if self.transports_only.is_some() && !is_transports_path(&lower) {
            return true;
        }
        if !self.refused_authors.is_empty()
            && ferryman_channel::access::comms_author_refused(path, None, &self.refused_authors)
                .is_some()
        {
            return true;
        }
        if ferryman_channel::access::roster_write_refused(path, &self.refused_roster).is_some() {
            return true;
        }
        self.patterns.iter().any(|pattern| {
            if pattern.contains('/') {
                // Anchored at the channel: the path itself, or anything under it.
                let pattern = pattern.trim_end_matches('/');
                ferryman_channel::policy::glob(pattern, &lower)
                    || components.iter().enumerate().any(|(index, _)| {
                        ferryman_channel::policy::glob(pattern, &components[..=index].join("/"))
                    })
            } else {
                components
                    .iter()
                    .any(|name| ferryman_channel::policy::glob(pattern, name))
            }
        })
    }
}

/// Names that are one machine's state whatever any `.stignore` says.
fn machine_local(name: &str) -> bool {
    name == ".stignore"
        || name == ".stfolder"
        || name == ".stversions"
        || name.starts_with("~syncthing~")
        || name.starts_with(".syncthing.")
        || name.contains(".sync-conflict-")
        || name.ends_with(".tmp")
}

/// Windows device names, which name a device rather than a file in any directory.
const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// The components of a path a peer named, or a refusal.
///
/// # Errors
/// Anything that is not a plain relative path of ordinary names.
pub fn safe_relative(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() || path.len() > 1024 {
        bail!("an empty or overlong path");
    }
    if path.starts_with('/') || path.contains('\\') || path.contains(':') || path.contains('\0') {
        bail!("'{path}' is not a relative channel path");
    }
    let components: Vec<&str> = path.split('/').collect();
    for name in &components {
        let stem = name
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.is_empty()
            || *name == "."
            || *name == ".."
            || name.ends_with('.')
            || name.ends_with(' ')
            || name.chars().any(char::is_control)
            || RESERVED.contains(&stem.as_str())
        {
            bail!("'{path}' has a component that is not an ordinary name");
        }
    }
    Ok(components)
}

fn mtime_ms(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

/// Remembered hashes, so a round re-reads only the files whose size or time changed.
#[derive(Debug, Default)]
pub struct HashCache {
    known: HashMap<PathBuf, (u64, i64, String)>,
}

impl HashCache {
    fn hash(&mut self, path: &Path, size: u64, mtime: i64) -> Option<String> {
        if let Some((s, m, hash)) = self.known.get(path)
            && *s == size
            && *m == mtime
        {
            return Some(hash.clone());
        }
        let hash = blake3::hash(&fs::read(path).ok()?).to_hex().to_string();
        // A file written a moment ago could be rewritten, same size, within the clock's
        // resolution: hash it again next round rather than remember it (git's "racy" rule).
        if now_ms().saturating_sub(mtime) >= SETTLE_MS {
            self.known
                .insert(path.to_path_buf(), (size, mtime, hash.clone()));
        }
        Some(hash)
    }

    /// Forget the files under `channel` that were not seen in the latest scan, so the
    /// cache follows the folder instead of growing with everything it ever held.
    fn forget_missing(&mut self, channel: &Path, seen: &std::collections::HashSet<PathBuf>) {
        self.known
            .retain(|path, _| !path.starts_with(channel) || seen.contains(path));
    }

    /// How many hashes are remembered (a test).
    #[must_use]
    pub fn len(&self) -> usize {
        self.known.len()
    }

    /// Whether nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }
}

/// How old a file must be before its hash is remembered.
const SETTLE_MS: i64 = 2_000;

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis()),
    )
    .unwrap_or(0)
}

/// Every file in `channel` that the lane would carry, by path.
#[must_use]
pub fn scan(channel: &Path, rules: &Rules, cache: &mut HashCache) -> BTreeMap<String, Entry> {
    let mut found = BTreeMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut pending = vec![(channel.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if rules.excludes(&relative) || safe_relative(&relative).is_err() {
                continue;
            }
            // Not followed: `symlink_metadata` describes the link, and a link is skipped.
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                pending.push((entry.path(), relative));
            } else if meta.is_file() && meta.len() <= MAX_FILE {
                let mtime = mtime_ms(&meta);
                seen.insert(entry.path());
                if let Some(hash) = cache.hash(&entry.path(), meta.len(), mtime) {
                    found.insert(
                        relative.clone(),
                        Entry {
                            path: relative,
                            size: meta.len(),
                            mtime,
                            hash,
                        },
                    );
                }
            }
        }
    }
    cache.forget_missing(channel, &seen);
    found
}

/// What one side wants from the other, and what it has that the other lacks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Paths to fetch from the other side.
    pub want: Vec<String>,
    /// Paths to send to the other side.
    pub give: Vec<String>,
}

/// Compare the other side's manifest with ours. `theirs` is trusted for nothing: entries
/// whose path is unsafe, excluded here, or too big are not wanted.
#[must_use]
pub fn plan(theirs: &[Entry], ours: &BTreeMap<String, Entry>, rules: &Rules) -> Plan {
    let mut plan = Plan::default();
    let mut seen = std::collections::BTreeSet::new();
    for entry in theirs {
        if entry.size > MAX_FILE
            || safe_relative(&entry.path).is_err()
            || rules.excludes_incoming(&entry.path)
            || !seen.insert(entry.path.as_str())
        {
            continue;
        }
        match ours.get(&entry.path) {
            None => plan.want.push(entry.path.clone()),
            Some(local) if local.hash == entry.hash => {}
            Some(local) if entry.mtime > local.mtime => plan.want.push(entry.path.clone()),
            Some(local) if local.mtime > entry.mtime => plan.give.push(entry.path.clone()),
            Some(_) => {}
        }
    }
    for path in ours.keys() {
        if !seen.contains(path.as_str()) {
            plan.give.push(path.clone());
        }
    }
    plan
}

/// The file at `path` in `channel`, ready to send: its entry as it is now, and its bytes.
/// `None` when it is gone, excluded, a link, or too big - the other side is told "skip".
#[must_use]
pub fn read_for_send(channel: &Path, rules: &Rules, path: &str) -> Option<(Entry, Vec<u8>)> {
    let components = safe_relative(path).ok()?;
    if rules.excludes(path) {
        return None;
    }
    let full = components
        .iter()
        .fold(channel.to_path_buf(), |dir, name| dir.join(name));
    let meta = fs::symlink_metadata(&full).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let bytes = fs::read(&full).ok()?;
    Some((
        Entry {
            path: path.to_owned(),
            size: bytes.len() as u64,
            mtime: mtime_ms(&meta),
            hash: blake3::hash(&bytes).to_hex().to_string(),
        },
        bytes,
    ))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Let a received file into `channel`. Returns whether it was written.
///
/// Every rule in the module documentation is checked here again, on this machine's own
/// terms, because the plan that asked for the file was built from what the peer said.
/// A file that is already here with the same contents, or a newer or equally new local
/// copy, is left alone (`Ok(false)`).
///
/// # Errors
/// The path or the contents break a rule, or the file cannot be written.
pub fn write_received(channel: &Path, rules: &Rules, entry: &Entry, bytes: &[u8]) -> Result<bool> {
    let components = safe_relative(&entry.path)?;
    if rules.excludes_incoming(&entry.path) {
        bail!("'{}' is excluded from this channel", entry.path);
    }
    if bytes.len() as u64 != entry.size || entry.size > MAX_FILE {
        bail!("'{}' is not the size it was said to be", entry.path);
    }
    if blake3::hash(bytes).to_hex().as_str() != entry.hash {
        bail!("'{}' does not match its hash", entry.path);
    }
    // By content as well as by name (ADR 0024): a file in a channel that says a Worker-level
    // agent wrote it was not written there by that agent, whatever it is called.
    if !rules.refused_authors.is_empty()
        && let Some(worker) = ferryman_channel::access::comms_author_refused(
            &entry.path,
            Some(bytes),
            &rules.refused_authors,
        )
    {
        bail!(
            "'{}' is authored by {worker}, a Worker, which writes to its hand-ins and never the channel",
            entry.path
        );
    }
    if let Some(Gate(check)) = &rules.transports_only
        && !check(&entry.path, bytes)
    {
        bail!(
            "'{}' is not a record this channel would honour, and nothing else is let in before first trust",
            entry.path
        );
    }
    let (file_name, parents) = components.split_last().context("a path with no name")?;
    let mut dir = channel.to_path_buf();
    for name in parents {
        dir.push(name);
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => bail!(
                "'{}' goes through something that is not a folder",
                entry.path
            ),
            Err(_) => fs::create_dir(&dir).with_context(|| format!("create {}", dir.display()))?,
        }
    }
    let target = dir.join(file_name);
    if let Ok(meta) = fs::symlink_metadata(&target) {
        if !meta.is_file() {
            bail!("'{}' is here and is not a plain file", entry.path);
        }
        if mtime_ms(&meta) >= entry.mtime {
            return Ok(false);
        }
        if blake3::hash(&fs::read(&target)?).to_hex().as_str() == entry.hash {
            return Ok(false);
        }
    }
    let temp = dir.join(format!(
        ".{file_name}.{}.{}{TEMP_SUFFIX}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> Result<()> {
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        let millis = u64::try_from(entry.mtime.max(0)).unwrap_or(0);
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_millis(millis))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, &target)?;
        Ok(())
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(error.context(format!("write {}", target.display())));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, mtime: i64, hash: &str) -> Entry {
        Entry {
            path: path.into(),
            size: 1,
            mtime,
            hash: hash.into(),
        }
    }

    fn ours(entries: &[Entry]) -> BTreeMap<String, Entry> {
        entries
            .iter()
            .map(|e| (e.path.clone(), e.clone()))
            .collect()
    }

    fn no_rules() -> Rules {
        Rules::for_channel(Path::new("/nonexistent"))
    }

    #[test]
    fn a_file_only_they_have_is_wanted_and_one_only_we_have_is_given() {
        let plan = plan(
            &[entry("orders/a.json", 1, "aa")],
            &ours(&[entry("orders/b.json", 1, "bb")]),
            &no_rules(),
        );
        assert_eq!(plan.want, ["orders/a.json"]);
        assert_eq!(plan.give, ["orders/b.json"]);
    }

    #[test]
    fn the_newer_copy_wins_and_the_same_contents_move_nowhere() {
        let plan = plan(
            &[
                entry("newer-there", 20, "x"),
                entry("newer-here", 10, "x"),
                entry("same", 5, "s"),
            ],
            &ours(&[
                entry("newer-there", 10, "y"),
                entry("newer-here", 20, "y"),
                entry("same", 99, "s"),
            ]),
            &no_rules(),
        );
        assert_eq!(plan.want, ["newer-there"]);
        assert_eq!(plan.give, ["newer-here"]);
    }

    #[test]
    fn equal_times_with_different_contents_keep_both_local_copies() {
        let plan = plan(
            &[entry("ledger.jsonl", 7, "a")],
            &ours(&[entry("ledger.jsonl", 7, "b")]),
            &no_rules(),
        );
        assert_eq!(plan, Plan::default());
    }

    #[test]
    fn unsafe_excluded_or_oversized_paths_they_offer_are_not_wanted() {
        let mut big = entry("big.json", 1, "z");
        big.size = MAX_FILE + 1;
        let plan = plan(
            &[
                entry("../outside.txt", 1, "a"),
                entry("a/../../x", 1, "a"),
                entry("/etc/passwd", 1, "a"),
                entry("C:/Windows/x", 1, "a"),
                entry("a\\..\\x", 1, "a"),
                entry("tools/ferry.exe", 1, "a"),
                entry("keys/fang.key", 1, "a"),
                entry(
                    "agents/fang.json.sync-conflict-20260101-000000-ABC.json",
                    1,
                    "a",
                ),
                entry("aux.json", 1, "a"),
                big,
            ],
            &BTreeMap::new(),
            &no_rules(),
        );
        assert!(plan.want.is_empty(), "{:?}", plan.want);
    }

    #[test]
    fn a_worker_only_peer_writes_nothing_into_the_channel_and_handins_stay_out_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let rules = Rules::for_channel(dir.path())
            .excluding("handins/")
            .refusing_incoming(true);
        // Whatever it offers is not let in, however innocent it looks.
        assert!(rules.excludes_incoming("tasks/t-1/order.json"));
        assert!(rules.excludes_incoming("agents/wisp-two.json"));
        // The old layout's hand-ins folder is not carried in either direction.
        assert!(rules.excludes("handins/wisp/o1/handin.json"));
        // A peer that is not Worker-only is let in as before.
        let open = Rules::for_channel(dir.path()).excluding("handins/");
        assert!(!open.excludes_incoming("tasks/t-1/order.json"));
        assert!(open.excludes_incoming("handins/x/y.json"));
    }

    #[test]
    fn plain_channel_paths_are_safe_and_traversal_is_not() {
        assert_eq!(
            safe_relative("tasks/t-1/order.json").unwrap(),
            ["tasks", "t-1", "order.json"]
        );
        for bad in [
            "",
            "..",
            "a//b",
            "./a",
            "a/.",
            "/a",
            "a\\b",
            "c:x",
            "nul",
            "a/con.txt",
            "a. ",
        ] {
            assert!(safe_relative(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_channels_stignore_is_obeyed_on_top_of_the_built_in_list() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".stignore"),
            "// note\n(?d)scratch\n/top/only\n!keepme\n",
        )
        .unwrap();
        let rules = Rules::for_channel(dir.path());
        assert!(rules.excludes("scratch/a.json"));
        assert!(rules.excludes("deep/scratch"));
        assert!(rules.excludes("top/only/x.json"));
        assert!(!rules.excludes("other/top/only"));
        assert!(rules.excludes("Run.PS1"));
        assert!(rules.excludes("keys"));
        assert!(rules.excludes(".stignore"));
        assert!(!rules.excludes("tasks/t-1/order.json"));
    }

    #[test]
    fn a_received_file_is_written_whole_with_its_time_and_never_outside() {
        let dir = tempfile::tempdir().unwrap();
        let channel = dir.path().join("channel");
        fs::create_dir(&channel).unwrap();
        let rules = Rules::for_channel(&channel);
        let bytes = b"{\"ok\":true}";
        let good = Entry {
            path: "tasks/t-1/order.json".into(),
            size: bytes.len() as u64,
            mtime: 1_700_000_000_000,
            hash: blake3::hash(bytes).to_hex().to_string(),
        };
        assert!(write_received(&channel, &rules, &good, bytes).unwrap());
        let written = channel.join("tasks/t-1/order.json");
        assert_eq!(fs::read(&written).unwrap(), bytes);
        assert_eq!(mtime_ms(&fs::metadata(&written).unwrap()), good.mtime);
        // Again: already here, nothing to do.
        assert!(!write_received(&channel, &rules, &good, bytes).unwrap());

        let mut escape = good.clone();
        escape.path = "../escape.json".into();
        assert!(write_received(&channel, &rules, &escape, bytes).is_err());
        assert!(!dir.path().join("escape.json").exists());

        let mut lie = good.clone();
        lie.path = "other.json".into();
        lie.hash = "00".into();
        assert!(write_received(&channel, &rules, &lie, bytes).is_err());
        assert!(!channel.join("other.json").exists());
    }

    #[test]
    fn an_older_copy_does_not_replace_a_newer_local_one() {
        let dir = tempfile::tempdir().unwrap();
        let rules = Rules::for_channel(dir.path());
        let newer = b"newer";
        let mut entry = Entry {
            path: "note.json".into(),
            size: newer.len() as u64,
            mtime: 2_000,
            hash: blake3::hash(newer).to_hex().to_string(),
        };
        assert!(write_received(dir.path(), &rules, &entry, newer).unwrap());
        let older = b"older";
        entry.mtime = 1_000;
        entry.size = older.len() as u64;
        entry.hash = blake3::hash(older).to_hex().to_string();
        assert!(!write_received(dir.path(), &rules, &entry, older).unwrap());
        assert_eq!(fs::read(dir.path().join("note.json")).unwrap(), newer);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_folder_cannot_carry_a_write_outside() {
        let dir = tempfile::tempdir().unwrap();
        let channel = dir.path().join("channel");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&channel).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, channel.join("tasks")).unwrap();
        let rules = Rules::for_channel(&channel);
        let bytes = b"x";
        let entry = Entry {
            path: "tasks/planted.json".into(),
            size: 1,
            mtime: 1,
            hash: blake3::hash(bytes).to_hex().to_string(),
        };
        assert!(write_received(&channel, &rules, &entry, bytes).is_err());
        assert!(!outside.join("planted.json").exists());
        // And the link is not offered either.
        assert!(scan(&channel, &rules, &mut HashCache::default()).is_empty());
    }

    #[test]
    fn hashes_are_remembered_for_old_files_only_and_follow_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        let channel = dir.path();
        fs::create_dir_all(channel.join("messages")).unwrap();
        let old = channel.join("messages/old.json");
        let young = channel.join("messages/young.json");
        fs::write(&old, b"one").unwrap();
        fs::write(&young, b"two").unwrap();
        // Age one of them past the settling window.
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        let mut cache = HashCache::default();
        let found = scan(channel, &no_rules(), &mut cache);
        assert_eq!(found.len(), 2);
        // The file touched a moment ago is hashed again next round; the old one is not.
        assert_eq!(cache.len(), 1);

        // A file that has gone is forgotten.
        fs::remove_file(&old).unwrap();
        assert_eq!(scan(channel, &no_rules(), &mut cache).len(), 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn a_remembered_hash_is_not_trusted_after_the_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.json");
        fs::write(&file, b"one").unwrap();
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        let age = |t| {
            fs::File::options()
                .write(true)
                .open(&file)
                .unwrap()
                .set_modified(t)
                .unwrap();
        };
        age(long_ago);
        let mut cache = HashCache::default();
        let first = scan(dir.path(), &no_rules(), &mut cache)["a.json"]
            .hash
            .clone();
        // Same size, different bytes, and the old time put back: a different time is what
        // the cache keys on, so make it different.
        fs::write(&file, b"two").unwrap();
        age(long_ago - std::time::Duration::from_secs(5));
        let second = scan(dir.path(), &no_rules(), &mut cache)["a.json"]
            .hash
            .clone();
        assert_ne!(first, second);
    }
}

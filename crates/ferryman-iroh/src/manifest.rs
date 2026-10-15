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
    "local",
];

/// The suffix of the lane's own temporary files. Ends in `.tmp`, so Syncthing (and this
/// lane) never carry one that is half written.
const TEMP_SUFFIX: &str = ".iroh.tmp";

/// What a channel keeps to itself.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Lowercased: excluding a file whose name differs only in case is the safe mistake.
    patterns: Vec<String>,
}

impl Rules {
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
        Self { patterns }
    }

    /// Whether `path` (relative, `/`-separated) stays where it is.
    #[must_use]
    pub fn excludes(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        let components: Vec<&str> = lower.split('/').collect();
        if components.iter().any(|name| machine_local(name)) {
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
        self.known
            .insert(path.to_path_buf(), (size, mtime, hash.clone()));
        Some(hash)
    }
}

/// Every file in `channel` that the lane would carry, by path.
#[must_use]
pub fn scan(channel: &Path, rules: &Rules, cache: &mut HashCache) -> BTreeMap<String, Entry> {
    let mut found = BTreeMap::new();
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
            || rules.excludes(&entry.path)
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
    if rules.excludes(&entry.path) {
        bail!("'{}' is excluded from this channel", entry.path);
    }
    if bytes.len() as u64 != entry.size || entry.size > MAX_FILE {
        bail!("'{}' is not the size it was said to be", entry.path);
    }
    if blake3::hash(bytes).to_hex().as_str() != entry.hash {
        bail!("'{}' does not match its hash", entry.path);
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
}

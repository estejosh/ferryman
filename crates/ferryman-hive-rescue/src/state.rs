//! What a machine remembers between runs: the highest sequence number seen from each
//! signer (replay protection), the newest accepted record of each kind (so addresses
//! survive a restart), and what it last posted.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::record::{Kind, Refused, Signed};

/// The file, in the machine's state directory.
pub const FILE: &str = "hive-rescue-state.json";
/// The previous good copy, kept beside it: read when the main file is unreadable.
pub const BACKUP: &str = "hive-rescue-state.json.bak";
/// How far before its own start a machine with no memory takes a record's issue time.
pub const FRESH_WINDOW: chrono::Duration = chrono::Duration::minutes(5);

/// What the last post said, to know when something new is worth a post.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Posted {
    pub at: Option<DateTime<Utc>>,
    pub seq: u64,
    pub kind: Option<Kind>,
    pub relay_url: Option<String>,
    pub relay_list_version: Option<DateTime<Utc>>,
    /// The cut-off episode the post was for (its start).
    pub cut_off_since: Option<DateTime<Utc>>,
    pub tx_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// Highest sequence number accepted, by canonical signer name.
    pub seen_seq: BTreeMap<String, u64>,
    pub latest_master: Option<Signed>,
    pub latest_backup: Option<Signed>,
    pub posted: Posted,
    pub last_poll: Option<DateTime<Utc>>,
    /// Our own next sequence number floor.
    pub own_seq: u64,
    /// Set when this machine started with no readable state (first run, a lost or damaged
    /// file): replay protection has no memory then, so records issued before this moment
    /// are not taken, ever. Records issued since are protected by `seen_seq` as usual.
    #[serde(default)]
    pub issued_floor: Option<DateTime<Utc>>,
    /// Whether the state was read from a file (not stored).
    #[serde(skip)]
    pub loaded: bool,
}

impl State {
    /// Read the file, or the backup copy when the file is unreadable. With neither, it is a
    /// fresh state with no memory: [`Self::loaded`] is false, and [`Self::start_cautiously`]
    /// says what to do about it.
    #[must_use]
    pub fn load(dir: &Path) -> Self {
        for name in [FILE, BACKUP] {
            if let Some(mut state) = std::fs::read(dir.join(name))
                .ok()
                .and_then(|b| serde_json::from_slice::<Self>(&b).ok())
            {
                state.loaded = true;
                return state;
            }
        }
        Self::default()
    }

    /// A machine that has no memory of what it saw takes only records issued from a few
    /// minutes before `now` on, and remembers that (in the file) so the floor stays.
    /// Without it, anything still unexpired from the last day could be replayed once.
    pub fn start_cautiously(&mut self, now: DateTime<Utc>) {
        if !self.loaded && self.issued_floor.is_none() {
            self.issued_floor = Some(now - FRESH_WINDOW);
        }
    }

    /// Write it durably: to a temporary file that is flushed to disk, then renamed over
    /// the file, the previous good file kept as the backup.
    ///
    /// # Errors
    /// The directory cannot be written.
    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?;
        let temp = dir.join(format!("{FILE}.tmp"));
        {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&serde_json::to_vec_pretty(self)?)?;
            file.sync_all()?;
        }
        let main = dir.join(FILE);
        if main.is_file() {
            // A copy, not a rename: the main file stays in place until the new one is.
            let _ = std::fs::copy(&main, dir.join(BACKUP));
        }
        std::fs::rename(&temp, &main)?;
        Ok(())
    }

    /// Whether a verified record would be taken: its sequence number higher than any seen
    /// from that signer, and issued no earlier than this machine's floor.
    ///
    /// # Errors
    /// [`Refused`] for a replay or an out-of-date record.
    pub fn would_accept(&self, record: &Signed) -> Result<(), Refused> {
        let signer = ferryman_channel::canonical_agent_name(&record.body.signer);
        let seen = self.seen_seq.get(&signer).copied().unwrap_or(0);
        if record.body.seq <= seen {
            return Err(Refused(format!(
                "sequence {} is not newer than {seen} already seen from {signer} (a replay)",
                record.body.seq
            )));
        }
        if let Some(floor) = self.issued_floor
            && record.body.issued < floor
        {
            return Err(Refused(
                "issued before this machine started with no memory of earlier records".into(),
            ));
        }
        Ok(())
    }

    /// Take an already-verified record into the ledger: its sequence number must be
    /// higher than any seen from that signer.
    ///
    /// # Errors
    /// [`Refused`] for a replay or an out-of-date record.
    pub fn accept(&mut self, record: &Signed) -> Result<(), Refused> {
        self.would_accept(record)?;
        let signer = ferryman_channel::canonical_agent_name(&record.body.signer);
        self.seen_seq.insert(signer, record.body.seq);
        match record.body.kind {
            Kind::Master => self.latest_master = Some(record.clone()),
            Kind::Backup => self.latest_backup = Some(record.clone()),
        }
        Ok(())
    }

    /// The next sequence number for this machine's own posts: seconds since 1970, or one
    /// more than the last, whichever is higher, so losing this file cannot send it back.
    pub fn next_own_seq(&mut self, now: DateTime<Utc>) -> u64 {
        let by_clock = u64::try_from(now.timestamp()).unwrap_or(0);
        self.own_seq = by_clock.max(self.own_seq + 1);
        self.own_seq
    }
}

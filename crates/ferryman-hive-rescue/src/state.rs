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
}

impl State {
    /// Read the file; anything unreadable is a fresh state (replay protection then starts
    /// over, which an expiry still bounds).
    #[must_use]
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Write it, atomically.
    ///
    /// # Errors
    /// The directory cannot be written.
    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        let temp = dir.join(format!("{FILE}.tmp"));
        std::fs::write(&temp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&temp, dir.join(FILE))?;
        Ok(())
    }

    /// Take an already-verified record into the ledger: its sequence number must be
    /// higher than any seen from that signer.
    ///
    /// # Errors
    /// [`Refused`] for a replay or an out-of-date record.
    pub fn accept(&mut self, record: &Signed) -> Result<(), Refused> {
        let signer = ferryman_channel::canonical_agent_name(&record.body.signer);
        let seen = self.seen_seq.get(&signer).copied().unwrap_or(0);
        if record.body.seq <= seen {
            return Err(Refused(format!(
                "sequence {} is not newer than {seen} already seen from {signer} (a replay)",
                record.body.seq
            )));
        }
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

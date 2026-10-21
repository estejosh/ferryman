//! Is the lane doing its job? Worked out from what the worker's lane last wrote
//! ([`Status`]), with no network and no clock of its own, so it is easy to test.
//!
//! Three things are worth a warning:
//!
//! - **a peer that keeps failing**: every exchange for [`ERROR_GRACE`] has ended in an error
//!   (one bad round is weather, not news);
//! - **a peer gone quiet**: no good exchange for the configured number of minutes
//!   (`alert_after_minutes`, default 15), counted from the lane's start for a peer that has
//!   never had one;
//! - **no relay**: the lane is meant to use a relay and none has been connected for
//!   [`ERROR_GRACE`].
//!
//! A peer that is both failing and quiet is one alert, not two. Each alert has a stable key
//! (see `ferryman_channel::lanealerts`), which is what makes it raised once and cleared
//! once rather than repeated every pass.

use chrono::{DateTime, Duration, Utc};

use crate::lane::{ERROR_GRACE, PeerStatus, Status};

/// One finding: a stable key, a short title, and a sentence saying what and since when.
pub type Finding = (String, String, String);

fn minutes(duration: Duration) -> i64 {
    duration.num_minutes().max(0)
}

fn who(id: &str, peer: &PeerStatus) -> String {
    let short = &id[..12.min(id.len())];
    if peer.agents.is_empty() {
        format!("peer {short}")
    } else {
        format!("{} ({short})", peer.agents.join(", "))
    }
}

/// What is wrong with the lane described by `status`, at `now`, with `quiet_for` as the
/// no-good-sync threshold. Empty when all is well.
#[must_use]
pub fn evaluate(status: &Status, now: DateTime<Utc>, quiet_for: Duration) -> Vec<Finding> {
    let mut found = Vec::new();
    if status.relay_expected
        && let Some(since) = status.relay_down_since
        && now - since >= ERROR_GRACE
    {
        found.push((
            "relay".to_owned(),
            "iroh relay unreachable".to_owned(),
            format!(
                "No relay has been connected for {} minute(s){}. Machines that cannot see each \
                 other directly cannot sync over the lane until one is.",
                minutes(now - since),
                status
                    .relay_problem
                    .as_deref()
                    .map_or_else(String::new, |why| format!(" ({why})"))
            ),
        ));
    }
    for (id, peer) in &status.peers {
        let key = format!("peer:{}", &id[..12.min(id.len())]);
        let name = who(id, peer);
        let failing = peer
            .failing_since
            .filter(|since| now - *since >= ERROR_GRACE)
            .and(peer.last_error.as_deref());
        let reference = peer.last_sync.or(status.started);
        let quiet = reference.is_some_and(|at| now - at >= quiet_for);
        let last_good = peer.last_sync.map_or_else(
            || "never since the lane started".to_owned(),
            |at| format!("{} minute(s) ago", minutes(now - at)),
        );
        if let Some(error) = failing {
            found.push((
                key,
                format!("iroh lane: {name} is failing"),
                format!("Last good sync {last_good}. Last error: {error}"),
            ));
        } else if quiet {
            found.push((
                key,
                format!("iroh lane: no sync with {name}"),
                format!(
                    "No successful sync for over {} minute(s); last good sync {last_good}.",
                    minutes(quiet_for)
                ),
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffff";

    fn status(now: DateTime<Utc>) -> Status {
        Status {
            started: Some(now - Duration::hours(2)),
            relay_expected: true,
            relay_connected: true,
            ..Status::default()
        }
    }

    fn peer(last_sync: Option<DateTime<Utc>>) -> PeerStatus {
        PeerStatus {
            agents: vec!["wisp".into()],
            last_sync,
            ..PeerStatus::default()
        }
    }

    #[test]
    fn a_healthy_lane_raises_nothing() {
        let now = Utc::now();
        let mut s = status(now);
        s.peers
            .insert(ID.into(), peer(Some(now - Duration::minutes(1))));
        assert!(evaluate(&s, now, Duration::minutes(15)).is_empty());
    }

    #[test]
    fn a_peer_quiet_for_longer_than_the_threshold_is_one_alert() {
        let now = Utc::now();
        let mut s = status(now);
        s.peers
            .insert(ID.into(), peer(Some(now - Duration::minutes(16))));
        let found = evaluate(&s, now, Duration::minutes(15));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "peer:aaaaaaaaaaaa");
        assert!(found[0].2.contains("16 minute(s) ago"), "{found:?}");
        // A longer threshold lets the same peer be.
        assert!(evaluate(&s, now, Duration::minutes(30)).is_empty());
    }

    #[test]
    fn a_peer_never_synced_is_counted_from_the_lane_start() {
        let now = Utc::now();
        let mut s = status(now);
        s.peers.insert(ID.into(), peer(None));
        assert_eq!(evaluate(&s, now, Duration::minutes(15)).len(), 1);
        s.started = Some(now - Duration::minutes(3));
        assert!(evaluate(&s, now, Duration::minutes(15)).is_empty());
    }

    #[test]
    fn a_failing_peer_is_raised_after_the_grace_with_its_error() {
        let now = Utc::now();
        let mut s = status(now);
        let mut p = peer(Some(now - Duration::minutes(4)));
        p.last_error = Some("no answer".into());
        p.failing_since = Some(now - Duration::seconds(30));
        s.peers.insert(ID.into(), p.clone());
        assert!(
            evaluate(&s, now, Duration::minutes(15)).is_empty(),
            "one bad round is not news"
        );
        p.failing_since = Some(now - Duration::minutes(3));
        s.peers.insert(ID.into(), p);
        let found = evaluate(&s, now, Duration::minutes(15));
        assert_eq!(found.len(), 1);
        assert!(found[0].2.contains("no answer"), "{found:?}");
    }

    #[test]
    fn failing_and_quiet_is_still_one_alert_and_the_error_wins() {
        let now = Utc::now();
        let mut s = status(now);
        let mut p = peer(Some(now - Duration::minutes(40)));
        p.last_error = Some("connect: timed out".into());
        p.failing_since = Some(now - Duration::minutes(40));
        s.peers.insert(ID.into(), p);
        let found = evaluate(&s, now, Duration::minutes(15));
        assert_eq!(found.len(), 1);
        assert!(found[0].1.contains("failing"));
    }

    #[test]
    fn an_unreachable_relay_is_raised_after_the_grace_only_when_one_is_expected() {
        let now = Utc::now();
        let mut s = status(now);
        s.relay_connected = false;
        s.relay_down_since = Some(now - Duration::minutes(3));
        s.relay_problem = Some("tls handshake failed".into());
        let found = evaluate(&s, now, Duration::minutes(15));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "relay");
        assert!(found[0].2.contains("tls handshake failed"));
        s.relay_expected = false;
        assert!(evaluate(&s, now, Duration::minutes(15)).is_empty());
        s.relay_expected = true;
        s.relay_down_since = Some(now - Duration::seconds(20));
        assert!(evaluate(&s, now, Duration::minutes(15)).is_empty());
    }
}

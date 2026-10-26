//! The iroh lane: channels synced machine to machine over QUIC, through our own relay.
//!
//! Syncthing carries a channel between machines on the same network, and between
//! networks only as well as its own discovery and relays let it. Away from home that is
//! the part that breaks. This lane carries the same channel folders over [iroh]: one QUIC
//! connection per peer, authenticated by ed25519 endpoint ids, reaching across NATs
//! through a relay that is ours (one small VPS, no domain, no public CA, no DNS) and
//! going direct whenever the two machines can see each other.
//!
//! It runs beside Syncthing, not instead of it. Both write channel files the same way
//! (temporary file, then rename), both preserve modification times, and a file that
//! arrives by one lane is simply already there when the other one looks.
//!
//! ```text
//! <machine state>/iroh.key              this machine's iroh secret key (never in a channel)
//! <machine state>/iroh-relay.token      the relay's access token, placed by hand
//! <machine state>/iroh-status.json      what the worker's lane last did, for `status`
//! <ferry root>/ferry.toml  [iroh]       whether the lane runs, and which relay
//! <channel>/transports/<agent>.json     each agent's signed endpoint id (the bootstrap)
//! ```
//!
//! # Who may connect
//!
//! Exactly the endpoint ids published in a channel's honoured TRANSPORTS records (see
//! [`ferryman_channel::transports`]): signed by an agent on that channel's roster and not
//! revoked. Anyone else is refused when the connection is accepted, before a byte of any
//! channel is read. And a peer is offered a channel only if it is trusted in THAT
//! channel: being in one project does not open another.
//!
//! # Two folders per project, and who may write what (ADR 0024)
//!
//! A project in layout 2 has two synced folders and the lane carries both: the channel
//! (`projects/<id>/comms`, exchanged as `<id>`) and the hand-ins folder
//! (`projects/<id>/handins`, exchanged as `<id>+handins`), under the same trust, the same
//! exclusions and the same safety rules. A peer that predates the hand-ins folder refuses
//! its key and the channel still syncs.
//!
//! A Worker-level agent (a level the project master signs) does not write the channel. The
//! receiving side holds that line, not the writer: a channel file authored by a Worker is
//! neither offered nor let in, by its name or by what it says it was signed by, and a Worker's
//! own files are taken from `handins/<agent>/` only. Beyond that, on a machine where every
//! agent is a Worker the lane listens to the channel and publishes none of it. The head's
//! `accepted.json` and `rejected.json` beside a hand-in are let in only from the head.
//!
//! # What moves
//!
//! See [`manifest`] for the rules: the channel's `.stignore` exclusions, no conflict
//! copies or temporary files, nothing over [`MAX_FILE`], never a deletion, never a path
//! outside the channel, and the newer modification time wins.
//!
//! [iroh]: https://www.iroh.computer

pub mod config;
pub mod health;
pub mod invite;
pub mod lane;
pub mod manifest;
pub mod tls;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

pub use config::IrohConfig;
pub use lane::{Lane, Status};

/// The protocol a connection speaks. A peer that offers anything else is not this lane.
pub const ALPN: &[u8] = b"ferryman/channel-sync/1";

/// The protocol the invite endpoint speaks, on its own endpoint and its own key. A peer
/// that offers the channel-sync ALPN here, or this ALPN on the lane, is refused.
pub const INVITE_ALPN: &[u8] = b"ferryman/invite/1";

/// The largest file the lane carries. A channel is coordination, not storage: orders,
/// results, records. Anything bigger is something that belongs in git or a hand-in.
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

/// The machine's iroh secret key, beside its operator seed.
pub const KEY_FILE: &str = "iroh.key";

/// The invite endpoint's iroh secret key, its own key beside the lane's. Never `iroh.key`:
/// the invite endpoint proves a different identity and must not be reachable as the lane.
pub const INVITE_KEY_FILE: &str = "invite-iroh.key";

/// Where the worker's lane writes what it last did.
pub const STATUS_FILE: &str = "iroh-status.json";

/// The machine state directory, or a refusal that says why there is none.
///
/// # Errors
/// No per-user directory can be determined on this machine.
pub fn machine_dir() -> Result<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().context(
        "no per-user state directory (LOCALAPPDATA, XDG_STATE_HOME or HOME) on this machine, \
         so there is nowhere private to keep an iroh key",
    )
}

/// This machine's iroh secret key, if it has one. Never creates.
///
/// # Errors
/// A key file that exists and is not 32 bytes of hex: a key that is quietly replaced
/// changes the endpoint id every channel has on record, so it is a failure, not a reset.
pub fn load_key(machine_dir: &Path) -> Result<Option<iroh::SecretKey>> {
    load_key_file(machine_dir, KEY_FILE)
}

/// The invite endpoint's iroh key, if it has one. Never creates. Kept apart from the lane's
/// key so the invite endpoint is a different identity.
pub fn load_invite_key(machine_dir: &Path) -> Result<Option<iroh::SecretKey>> {
    load_key_file(machine_dir, INVITE_KEY_FILE)
}

fn load_key_file(machine_dir: &Path, file: &str) -> Result<Option<iroh::SecretKey>> {
    let path = machine_dir.join(file);
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    // As with the operator seed, the hex error is not chained: it names the character.
    let bytes = hex::decode(text.trim())
        .map_err(|_| anyhow!("{} is not an iroh key; move it aside", path.display()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow!(
            "{} is not a 32-byte iroh key; move it aside",
            path.display()
        )
    })?;
    Ok(Some(iroh::SecretKey::from_bytes(&bytes)))
}

/// This machine's iroh secret key, created on first use. Returns it and whether it is new.
///
/// Generated once, kept next to the operator seed, owner-only, and never put in a
/// channel: the endpoint id it proves is what every TRANSPORTS record names, so it is
/// what lets this machine in.
///
/// # Errors
/// The key file is unreadable or cannot be written.
pub fn load_or_create_key(machine_dir: &Path) -> Result<(iroh::SecretKey, bool)> {
    load_or_create_key_file(machine_dir, KEY_FILE)
}

/// The invite endpoint's iroh key, created on first use. Its own key, beside the lane's:
/// the endpoint that serves `ferryman/invite/1` must never share the lane's identity.
pub fn load_or_create_invite_key(machine_dir: &Path) -> Result<(iroh::SecretKey, bool)> {
    load_or_create_key_file(machine_dir, INVITE_KEY_FILE)
}

fn load_or_create_key_file(
    machine_dir: &Path,
    file: &str,
) -> Result<(iroh::SecretKey, bool)> {
    if let Some(key) = load_key_file(machine_dir, file)? {
        return Ok((key, false));
    }
    fs::create_dir_all(machine_dir)?;
    let path = machine_dir.join(file);
    let key = iroh::SecretKey::generate();
    // `create_new`: two processes starting at once must not each write a key and leave
    // the machine with whichever lost the race on record somewhere.
    let mut opened = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return load_key_file(machine_dir, file)?
                .map(|key| (key, false))
                .ok_or_else(|| anyhow!("{} appeared and then vanished", path.display()));
        }
        Err(error) => bail!("create {}: {error}", path.display()),
    };
    opened.write_all(hex::encode(key.to_bytes()).as_bytes())?;
    opened.sync_all()?;
    drop(opened);
    ferryman_channel::restrict_to_owner(&path)?;
    Ok((key, true))
}

/// The endpoint id as the TRANSPORTS records write it: 64 lowercase hex characters.
#[must_use]
pub fn endpoint_hex(id: &iroh::EndpointId) -> String {
    hex::encode(id.as_bytes())
}

/// Publish `identity`'s TRANSPORTS record into every channel in `routes`.
///
/// Returns how many records were written (an unchanged one is not rewritten) and a line
/// for each channel that could not take one.
#[must_use]
pub fn publish_everywhere(
    routes: &[ferryman_channel::ProjectRoute],
    identity: &ferryman_channel::AgentIdentity,
    endpoint: &iroh::EndpointId,
    relay_url: Option<&str>,
) -> (usize, Vec<String>) {
    let hex = endpoint_hex(endpoint);
    let mut written = 0;
    let mut failed = Vec::new();
    for route in routes {
        match ferryman_channel::transports::publish(route, identity, &hex, relay_url) {
            Ok(true) => written += 1,
            Ok(false) => {}
            Err(error) => failed.push(format!("{}: {error:#}", route.project_id)),
        }
    }
    (written, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_made_once_and_then_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (first, created) = load_or_create_key(dir.path()).unwrap();
        assert!(created);
        let (again, created) = load_or_create_key(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(first.public(), again.public());
    }

    #[test]
    fn a_damaged_key_is_refused_rather_than_replaced() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(KEY_FILE), "not a key").unwrap();
        assert!(load_or_create_key(dir.path()).is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join(KEY_FILE)).unwrap(),
            "not a key"
        );
    }
}

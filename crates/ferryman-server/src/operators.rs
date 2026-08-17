//! Password-sealed operator identities for the web dashboard.
//!
//! A human operator is a separate principal from the machine identity a worker
//! signs under. Their ed25519 signing seed is sealed at rest with a key derived
//! from their password (PBKDF2-SHA256 + XChaCha20-Poly1305), so the dashboard
//! process never holds the key until they log in - and holds it only in memory
//! for the lifetime of a session.
//!
//! The files live under the project's *private* attachment directory, never in
//! the synced channel. Only the public key is ever published (to the roster, by
//! the caller), exactly like any other agent.

use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ferryman_channel::{
    AgentIdentity, AgentRoute, ProjectRoute, is_safe_component, register_agent_key,
};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Keep the operator directory readable only by its owner.
///
/// Separate from [`ferryman_channel::restrict_to_owner`] because a directory needs the
/// execute bit to be traversable at all: 0600 on a directory makes it unusable, so this is
/// 0700 rather than a copy of the file version with a different constant.
fn restrict_dir_to_owner(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict {} to its owner", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

const FORMAT: &str = "ferryman-operator/v1";
const ITERATIONS: u32 = 600_000;
/// The smallest password we will accept for an identity that can approve work.
const MIN_PASSWORD_LEN: usize = 8;

/// Create a password-sealed operator identity and publish its public key to the
/// roster. This is the whole "create an operator" operation, shared by the
/// dashboard's sign-up endpoint and `ferry enable --dashboard`, so both paths
/// seal the key and register it identically.
pub fn create_operator_identity(
    route: &ProjectRoute,
    name: &str,
    password: &str,
) -> Result<AgentIdentity> {
    let store = OperatorStore::new(&route.attachment);
    let identity = store.create(name, password)?;
    let published = AgentRoute {
        name: identity.name().to_string(),
        role: "operator".to_string(),
        capabilities: Vec::new(),
        public_key: Some(identity.public_key_hex()),
    };
    // Publish the public key to the roster so the fleet can verify this
    // operator's signatures. If publication fails, remove the just-written
    // operator file: leaving it would record an identity the roster has never
    // heard of, and the name would then be "taken" while nothing can verify
    // anything it signs - a lockout the human cannot see or fix.
    if let Err(error) = register_agent_key(route, &published, &identity) {
        let _ = store.remove(name);
        return Err(error);
    }
    Ok(identity)
}

/// Where operator identities for one project are kept, keyed by name.
#[derive(Clone)]
pub struct OperatorStore {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct OperatorRecord {
    format: String,
    name: String,
    salt_hex: String,
    nonce_hex: String,
    iterations: u32,
    sealed_seed_hex: String,
    public_key_hex: String,
}

impl OperatorStore {
    /// Operator identities live beside the attachment, out of the synced folder.
    #[must_use]
    pub fn new(attachment: &Path) -> Self {
        Self {
            dir: attachment.join("operators"),
        }
    }

    /// Create a new operator identity, sealing its signing seed under the
    /// password. Refuses to replace an existing name: an operator is an
    /// identity, and quietly overwriting its key would lock it out.
    pub fn create(&self, name: &str, password: &str) -> Result<AgentIdentity> {
        if !is_safe_component(name) {
            bail!("operator name must be a path-safe identifier (letters, digits, `-`, `_`, `.`)");
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("password must be at least {MIN_PASSWORD_LEN} characters");
        }
        if self.path(name).exists() {
            bail!("an operator named '{name}' already exists");
        }

        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let identity = AgentIdentity::from_seed(name, seed);

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut salt);
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&derive_key(password, &salt, ITERATIONS))?;
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), seed.as_ref())
            .map_err(|_| anyhow::anyhow!("could not seal the operator key"))?;

        let record = OperatorRecord {
            format: FORMAT.into(),
            name: name.to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            iterations: ITERATIONS,
            sealed_seed_hex: hex::encode(sealed),
            public_key_hex: identity.public_key_hex(),
        };

        std::fs::create_dir_all(&self.dir)?;
        // Owner-only on the directory before anything is written into it, so there is no
        // instant at which a world-readable file exists.
        restrict_dir_to_owner(&self.dir)?;
        let path = self.path(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("could not create operator identity {name}"))?;
        serde_json::to_writer_pretty(file, &record)?;
        // This file is a password-cracking kit: salt, nonce, iteration count and the
        // sealed seed are everything an offline attack needs, and the only thing standing
        // between it and a forged signature that the whole fleet accepts is one password.
        // 600k PBKDF2 iterations is a strong ONLINE policy and a weak offline one, so the
        // file must not be readable by other accounts on this machine in the first place.
        //
        // The signing key next door has always done this (`restrict_to_owner`, used since
        // keys existed). This did not, which is the kind of gap that only shows up when
        // someone compares two files that should have matched.
        ferryman_channel::restrict_to_owner(&path)
            .with_context(|| format!("restrict {} to its owner", path.display()))?;
        Ok(identity)
    }

    /// Recover an operator's identity from its name and password. A wrong
    /// password and an unknown name are reported identically, so the store does
    /// not reveal which operators exist. The name is validated first: a
    /// traversal-looking name is rejected before any file is opened.
    pub fn login(&self, name: &str, password: &str) -> Result<AgentIdentity> {
        if !is_safe_component(name) {
            return Err(anyhow::anyhow!("operator name or password is incorrect"));
        }
        let record: OperatorRecord = serde_json::from_reader(
            std::fs::File::open(self.path(name))
                .map_err(|_| anyhow::anyhow!("operator name or password is incorrect"))?,
        )
        .map_err(|_| anyhow::anyhow!("operator identity file is unreadable"))?;
        if record.format != FORMAT {
            bail!("unsupported operator identity format");
        }
        let salt = hex::decode(&record.salt_hex)?;
        let nonce = hex::decode(&record.nonce_hex)?;
        if salt.len() != 16 || nonce.len() != 24 {
            bail!("operator identity file is malformed");
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(&derive_key(password, &salt, record.iterations))?;
        let seed = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                hex::decode(&record.sealed_seed_hex)?.as_ref(),
            )
            .map_err(|_| anyhow::anyhow!("operator name or password is incorrect"))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("operator identity file is malformed"))?;
        let identity = AgentIdentity::from_seed(&record.name, seed);
        // The seed and the published key must agree, or the file was tampered with.
        if identity.public_key_hex() != record.public_key_hex {
            bail!("operator identity file is inconsistent");
        }
        Ok(identity)
    }

    /// Whether at least one operator identity exists. Lets the dashboard put a
    /// first-time visitor straight onto "create operator" rather than a sign-in
    /// form with nothing to sign into. Reveals only the *count* being zero or
    /// not, never which operators exist.
    pub fn any(&self) -> bool {
        std::fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .any(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            })
            .unwrap_or(false)
    }

    /// Remove an operator identity file. Used to unwind a half-finished
    /// creation (file written, roster registration failed) so the name is not
    /// left occupied by an identity nobody can verify.
    pub fn remove(&self, name: &str) -> Result<()> {
        let path = self.path(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("removing operator file for '{name}'"))?;
        }
        Ok(())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sealed file is a complete offline-cracking kit, so no other account on the
    /// machine may read it. Asserted rather than assumed: the signing key beside it has
    /// been owner-only since keys existed, this file was world-readable, and nothing
    /// failed - a permission bug produces no error and no wrong output, only a
    /// consequence somewhere else entirely.
    #[cfg(unix)]
    #[test]
    fn the_sealed_operator_file_is_not_readable_by_other_accounts() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = OperatorStore::new(dir.path());
        store.create("alice", "hunter2-secret").unwrap();

        let file = std::fs::metadata(store.path("alice"))
            .unwrap()
            .permissions();
        assert_eq!(
            file.mode() & 0o777,
            0o600,
            "the sealed seed must be owner-only, not {:o}",
            file.mode() & 0o777
        );

        // The directory the store actually owns - `operators/` under the attachment, not
        // the attachment itself, which belongs to the project and is not ours to lock
        // down. 0700 rather than 0600: a directory without the execute bit cannot be
        // traversed, so copying the file mode here would break login.
        let parent = std::fs::metadata(dir.path().join("operators"))
            .unwrap()
            .permissions();
        assert_eq!(
            parent.mode() & 0o777,
            0o700,
            "the operator directory must be owner-only and traversable, not {:o}",
            parent.mode() & 0o777
        );
    }

    #[test]
    fn password_round_trip_and_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorStore::new(dir.path());

        assert!(
            store.create("op/alice", "secret123").is_err(),
            "path-unsafe name"
        );
        assert!(store.create("alice", "short").is_err(), "short password");

        let identity = store.create("alice", "hunter2-secret").unwrap();
        assert_eq!(identity.name(), "alice");

        let unlocked = store.login("alice", "hunter2-secret").unwrap();
        assert_eq!(unlocked.name(), "alice");
        assert_eq!(unlocked.public_key_hex(), identity.public_key_hex());

        // Wrong password and unknown name are reported identically.
        assert_eq!(
            store.login("alice", "nope").unwrap_err().to_string(),
            store.login("nobody", "nope").unwrap_err().to_string()
        );

        // Existing names cannot be overwritten.
        assert!(store.create("alice", "whatever123").is_err());
    }

    #[test]
    fn login_refuses_path_traversal_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorStore::new(dir.path());
        store.create("alice", "hunter2-secret").unwrap();

        // A traversal-looking name must be rejected like an unknown name, before
        // any file outside the operators directory is opened.
        for name in ["../alice", "..", ".", "a/b", "/etc/passwd"] {
            assert!(
                store.login(name, "hunter2-secret").is_err(),
                "traversal name '{name}' must not be readable"
            );
        }
        // The honest path still works.
        assert!(store.login("alice", "hunter2-secret").is_ok());
    }

    #[test]
    fn remove_unwinds_a_failed_registration() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorStore::new(dir.path());
        store.create("alice", "hunter2-secret").unwrap();
        store.remove("alice").unwrap();
        // The name is free again: a retry can recreate it.
        let identity = store.create("alice", "hunter2-secret").unwrap();
        assert_eq!(identity.name(), "alice");
        // Removing a name that was never created is not an error.
        store.remove("nobody").unwrap();
    }
}

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
    let identity = OperatorStore::new(&route.attachment).create(name, password)?;
    let published = AgentRoute {
        name: identity.name().to_string(),
        role: "operator".to_string(),
        capabilities: Vec::new(),
        public_key: Some(identity.public_key_hex()),
    };
    register_agent_key(route, &published, &identity)?;
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
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path(name))
            .with_context(|| format!("could not create operator identity {name}"))?;
        serde_json::to_writer_pretty(file, &record)?;
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
        let record: OperatorRecord =
            serde_json::from_reader(std::fs::File::open(self.path(name)).map_err(|_| {
                anyhow::anyhow!("operator name or password is incorrect")
            })?)
            .map_err(|_| anyhow::anyhow!("operator identity file is unreadable"))?;
        if record.format != FORMAT {
            bail!("unsupported operator identity format");
        }
        let salt = hex::decode(&record.salt_hex)?;
        let nonce = hex::decode(&record.nonce_hex)?;
        if salt.len() != 16 || nonce.len() != 24 {
            bail!("operator identity file is malformed");
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&derive_key(
            password,
            &salt,
            record.iterations,
        ))?;
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

    #[test]
    fn password_round_trip_and_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorStore::new(dir.path());

        assert!(store.create("op/alice", "secret123").is_err(), "path-unsafe name");
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
}


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
        // An operator must be able to RECEIVE. This was an empty list, and the
        // consequence was quiet rather than loud: nothing refused, but every path that
        // routes by capability skipped the human. The one principal in the fleet that
        // exists to be told things could not be told anything.
        capabilities: vec!["messages.receive".to_string()],
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

/// What a sealed record says about itself, without opening it.
///
/// Only the two public facts: who it claims to be, and the key it will sign with. Enough
/// to check a record against the roster before installing it, and nothing that helps
/// anyone open it.
pub struct SealedSummary {
    pub name: String,
    pub public_key: String,
}

/// Read the public half of a sealed record. No password, so no seed.
pub fn peek(sealed: &[u8]) -> Result<SealedSummary> {
    let record: OperatorRecord =
        serde_json::from_slice(sealed).context("this is not an operator identity file")?;
    if record.format != FORMAT {
        bail!("unsupported operator identity format");
    }
    Ok(SealedSummary {
        name: ferryman_channel::canonical_agent_name(&record.name),
        public_key: record.public_key_hex,
    })
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
        let name = &ferryman_channel::canonical_agent_name(name);
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

    /// Whether this machine holds a sealed identity for `name`.
    ///
    /// Deliberately narrower than `any()`: this answers "can I offer to unseal this one",
    /// which the CLI needs before prompting for a password. It leaks that a *named*
    /// operator exists, which `login` is careful not to - acceptable here because the
    /// caller already holds the private attachment directory, and prompting for the
    /// password of an operator that cannot exist is a worse answer than saying so.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.path(name).is_file()
    }

    /// The sealed record itself, for carrying an operator between their own machines.
    ///
    /// Returns the file's bytes verbatim. It is safe to move over any channel *because*
    /// it is sealed: salt, nonce, iteration count and the ciphertext, and nothing that
    /// opens them. That is the property the format was designed for, and the reason an
    /// operator does not need a second identity per machine the way an agent does.
    ///
    /// It is still a password-cracking kit, so this hands back bytes rather than writing
    /// them somewhere convenient - the caller decides where, and the CLI restricts it.
    pub fn export(&self, name: &str) -> Result<Vec<u8>> {
        std::fs::read(self.path(name))
            .with_context(|| format!("no operator identity for '{name}' on this machine"))
    }

    /// Install a sealed record exported from another machine.
    ///
    /// Refuses to overwrite: replacing an operator's sealed seed with another is how a
    /// person loses the identity everything they have ever signed is verified against.
    /// The record is opened and checked before it is stored, so a corrupt or foreign file
    /// is rejected here rather than at the first attempt to sign with it.
    pub fn import(&self, sealed: &[u8]) -> Result<String> {
        let record: OperatorRecord =
            serde_json::from_slice(sealed).context("this is not an operator identity file")?;
        if record.format != FORMAT {
            bail!("unsupported operator identity format");
        }
        let name = ferryman_channel::canonical_agent_name(&record.name);
        if !is_safe_component(&name) {
            bail!("operator identity file names an operator that cannot exist");
        }
        if self.path(&name).exists() {
            bail!(
                "an operator named '{name}' already exists on this machine; remove it \
                 deliberately if you mean to replace it"
            );
        }
        std::fs::create_dir_all(&self.dir)?;
        restrict_dir_to_owner(&self.dir)?;
        let path = self.path(&name);
        std::fs::write(&path, sealed)?;
        ferryman_channel::restrict_to_owner(&path)
            .with_context(|| format!("restrict {} to its owner", path.display()))?;
        Ok(name)
    }

    /// The operators this machine can sign as, for `ferry operator list`.
    pub fn names(&self) -> Result<Vec<String>> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(Vec::new());
        };
        let mut names: Vec<String> = entries
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .filter_map(|path| path.file_stem()?.to_str().map(str::to_owned))
            .collect();
        names.sort();
        Ok(names)
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

    /// An operator name is folded exactly like every other agent name, and for the same
    /// reason: this is a filename. `OP.json` and `op.json` are one file on NTFS and two
    /// on ext4, so without folding a human operator becomes two principals with two keys
    /// the moment they work from a second machine - which is precisely the split that
    /// `canonical_agent_name` exists to prevent, appearing again in the one identity that
    /// is a *person* rather than a machine.
    fn path(&self, name: &str) -> PathBuf {
        let name = ferryman_channel::canonical_agent_name(name);
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

    /// One person, one identity, however they capitalise their own name.
    ///
    /// This is the same fold as every agent name, and it matters more here, not less:
    /// an operator is the identity that approves work, and it is the only one that
    /// deliberately moves between machines - so it meets both a case-folding and a
    /// case-sensitive filesystem in the course of ordinary use.
    #[test]
    fn an_operator_is_one_identity_however_it_is_capitalised() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorStore::new(dir.path());
        let created = store.create("OP", "correct horse battery").unwrap();
        assert_eq!(
            created.name(),
            "op",
            "the identity itself carries the folded name"
        );

        // The same person, typed four ways, is the same key every time.
        for spelling in ["op", "OP", "Op", "oP"] {
            assert!(store.exists(spelling), "{spelling} should be found");
            let back = store.login(spelling, "correct horse battery").unwrap();
            assert_eq!(back.public_key_hex(), created.public_key_hex());
        }
        // And a second registration under another spelling is refused, rather than
        // quietly minting a second operator who signs as the same person.
        assert!(store.create("op", "another password").is_err());
    }

    /// The sealed record survives the journey between two machines, and is useless
    /// on the way.
    #[test]
    fn an_operator_can_be_carried_to_another_machine() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let (here, there) = (
            OperatorStore::new(first.path()),
            OperatorStore::new(second.path()),
        );

        let original = here.create("op", "correct horse battery").unwrap();
        let sealed = here.export("op").unwrap();

        // What travels is ciphertext: the seed must not be recoverable from the file.
        let seed_hex = hex::encode(original.seed_bytes());
        assert!(
            !String::from_utf8_lossy(&sealed).contains(&seed_hex),
            "the exported file must not contain the signing seed"
        );

        assert_eq!(there.import(&sealed).unwrap(), "op");
        let carried = there.login("op", "correct horse battery").unwrap();
        assert_eq!(
            carried.public_key_hex(),
            original.public_key_hex(),
            "the same person signs with the same key on both machines"
        );
        assert!(
            there.login("op", "the wrong password").is_err(),
            "carrying the file must not carry the password with it"
        );
        // Importing over an existing operator would destroy the identity everything
        // that person has signed is verified against.
        assert!(there.import(&sealed).is_err());
    }

    /// An operator that cannot be sent to is not an operator. This published an empty
    /// capability list, so every path that routes by capability skipped the human.
    #[test]
    fn a_created_operator_can_receive_messages() {
        let dir = tempfile::tempdir().unwrap();
        let route = ferryman_channel::ProjectRoute {
            project_id: "ferryman".into(),
            workspace: dir.path().join("workspace"),
            attachment: dir.path().join("workspace/.ferryman"),
            communications: dir.path().join("workspace/.ferryman/ferryman"),
            shared_remote: "ferryman-ferryman".into(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        std::fs::create_dir_all(&route.communications).unwrap();
        create_operator_identity(&route, "op", "correct horse battery").unwrap();

        let roster = ferryman_channel::read_agent_roster(&route.communications).unwrap();
        let op = roster
            .iter()
            .find(|a| a.name == "op")
            .expect("op is in the roster");
        assert!(
            op.capabilities.iter().any(|c| c == "messages.receive"),
            "an operator must be addressable, got {:?}",
            op.capabilities
        );
    }

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

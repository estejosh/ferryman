//! Password-sealed operator identities for the web dashboard.
//!
//! A human operator's ed25519 signing key derives from the machine's one operator
//! seed (ADR 0016), exactly as every agent's key does: `HKDF-SHA256(seed,
//! "ferryman/v1/operator")`. The password is no longer the root of the identity; it
//! is the LOCAL UNLOCK. It seals the derived signing key at rest with PBKDF2-SHA256
//! and XChaCha20-Poly1305, so the dashboard process never holds the key until the
//! person logs in, and holds it only in memory for the lifetime of a session.
//!
//! The recovery phrase restores the seed, and therefore the identity. An operator
//! whose key predates the seed keeps its key forever, exactly as an agent's does:
//! derivation is a bootstrap for new identities, never a re-key of an old one.
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
use ferryman_channel::seed::OperatorSeed;
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
    create_operator_identity_in(
        route,
        &OperatorStore::new(&route.attachment),
        name,
        password,
    )
}

/// The same, with the store given rather than discovered.
///
/// `AgentIdentity::load_or_create_in` exists for this reason and this is the same need: a
/// test of the whole create-and-publish path must be able to say which machine it is on.
/// Without it the only test covering this path wrote an operator into the developer's real
/// state directory, and then failed on the *second* run because the name it had polluted
/// was still there.
pub fn create_operator_identity_in(
    route: &ProjectRoute,
    store: &OperatorStore,
    name: &str,
    password: &str,
) -> Result<AgentIdentity> {
    create_operator_identity_scoped(route, store, name, password, false)
}

/// The same, choosing whether the operator belongs to this project or to the machine.
pub fn create_operator_identity_scoped(
    route: &ProjectRoute,
    store: &OperatorStore,
    name: &str,
    password: &str,
    this_project_only: bool,
) -> Result<AgentIdentity> {
    let identity = store.create_scoped(name, password, this_project_only)?;
    publish_operator(route, store, identity)
}

/// Create an operator from an already-derived signing seed, then publish it.
///
/// The dashboard's first-run path calls this after deriving the operator key from the
/// machine seed itself, so it can create the seed, show the recovery phrase, and seal the
/// derived key under the password in one breath. `create_operator_identity` above derives
/// the seed itself; this exists for the one caller that must also *show* the seed's phrase.
pub fn create_operator_identity_from_seed(
    route: &ProjectRoute,
    store: &OperatorStore,
    name: &str,
    password: &str,
    signing_seed: [u8; 32],
) -> Result<AgentIdentity> {
    let identity = store.create_scoped_with_seed(name, password, false, signing_seed)?;
    publish_operator(route, store, identity)
}

/// Publish an operator's public key to the roster, unwinding the just-written file on
/// failure so a name is never left occupied by an identity nothing can verify.
fn publish_operator(
    route: &ProjectRoute,
    store: &OperatorStore,
    identity: AgentIdentity,
) -> Result<AgentIdentity> {
    let published = AgentRoute {
        name: identity.name().to_string(),
        role: "operator".to_string(),
        // An operator must be able to RECEIVE. This was an empty list, and the
        // consequence was quiet rather than loud: nothing refused, but every path that
        // routes by capability skipped the human. The one principal in the fleet that
        // exists to be told things could not be told anything.
        capabilities: vec!["messages.receive".to_string()],
        public_key: Some(identity.public_key_hex()),
        encryption_key: None,
    };
    // Publish the public key to the roster so the fleet can verify this
    // operator's signatures. If publication fails, remove the just-written
    // operator file: leaving it would record an identity the roster has never
    // heard of, and the name would then be "taken" while nothing can verify
    // anything it signs - a lockout the human cannot see or fix.
    if let Err(error) = register_agent_key(route, &published, &identity) {
        let _ = store.remove(identity.name());
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

/// Where this machine's operator identities live, keyed by name.
///
/// # Two directories, and why an operator gets what a machine key already got
///
/// A machine key used to live only under a project's `.ferryman/`, so one machine working
/// on three projects had three keys under one name. The note on
/// `AgentIdentity::load_or_create` puts it plainly: *an identity that changes per
/// directory is not an identity*. It was fixed by storing the key once per machine.
///
/// An operator is a **person**, which is a stronger version of the same argument, and it
/// did not get the same treatment - so being the operator of nineteen projects meant
/// nineteen imports, and twenty after the next project.
///
/// So identities are read machine-wide, from beside the machine key. What makes that safe
/// here, and would not be safe for a machine key, is that these records are **sealed**: a
/// machine key is plaintext on disk, so one per machine is the only prudent number, while
/// an operator record is ciphertext whose password its owner holds. Several people can
/// therefore keep an identity on one machine without being able to sign as one another,
/// which is exactly what a shared workstation needs.
///
/// # Why the project directory does not simply go away
///
/// Machine-wide must not mean machine-*only*. A project may deliberately have a different
/// operator from the rest of the machine - a client's repository approved by that client's
/// account, not by whoever owns the laptop. So a project-local record still exists and
/// still WINS for that name. The order is specific-beats-general, the same rule paths and
/// configuration already follow here.
///
/// Existing installs are unaffected: everything already written is project-local, and
/// project-local is what is consulted first.
#[derive(Clone)]
pub struct OperatorStore {
    /// This project's own operators. Checked first; a name here overrides the machine.
    project: PathBuf,
    /// Every operator this machine knows. `None` only when the machine has no state
    /// directory at all, which is the same condition under which a machine key has
    /// nowhere to live either.
    machine: Option<PathBuf>,
    /// The machine state directory itself, where the operator seed lives. `None` under
    /// the same condition as `machine`; distinct from `machine` because the seed is not an
    /// operator record - it is the root the operator's key derives from (ADR 0016).
    machine_state: Option<PathBuf>,
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
    /// Operator identities live out of the synced folder: beside the machine key for the
    /// ones that belong to this person wherever they work, and beside the attachment for
    /// any this project overrides.
    #[must_use]
    pub fn new(attachment: &Path) -> Self {
        Self::with_machine_dir(attachment, ferryman_channel::licensing::machine_state_dir())
    }

    /// The same, with the machine directory given rather than discovered.
    ///
    /// Exactly the reason `AgentIdentity::load_or_create_in` exists, and needed here for
    /// the same two: a test must be able to describe a *different machine* to check that
    /// an identity crosses between them, and `use_machine_state_dir` is first-call-wins,
    /// so a test cannot switch machines by setting it twice - it would silently keep the
    /// first and quietly assert nothing.
    ///
    /// It also keeps the suite out of the developer's real home directory. Before the
    /// store had a machine tier, `new` touched nothing outside the temporary attachment
    /// it was given; now it would write operator records into this machine's actual state
    /// directory as a side effect of running tests, which is the fault that note on
    /// `use_machine_state_dir` was written about.
    #[must_use]
    pub fn with_machine_dir(attachment: &Path, machine_dir: Option<PathBuf>) -> Self {
        Self {
            project: attachment.join("operators"),
            machine: machine_dir.as_ref().map(|dir| dir.join("operators")),
            machine_state: machine_dir,
        }
    }

    /// Both directories, most specific first. The single place the precedence rule is
    /// written down, so no method can disagree with another about it.
    fn search_path(&self) -> Vec<&Path> {
        let mut dirs: Vec<&Path> = vec![self.project.as_path()];
        dirs.extend(self.machine.as_deref());
        dirs
    }

    /// Where a record for `name` already is, if it is anywhere.
    fn existing_path(&self, name: &str) -> Option<PathBuf> {
        self.search_path()
            .into_iter()
            .map(|dir| Self::path_in(dir, name))
            .find(|path| path.is_file())
    }

    /// Where a NEW record for `name` should be written: machine-wide, so the person is
    /// themselves in every project on this machine rather than in the one they happened
    /// to be standing in. Falls back to the project only when the machine has no state
    /// directory to write to.
    fn write_dir(&self) -> &Path {
        self.machine.as_deref().unwrap_or(self.project.as_path())
    }

    /// The machine's operator seed, if this machine has a state directory and a seed in
    /// it. `None` is an ordinary answer - a machine that predates ADR 0016 has no seed -
    /// and an unreadable seed is a loud error, exactly as `OperatorSeed::load` promises.
    fn machine_seed(&self) -> Result<Option<OperatorSeed>> {
        match self.machine_state.as_deref() {
            Some(dir) => OperatorSeed::load(dir),
            None => Ok(None),
        }
    }

    /// The machine state directory this store reads the seed from and writes records to,
    /// if any. The dashboard needs this to create and read the seed in the *same* place the
    /// store reads operator records from, so the two can never disagree about which machine
    /// they are on.
    #[must_use]
    pub fn machine_state_dir(&self) -> Option<&Path> {
        self.machine_state.as_deref()
    }

    /// Create a new operator identity, sealing its signing seed under the
    /// password. Refuses to replace an existing name: an operator is an
    /// identity, and quietly overwriting its key would lock it out.
    pub fn create(&self, name: &str, password: &str) -> Result<AgentIdentity> {
        self.create_scoped(name, password, false)
    }

    /// The same, choosing whether the new record belongs to this project or to the
    /// machine.
    ///
    /// Scope is a property of the WRITE, not of the store, and the difference is not
    /// cosmetic. A store narrowed to the project would also narrow its reads, so the
    /// duplicate check below would stop seeing a machine-wide record - and creating
    /// `shin` for one project would silently mint a second key for a `shin` this machine
    /// already knows. That is the exact fault the store exists to prevent, arriving
    /// through the door built to allow the legitimate case.
    pub fn create_scoped(
        &self,
        name: &str,
        password: &str,
        this_project_only: bool,
    ) -> Result<AgentIdentity> {
        // The signing key derives from the machine's one seed when it has one (ADR 0016);
        // otherwise it is minted at random, which is the behaviour every machine that
        // predates the seed already has and the one a seedless machine must keep. An
        // operator whose key already exists is never re-keyed: the duplicate check inside
        // `create_scoped_with_seed` refuses, exactly as it always has.
        let signing_seed = match self.machine_seed()? {
            Some(seed) => seed.operator_signing_seed()?,
            None => {
                let mut minted = [0u8; 32];
                rand::Rng::fill_bytes(&mut rand::rng(), &mut minted);
                minted
            }
        };
        self.create_scoped_with_seed(name, password, this_project_only, signing_seed)
    }

    /// The same, sealing a signing seed the caller already holds rather than deriving or
    /// minting one. The dashboard's first-run path uses this after deriving the key from
    /// the seed it just created, so it can show the recovery phrase in the same request.
    pub fn create_scoped_with_seed(
        &self,
        name: &str,
        password: &str,
        this_project_only: bool,
        signing_seed: [u8; 32],
    ) -> Result<AgentIdentity> {
        if !is_safe_component(name) {
            bail!("operator name must be a path-safe identifier (letters, digits, `-`, `_`, `.`)");
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            bail!("password must be at least {MIN_PASSWORD_LEN} characters");
        }
        // Anywhere, not just here. Creating `op` in a second project when the machine
        // already knows `op` would mint a second key for one person - the exact fault
        // this store exists to prevent, arriving by the back door.
        if self.existing_path(name).is_some() {
            bail!("an operator named '{name}' already exists on this machine");
        }

        let name = &ferryman_channel::canonical_agent_name(name);
        let identity = AgentIdentity::from_seed(name, signing_seed);

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut salt);
        rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&derive_key(password, &salt, ITERATIONS))?;
        let sealed = cipher
            .encrypt(&XNonce::from(nonce), signing_seed.as_ref())
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

        let dir = if this_project_only {
            self.project.as_path()
        } else {
            self.write_dir()
        };
        std::fs::create_dir_all(dir)?;
        // Owner-only on the directory before anything is written into it, so there is no
        // instant at which a world-readable file exists.
        restrict_dir_to_owner(dir)?;
        let path = Self::path_in(dir, name);
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
        let path = self
            .existing_path(name)
            .ok_or_else(|| anyhow::anyhow!("operator name or password is incorrect"))?;
        let record: OperatorRecord = serde_json::from_reader(
            std::fs::File::open(path)
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
                &XNonce::try_from(nonce.as_slice())
                    .map_err(|_| anyhow::anyhow!("operator identity file is malformed"))?,
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
        self.search_path().into_iter().any(|dir| {
            std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .filter_map(std::result::Result::ok)
                        .any(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                })
                .unwrap_or(false)
        })
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
        self.existing_path(name).is_some()
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
        let path = self
            .existing_path(name)
            .ok_or_else(|| anyhow::anyhow!("no operator identity for '{name}' on this machine"))?;
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))
    }

    /// Install a sealed record exported from another machine.
    ///
    /// Refuses to overwrite: replacing an operator's sealed seed with another is how a
    /// person loses the identity everything they have ever signed is verified against.
    /// The record is opened and checked before it is stored, so a corrupt or foreign file
    /// is rejected here rather than at the first attempt to sign with it.
    pub fn import(&self, sealed: &[u8], this_project_only: bool) -> Result<String> {
        let record: OperatorRecord =
            serde_json::from_slice(sealed).context("this is not an operator identity file")?;
        if record.format != FORMAT {
            bail!("unsupported operator identity format");
        }
        let name = ferryman_channel::canonical_agent_name(&record.name);
        if !is_safe_component(&name) {
            bail!("operator identity file names an operator that cannot exist");
        }
        // Machine-wide unless the caller is deliberately giving THIS project a different
        // operator from the rest of the machine. One import, then this person is
        // themselves in every project here - which is the whole point, and the reason a
        // per-project store was the wrong shape for a human.
        let dir = if this_project_only {
            self.project.as_path()
        } else {
            self.write_dir()
        };
        let path = Self::path_in(dir, &name);
        if path.exists() {
            bail!(
                "an operator named '{name}' already exists here; remove it deliberately \
                 if you mean to replace it"
            );
        }
        // Shadowing is legitimate; shadowing by accident is not. The two directions are
        // not symmetric, so they are not treated as if they were:
        //
        //   --this-project-only over a machine-wide record  -> exactly what was asked
        //      for. A client repository approved by that client's account rather than by
        //      whoever owns the laptop is a real arrangement, and the flag is how you say
        //      so. Allowed silently.
        //
        //   machine-wide under an existing PROJECT record   -> the import appears to
        //      succeed and then does nothing here, because project-local wins. That is a
        //      lie told by a success message, so it is refused instead.
        if !this_project_only
            && let Some(existing) = self.existing_path(&name)
            && existing.starts_with(&self.project)
        {
            bail!(
                "'{name}' is already an operator of THIS project ({}), and a project's own \
                 record wins over the machine's. Importing machine-wide would report \
                 success and change nothing here. Remove that record first if the machine \
                 copy is meant to take over.",
                existing.display()
            );
        }
        std::fs::create_dir_all(dir)?;
        restrict_dir_to_owner(dir)?;
        std::fs::write(&path, sealed)?;
        ferryman_channel::restrict_to_owner(&path)
            .with_context(|| format!("restrict {} to its owner", path.display()))?;
        Ok(name)
    }

    /// The operators this machine can sign as, for `ferry operator list`.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = Vec::new();
        for dir in self.search_path() {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for path in entries
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            {
                let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                // One name, one entry: a project record and a machine record for the same
                // person are the same person, and only one of them is ever used. Listing
                // both would suggest a choice the caller does not have.
                if !names.iter().any(|known| known == name) {
                    names.push(name.to_owned());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// Whether `name` is answered by this project specifically rather than by the
    /// machine, so callers can show where an identity is coming from.
    #[must_use]
    pub fn is_project_local(&self, name: &str) -> bool {
        self.existing_path(name)
            .is_some_and(|path| path.starts_with(&self.project))
    }

    /// Remove an operator identity file. Used to unwind a half-finished
    /// creation (file written, roster registration failed) so the name is not
    /// left occupied by an identity nobody can verify.
    pub fn remove(&self, name: &str) -> Result<()> {
        if let Some(path) = self.existing_path(name) {
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
    fn path_in(dir: &Path, name: &str) -> PathBuf {
        let name = ferryman_channel::canonical_agent_name(name);
        dir.join(format!("{name}.json"))
    }
}

/// A store whose "machine" is this test's own temporary directory.
///
/// Every test in this crate that creates an operator must go through here, because the
/// store became machine-wide and a machine is now a shared namespace: two tests both
/// creating `alice` are, correctly, one person being created twice. They collided as soon
/// as the tier was added - and before that they were writing into the developer's real
/// state directory without anything saying so.
///
/// The machine directory is placed under the test's own attachment. That is not where a
/// machine directory belongs in production, and it does not need to be: what a test needs
/// is a machine of its own, and each test already has a temporary directory that is
/// exactly that.
#[cfg(test)]
pub(crate) fn test_store(attachment: &Path) -> OperatorStore {
    OperatorStore::with_machine_dir(attachment, Some(attachment.join("machine")))
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
        let machine = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &dir);
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

    /// A store on a named machine, with nothing discovered from the real one.
    ///
    /// Every test here builds its store through this, and none calls `OperatorStore::new`.
    /// That is not style. `new` consults this machine's actual state directory, so a test
    /// using it writes operator records into the developer's real home - and, because the
    /// suite runs in parallel and tests share names like `alice`, they then collide with
    /// each other and fail with "already exists on this machine". Both happened here on
    /// the first run of the two-tier store; the second symptom is the only reason the
    /// first was noticed.
    fn store_on(machine: &tempfile::TempDir, project: &tempfile::TempDir) -> OperatorStore {
        OperatorStore::with_machine_dir(project.path(), Some(machine.path().to_path_buf()))
    }

    /// The dashboard operator derives from the machine seed, and its password is only the
    /// local unlock (ADR 0016). Creating an operator on a machine that holds a seed must
    /// yield the seed's operator fingerprint, not a fresh random key.
    #[test]
    fn a_new_operator_derives_from_the_machine_seed() {
        let machine = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let seed = ferryman_channel::seed::OperatorSeed::create_in(machine.path()).unwrap();
        let store = store_on(&machine, &project);

        let created = store.create("op", "correct horse battery").unwrap();
        assert_eq!(
            created.public_key_hex(),
            seed.operator_fingerprint().unwrap(),
            "a new operator must be the seed's operator identity, not a second random key"
        );

        // The password still unlocks it: the derived key is sealed at rest, exactly as a
        // minted one was.
        let back = store.login("op", "correct horse battery").unwrap();
        assert_eq!(back.public_key_hex(), created.public_key_hex());
    }

    /// An operator created before the machine had a seed is never re-keyed. Minting a seed
    /// afterwards must not change the operator's published key.
    #[test]
    fn an_operator_that_predates_the_seed_keeps_its_key() {
        let machine = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &project);
        let created = store.create("op", "correct horse battery").unwrap();

        // A seed appears later (e.g. a future `ferry enable`), and it does not touch the
        // existing operator.
        let seed = ferryman_channel::seed::OperatorSeed::create_in(machine.path()).unwrap();
        assert_ne!(
            created.public_key_hex(),
            seed.operator_fingerprint().unwrap(),
            "the pre-seed operator must not be re-keyed by the arrival of a seed"
        );
        let back = store.login("op", "correct horse battery").unwrap();
        assert_eq!(back.public_key_hex(), created.public_key_hex());
    }

    /// One import, and the person is themselves in every project on the machine.
    ///
    /// This is the whole reason the store has two tiers. Nineteen channels used to mean
    /// nineteen imports, and twenty after the next project - the same "an identity that
    /// changes per directory is not an identity" fault the machine key was fixed for,
    /// reappearing in the identity that is a *person*.
    #[test]
    fn one_import_covers_every_project_on_the_machine() {
        let machine = tempfile::tempdir().unwrap();
        let first = tempfile::tempdir().unwrap();
        store_on(&machine, &first)
            .create("op", "correct horse battery")
            .unwrap();

        // A project that has never seen this file, on the same machine, can sign as op.
        let untouched = tempfile::tempdir().unwrap();
        let elsewhere = store_on(&machine, &untouched);
        assert!(elsewhere.exists("op"), "op should be known machine-wide");
        assert!(elsewhere.login("op", "correct horse battery").is_ok());
        assert!(
            !elsewhere.is_project_local("op"),
            "it is the machine answering, not this project"
        );

        // And a DIFFERENT machine knows nothing about them, which is the other half of
        // the claim: machine-wide is a scope, not a broadcast.
        let other_machine = tempfile::tempdir().unwrap();
        assert!(!store_on(&other_machine, &untouched).exists("op"));
    }

    /// Several people may keep an identity on one machine without being able to sign as
    /// one another. This is what makes machine-wide storage safe HERE and not for a
    /// machine key: a machine key is plaintext, these records are ciphertext.
    #[test]
    fn two_different_operators_can_share_a_machine() {
        let machine = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &project);

        let op = store.create("op", "correct horse battery").unwrap();
        let alice = store.create("alice", "a different password").unwrap();
        assert_ne!(op.public_key_hex(), alice.public_key_hex());
        assert_eq!(
            store.names().unwrap(),
            vec!["alice".to_string(), "op".to_string()]
        );

        // Sharing a machine is not sharing an identity.
        assert!(store.login("alice", "correct horse battery").is_err());
        assert!(store.login("op", "a different password").is_err());
        assert_eq!(
            store
                .login("alice", "a different password")
                .unwrap()
                .public_key_hex(),
            alice.public_key_hex()
        );
    }

    /// A project may deliberately have a different operator from the rest of the machine,
    /// and the specific one wins. Machine-wide must not mean machine-only.
    #[test]
    fn a_project_can_override_the_machine_wide_operator() {
        let machine = tempfile::tempdir().unwrap();
        let ordinary = tempfile::tempdir().unwrap();
        let machine_wide = store_on(&machine, &ordinary)
            .create("op", "correct horse battery")
            .unwrap();

        // The client builds their identity on their own machine and carries it here.
        let their_machine = tempfile::tempdir().unwrap();
        let their_project = tempfile::tempdir().unwrap();
        let theirs = store_on(&their_machine, &their_project);
        let client_identity = theirs.create("op", "the client's password").unwrap();
        let sealed = theirs.export("op").unwrap();

        // Installed for the client's repository only.
        let client_repo = tempfile::tempdir().unwrap();
        let client_store = store_on(&machine, &client_repo);
        client_store.import(&sealed, true).unwrap();

        assert!(
            client_store.is_project_local("op"),
            "the project's own record answers here"
        );
        assert_eq!(
            client_store
                .login("op", "the client's password")
                .unwrap()
                .public_key_hex(),
            client_identity.public_key_hex(),
        );
        // Every other project on the same machine is untouched.
        let another = tempfile::tempdir().unwrap();
        assert_eq!(
            store_on(&machine, &another)
                .login("op", "correct horse battery")
                .unwrap()
                .public_key_hex(),
            machine_wide.public_key_hex(),
        );
    }

    /// The arrangement this was actually asked for: two people, one machine, one of them
    /// the operator of a single project.
    ///
    /// Josh operates every project on the machine; Shin operates one of them and nothing
    /// else. Both hold an identity here, neither can sign as the other, and Shin's does
    /// not follow the machine into Josh's other projects.
    #[test]
    fn one_project_can_have_its_own_operator_alongside_the_machines() {
        let machine = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        let owner = store_on(&machine, &shared)
            .create("op", "josh's password")
            .unwrap();

        // Shin is created for their project only.
        let their_project = tempfile::tempdir().unwrap();
        let theirs = store_on(&machine, &their_project);
        let shin = theirs
            .create_scoped("shin", "shin's password", true)
            .unwrap();

        assert!(theirs.is_project_local("shin"));
        assert!(
            !theirs.is_project_local("op"),
            "op is the machine's, not this project's"
        );
        // Both are usable in the project they share, and only with their own password.
        assert_eq!(
            theirs
                .login("shin", "shin's password")
                .unwrap()
                .public_key_hex(),
            shin.public_key_hex()
        );
        assert_eq!(
            theirs
                .login("op", "josh's password")
                .unwrap()
                .public_key_hex(),
            owner.public_key_hex()
        );
        assert!(theirs.login("shin", "josh's password").is_err());

        // And Shin is absent from every other project on this machine.
        let elsewhere = store_on(&machine, &tempfile::tempdir().unwrap());
        assert!(
            !elsewhere.exists("shin"),
            "shin must not follow the machine"
        );
        assert!(elsewhere.exists("op"));
    }

    /// Creating a project-scoped operator must still SEE the machine, or it would mint a
    /// second key for a person this machine already knows - the fault the store exists to
    /// prevent, arriving through the door built for the legitimate case.
    #[test]
    fn a_project_scoped_create_cannot_duplicate_a_machine_wide_name() {
        let machine = tempfile::tempdir().unwrap();
        store_on(&machine, &tempfile::tempdir().unwrap())
            .create("op", "josh's password")
            .unwrap();

        let error = store_on(&machine, &tempfile::tempdir().unwrap())
            .create_scoped("op", "a different password", true)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("already exists on this machine"),
            "got: {error:#}"
        );
    }

    /// Importing machine-wide underneath an existing project record would report success
    /// and change nothing, because the project record keeps winning. A success message
    /// that is not true is worse than a refusal.
    #[test]
    fn a_machine_wide_import_refuses_to_hide_under_a_project_record() {
        let their_machine = tempfile::tempdir().unwrap();
        let their_project = tempfile::tempdir().unwrap();
        let theirs = store_on(&their_machine, &their_project);
        theirs.create("op", "correct horse battery").unwrap();
        let sealed = theirs.export("op").unwrap();

        let machine = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &project);
        store.import(&sealed, true).unwrap();

        let error = store.import(&sealed, false).unwrap_err();
        assert!(
            format!("{error:#}").contains("wins over the machine"),
            "got: {error:#}"
        );
    }

    /// The sealed record survives the journey between two machines, and is useless
    /// on the way.
    #[test]
    fn an_operator_can_be_carried_to_another_machine() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let (machine_a, machine_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (here, there) = (store_on(&machine_a, &first), store_on(&machine_b, &second));

        let original = here.create("op", "correct horse battery").unwrap();
        let sealed = here.export("op").unwrap();

        // What travels is ciphertext: the seed must not be recoverable from the file.
        let seed_hex = hex::encode(original.seed_bytes());
        assert!(
            !String::from_utf8_lossy(&sealed).contains(&seed_hex),
            "the exported file must not contain the signing seed"
        );

        assert_eq!(there.import(&sealed, false).unwrap(), "op");
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
        assert!(there.import(&sealed, false).is_err());
    }

    /// An operator that cannot be sent to is not an operator. This published an empty
    /// capability list, so every path that routes by capability skipped the human.
    #[test]
    fn a_created_operator_can_receive_messages() {
        // Redirect the whole machine, not just the operator store. `register_agent_key`
        // also publishes to the FLEET roster, which lives under the same machine
        // directory - so injecting the store alone left this test writing `op` into the
        // developer's real fleet, and failing on the next run with "already published
        // with a different key". Two separate leaks through one directory; fixing the
        // first only made the second legible.
        //
        // First call wins process-wide, which is what makes this safe to call from a
        // test: every test in this binary then agrees on the same fake machine.
        ferryman_channel::licensing::use_machine_state_dir_per_thread(
            std::env::temp_dir().join(format!("ferryman-optest-{}", std::process::id())),
        );
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
        let machine = tempfile::tempdir().unwrap();
        create_operator_identity_in(
            &route,
            &OperatorStore::with_machine_dir(&route.attachment, Some(machine.path().to_path_buf())),
            "op",
            "correct horse battery",
        )
        .unwrap();

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

        let machine = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &dir);
        store.create("alice", "hunter2-secret").unwrap();

        let file = std::fs::metadata(store.existing_path("alice").expect("just created"))
            .unwrap()
            .permissions();
        assert_eq!(
            file.mode() & 0o777,
            0o600,
            "the sealed seed must be owner-only, not {:o}",
            file.mode() & 0o777
        );

        // The directory the store actually owns - `operators/`, not the directory it sits
        // under, which belongs to the project or to the machine and is not ours to lock
        // down. 0700 rather than 0600: a directory without the execute bit cannot be
        // traversed, so copying the file mode here would break login.
        //
        // Read from the store rather than rebuilt from `dir`, because a new record is now
        // written machine-wide: hardcoding the project path here would have checked the
        // permissions of a directory the record is no longer in, and passed.
        let parent = std::fs::metadata(machine.path().join("operators"))
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
        let machine = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &dir);

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
        let machine = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &dir);
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
        let machine = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = store_on(&machine, &dir);
        store.create("alice", "hunter2-secret").unwrap();
        store.remove("alice").unwrap();
        // The name is free again: a retry can recreate it.
        let identity = store.create("alice", "hunter2-secret").unwrap();
        assert_eq!(identity.name(), "alice");
        // Removing a name that was never created is not an error.
        store.remove("nobody").unwrap();
    }
}

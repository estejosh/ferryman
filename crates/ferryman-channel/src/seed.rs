//! One seed on a machine, and every identity derives from it (ADR 0016).
//!
//! # What this is for
//!
//! Before this, every key on a machine was minted at random the first time some
//! command needed it: one per agent for signing, another per agent for sealed
//! secrets. Nothing tied them together, so there was nothing to back up, nothing to
//! restore, and one fingerprint per agent per project for anyone trying to verify a
//! stranger out of band. The seed is the one secret that has to survive.
//!
//! ```text
//! signing    key for agent A = HKDF-SHA256(seed, info = "ferryman/v1/sign/"    || A)
//! encryption key for agent A = HKDF-SHA256(seed, info = "ferryman/v1/encrypt/" || A)
//! ```
//!
//! Distinct keys per agent, because the property the whole design rests on is that
//! when something breaks at 3am you can tell *which agent* did it. HKDF is one-way,
//! so an agent holding its own derived key learns nothing about the seed or about
//! its siblings.
//!
//! # Derivation is a bootstrap, not a permanent binding
//!
//! The derived key is written to the keystore on first use and **the keystore wins
//! from then on**. That is the difference between this and Nostr's model, which the
//! ADR takes the idea from: an agent whose key must change writes a new one and the
//! roster reports `KeyChanged` exactly as it does today, without the seed changing
//! and without touching any sibling. Recovery re-derives; rotation overrides.
//!
//! # Where it lives, and where it must never live
//!
//! The machine state directory ([`crate::licensing::machine_state_dir`]), owner-only,
//! beside the device id and the per-agent keys. It is machine state and it never
//! travels: not into a project attachment, not into the channel, not into anything
//! Syncthing carries. It is never logged, printed, or put in an error message -
//! [`OperatorSeed`]'s `Debug` redacts it, and the load errors name the path only.
//!
//! # The cost, stated plainly
//!
//! One seed is one blast radius. A leaked agent key forges that agent; a leaked seed
//! forges every identity that has not since rotated. That is the trade every hardware
//! wallet makes, and it is only acceptable because the seed does not travel.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::secrets::EncryptionIdentity;
use crate::{AgentIdentity, canonical_agent_name, is_safe_component};

/// The file that holds this machine's seed, inside the machine state directory.
const SEED_FILE: &str = "operator.seed";

/// HKDF `info` prefix for a signing key. Versioned, and distinct from the encryption
/// prefix, so one seed cannot produce the same 32 bytes for two different jobs.
const SIGNING_INFO: &str = "ferryman/v1/sign/";

/// HKDF `info` prefix for an encryption key. See [`SIGNING_INFO`].
const ENCRYPTION_INFO: &str = "ferryman/v1/encrypt/";

/// A machine's operator seed: 32 random bytes, created once, from which every
/// identity on that machine can be derived.
pub struct OperatorSeed {
    bytes: [u8; 32],
}

/// Never shows the seed. A seed may reach a log line or a test failure by accident -
/// through `{:?}` on a struct that holds one - and that single leak forges every
/// identity on the machine. The same reason [`AgentIdentity`] redacts its own.
impl std::fmt::Debug for OperatorSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorSeed(<redacted>)")
    }
}

impl OperatorSeed {
    /// Where the seed lives for a given machine state directory.
    #[must_use]
    pub fn path_in(machine_dir: &Path) -> PathBuf {
        machine_dir.join(SEED_FILE)
    }

    /// Load this machine's seed, or `None` when there is not one.
    ///
    /// `None` is an ordinary answer, not a failure: a machine that predates this, or
    /// one whose operator has not opted in, has no seed and mints keys at random
    /// exactly as before.
    ///
    /// A seed file that exists but cannot be read as 32 bytes **is** a failure, and a
    /// loud one. Quietly minting a random key there would produce an identity that no
    /// later recovery from the phrase could reproduce, and the operator would not find
    /// out until the day they needed it.
    pub fn load(machine_dir: &Path) -> Result<Option<Self>> {
        let path = Self::path_in(machine_dir);
        if !path.is_file() {
            return Ok(None);
        }
        let encoded =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        // The hex error is deliberately dropped rather than chained: `hex::FromHexError`
        // names the offending character, and the offending character is seed material.
        // The path is all an operator needs in order to act on this.
        // Both errors name the remedy, because a corrupt seed is otherwise a wedge: this
        // refuses, and so do `create_in` and `restore_in`, so nothing on the machine can
        // mint a new identity again until a person moves the file.
        let bytes = hex::decode(encoded.trim()).map_err(|_| {
            anyhow!(
                "{} is not a valid operator seed. Move it aside and restore from the \
                 recovery phrase, or let this machine mint fresh keys without it.",
                path.display()
            )
        })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow!(
                "{} is not a 32-byte operator seed. Move it aside and restore from the \
                 recovery phrase, or let this machine mint fresh keys without it.",
                path.display()
            )
        })?;
        Ok(Some(Self { bytes }))
    }

    /// Load the seed belonging to *this* machine, wherever its state directory is.
    ///
    /// `None` when there is no seed, and also when no per-user directory can be
    /// determined - a machine with no home directory must still work, and it works the
    /// way it always did.
    pub fn load_for_machine() -> Result<Option<Self>> {
        match crate::licensing::machine_state_dir() {
            Some(dir) => Self::load(&dir),
            None => Ok(None),
        }
    }

    /// The seed for an optional machine directory: `None` in, `None` out.
    ///
    /// The shape `AgentIdentity::load_or_create_in` needs, where the machine directory
    /// is optional because a machine with no per-user directory must still work - and
    /// because a test constructs an identity belonging to a *different* machine by passing
    /// `None`. Such a caller has no seed by definition, and must not fall back to this
    /// machine's.
    pub(crate) fn load_from(machine_dir: Option<&Path>) -> Result<Option<Self>> {
        match machine_dir {
            Some(dir) => Self::load(dir),
            None => Ok(None),
        }
    }

    /// Create this machine's seed. Once.
    ///
    /// Refuses to replace an existing one. Replacing a seed does not lose one key: it
    /// silently changes what every future identity on the machine derives to, while the
    /// keys already written keep the old derivation - a state in which a restored phrase
    /// produces strangers. The only correct answer to "there is already a seed here" is
    /// to stop.
    pub fn create_in(machine_dir: &Path) -> Result<Self> {
        let path = Self::path_in(machine_dir);
        if path.exists() {
            bail!(
                "an operator seed already exists at {} - refusing to replace it, because \
                 everything derived from it would stop matching what the fleet has seen",
                path.display()
            )
        }
        let mut bytes = [0_u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
        write_new(&path, &bytes)?;
        Ok(Self { bytes })
    }

    /// Rebuild a seed from bytes, for restoring one from a recovery phrase.
    ///
    /// Writes nothing; persisting a restored seed is [`Self::restore_in`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Write a seed recovered from a phrase onto a machine that has none.
    ///
    /// The same refusal as [`Self::create_in`]: a machine that already has a seed is not
    /// recovered by being handed a second one.
    pub fn restore_in(&self, machine_dir: &Path) -> Result<()> {
        let path = Self::path_in(machine_dir);
        if path.exists() {
            bail!(
                "an operator seed already exists at {} - refusing to replace it",
                path.display()
            )
        }
        write_new(&path, &self.bytes)
    }

    /// The raw seed.
    ///
    /// The only legitimate caller is the code that turns a seed into a recovery phrase
    /// for an operator to write down, or back again. Deliberately not called `bytes()`:
    /// every use of it is a decision to handle the one secret that forges every identity
    /// on the machine, and it must never be logged, printed to a terminal that is not
    /// showing the phrase itself, or written anywhere but [`Self::path_in`].
    #[must_use]
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// This agent's signing identity, derived.
    ///
    /// Indistinguishable from a minted one to every reader: an ed25519 keypair whose
    /// private half happens to have come from HKDF rather than from the RNG.
    ///
    /// # Warning
    ///
    /// This derives and **does not consult the keystore**. Reaching for it instead of
    /// [`AgentIdentity::load_or_create`] re-keys an agent that already has a key on
    /// disk, and every signature that agent has already published then reads as an
    /// impostor to every other machine. Derivation is a bootstrap, not a binding: for
    /// "give me this agent's identity", the answer is always `load_or_create`.
    pub fn signing_identity(&self, agent: &str) -> Result<AgentIdentity> {
        Ok(AgentIdentity::from_seed(agent, self.signing_seed(agent)?))
    }

    /// This agent's encryption identity, derived. Carries the same warning as
    /// [`Self::signing_identity`]: it does not consult the keystore.
    pub fn encryption_identity(&self, agent: &str) -> Result<EncryptionIdentity> {
        Ok(EncryptionIdentity::from_seed(
            agent,
            self.encryption_seed(agent)?,
        ))
    }

    /// The 32 bytes an agent's ed25519 signing key is built from.
    pub(crate) fn signing_seed(&self, agent: &str) -> Result<[u8; 32]> {
        self.derive(SIGNING_INFO, agent)
    }

    /// The 32 bytes an agent's X25519 encryption key is built from.
    pub(crate) fn encryption_seed(&self, agent: &str) -> Result<[u8; 32]> {
        self.derive(ENCRYPTION_INFO, agent)
    }

    /// HKDF-SHA256, keyed with the seed, bound to a purpose and an agent.
    ///
    /// The same construction, from the same crate, that [`crate::secrets`] already uses
    /// to derive a sealed-secret slot key: one way to do key derivation in this crate,
    /// not two. The salt is `None` - HKDF's zero-filled salt - because the input keying
    /// material is already 32 uniformly random bytes, which is the case RFC 5869 says a
    /// salt is unnecessary for. All of the separation lives in `info`.
    ///
    /// The name is case-folded first. [`canonical_agent_name`] exists because `Fang` and
    /// `fang` were once two identities with two keys, and deriving from a raw name would
    /// reintroduce exactly that: two derivations sharing one key file, and a roster that
    /// reads the mismatch as impersonation.
    fn derive(&self, purpose: &str, agent: &str) -> Result<[u8; 32]> {
        if !is_safe_component(agent) {
            bail!("agent name must be a path-safe identifier")
        }
        let agent = canonical_agent_name(agent);
        let mut info = Vec::with_capacity(purpose.len() + agent.len());
        info.extend_from_slice(purpose.as_bytes());
        info.extend_from_slice(agent.as_bytes());
        let mut derived = [0_u8; 32];
        Hkdf::<Sha256>::new(None, &self.bytes)
            .expand(&info, &mut derived)
            // Unreachable for a 32-byte output - HKDF's limit is 255 hash lengths - and
            // still not an `expect`: this is signing-key code, and a panic here would
            // abort in the middle of establishing an identity.
            .map_err(|_| anyhow!("could not derive a key from the operator seed"))?;
        Ok(derived)
    }
}

/// Write a new secret file, owner-only from the moment it exists.
///
/// `create_new` so an existing seed cannot be clobbered by a race between two
/// processes, and the mode is set in the `open` call rather than afterwards: a
/// `write`-then-`chmod` leaves the seed briefly readable at whatever the umask allows,
/// which on a shared machine is every account on it.
fn write_new(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(hex::encode(bytes).as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    file.flush()?;
    // The one file in this crate where a torn write is not self-healing: a half-written
    // key file can be re-minted, a half-written seed wedges every future mint and takes
    // the recovery phrase with it.
    file.sync_all()
        .with_context(|| format!("flush {} to disk", path.display()))?;
    // Windows has no `mode`, and the state directory there is already per-user. Going
    // through the one resolver for "owner only" keeps this from becoming a second
    // implementation of it that drifts from the first.
    crate::restrict_to_owner(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRoute, Message, SignatureCheck, verify_message};
    use serde_json::json;

    /// A seed with known bytes, so a test states what it expects rather than
    /// discovering it.
    fn seed(byte: u8) -> OperatorSeed {
        OperatorSeed::from_bytes([byte; 32])
    }

    fn write_key(state_dir: &Path, file: &str, bytes: [u8; 32]) {
        let keys = state_dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join(file), hex::encode(bytes)).unwrap();
    }

    /// Same seed, same name, same key - every time, and from a seed rebuilt out of its
    /// own bytes as one restored from a phrase would be.
    ///
    /// This is the whole promise of recovery. If it ever fails, a restored machine comes
    /// back as a stranger to every roster that knew it.
    #[test]
    fn one_seed_and_one_name_derive_the_same_key_every_time() {
        let seed = seed(1);
        let first = seed.signing_identity("fang").unwrap();
        let second = seed.signing_identity("fang").unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());

        let restored = OperatorSeed::from_bytes(seed.expose_bytes());
        assert_eq!(
            restored.signing_identity("fang").unwrap().public_key_hex(),
            first.public_key_hex(),
            "a seed rebuilt from its own bytes derived a different signing key"
        );
        assert_eq!(
            restored
                .encryption_identity("fang")
                .unwrap()
                .public_key_hex(),
            seed.encryption_identity("fang").unwrap().public_key_hex(),
            "a seed rebuilt from its own bytes derived a different encryption key"
        );
    }

    /// Two agents under one seed hold DIFFERENT keys.
    ///
    /// This is the property per-agent keys exist for: when something breaks at 3am, the
    /// question is which agent did it, not which machine. If one seed ever produced one
    /// key for two names, every agent on a machine could sign as every other and the
    /// answer to that question would be unrecoverable from the record.
    #[test]
    fn two_agents_under_one_seed_never_share_a_key() {
        let seed = seed(2);
        let fang = seed.signing_identity("fang").unwrap();
        let wisp = seed.signing_identity("wisp").unwrap();
        assert_ne!(
            fang.public_key_hex(),
            wisp.public_key_hex(),
            "two agents share a signing key: 'which agent did what' is now unanswerable"
        );
        assert_ne!(
            seed.encryption_identity("fang").unwrap().public_key_hex(),
            seed.encryption_identity("wisp").unwrap().public_key_hex(),
            "two agents share an encryption key: either can open the other's secrets"
        );
        // And the two jobs are separated for one agent, which is what the distinct `info`
        // prefixes are for: a signing-key compromise must not hand over ciphertext.
        assert_ne!(
            seed.signing_seed("fang").unwrap(),
            seed.encryption_seed("fang").unwrap(),
            "one agent's signing and encryption keys are the same 32 bytes"
        );
    }

    /// `Fang` and `fang` are one identity, before derivation as well as after it.
    ///
    /// The key store is `keys/<name>.key`, so an unfolded derivation would give two
    /// spellings two different keys competing for one file on a folding filesystem and
    /// two files on a case-sensitive one - which is the exact split
    /// `canonical_agent_name` was introduced to end.
    #[test]
    fn a_name_is_folded_before_anything_is_derived_from_it() {
        let seed = seed(3);
        let folded = seed.signing_identity("fang").unwrap().public_key_hex();
        for spelling in ["Fang", "FANG", "fAnG"] {
            assert_eq!(
                seed.signing_identity(spelling).unwrap().public_key_hex(),
                folded,
                "'{spelling}' derived a second identity"
            );
        }
        assert!(
            seed.signing_identity("../elsewhere").is_err(),
            "a name that is not path-safe must be refused, not derived from"
        );
    }

    /// An identity that already has a key KEEPS it when a seed is present.
    ///
    /// The impersonation guard, and the reason derivation is only ever reached after both
    /// key stores have been consulted. An agent whose key changed under it would begin
    /// signing as a key the roster has not seen, and the roster - rightly - reports that
    /// as impersonation. Checked in both stores, because either one alone establishes an
    /// identity.
    #[test]
    fn an_agent_with_a_key_on_disk_keeps_it_when_a_seed_is_present() {
        let established = [9_u8; 32];
        let expected = AgentIdentity::from_seed("fang", established).public_key_hex();

        // The key in the project attachment.
        let attachment = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        write_key(attachment.path(), "fang.key", established);
        let seed = OperatorSeed::create_in(machine.path()).unwrap();
        let identity = AgentIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            identity.public_key_hex(),
            expected,
            "an established identity was re-keyed from the seed - everything it has \
             already signed now reads as an impostor"
        );
        assert_ne!(
            identity.public_key_hex(),
            seed.signing_identity("fang").unwrap().public_key_hex(),
            "the derived key must not have won over the one already on disk"
        );

        // The key in the machine store, with a fresh attachment joining it.
        let joining = tempfile::tempdir().unwrap();
        let machine_two = tempfile::tempdir().unwrap();
        write_key(machine_two.path(), "fang.key", established);
        OperatorSeed::create_in(machine_two.path()).unwrap();
        let joined = AgentIdentity::load_or_create_in(
            "fang",
            joining.path(),
            Some(machine_two.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            joined.public_key_hex(),
            expected,
            "a new attachment on a seeded machine minted a second key for an agent that \
             already had one"
        );

        // And the same for the encryption key, which ADR 0015 wrongly claimed already
        // derived: an established one is still kept.
        let sealed = [5_u8; 32];
        let attachment_three = tempfile::tempdir().unwrap();
        let machine_three = tempfile::tempdir().unwrap();
        write_key(attachment_three.path(), "fang.enc.key", sealed);
        OperatorSeed::create_in(machine_three.path()).unwrap();
        let recipient = EncryptionIdentity::load_or_create_in(
            "fang",
            attachment_three.path(),
            Some(machine_three.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            recipient.public_key_hex(),
            EncryptionIdentity::from_seed("fang", sealed).public_key_hex(),
            "an established encryption key was replaced - every secret already sealed to \
             it can no longer be opened"
        );
    }

    /// A machine with no seed works exactly as it did before: random mint, no panic, and
    /// no seed brought into existence behind the operator's back.
    #[test]
    fn a_machine_with_no_seed_still_mints_at_random() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        let first = AgentIdentity::load_or_create_in("fang", one.path(), None).unwrap();
        let second = AgentIdentity::load_or_create_in("fang", two.path(), None).unwrap();
        assert_ne!(
            first.public_key_hex(),
            second.public_key_hex(),
            "two unseeded machines minted the same key"
        );
        assert_eq!(
            AgentIdentity::load_or_create_in("fang", one.path(), None)
                .unwrap()
                .public_key_hex(),
            first.public_key_hex(),
            "a minted key must still be found on the next run"
        );

        // A machine directory that simply has no seed in it, which is every machine that
        // has not opted in.
        let attachment = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        let third = AgentIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        assert_ne!(third.public_key_hex(), first.public_key_hex());
        let sealed = EncryptionIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(sealed.public_key_hex().len(), 64);
        assert!(
            !OperatorSeed::path_in(machine.path()).exists(),
            "minting a key must not create a seed nobody asked for"
        );
    }

    /// Derive, then PERSIST - and from then on the keystore wins.
    ///
    /// The persist step is what keeps rotation possible, and it is the reason this is not
    /// simply Nostr's model. Skipping the write to save a disk operation would make the
    /// seed a permanent binding: an agent that had to re-key could not, because the next
    /// run would derive the old key straight back.
    #[test]
    fn a_derived_key_is_persisted_and_the_keystore_wins_from_then_on() {
        let attachment = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        let seed = OperatorSeed::create_in(machine.path()).unwrap();

        let derived = AgentIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            derived.public_key_hex(),
            seed.signing_identity("fang").unwrap().public_key_hex(),
            "a new identity on a seeded machine was minted at random instead of derived"
        );
        assert!(
            attachment.path().join("keys").join("fang.key").is_file(),
            "the derived key was not written to the project keystore"
        );
        assert!(
            machine.path().join("keys").join("fang.key").is_file(),
            "the derived key was not written to the machine keystore"
        );

        // The seed going away does not change who this agent is.
        std::fs::remove_file(OperatorSeed::path_in(machine.path())).unwrap();
        assert_eq!(
            AgentIdentity::load_or_create_in(
                "fang",
                attachment.path(),
                Some(machine.path().to_path_buf())
            )
            .unwrap()
            .public_key_hex(),
            derived.public_key_hex()
        );

        // Rotation: a different key in the keystore beats the seed, without the seed
        // changing and without any sibling being touched. The roster reports `KeyChanged`
        // for that, exactly as it does today.
        let rotated = [7_u8; 32];
        write_key(attachment.path(), "fang.key", rotated);
        write_key(machine.path(), "fang.key", rotated);
        seed.restore_in(machine.path()).unwrap();
        let after = AgentIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            after.public_key_hex(),
            AgentIdentity::from_seed("fang", rotated).public_key_hex(),
            "the seed overrode a deliberately rotated key"
        );
        assert_eq!(
            seed.expose_bytes(),
            OperatorSeed::load(machine.path())
                .unwrap()
                .unwrap()
                .expose_bytes(),
            "rotating one agent must not have changed the seed"
        );
    }

    /// A sealed-secrets key derives and persists the same way. ADR 0015 said this was
    /// already true; it was not, and this is the change that makes it true.
    #[test]
    fn an_encryption_key_derives_and_is_persisted_too() {
        let attachment = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        let seed = OperatorSeed::create_in(machine.path()).unwrap();

        let derived = EncryptionIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        assert_eq!(
            derived.public_key_hex(),
            seed.encryption_identity("fang").unwrap().public_key_hex()
        );
        assert!(
            attachment
                .path()
                .join("keys")
                .join("fang.enc.key")
                .is_file()
        );
        assert!(machine.path().join("keys").join("fang.enc.key").is_file());
    }

    /// A derived identity is indistinguishable from a minted one to a reader.
    ///
    /// The roster path is the only thing that decides whether a signature counts, and it
    /// must not learn - or be able to tell - where a private key came from.
    #[test]
    fn a_derived_identity_signs_something_the_roster_calls_valid() {
        let attachment = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        OperatorSeed::create_in(machine.path()).unwrap();
        let fang = AgentIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();

        let mut message = Message::new(
            "demo",
            "fang",
            "wisp",
            "text/plain",
            json!({ "text": "derived, and still me" }),
            true,
            None,
        );
        fang.sign(&mut message);
        let roster = vec![AgentRoute {
            name: "fang".into(),
            role: "worker".into(),
            capabilities: vec![],
            public_key: Some(fang.public_key_hex()),
            encryption_key: None,
        }];
        assert_eq!(verify_message(&message, &roster), SignatureCheck::Valid);
    }

    /// The seed is machine state and it never travels.
    ///
    /// Not into the attachment, which is where the channel and Syncthing reach. A seed
    /// that replicated would hand every machine in the fleet the ability to sign as every
    /// agent on this one.
    #[test]
    fn the_seed_never_lands_in_a_project_directory() {
        let attachment = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        let seed = OperatorSeed::create_in(machine.path()).unwrap();
        AgentIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();
        EncryptionIdentity::load_or_create_in(
            "fang",
            attachment.path(),
            Some(machine.path().to_path_buf()),
        )
        .unwrap();

        assert!(!OperatorSeed::path_in(attachment.path()).exists());
        let secret = hex::encode(seed.expose_bytes());
        for file in files_under(attachment.path()) {
            let contents = std::fs::read_to_string(&file).unwrap_or_default();
            assert!(
                !contents.contains(&secret),
                "{} holds the operator seed",
                file.display()
            );
        }
    }

    /// Every file below `root`, so the test above checks all of them rather than the ones
    /// it thought of.
    fn files_under(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else {
            return found;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(files_under(&path));
            } else {
                found.push(path);
            }
        }
        found
    }

    /// Owner-only on disk, and never replaced once it exists.
    #[test]
    fn the_seed_file_is_owner_only_and_is_never_replaced() {
        let machine = tempfile::tempdir().unwrap();
        let created = OperatorSeed::create_in(machine.path()).unwrap();
        let path = OperatorSeed::path_in(machine.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "the one secret that must survive was readable by other accounts"
            );
        }

        let err = OperatorSeed::create_in(machine.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"), "got: {err}");
        assert!(
            seed(4).restore_in(machine.path()).is_err(),
            "restoring over an existing seed must be refused"
        );
        assert_eq!(
            OperatorSeed::load(machine.path())
                .unwrap()
                .unwrap()
                .expose_bytes(),
            created.expose_bytes(),
            "the seed on disk is not the one that was created"
        );
        assert!(
            OperatorSeed::load(&machine.path().join("elsewhere"))
                .unwrap()
                .is_none(),
            "a machine with no seed reports none rather than failing"
        );
        assert!(path.is_file());
    }

    /// A seed that cannot be read fails loudly, and says nothing about its contents.
    ///
    /// Loudly, because minting a random key instead would produce an identity that no
    /// later recovery could reproduce, and nobody would find out until the day it
    /// mattered.
    #[test]
    fn an_unreadable_seed_fails_loudly_without_quoting_itself() {
        let machine = tempfile::tempdir().unwrap();
        let attachment = tempfile::tempdir().unwrap();
        let path = OperatorSeed::path_in(machine.path());

        std::fs::write(&path, "zz-not-hex").unwrap();
        let err = OperatorSeed::load(machine.path()).unwrap_err().to_string();
        assert!(err.contains("not a valid operator seed"), "got: {err}");
        assert!(
            !err.contains("zz-not-hex"),
            "the error quoted the file's contents: {err}"
        );
        assert!(
            AgentIdentity::load_or_create_in(
                "fang",
                attachment.path(),
                Some(machine.path().to_path_buf())
            )
            .is_err(),
            "a broken seed must stop the run, not silently mint an unrecoverable key"
        );

        std::fs::write(&path, hex::encode([1_u8; 16])).unwrap();
        let err = OperatorSeed::load(machine.path()).unwrap_err().to_string();
        assert!(err.contains("32-byte operator seed"), "got: {err}");
    }

    /// The seed is not in its own `Debug` output.
    #[test]
    fn a_seed_is_not_in_its_own_debug_output() {
        let seed = seed(0xab);
        let shown = format!("{seed:?}");
        assert!(
            !shown.contains(&hex::encode(seed.expose_bytes())),
            "the seed printed itself: {shown}"
        );
        assert!(shown.contains("redacted"), "got: {shown}");
    }

    /// The derivation is a wire format, and this pins it.
    ///
    /// Every machine that has already derived a key holds the result on disk. Changing the
    /// `info` strings, the salt, or the hash would leave those keys unreproducible from
    /// the same phrase - a silent break no other test here would catch, because the others
    /// all compare the derivation against itself.
    ///
    /// The two values were computed independently, from RFC 5869 HKDF-SHA256 with a
    /// zero-filled salt over the same `info` strings, rather than copied out of this
    /// implementation's own output. A test that only records what the code does would pass
    /// just as happily if the code were wrong.
    #[test]
    fn the_derivation_itself_is_pinned() {
        let seed = OperatorSeed::from_bytes([0x2a; 32]);
        assert_eq!(
            hex::encode(seed.signing_seed("fang").unwrap()),
            "b7b4c9dfc34bfe2def7d33f695c06039a3cabe572ba0ebf984ef2b34cf2d2b65",
            "the signing derivation changed: every already-derived key is unreachable"
        );
        assert_eq!(
            hex::encode(seed.encryption_seed("fang").unwrap()),
            "dd527bbe58d217722789dd3854dae7180d3ef0e8be8766f8c3290f9ab3e82282",
            "the encryption derivation changed: sealed secrets become unopenable"
        );
    }
}

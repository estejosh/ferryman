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
use bip39::{Language, Mnemonic};
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

/// HKDF `info` for the MACHINE's operator fingerprint - the one value a person reads
/// aloud to verify, out of band, that they are talking to the right machine.
///
/// A purpose string of its own, with no name after it: there is exactly one of these per
/// seed, which is the property that makes it a *machine* fingerprint. It is never used as
/// a signing key for a person - see [`OPERATOR_KEY_INFO`].
const OPERATOR_INFO: &str = "ferryman/v1/operator";

/// HKDF `info` prefix for one NAMED operator's signing key.
///
/// The name goes after the prefix, exactly as [`SIGNING_INFO`] and [`ENCRYPTION_INFO`]
/// carry an agent's. It has to. With a bare purpose string every operator created on a
/// machine derived the same 32 bytes, so a second operator published a byte-identical
/// public key under a different roster name - two names sharing one key, which is the
/// impersonation shape this project exists to prevent, and it happened silently with no
/// error and no test failing.
///
/// # Why it cannot collide with any other derivation from this seed
///
/// Every `info` in the scheme is one of four fixed byte strings, optionally followed by a
/// canonical name:
///
/// ```text
/// "ferryman/v1/sign/"     || agent
/// "ferryman/v1/encrypt/"  || agent
/// "ferryman/v1/operator/" || operator
/// "ferryman/v1/operator"                 (the machine fingerprint, nothing appended)
/// ```
///
/// The three prefixes share `"ferryman/v1/"` and then differ at index 12 - `s`, `e`, `o` -
/// so two `info` strings built from different prefixes differ at byte 12 whatever names
/// are appended. No agent name can make an agent key equal an operator key, and no
/// operator name can make an operator key equal an agent key.
///
/// Against the bare machine fingerprint the separation is by length: that string is 20
/// bytes and a per-operator string is at least 21, because [`is_safe_component`] refuses
/// an empty name, and its byte at index 20 is `/`.
///
/// Finally, [`is_safe_component`] admits only ASCII alphanumerics, `.`, `-` and `_`, so a
/// name can never contain `/` and the boundary between prefix and name is unambiguous.
const OPERATOR_KEY_INFO: &str = "ferryman/v1/operator/";

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

    /// The MACHINE's operator identity, derived from the seed.
    ///
    /// One per seed, and deliberately not bound to any name: its public key is the single
    /// fingerprint a person reads aloud to a colleague to verify, out of band, that they
    /// are talking to the right machine (ADR 0016).
    ///
    /// This is not the key any operator signs with. A *person* signs with
    /// [`Self::operator_identity_for`], which binds their name.
    ///
    /// Like [`Self::signing_identity`], this derives and does not consult the keystore.
    pub fn operator_identity(&self) -> Result<AgentIdentity> {
        Ok(AgentIdentity::from_seed(
            "operator",
            self.machine_signing_seed()?,
        ))
    }

    /// The 32 bytes behind the machine fingerprint. Private: nothing outside this module
    /// has any business sealing these as somebody's signing key, which is exactly the
    /// mistake that gave every operator on a machine one shared key.
    fn machine_signing_seed(&self) -> Result<[u8; 32]> {
        let mut derived = [0_u8; 32];
        Hkdf::<Sha256>::new(None, &self.bytes)
            .expand(OPERATOR_INFO.as_bytes(), &mut derived)
            .map_err(|_| anyhow!("could not derive the operator identity from the seed"))?;
        Ok(derived)
    }

    /// One named operator's signing identity, derived.
    ///
    /// Two operators on one machine are two people, so they get two keys - the same reason
    /// two agents do. The name is canonicalised and an unsafe one is refused, exactly as in
    /// [`Self::signing_seed`]; see [`OPERATOR_KEY_INFO`] for why this can never collide
    /// with an agent's key or with the machine fingerprint.
    ///
    /// Like [`Self::signing_identity`], this derives and does not consult the keystore.
    pub fn operator_identity_for(&self, operator: &str) -> Result<AgentIdentity> {
        Ok(AgentIdentity::from_seed(
            &canonical_agent_name(operator),
            self.operator_signing_seed(operator)?,
        ))
    }

    /// The 32 bytes a named operator's ed25519 signing key is built from.
    ///
    /// The third derivation alongside [`SIGNING_INFO`] and [`ENCRYPTION_INFO`], and bound
    /// to the operator's name for the same reason those are bound to an agent's.
    /// [`Self::operator_identity_for`] wraps these bytes in a keypair; this exists so the
    /// dashboard can seal an operator's signing key under their password (ADR 0016)
    /// exactly as it sealed a minted one before - the password is the local unlock, and
    /// the seed is what it unlocks.
    pub fn operator_signing_seed(&self, operator: &str) -> Result<[u8; 32]> {
        self.derive(OPERATOR_KEY_INFO, operator)
    }

    /// The machine fingerprint: the public key of [`Self::operator_identity`], as hex.
    ///
    /// Safe to print and safe to publish - it is a public key, not secret material -
    /// and it is the one value a person checks out of band rather than the O(agents)
    /// fingerprints the fleet used to ask for.
    pub fn operator_fingerprint(&self) -> Result<String> {
        Ok(self.operator_identity()?.public_key_hex())
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
            bail!("name must be a path-safe identifier")
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

/// 32 seed bytes as a BIP-39 English recovery phrase (24 words).
///
/// The phrase is the seed in words, and it is the one secret that has to survive. It is
/// shown to a person exactly once - by `ferry enable` at a terminal, or by the dashboard
/// on first run - and never stored anywhere. This function is deliberately a free function
/// over raw bytes rather than a method, so the only place that can produce a phrase is the
/// place that already holds the seed in the clear for the split second it exists.
pub fn seed_to_phrase(bytes: [u8; 32]) -> Result<String> {
    let mnemonic = Mnemonic::from_entropy(&bytes, Language::English)
        .map_err(|_| anyhow!("could not turn the operator seed into a recovery phrase"))?;
    Ok(mnemonic.phrase().to_string())
}

/// A BIP-39 English recovery phrase back into 32 seed bytes, validating its checksum.
///
/// The phrase itself is never echoed: an invalid phrase fails with a message that names the
/// problem but not the words, so a mistyped phrase cannot be copied out of an error log.
pub fn phrase_to_seed(phrase: &str) -> Result<[u8; 32]> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).map_err(|_| {
        anyhow!(
            "that did not read as a 24-word BIP-39 English recovery phrase - \
             check the words and the order, then try again"
        )
    })?;
    let entropy = mnemonic.entropy();
    entropy
        .try_into()
        .map_err(|_| anyhow!("the phrase did not hold a 32-byte operator seed"))
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

    /// Two operators on one machine are two people, and two people are two keys.
    ///
    /// Before the operator derivation carried a name, both of these were the same 32
    /// bytes: a second operator published a byte-identical public key under a different
    /// roster name, which is precisely the impersonation the roster exists to catch, and
    /// nothing anywhere said a word about it.
    #[test]
    fn two_operators_on_one_machine_do_not_share_a_key() {
        let seed = seed(7);
        let first = seed.operator_identity_for("ada").unwrap();
        let second = seed.operator_identity_for("grace").unwrap();
        assert_ne!(
            first.public_key_hex(),
            second.public_key_hex(),
            "two named operators on one seed must not share one signing key"
        );
        assert_eq!(first.name(), "ada");
        assert_eq!(second.name(), "grace");
    }

    /// The other half of the same claim: binding the name must not cost recovery. The
    /// same seed and the same name derive the same key, including from a seed rebuilt out
    /// of its own bytes the way a restored phrase rebuilds one.
    #[test]
    fn one_operator_name_derives_the_same_key_every_time() {
        let seed = seed(7);
        let first = seed.operator_identity_for("ada").unwrap();
        let again = seed.operator_identity_for("ada").unwrap();
        assert_eq!(first.public_key_hex(), again.public_key_hex());

        let restored = OperatorSeed::from_bytes(seed.expose_bytes());
        assert_eq!(
            restored
                .operator_identity_for("ada")
                .unwrap()
                .public_key_hex(),
            first.public_key_hex(),
            "a restored seed must bring the same operator back, not a stranger"
        );

        // One person, however they capitalise their own name.
        assert_eq!(
            seed.operator_identity_for("Ada").unwrap().public_key_hex(),
            first.public_key_hex()
        );
        // And an unsafe name is refused rather than quietly folded into something else.
        assert!(seed.operator_signing_seed("../etc").is_err());
        assert!(seed.operator_signing_seed("").is_err());
    }

    /// An operator's key, an agent's key of the same name, and the machine fingerprint are
    /// three different keys. The `info` strings cannot collide, and this says so out loud.
    #[test]
    fn an_operator_key_never_collides_with_an_agent_key_or_the_fingerprint() {
        let seed = seed(7);
        let operator = seed.operator_signing_seed("fang").unwrap();
        assert_ne!(operator, seed.signing_seed("fang").unwrap());
        assert_ne!(operator, seed.encryption_seed("fang").unwrap());
        assert_ne!(
            seed.operator_identity_for("operator")
                .unwrap()
                .public_key_hex(),
            seed.operator_fingerprint().unwrap(),
            "an operator NAMED `operator` must not be handed the machine fingerprint key"
        );
    }

    /// The operator fingerprint is a wire format too, and this pins it.
    ///
    /// It is the one fingerprint a person reads aloud to verify a machine out of band
    /// (ADR 0016), so two machines that disagree on it would disagree on who they are
    /// talking to. The value was computed independently - HKDF-SHA256 with a
    /// zero-filled salt over the `info` string, then ed25519 - rather than copied from
    /// this implementation's own output.
    #[test]
    fn the_operator_fingerprint_is_pinned() {
        let seed = OperatorSeed::from_bytes([0x2a; 32]);
        assert_eq!(
            seed.operator_fingerprint().unwrap(),
            "88f62b90e0e514a6aa278bc4d5cfd1874321ae191487edfe9abf23ab8049645c",
            "the operator fingerprint changed: two machines would disagree on who they are"
        );
    }
}

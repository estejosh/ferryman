//! What this deployment is entitled to, provable without asking anyone.
//!
//! # Why this exists
//!
//! Until this module there was no paid tier in the code at all - three free-tier
//! constants, a counter, and a message telling you that you were over. Nobody who paid
//! could tell Ferryman they had paid, including the person selling it. The first person
//! to hit it was the author, on his own machines.
//!
//! # Why it needs no server
//!
//! An entitlement is a signed statement by the licensor about one subject. The public
//! key is compiled into the binary, so checking one is arithmetic on bytes already in
//! hand: no activation call, nothing to be reachable, nothing that can be down. That is
//! the same promise the rest of Ferryman makes, and a licence check that phoned home
//! would quietly withdraw it.
//!
//! # Why it is checked against the BUILD, not the clock
//!
//! A yearly licence checked against the system clock is defeated by setting the clock
//! back, and the usual fix is a server. There is another way: the release date is
//! stamped into the binary at compile time, and an entitlement covers every build
//! released while it was valid. Moving your clock changes nothing, because the clock is
//! never consulted. Staying on a build you were licensed for is not a loophole - it is
//! the deal.
//!
//! # Why it never blocks
//!
//! Being over the allowance is reported and never enforced. A local-first tool that
//! stopped working because it could not verify something would betray the whole pitch,
//! and LICENSE already says failure to report is not enforced. This keeps that promise.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The licensor's public key, compiled in.
///
/// Public by design: it proves nothing and grants nothing on its own. It is the half
/// that lets any copy of Ferryman check a licence without asking anyone, which is the
/// whole reason this needs no activation server. The secret half exists on exactly one
/// machine, sealed with a password, and signs entitlements a few times a year.
///
/// Replacing this invalidates every entitlement ever issued under the old key, so it
/// changes when the licensor key changes and at no other time.
const LICENSOR_PUBLIC_KEY: &str =
    "5bf2c0718cdc8419d1ba0dbd4867f5fd4c1f0ee75bb08e8a8d7f6f5df0fff5ae";

/// The key an entitlement must be signed by.
///
/// Tests install their own licensor per thread rather than through the environment:
/// tests run in parallel and each needs a different licensor, and `set_var` is unsafe
/// in this edition while this crate forbids unsafe. An override grants nothing anyway -
/// it only changes whose signature counts here, which anyone editing their own copy
/// could do regardless.
#[must_use]
pub fn licensor_key() -> Option<VerifyingKey> {
    if let Some(key) = LICENSOR_OVERRIDE.with(|slot| *slot.borrow()) {
        return Some(key);
    }
    let bytes: [u8; 32] = hex::decode(LICENSOR_PUBLIC_KEY.trim())
        .ok()?
        .try_into()
        .ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

thread_local! {
    static LICENSOR_OVERRIDE: std::cell::RefCell<Option<VerifyingKey>> =
        const { std::cell::RefCell::new(None) };
}

/// Trust this licensor on this thread. For tests, and for a build that has to check a
/// key it was not compiled with.
pub fn use_licensor_key(key: VerifyingKey) {
    LICENSOR_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(key));
}

/// When this binary was built, which is what a licence window is measured against.
///
/// Stamped by `build.rs`. Absent on a build that could not determine it, which reads as
/// "no build date" and lets every entitlement cover it - erring towards the customer.
#[must_use]
pub fn build_date() -> Option<DateTime<Utc>> {
    let stamped = option_env!("FERRYMAN_BUILD_DATE")?.trim();
    let day = NaiveDate::parse_from_str(stamped, "%Y-%m-%d").ok()?;
    Some(Utc.from_utc_datetime(&day.and_hms_opt(0, 0, 0)?))
}

/// One signed statement by the licensor about one subject.
///
/// `None` in an allowance means unlimited. That is deliberate rather than a sentinel
/// number: an entitlement that says `"seats": null` cannot be misread as zero, and a
/// reader who does not know the convention sees something obviously not a count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlement {
    /// Unique per issue, so one can be named in a revocation without naming the buyer.
    pub id: String,
    /// The operator fingerprint this is issued to.
    ///
    /// Not a machine id and not an email. A machine id makes every reinstall a support
    /// ticket; an email proves nothing. The fingerprint is derived from the operator's
    /// seed (ADR 0016), survives a wiped machine, and comes back from the recovery
    /// phrase - it is already the thing Ferryman treats as the person.
    pub subject: String,
    #[serde(default)]
    pub seats: Option<usize>,
    #[serde(default)]
    pub computers: Option<usize>,
    #[serde(default)]
    pub mobile_devices: Option<usize>,
    pub issued: DateTime<Utc>,
    /// Builds released before this are covered. `None` is lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covers_builds_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub note: String,
    /// Who referred this customer, if anyone, and is owed commission on it.
    ///
    /// Recorded on the licence itself rather than in a ledger somewhere else, so the
    /// claim and the sale cannot drift apart: the thing the customer holds is the thing
    /// that says who introduced them, and it is signed, so neither party can edit it
    /// afterwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referred_by: Option<String>,
    /// The licensor key this was signed with, so a reader can see which one to check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The exact bytes a signature covers.
///
/// Built field by field rather than by serialising the struct, so adding a field later
/// cannot silently change what every already-issued entitlement was signed over. The
/// same reasoning as `ReleaseDenial` being its own record: consent is over bytes, and
/// bytes that move retroactively invalidate consent that was real.
#[must_use]
fn payload(entitlement: &Entitlement) -> String {
    let allowance = |value: Option<usize>| match value {
        Some(count) => count.to_string(),
        None => "unlimited".to_string(),
    };
    let base = format!(
        "ferryman-entitlement-v1\nid={}\nsubject={}\nseats={}\ncomputers={}\nmobile={}\nissued={}\ncovers_before={}\nnote={}",
        entitlement.id,
        entitlement.subject,
        allowance(entitlement.seats),
        allowance(entitlement.computers),
        allowance(entitlement.mobile_devices),
        entitlement.issued.to_rfc3339(),
        entitlement
            .covers_builds_before
            .map_or_else(|| "lifetime".to_string(), |at| at.to_rfc3339()),
        entitlement.note,
    );
    // Appended only when present, so a licence with no referrer signs exactly the bytes
    // it signed before this field existed. Adding a field unconditionally would have
    // broken every entitlement already issued - including the first one - and the only
    // symptom would be customers reporting that their licence stopped verifying.
    match &entitlement.referred_by {
        None => base,
        Some(referrer) => format!("{base}\nreferred_by={referrer}"),
    }
}

impl Entitlement {
    /// Sign this entitlement as the licensor. Only the licensor can do this usefully;
    /// a signature by any other key simply will not verify anywhere.
    pub fn sign(&mut self, key: &SigningKey) {
        let signature = key.sign(payload(self).as_bytes());
        self.signed_by = Some(hex::encode(key.verifying_key().to_bytes()));
        self.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Whether this was signed by the licensor this binary trusts.
    #[must_use]
    pub fn verifies(&self) -> bool {
        let (Some(key), Some(signature)) = (licensor_key(), self.signature.as_ref()) else {
            return false;
        };
        let Some(bytes) = hex::decode(signature)
            .ok()
            .and_then(|raw| <[u8; 64]>::try_from(raw).ok())
        else {
            return false;
        };
        key.verify(payload(self).as_bytes(), &Signature::from_bytes(&bytes))
            .is_ok()
    }

    /// Whether this entitlement covers the build in hand.
    ///
    /// The clock is never consulted. A build with no stamped date is covered, because
    /// refusing one would punish a customer for how their copy was compiled.
    #[must_use]
    pub fn covers(&self, build: Option<DateTime<Utc>>) -> bool {
        match (self.covers_builds_before, build) {
            (None, _) | (_, None) => true,
            (Some(until), Some(built)) => built < until,
        }
    }
}

/// Where this deployment stands, as one answer rather than a pile of booleans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "standing", rename_all = "snake_case")]
pub enum Standing {
    /// No entitlement installed. The free tier, which is a legitimate place to be.
    Free,
    /// Signed by the licensor and covering this build.
    Licensed(Entitlement),
    /// Genuine, but this build was released after the window closed. The customer keeps
    /// every build they paid for; this one is newer than what they bought.
    Lapsed(Entitlement),
    /// Present and not trustworthy. Says so rather than falling back silently, because
    /// a customer whose file does not verify needs to know today, not at renewal.
    Unverified(String),
}

impl Standing {
    /// The entitlement behind this standing, if any survived verification.
    ///
    /// Includes a lapsed one, because a reader showing the customer their licence should
    /// still show it. For deciding what is ALLOWED, use [`Self::licensed`].
    #[must_use]
    pub fn entitlement(&self) -> Option<&Entitlement> {
        match self {
            Self::Licensed(entitlement) | Self::Lapsed(entitlement) => Some(entitlement),
            Self::Free | Self::Unverified(_) => None,
        }
    }

    /// The entitlement that actually grants anything here.
    ///
    /// Only a licence covering this build grants. A lapsed one does not, or the window
    /// would mean nothing; an unverified one does not, or a text editor would be a
    /// licence generator.
    #[must_use]
    pub fn licensed(&self) -> Option<&Entitlement> {
        match self {
            Self::Licensed(entitlement) => Some(entitlement),
            Self::Lapsed(_) | Self::Free | Self::Unverified(_) => None,
        }
    }

    /// What a person should be told, in one line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Free => "free tier".to_string(),
            Self::Licensed(entitlement) => match entitlement.covers_builds_before {
                None => format!("licensed to {} (lifetime)", entitlement.subject),
                Some(until) => format!(
                    "licensed to {}, covering builds released before {}",
                    entitlement.subject,
                    until.format("%Y-%m-%d")
                ),
            },
            Self::Lapsed(entitlement) => format!(
                "this build is newer than the licence, which covers builds released before {}. \
                 Nothing stops working: the builds it covers stay licensed forever, and a \
                 renewal covers this one",
                entitlement
                    .covers_builds_before
                    .map_or_else(|| "-".to_string(), |at| at.format("%Y-%m-%d").to_string())
            ),
            Self::Unverified(why) => format!("licence file present but not usable: {why}"),
        }
    }
}

/// Where the installed entitlement lives. Machine-wide, never inside a channel: a
/// licence is about this deployment, and a channel is carried to other people.
#[must_use]
pub fn installed_path() -> Option<PathBuf> {
    crate::licensing::machine_state_dir().map(|dir| dir.join("licence.json"))
}

/// Read the installed entitlement and say where this deployment stands.
#[must_use]
pub fn standing() -> Standing {
    let Some(path) = installed_path().filter(|path| path.is_file()) else {
        return Standing::Free;
    };
    standing_from(&path)
}

fn standing_from(path: &Path) -> Standing {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => return Standing::Unverified(format!("cannot read it: {error}")),
    };
    let entitlement: Entitlement = match serde_json::from_str(&text) {
        Ok(entitlement) => entitlement,
        Err(error) => return Standing::Unverified(format!("not an entitlement: {error}")),
    };
    if !entitlement.verifies() {
        return Standing::Unverified(if licensor_key().is_none() {
            "this build carries no licensor key to check it against".to_string()
        } else {
            "the signature is not the licensor's".to_string()
        });
    }
    if entitlement.covers(build_date()) {
        Standing::Licensed(entitlement)
    } else {
        Standing::Lapsed(entitlement)
    }
}

/// Install an entitlement file for this machine, refusing one that does not verify.
///
/// Checked before it is stored rather than after, so a bad file is a message at the
/// moment someone can still do something about it, not a surprise months later.
pub fn install(from: &Path) -> Result<Entitlement> {
    let text = std::fs::read_to_string(from).with_context(|| format!("read {}", from.display()))?;
    let entitlement: Entitlement =
        serde_json::from_str(&text).context("that file is not a Ferryman entitlement")?;
    if !entitlement.verifies() {
        bail!(
            "that entitlement is not signed by the licensor this build trusts, so installing \
             it would prove nothing"
        );
    }
    let path = installed_path().context("no machine state directory to install into")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::atomic_json(&path, &entitlement).with_context(|| format!("write {}", path.display()))?;
    Ok(entitlement)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A licensor nobody else has, minted per test so parallel tests never share one.
    fn licensor() -> SigningKey {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        use_licensor_key(key.verifying_key());
        key
    }

    fn entitlement(covers_before: Option<DateTime<Utc>>) -> Entitlement {
        Entitlement {
            id: "ent-1".to_string(),
            subject: "0b80fc0a".to_string(),
            seats: Some(3),
            computers: Some(5),
            mobile_devices: None,
            issued: Utc.with_ymd_and_hms(2026, 9, 11, 0, 0, 0).unwrap(),
            covers_builds_before: covers_before,
            note: "paid in usdc".to_string(),
            referred_by: None,
            signed_by: None,
            signature: None,
        }
    }

    /// A build that ships without a readable licensor key can never accept a licence,
    /// and the symptom would be every paying customer's file reading as unverified. So
    /// the compiled-in key is checked here rather than discovered in the field.
    #[test]
    fn the_compiled_in_licensor_key_is_a_usable_public_key() {
        assert!(
            !LICENSOR_PUBLIC_KEY.is_empty(),
            "no licensor key compiled in: nothing could ever be licensed"
        );
        let bytes: [u8; 32] = hex::decode(LICENSOR_PUBLIC_KEY)
            .expect("licensor key is not hex")
            .try_into()
            .expect("licensor key is not 32 bytes");
        VerifyingKey::from_bytes(&bytes).expect("licensor key is not a valid ed25519 key");
    }

    /// Adding the referrer field must not have invalidated the licences issued before
    /// it existed - the first one of which is the author's own lifetime grant. A licence
    /// with no referrer has to sign exactly the bytes it signed yesterday.
    #[test]
    fn adding_the_referrer_did_not_change_what_an_existing_licence_signs_over() {
        let key = licensor();
        let mut without = entitlement(None);
        without.sign(&key);
        assert!(without.verifies());

        // The bytes, spelled out, so a future edit to `payload` fails here rather than
        // in a customer's install.
        assert_eq!(
            payload(&without),
            "ferryman-entitlement-v1\nid=ent-1\nsubject=0b80fc0a\nseats=3\ncomputers=5\n\
             mobile=unlimited\nissued=2026-09-11T00:00:00+00:00\ncovers_before=lifetime\n\
             note=paid in usdc"
        );

        // And a referred licence signs over the referrer, so it cannot be added,
        // removed or redirected after the fact by whoever wants the commission.
        let mut referred = entitlement(None);
        referred.referred_by = Some("mohammad".to_string());
        referred.sign(&key);
        assert!(referred.verifies());
        assert_ne!(payload(&without), payload(&referred));

        referred.referred_by = Some("someone-else".to_string());
        assert!(!referred.verifies(), "a commission cannot be redirected");
    }

    /// The whole point: a licence proves itself with nothing to ask.
    #[test]
    fn an_entitlement_the_licensor_signed_verifies_offline() {
        let key = licensor();
        let mut ent = entitlement(None);
        assert!(!ent.verifies(), "unsigned proves nothing");
        ent.sign(&key);
        assert!(ent.verifies());
    }

    /// Editing the allowance after signing must break it, or the file is a suggestion.
    #[test]
    fn raising_your_own_seat_count_stops_it_verifying() {
        let key = licensor();
        let mut ent = entitlement(None);
        ent.sign(&key);
        ent.seats = Some(500);
        assert!(!ent.verifies());
    }

    /// A different key's signature is not the licensor's, however well formed.
    #[test]
    fn somebody_elses_licensor_does_not_count() {
        let _real = licensor();
        let mut ent = entitlement(None);
        ent.sign(&SigningKey::from_bytes(&[9u8; 32]));
        assert!(!ent.verifies());
    }

    /// The trick that removes the server: expiry is measured against the build, not the
    /// clock. A customer who sets their clock forward, back, or to 1970 changes nothing.
    #[test]
    fn the_licence_window_is_measured_against_the_build_not_the_clock() {
        let window = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
        let ent = entitlement(Some(window));

        let before = Utc.with_ymd_and_hms(2026, 12, 31, 0, 0, 0).unwrap();
        let after = Utc.with_ymd_and_hms(2027, 1, 2, 0, 0, 0).unwrap();
        assert!(ent.covers(Some(before)), "a build they paid for");
        assert!(
            !ent.covers(Some(after)),
            "a build released after the window"
        );

        // Lifetime covers anything, and an unstamped build is covered rather than
        // punished for how it was compiled.
        assert!(entitlement(None).covers(Some(after)));
        assert!(ent.covers(None));
    }

    /// A build newer than the window is lapsed, not unlicensed - and never blocked. The
    /// builds they paid for stay licensed forever.
    #[test]
    fn a_build_past_the_window_reads_as_lapsed_and_says_so_kindly() {
        let key = licensor();
        let mut ent = entitlement(Some(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()));
        ent.sign(&key);

        let lapsed = Standing::Lapsed(ent.clone());
        assert!(lapsed.entitlement().is_some());
        assert!(
            lapsed.describe().contains("Nothing stops working"),
            "the wording has to say so: {}",
            lapsed.describe()
        );

        let licensed = Standing::Licensed(ent);
        assert!(licensed.describe().contains("licensed to"));
        assert_eq!(Standing::Free.describe(), "free tier");
    }

    /// An unreadable or forged file must be named as such, never treated as absent: a
    /// customer whose licence does not verify has to find out while they can still act.
    #[test]
    fn a_file_that_does_not_verify_is_reported_not_ignored() {
        let key = licensor();
        let dir = tempfile::tempdir().unwrap();

        let good = dir.path().join("good.json");
        let mut ent = entitlement(None);
        ent.sign(&key);
        std::fs::write(&good, serde_json::to_string(&ent).unwrap()).unwrap();
        assert!(matches!(standing_from(&good), Standing::Licensed(_)));

        let tampered = dir.path().join("tampered.json");
        ent.seats = Some(9000);
        std::fs::write(&tampered, serde_json::to_string(&ent).unwrap()).unwrap();
        assert!(matches!(standing_from(&tampered), Standing::Unverified(_)));

        let rubbish = dir.path().join("rubbish.json");
        std::fs::write(&rubbish, "not json").unwrap();
        assert!(matches!(standing_from(&rubbish), Standing::Unverified(_)));
    }
}

/// A licence holder asserting that their licence governs this project.
///
/// # Why a claim exists at all
///
/// An entitlement is signed but not secret - it is published, quoted, and sent around,
/// and it grants to a fingerprint rather than to whoever is holding the file. So a
/// channel cannot simply believe an entitlement that appears in it: anyone could copy
/// the author's own unlimited licence into their channel and be licensed for nothing.
///
/// What makes the claim safe is that the subject of an entitlement is itself a public
/// key - the machine operator identity derived from the seed (ADR 0016). Only the holder
/// of that seed can sign as it. So a claim carries a signature BY THE SUBJECT over this
/// project, and a copied entitlement is worthless without the seed behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenceClaim {
    pub project_id: String,
    /// The entitlement being claimed, in full: a reader must not have to fetch it.
    pub entitlement: Entitlement,
    /// The name this claimant goes by on the roster, so it can be matched to the master.
    pub claimed_by: String,
    pub claimed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The bytes a claim's signature covers: this entitlement, this project, nobody else's.
///
/// The project id is in here deliberately. Without it a claim published in one channel
/// could be lifted into another, and a single seat licence would cover every project its
/// holder could reach.
#[must_use]
fn claim_payload(claim: &LicenceClaim) -> String {
    format!(
        "ferryman-licence-claim-v1\nproject={}\nentitlement={}\nsubject={}\nby={}\nat={}",
        claim.project_id,
        claim.entitlement.id,
        claim.entitlement.subject,
        claim.claimed_by,
        claim.claimed_at.to_rfc3339(),
    )
}

impl LicenceClaim {
    /// Sign this claim with the seed-derived machine operator key - the key whose public
    /// half IS the entitlement's subject. Signing with anything else produces a claim
    /// that cannot verify, which is the whole point.
    pub fn sign(&mut self, machine: &SigningKey) {
        let signature = machine.sign(claim_payload(self).as_bytes());
        self.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Whether this claim is one the subject actually made.
    ///
    /// Three things have to hold, and dropping any one of them opens a hole: the
    /// entitlement is the licensor's, the signature is by the subject named in it, and
    /// it was made over THIS project.
    #[must_use]
    pub fn verifies(&self) -> bool {
        if !self.entitlement.verifies() {
            return false;
        }
        let Some(subject) = hex::decode(&self.entitlement.subject)
            .ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        else {
            return false;
        };
        let Some(signature) = self
            .signature
            .as_ref()
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|raw| <[u8; 64]>::try_from(raw).ok())
        else {
            return false;
        };
        subject
            .verify(
                claim_payload(self).as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .is_ok()
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;

    fn licensor() -> SigningKey {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        use_licensor_key(key.verifying_key());
        key
    }

    /// A claim by the seed holder, over their own project, with the licensor's
    /// entitlement. This is the only shape that should ever be believed.
    fn claim(
        licensor: &SigningKey,
        machine: &SigningKey,
        project: &str,
        seats: Option<usize>,
    ) -> LicenceClaim {
        let mut entitlement = Entitlement {
            id: "ent-9".to_string(),
            subject: hex::encode(machine.verifying_key().to_bytes()),
            seats,
            computers: None,
            mobile_devices: None,
            issued: Utc.with_ymd_and_hms(2026, 9, 11, 0, 0, 0).unwrap(),
            covers_builds_before: None,
            note: String::new(),
            referred_by: None,
            signed_by: None,
            signature: None,
        };
        entitlement.sign(licensor);
        let mut claim = LicenceClaim {
            project_id: project.to_string(),
            entitlement,
            claimed_by: "josh".to_string(),
            claimed_at: Utc.with_ymd_and_hms(2026, 9, 11, 0, 0, 0).unwrap(),
            signature: None,
        };
        claim.sign(machine);
        claim
    }

    /// The holder of the seed, claiming their own licence covers their own project.
    #[test]
    fn the_licence_holder_can_say_their_licence_governs_their_project() {
        let licensor = licensor();
        let machine = SigningKey::from_bytes(&[12u8; 32]);
        assert!(claim(&licensor, &machine, "redaktly", Some(3)).verifies());
    }

    /// The attack this whole mechanism exists to stop: an entitlement is a public file,
    /// so anyone can copy the author's unlimited licence into their own channel. Without
    /// the seed behind it, the claim is worthless.
    #[test]
    fn copying_somebody_elses_licence_into_your_channel_gets_you_nothing() {
        let licensor = licensor();
        let josh = SigningKey::from_bytes(&[12u8; 32]);
        let david = SigningKey::from_bytes(&[13u8; 32]);

        let stolen = claim(&licensor, &josh, "redaktly", None);
        let mut republished = stolen.clone();
        republished.project_id = "davids-thing".to_string();
        republished.claimed_by = "david".to_string();
        // David signs with his own seed, because Josh's is the one thing he does not have.
        republished.sign(&david);

        assert!(stolen.verifies(), "the original is genuine");
        assert!(
            !republished.verifies(),
            "holding the file is not holding the licence"
        );
    }
}

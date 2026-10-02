//! Interface contracts: one agreed shape, shared between orders.
//!
//! Two agents building the two halves of one feature - a frontend and a backend - drift:
//! the payload one sends is not the one the other expects, and nobody notices until the
//! halves meet. An interface contract is the thing they both build to, written down and
//! frozen before either starts.
//!
//! ```text
//! <channel>/contracts/
//!   user-api@1.json         proposed by any member, signed by them
//!   user-api@1.lock.json    the master's signed lock over exactly those contents
//! ```
//!
//! # The life of a contract
//!
//! 1. **Proposed.** Any project member writes `name@version.json`: a description, an
//!    optional `request` [`Shape`], a `response` [`Shape`], signed by their own key.
//!    Proposing raises one signed question to the master (so Telegram shows Lock / Reject
//!    buttons), once, however many times it is asked for.
//! 2. **Locked.** The master - or a delegate holding their `improve` delegation, which is
//!    the scope that already answers the fleet's questions - signs a lock over the
//!    contract's exact contents. From then on it is immutable: a change is a new version.
//! 3. Orders reference it with an [`InterfaceRef`] naming the version and a [`Side`]. A
//!    worker does not start an order whose contract is missing or not locked
//!    ([`hold_reason`]); a provider's result is checked against the locked response shape
//!    ([`provider_violations`]); a consumer's prompt carries the shapes
//!    ([`prompt_block`]).
//!
//! # Why the lock is its own file
//!
//! The lock could be written into the contract's file, but then two principals write one
//! path, which is the single thing the synced-folder rules forbid: Syncthing would make a
//! conflict copy, and which of the two survived would be luck. So the contract has one
//! writer and the lock has one writer, and [`read_contract`] joins them into the
//! `lock` field.
//!
//! # What a reader accepts
//!
//! - a contract whose signature does not verify against the roster, or whose proposer has
//!   been revoked, does not exist;
//! - a lock that is not the master's (or a valid delegate's), or whose signature does not
//!   verify, is ignored, and the contract stays *proposed*;
//! - a validly signed lock over contents the file no longer has means the contract was
//!   edited after it was locked: the contract is ignored altogether, not demoted, so no
//!   order can act on a shape the master never signed.
//!
//! The lock signs a digest of the canonical contents rather than the file's bytes, so a
//! checkout that rewrites line endings cannot unlock a contract.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    AgentIdentity, Order, ProjectRoute, SignatureCheck, check_signature, contract::Shape,
    delegation, is_safe_component, questions,
};

const DIR: &str = "contracts";

/// The answer that locks a contract.
pub const LOCK: &str = "Lock";
/// The answer that declines one.
pub const REJECT: &str = "Reject";

/// Which half of an interface an order builds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    /// The order implements the interface: its result is checked against the response.
    Provides,
    /// The order calls the interface: it is handed the shapes to build to.
    Consumes,
}

impl Side {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provides => "provides",
            Self::Consumes => "consumes",
        }
    }
}

/// An order's reference to one version of one contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceRef {
    pub name: String,
    pub version: String,
    pub side: Side,
}

impl InterfaceRef {
    /// `user-api@1:provides`. This is also what is signed into the order.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}@{}:{}", self.name, self.version, self.side.as_str())
    }

    /// Read `name@version:provides|consumes`, as `ferry channel order --interface` takes it.
    pub fn parse(text: &str) -> Result<Self> {
        let (reference, side) = text.rsplit_once(':').with_context(|| {
            format!("'{text}' is not name@version:provides|consumes (the side is missing)")
        })?;
        let (name, version) = parse_ref(reference)?;
        let side = match side.trim().to_ascii_lowercase().as_str() {
            "provides" => Side::Provides,
            "consumes" => Side::Consumes,
            other => bail!("the side of an interface is 'provides' or 'consumes', not '{other}'"),
        };
        Ok(Self {
            name,
            version,
            side,
        })
    }

    /// `user-api@1`.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// Split `name@version`, refusing anything that could not be a file name.
pub fn parse_ref(text: &str) -> Result<(String, String)> {
    let Some((name, version)) = text.trim().split_once('@') else {
        bail!("'{text}' is not name@version");
    };
    if !is_safe_component(name) || !is_safe_component(version) {
        bail!("'{text}': the name and the version use letters, digits, '.', '-' and '_' only");
    }
    Ok((name.to_string(), version.to_string()))
}

/// The master's signature over one contract's exact contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lock {
    /// The master, whose lock it is.
    pub by: String,
    pub at: DateTime<Utc>,
    /// The digest of the contract this lock was signed over. Recorded so that a lock which
    /// no longer fits its contract (the contract was edited) can be told from a lock that
    /// was never valid.
    pub digest: String,
    /// Who signed it: the master, or their `improve` delegate.
    pub signed_by: String,
    pub signature: String,
}

/// A frozen agreement about one interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceContract {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    /// What a caller sends, when the interface takes anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Shape>,
    /// What the interface returns.
    pub response: Shape,
    pub proposed_by: String,
    pub proposed_at: DateTime<Utc>,
    /// The proposer's signature over the contents.
    pub signature: String,
    /// Present once the master has locked it. Never written into the proposal's own file;
    /// see the module documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<Lock>,
}

/// Where a contract stands.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Signed by its proposer, waiting for the master.
    Proposed,
    /// Frozen by the master.
    Locked,
    /// The master said no. A new version is the way forward.
    Rejected,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Locked => "locked",
            Self::Rejected => "rejected",
        }
    }
}

/// The orders on each side of one contract.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct InterfaceOrders {
    pub providers: Vec<Order>,
    pub consumers: Vec<Order>,
}

impl InterfaceContract {
    /// `user-api@1`.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Whether the master has locked it.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.lock.is_some()
    }
}

// --- what is signed ---------------------------------------------------------------------

/// What the proposer signs. Includes the project, so a contract cannot be copied into
/// another project's channel and still verify.
fn contract_payload(project: &str, contract: &InterfaceContract) -> String {
    let body = json!({
        "description": contract.description,
        "request": contract.request,
        "response": contract.response,
    });
    let canonical = serde_jcs::to_string(&body).unwrap_or_default();
    format!(
        "ferryman-interface-v1\n{project}\n{}\n{}\n{}\n{}\n{}",
        contract.name,
        contract.version,
        contract.proposed_by,
        contract.proposed_at.to_rfc3339(),
        hex::encode(Sha256::digest(canonical.as_bytes())),
    )
}

/// A fingerprint of everything the proposer signed.
#[must_use]
pub fn digest(project: &str, contract: &InterfaceContract) -> String {
    hex::encode(Sha256::digest(
        contract_payload(project, contract).as_bytes(),
    ))
}

fn lock_payload(project: &str, name: &str, version: &str, lock: &Lock) -> String {
    format!(
        "ferryman-interface-lock-v1\n{project}\n{name}\n{version}\n{}\n{}\n{}",
        lock.digest,
        lock.by,
        lock.at.to_rfc3339()
    )
}

// --- storage ----------------------------------------------------------------------------

fn dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join(DIR)
}

fn contract_path(route: &ProjectRoute, name: &str, version: &str) -> PathBuf {
    dir(route).join(format!("{name}@{version}.json"))
}

fn lock_path(route: &ProjectRoute, name: &str, version: &str) -> PathBuf {
    dir(route).join(format!("{name}@{version}.lock.json"))
}

/// The proposer's contract, when it verifies. Without the lock.
fn read_proposal(route: &ProjectRoute, name: &str, version: &str) -> Option<InterfaceContract> {
    if !is_safe_component(name) || !is_safe_component(version) {
        return None;
    }
    let mut contract: InterfaceContract =
        serde_json::from_slice(&fs::read(contract_path(route, name, version)).ok()?).ok()?;
    // A file that says it is some other contract is a copied or renamed one.
    if contract.name != name || contract.version != version {
        return None;
    }
    if check_signature(
        Some(&contract.proposed_by),
        Some(&contract.signature),
        &contract_payload(&route.project_id, &contract),
        &route.agents,
    ) != SignatureCheck::Valid
        || crate::master::is_revoked(route, &contract.proposed_by).unwrap_or(true)
    {
        return None;
    }
    // Whatever the file says about a lock does not count; only the lock file does.
    contract.lock = None;
    Some(contract)
}

enum LockCheck {
    Valid(Lock),
    /// Not the master's, or not signed. The contract is simply unlocked.
    Forged,
    /// The master did sign, over something the contract no longer says.
    EditedAfterLock,
    Absent,
}

fn check_lock(route: &ProjectRoute, contract: &InterfaceContract) -> LockCheck {
    let Ok(bytes) = fs::read(lock_path(route, &contract.name, &contract.version)) else {
        return LockCheck::Absent;
    };
    let Ok(lock) = serde_json::from_slice::<Lock>(&bytes) else {
        return LockCheck::Forged;
    };
    let Ok(Some(master)) = crate::master::read_master(route) else {
        return LockCheck::Forged;
    };
    let authorised = lock.by.eq_ignore_ascii_case(&master.master)
        && delegation::authority(
            &route.communications,
            &route.project_id,
            &lock.by,
            &lock.signed_by,
            delegation::IMPROVE,
            Utc::now(),
        )
        .allowed()
        && check_signature(
            Some(&lock.signed_by),
            Some(&lock.signature),
            &lock_payload(&route.project_id, &contract.name, &contract.version, &lock),
            &route.agents,
        ) == SignatureCheck::Valid;
    if !authorised {
        return LockCheck::Forged;
    }
    if lock.digest == digest(&route.project_id, contract) {
        LockCheck::Valid(lock)
    } else {
        LockCheck::EditedAfterLock
    }
}

/// One contract, when it is genuine: signed by its proposer and, if locked, locked by the
/// master over exactly what it says now. A forged, unsigned or edited-after-lock file is
/// `None`, exactly like any other signed channel file that does not verify.
#[must_use]
pub fn read_contract(route: &ProjectRoute, name: &str, version: &str) -> Option<InterfaceContract> {
    let mut contract = read_proposal(route, name, version)?;
    match check_lock(route, &contract) {
        LockCheck::Valid(lock) => contract.lock = Some(lock),
        LockCheck::EditedAfterLock => return None,
        LockCheck::Forged | LockCheck::Absent => {}
    }
    Some(contract)
}

/// Every genuine contract, by name and then version.
#[must_use]
pub fn list_contracts(route: &ProjectRoute) -> Vec<InterfaceContract> {
    let Ok(entries) = fs::read_dir(dir(route)) else {
        return Vec::new();
    };
    let mut found: Vec<InterfaceContract> = entries
        .flatten()
        .filter_map(|entry| {
            let file = entry.file_name().to_str()?.to_string();
            let stem = file.strip_suffix(".json")?;
            if stem.ends_with(".lock") || stem.contains(".sync-conflict-") {
                return None;
            }
            let (name, version) = stem.split_once('@')?;
            read_contract(route, name, version)
        })
        .collect();
    found.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    found
}

/// The contract if, and only if, it is locked.
#[must_use]
pub fn locked(route: &ProjectRoute, name: &str, version: &str) -> Option<InterfaceContract> {
    read_contract(route, name, version).filter(InterfaceContract::is_locked)
}

/// Where a contract stands: locked, rejected by the master, or still waiting.
#[must_use]
pub fn status(route: &ProjectRoute, contract: &InterfaceContract) -> Status {
    if contract.is_locked() {
        return Status::Locked;
    }
    let rejected = questions::read(route, &question_id(&route.project_id, contract))
        .and_then(|question| questions::answer_to(route, &question))
        .is_some_and(|answer| answer.answer.eq_ignore_ascii_case(REJECT));
    if rejected {
        Status::Rejected
    } else {
        Status::Proposed
    }
}

/// The contracts waiting for the master: properly signed, not yet locked, not rejected.
///
/// Plain data for a reviewer that wants to look before the master decides.
pub fn pending_locks(route: &ProjectRoute) -> Result<Vec<InterfaceContract>> {
    Ok(list_contracts(route)
        .into_iter()
        .filter(|contract| status(route, contract) == Status::Proposed)
        .collect())
}

/// The orders on each side of `name@version`: every order whose signature verifies and
/// that references it, split by side, oldest first. Plain data, so a reviewer can read the
/// contract and both halves together.
pub fn orders_for_interface(
    route: &ProjectRoute,
    name: &str,
    version: &str,
) -> Result<InterfaceOrders> {
    let mut found = InterfaceOrders::default();
    for task in crate::list_tasks(route)? {
        let Some(reference) = &task.order.interface else {
            continue;
        };
        if reference.name != name
            || reference.version != version
            || crate::verify_order_in(route, &task.order) != SignatureCheck::Valid
        {
            continue;
        }
        match reference.side {
            Side::Provides => found.providers.push(task.order),
            Side::Consumes => found.consumers.push(task.order),
        }
    }
    Ok(found)
}

// --- proposing, locking, rejecting ------------------------------------------------------

/// The id of the question that asks the master about this contract. Deterministic, and
/// carries a slice of the contract's digest, so asking twice is asking once - and a
/// proposal that was somehow replaced by different contents asks again.
#[must_use]
pub fn question_id(project: &str, contract: &InterfaceContract) -> String {
    format!(
        "contract-{}-{}-{}",
        contract.name,
        contract.version,
        &digest(project, contract)[..8]
    )
}

/// The contract a question is about, when it is one of ours.
#[must_use]
pub fn contract_for_question(
    route: &ProjectRoute,
    question_id_text: &str,
) -> Option<InterfaceContract> {
    list_contracts(route)
        .into_iter()
        .find(|contract| question_id(&route.project_id, contract) == question_id_text)
}

fn compact(shape: &Option<Shape>) -> String {
    match shape {
        None => "(none)".to_string(),
        Some(shape) => serde_json::to_string(shape).unwrap_or_default(),
    }
}

fn question_text(project: &str, contract: &InterfaceContract) -> String {
    let mut text = format!(
        "{} proposes interface contract {}",
        contract.proposed_by,
        contract.reference()
    );
    if !contract.description.trim().is_empty() {
        text.push_str(&format!(": {}", contract.description.trim()));
    }
    text.push_str(&format!(
        "\n\nrequest: {}\nresponse: {}\n\nLock freezes it. Orders that provide or consume it wait \
         until you do, and a locked contract never changes: a change is a new version. \
         (digest {})",
        compact(&contract.request),
        serde_json::to_string(&contract.response).unwrap_or_default(),
        &digest(project, contract)[..12]
    ));
    text
}

/// Raise the question that asks the master to lock `contract`, once. `false` when it was
/// already asked.
pub fn ensure_question(
    route: &ProjectRoute,
    asker: &AgentIdentity,
    contract: &InterfaceContract,
) -> Result<bool> {
    questions::ask(
        route,
        asker,
        &question_id(&route.project_id, contract),
        questions::CONTRACT,
        &question_text(&route.project_id, contract),
        &[LOCK.to_string(), REJECT.to_string()],
        None,
    )
}

/// Propose a contract, signed by `proposer`, and ask the master to lock it.
///
/// Written once: `name@version` that already exists is refused, because a contract the
/// fleet may already be building to must not be quietly replaced. Propose `@2` instead.
pub fn propose(
    route: &ProjectRoute,
    proposer: &AgentIdentity,
    name: &str,
    version: &str,
    description: &str,
    request: Option<Shape>,
    response: Shape,
) -> Result<InterfaceContract> {
    if !is_safe_component(name) || !is_safe_component(version) {
        bail!("a contract's name and version use letters, digits, '.', '-' and '_' only");
    }
    let path = contract_path(route, name, version);
    if path.exists() {
        bail!(
            "{name}@{version} already exists; a contract is written once - propose a new version"
        );
    }
    let mut contract = InterfaceContract {
        name: name.to_string(),
        version: version.to_string(),
        description: description.trim().to_string(),
        request,
        response,
        proposed_by: proposer.name().to_string(),
        proposed_at: Utc::now(),
        signature: String::new(),
        lock: None,
    };
    contract.signature =
        proposer.sign_bytes(contract_payload(&route.project_id, &contract).as_bytes());
    if check_signature(
        Some(&contract.proposed_by),
        Some(&contract.signature),
        &contract_payload(&route.project_id, &contract),
        &route.agents,
    ) != SignatureCheck::Valid
    {
        bail!(
            "{} is not on this channel's roster under the key that signed this, so no one \
             would read the proposal; join the channel first",
            proposer.name()
        );
    }
    crate::atomic_json(&path, &contract)?;
    ensure_question(route, proposer, &contract).with_context(|| {
        format!("{name}@{version} was written, but the question to the master was not")
    })?;
    Ok(contract)
}

/// Check that `by`, signed for by `signer`, may decide contracts, and return the master.
fn deciding_authority(route: &ProjectRoute, by: &str, signer: &AgentIdentity) -> Result<String> {
    let Some(master) = crate::master::read_master(route)? else {
        bail!("{} has no master to lock contracts", route.project_id);
    };
    if !by.eq_ignore_ascii_case(&master.master) {
        bail!(
            "only {}, the master, decides interface contracts",
            master.master
        );
    }
    if let delegation::Authority::Refused(why) = delegation::authority(
        &route.communications,
        &route.project_id,
        by,
        signer.name(),
        delegation::IMPROVE,
        Utc::now(),
    ) {
        bail!("{} cannot decide for {by}: {why}", signer.name());
    }
    Ok(master.master)
}

/// Answer the contract's question, when there is one that is still open. Best effort: the
/// lock or the rejection is the act; the answer only clears the button.
fn settle_question(
    route: &ProjectRoute,
    contract: &InterfaceContract,
    answer: &str,
    by: &str,
    signer: &AgentIdentity,
) {
    let id = question_id(&route.project_id, contract);
    if let Some(question) = questions::read(route, &id)
        && questions::answer_to(route, &question).is_none()
    {
        let _ = questions::answer(route, &id, answer, by, signer);
    }
}

/// Lock `name@version`: the master (`by`), signed for by `signer` - themselves, or a
/// delegate holding their `improve` delegation - freezes the contract as it reads now.
pub fn lock(
    route: &ProjectRoute,
    name: &str,
    version: &str,
    by: &str,
    signer: &AgentIdentity,
) -> Result<InterfaceContract> {
    let master = deciding_authority(route, by, signer)?;
    let Some(contract) = read_contract(route, name, version) else {
        bail!(
            "there is no genuine contract {name}@{version} in {}",
            route.project_id
        );
    };
    if contract.is_locked() {
        bail!("{name}@{version} is already locked");
    }
    if status(route, &contract) == Status::Rejected {
        bail!("{name}@{version} was rejected; propose a new version");
    }
    let mut lock = Lock {
        by: master,
        at: Utc::now(),
        digest: digest(&route.project_id, &contract),
        signed_by: signer.name().to_string(),
        signature: String::new(),
    };
    lock.signature =
        signer.sign_bytes(lock_payload(&route.project_id, name, version, &lock).as_bytes());
    let path = lock_path(route, name, version);
    if path.exists() {
        // A lock file that is there but did not count (it was forged, say) is replaced:
        // `read_contract` just said this contract is not locked.
        fs::remove_file(&path).context("remove the lock that did not verify")?;
    }
    crate::atomic_json(&path, &lock)?;
    let locked = read_contract(route, name, version)
        .filter(InterfaceContract::is_locked)
        .with_context(|| format!("{name}@{version}: the lock was written but does not verify"))?;
    settle_question(route, &locked, LOCK, by, signer);
    Ok(locked)
}

/// Decline `name@version`. The contract is not deleted - the fleet should be able to see
/// what was refused - but it can no longer be locked, and orders that reference it keep
/// waiting until they are re-issued against a version the master did lock.
pub fn reject(
    route: &ProjectRoute,
    name: &str,
    version: &str,
    by: &str,
    signer: &AgentIdentity,
) -> Result<InterfaceContract> {
    deciding_authority(route, by, signer)?;
    let Some(contract) = read_contract(route, name, version) else {
        bail!(
            "there is no genuine contract {name}@{version} in {}",
            route.project_id
        );
    };
    if contract.is_locked() {
        bail!(
            "{name}@{version} is locked; a locked contract is replaced by a new version, not rejected"
        );
    }
    // The master asks the question themselves if the proposer's never arrived.
    ensure_question(route, signer, &contract)?;
    let id = question_id(&route.project_id, &contract);
    let question = questions::read(route, &id)
        .with_context(|| format!("the question about {name}@{version} is not readable"))?;
    if questions::answer_to(route, &question).is_none() {
        questions::answer(route, &id, REJECT, by, signer)?;
    }
    Ok(contract)
}

// --- using a contract -------------------------------------------------------------------

/// Why an order must not be started yet, when its interface contract is missing or not
/// locked. The wording is the record shown to everyone: it names the contract and says
/// what it is waiting for.
#[must_use]
pub fn hold_reason(route: &ProjectRoute, order: &Order) -> Option<String> {
    let reference = order.interface.as_ref()?;
    let wanted = reference.reference();
    if locked(route, &reference.name, &reference.version).is_some() {
        return None;
    }
    let state = match read_contract(route, &reference.name, &reference.version) {
        None => "it has not been proposed yet".to_string(),
        Some(contract) => match status(route, &contract) {
            Status::Rejected => "the master rejected it; a new version is needed".to_string(),
            _ => "proposed, waiting for the master to lock it".to_string(),
        },
    };
    Some(format!(
        "waiting for contract {wanted} to be locked ({state})"
    ))
}

/// What a provider's result gets wrong against the locked contract it provides. The
/// result must carry a `response`: a real response its implementation returns, which is
/// held to the contract's `response` shape. A `request` it declares it accepts is held to
/// the contract's `request` shape, when the contract has one; a provider that declares
/// none is not penalised for it.
#[must_use]
pub fn provider_violations(
    route: &ProjectRoute,
    reference: &InterfaceRef,
    payload: &Value,
) -> Vec<String> {
    let Some(contract) = locked(route, &reference.name, &reference.version) else {
        return vec![format!(
            "interface {} is not locked, so there is nothing to check this result against",
            reference.reference()
        )];
    };
    let mut out = match payload.get("response") {
        None | Some(Value::Null) => vec![format!(
            "result.response: missing; this order provides {}, so its result must include a \
             response that fits the contract",
            contract.reference()
        )],
        Some(response) => contract.response.check_at(response, "result.response"),
    };
    if let (Some(shape), Some(request)) = (&contract.request, payload.get("request"))
        && !request.is_null()
    {
        out.extend(shape.check_at(request, "result.request"));
    }
    out
}

/// What the engine is told about the interface its order provides or consumes: the locked
/// shapes, and what to do with them. `None` for an order with no interface, and for one
/// whose contract is not locked (a worker holds such an order instead of starting it).
#[must_use]
pub fn prompt_block(route: &ProjectRoute, order: &Order) -> Option<String> {
    let reference = order.interface.as_ref()?;
    let contract = locked(route, &reference.name, &reference.version)?;
    let pretty = |shape: &Shape| serde_json::to_string_pretty(shape).unwrap_or_default();
    let mut text = format!(
        "INTERFACE CONTRACT {} - locked, and it will not change. This order {} it.\n",
        contract.reference(),
        reference.side.as_str()
    );
    if !contract.description.trim().is_empty() {
        text.push_str(&format!("{}\n", contract.description.trim()));
    }
    if let Some(request) = &contract.request {
        text.push_str(&format!("\nRequest shape:\n{}\n", pretty(request)));
    }
    text.push_str(&format!(
        "\nResponse shape:\n{}\n",
        pretty(&contract.response)
    ));
    match reference.side {
        Side::Consumes => text.push_str(
            "\nBuild exactly to these shapes: read only the fields they name and send only what \
             the request shape allows. Do not invent fields. If you believe the contract is \
             wrong, say so in your answer rather than working around it - the provider is \
             building to the same text.\n",
        ),
        Side::Provides => text.push_str(
            "\nImplement exactly these shapes. Your result is checked mechanically: end your \
             answer with a fenced ```json block holding an object with a \"response\" key (a \
             real response your implementation returns, matching the response shape) and, if \
             the contract has a request shape, a \"request\" key (a request it accepts).\n",
        ),
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRoute;
    use std::path::Path;

    fn person(name: &str, seed: u8) -> AgentIdentity {
        AgentIdentity::from_seed(name, [seed; 32])
    }

    fn route(dir: &Path, members: &[&AgentIdentity]) -> ProjectRoute {
        let communications = dir.join("demo-ferryman");
        fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: "demo".into(),
            workspace: dir.join("demo"),
            attachment: dir.join("attachment"),
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in members {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, members[0], members[0].name()).unwrap();
        route
    }

    fn shape(value: Value) -> Shape {
        Shape::parse(&value).unwrap()
    }

    fn user_response() -> Shape {
        shape(json!({
            "type": "object",
            "required": ["user"],
            "properties": { "user": {
                "type": "object",
                "required": ["id", "name"],
                "properties": { "id": { "type": "integer" }, "name": { "type": "string" } }
            } }
        }))
    }

    fn user_request() -> Shape {
        shape(json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "integer" } }
        }))
    }

    struct World {
        _dir: tempfile::TempDir,
        route: ProjectRoute,
        josh: AgentIdentity,
        wisp: AgentIdentity,
        fang: AgentIdentity,
        bridge: AgentIdentity,
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let josh = person("josh", 1);
        let wisp = person("wisp", 2);
        let fang = person("fang", 3);
        let bridge = person("telegram-grouchly", 4);
        let route = route(dir.path(), &[&josh, &wisp, &fang, &bridge]);
        World {
            _dir: dir,
            route,
            josh,
            wisp,
            fang,
            bridge,
        }
    }

    fn propose_user_api(w: &World) -> InterfaceContract {
        propose(
            &w.route,
            &w.wisp,
            "user-api",
            "1",
            "GET /users/:id",
            Some(user_request()),
            user_response(),
        )
        .unwrap()
    }

    fn delegate(w: &World, scope: &str) {
        crate::delegation::grant(
            &w.route.communications,
            "demo",
            &w.josh,
            "telegram-grouchly",
            &[scope.to_string()],
            None,
        )
        .unwrap();
    }

    fn contract_order(id: &str, name: &str, side: Option<Side>) -> Order {
        let mut order = crate::overlap::tests::order(id, &[]);
        order.interface = side.map(|side| InterfaceRef {
            name: name.into(),
            version: "1".into(),
            side,
        });
        order
    }

    fn issue(w: &World, mut order: Order) -> Order {
        w.josh.sign_order(&mut order);
        crate::issue_order(&w.route, &order).unwrap();
        order
    }

    // --- references -----------------------------------------------------------------

    #[test]
    fn a_reference_is_read_and_written_the_same_way() {
        let parsed = InterfaceRef::parse("user-api@1:provides").unwrap();
        assert_eq!(
            parsed,
            InterfaceRef {
                name: "user-api".into(),
                version: "1".into(),
                side: Side::Provides
            }
        );
        assert_eq!(parsed.describe(), "user-api@1:provides");
        assert_eq!(parsed.reference(), "user-api@1");
        assert_eq!(
            InterfaceRef::parse("a.b@1.2:Consumes").unwrap().side,
            Side::Consumes
        );
        for bad in [
            "user-api",
            "user-api@1",
            "user-api@1:both",
            "@1:provides",
            "a/b@1:provides",
            "a@:provides",
        ] {
            assert!(InterfaceRef::parse(bad).is_err(), "{bad}");
        }
    }

    // --- propose, lock, verify ------------------------------------------------------

    #[test]
    fn a_proposal_reads_back_signed_and_unlocked() {
        let w = world();
        let proposed = propose_user_api(&w);
        assert!(!proposed.is_locked());
        let read = read_contract(&w.route, "user-api", "1").unwrap();
        assert_eq!(read, proposed);
        assert_eq!(read.proposed_by, "wisp");
        assert_eq!(status(&w.route, &read), Status::Proposed);
        assert_eq!(list_contracts(&w.route).len(), 1);
        assert!(locked(&w.route, "user-api", "1").is_none());
    }

    #[test]
    fn a_contract_is_written_once() {
        let w = world();
        propose_user_api(&w);
        let error = propose(
            &w.route,
            &w.wisp,
            "user-api",
            "1",
            "other",
            None,
            user_response(),
        )
        .unwrap_err();
        assert!(format!("{error}").contains("already exists"), "{error}");
        // A new version is the way to change it.
        propose(
            &w.route,
            &w.wisp,
            "user-api",
            "2",
            "v2",
            None,
            user_response(),
        )
        .unwrap();
        assert_eq!(list_contracts(&w.route).len(), 2);
    }

    #[test]
    fn someone_off_the_roster_cannot_propose() {
        let w = world();
        let stranger = person("stranger", 9);
        let error = propose(&w.route, &stranger, "x", "1", "", None, user_response()).unwrap_err();
        assert!(format!("{error}").contains("roster"), "{error}");
        assert!(list_contracts(&w.route).is_empty());
    }

    #[test]
    fn the_master_locks_it_and_it_reads_back_locked() {
        let w = world();
        propose_user_api(&w);
        let locked_now = lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        let lock = locked_now.lock.as_ref().unwrap();
        assert_eq!(lock.by, "josh");
        assert_eq!(lock.signed_by, "josh");
        let again = read_contract(&w.route, "user-api", "1").unwrap();
        assert!(again.is_locked());
        assert_eq!(status(&w.route, &again), Status::Locked);
        assert!(locked(&w.route, "user-api", "1").is_some());
        assert!(
            lock_path(&w.route, "user-api", "1").exists(),
            "its own file"
        );
        // The proposal's file was never rewritten.
        let on_disk: InterfaceContract =
            serde_json::from_slice(&fs::read(contract_path(&w.route, "user-api", "1")).unwrap())
                .unwrap();
        assert!(on_disk.lock.is_none());
        assert!(lock_err(&w, "user-api", "1").contains("already locked"));
    }

    fn lock_err(w: &World, name: &str, version: &str) -> String {
        format!(
            "{:#}",
            lock(&w.route, name, version, "josh", &w.josh).unwrap_err()
        )
    }

    #[test]
    fn only_the_master_or_an_improve_delegate_may_lock() {
        let w = world();
        propose_user_api(&w);
        // A member signing in the master's name, or in their own.
        assert!(lock(&w.route, "user-api", "1", "josh", &w.wisp).is_err());
        assert!(lock(&w.route, "user-api", "1", "wisp", &w.wisp).is_err());
        // The proposer is not the master just by proposing.
        assert!(lock(&w.route, "user-api", "1", "wisp", &w.josh).is_err());
        // A delegate with the wrong scope.
        delegate(&w, "orders");
        assert!(lock(&w.route, "user-api", "1", "josh", &w.bridge).is_err());
        assert!(
            !read_contract(&w.route, "user-api", "1")
                .unwrap()
                .is_locked()
        );
        // And with the right one.
        delegate(&w, "improve");
        let by_bridge = lock(&w.route, "user-api", "1", "josh", &w.bridge).unwrap();
        let lock = by_bridge.lock.unwrap();
        assert_eq!(
            (lock.by.as_str(), lock.signed_by.as_str()),
            ("josh", "telegram-grouchly")
        );
        assert!(locked(&w.route, "user-api", "1").is_some());
    }

    #[test]
    fn a_forged_lock_is_ignored_and_the_contract_stays_proposed() {
        let w = world();
        let proposed = propose_user_api(&w);
        let make = |by: &str, signer: &AgentIdentity| {
            let mut forged = Lock {
                by: by.into(),
                at: Utc::now(),
                digest: digest("demo", &proposed),
                signed_by: signer.name().into(),
                signature: String::new(),
            };
            forged.signature =
                signer.sign_bytes(lock_payload("demo", "user-api", "1", &forged).as_bytes());
            forged
        };
        // wisp locks it "as itself", wisp locks it "as josh", and a lock with no signature.
        for forged in [make("wisp", &w.wisp), make("josh", &w.wisp), {
            let mut unsigned = make("josh", &w.josh);
            unsigned.signature = String::new();
            unsigned
        }] {
            crate::atomic_json(&lock_path(&w.route, "user-api", "1"), &forged).unwrap();
            let read = read_contract(&w.route, "user-api", "1").unwrap();
            assert!(!read.is_locked(), "{forged:?}");
            assert!(locked(&w.route, "user-api", "1").is_none());
            assert_eq!(status(&w.route, &read), Status::Proposed);
        }
        // Garbage in the lock file is the same.
        fs::write(lock_path(&w.route, "user-api", "1"), b"{ not json").unwrap();
        assert!(
            !read_contract(&w.route, "user-api", "1")
                .unwrap()
                .is_locked()
        );
        // The real lock replaces whatever was there.
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        assert!(locked(&w.route, "user-api", "1").is_some());
    }

    #[test]
    fn a_contract_edited_after_it_was_locked_is_ignored_entirely() {
        let w = world();
        propose_user_api(&w);
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        assert!(locked(&w.route, "user-api", "1").is_some());

        // The proposer re-signs a changed response over the same name and version. Its own
        // signature is perfectly good; the master never signed THIS.
        let mut edited = read_contract(&w.route, "user-api", "1").unwrap();
        edited.response = shape(json!({ "type": "object" }));
        edited.signature = w
            .wisp
            .sign_bytes(contract_payload("demo", &edited).as_bytes());
        edited.lock = None;
        crate::atomic_json(&contract_path(&w.route, "user-api", "1"), &edited).unwrap();

        assert!(read_contract(&w.route, "user-api", "1").is_none());
        assert!(locked(&w.route, "user-api", "1").is_none());
        assert!(list_contracts(&w.route).is_empty());
        assert!(pending_locks(&w.route).unwrap().is_empty());
        // So an order built on it holds, rather than building to the edited shape.
        let order = contract_order("t-1", "user-api", Some(Side::Consumes));
        assert!(
            hold_reason(&w.route, &order)
                .unwrap()
                .contains("not been proposed")
        );
    }

    #[test]
    fn a_hand_edited_file_that_no_longer_matches_its_signature_is_ignored() {
        let w = world();
        propose_user_api(&w);
        let path = contract_path(&w.route, "user-api", "1");
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("GET /users/:id", "DELETE /users");
        fs::write(&path, text).unwrap();
        assert!(read_contract(&w.route, "user-api", "1").is_none());
    }

    #[test]
    fn an_unsigned_or_unknown_signer_contract_does_not_exist() {
        let w = world();
        let mut forged = InterfaceContract {
            name: "ghost".into(),
            version: "1".into(),
            description: String::new(),
            request: None,
            response: user_response(),
            proposed_by: "wisp".into(),
            proposed_at: Utc::now(),
            signature: String::new(),
            lock: None,
        };
        crate::atomic_json(&contract_path(&w.route, "ghost", "1"), &forged).unwrap();
        assert!(read_contract(&w.route, "ghost", "1").is_none(), "unsigned");
        // Signed by a key the roster does not hold for that name.
        let stranger = person("wisp", 99);
        forged.signature = stranger.sign_bytes(contract_payload("demo", &forged).as_bytes());
        crate::atomic_json(&contract_path(&w.route, "ghost", "1"), &forged).unwrap();
        assert!(read_contract(&w.route, "ghost", "1").is_none(), "wrong key");
        assert!(list_contracts(&w.route).is_empty());
    }

    #[test]
    fn a_contract_copied_under_another_name_or_project_does_not_verify() {
        let w = world();
        propose_user_api(&w);
        fs::copy(
            contract_path(&w.route, "user-api", "1"),
            contract_path(&w.route, "billing-api", "1"),
        )
        .unwrap();
        assert!(
            read_contract(&w.route, "billing-api", "1").is_none(),
            "renamed"
        );

        // Another project, same people and keys.
        let other_dir = tempfile::tempdir().unwrap();
        let mut other = route(other_dir.path(), &[&w.josh, &w.wisp, &w.fang, &w.bridge]);
        other.project_id = "elsewhere".into();
        fs::create_dir_all(dir(&other)).unwrap();
        fs::copy(
            contract_path(&w.route, "user-api", "1"),
            contract_path(&other, "user-api", "1"),
        )
        .unwrap();
        assert!(
            read_contract(&other, "user-api", "1").is_none(),
            "other project"
        );
    }

    #[test]
    fn a_revoked_proposers_contract_is_not_read() {
        let w = world();
        propose_user_api(&w);
        crate::master::revoke_member(&w.route, &w.josh, "wisp", "left the team").unwrap();
        assert!(read_contract(&w.route, "user-api", "1").is_none());
    }

    // --- the question to the master ---------------------------------------------------

    #[test]
    fn proposing_raises_one_question_and_asking_again_adds_none() {
        let w = world();
        let proposed = propose_user_api(&w);
        let pending = questions::pending(&w.route);
        assert_eq!(pending.len(), 1);
        let question = &pending[0];
        assert_eq!(question.kind, questions::CONTRACT);
        assert_eq!(question.options, vec!["Lock", "Reject"]);
        assert_eq!(question.asked_by, "wisp");
        assert!(question.text.contains("user-api@1"), "{}", question.text);
        assert!(
            question.text.contains("GET /users/:id"),
            "{}",
            question.text
        );
        assert_eq!(question.id, question_id("demo", &proposed));

        // However it is asked for, by whoever, it is asked once.
        assert!(!ensure_question(&w.route, &w.wisp, &proposed).unwrap());
        assert!(!ensure_question(&w.route, &w.fang, &proposed).unwrap());
        assert_eq!(questions::pending(&w.route).len(), 1);
        assert_eq!(
            contract_for_question(&w.route, &question.id)
                .unwrap()
                .reference(),
            "user-api@1"
        );
    }

    #[test]
    fn locking_answers_the_question_so_the_button_goes_away() {
        let w = world();
        propose_user_api(&w);
        assert_eq!(questions::pending(&w.route).len(), 1);
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        assert!(questions::pending(&w.route).is_empty());
        let (question, answer) = questions::list(&w.route).remove(0);
        assert_eq!(question.kind, questions::CONTRACT);
        assert_eq!(answer.unwrap().answer, "Lock");
    }

    #[test]
    fn rejecting_closes_the_question_and_the_contract_can_no_longer_be_locked() {
        let w = world();
        propose_user_api(&w);
        assert_eq!(pending_locks(&w.route).unwrap().len(), 1);
        reject(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        let read = read_contract(&w.route, "user-api", "1").unwrap();
        assert_eq!(status(&w.route, &read), Status::Rejected);
        assert!(pending_locks(&w.route).unwrap().is_empty());
        assert!(questions::pending(&w.route).is_empty());
        assert!(
            format!(
                "{:#}",
                lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap_err()
            )
            .contains("rejected")
        );
        let order = contract_order("t-1", "user-api", Some(Side::Provides));
        assert!(hold_reason(&w.route, &order).unwrap().contains("rejected"));
        // Only the master rejects.
        propose(
            &w.route,
            &w.wisp,
            "user-api",
            "2",
            "",
            None,
            user_response(),
        )
        .unwrap();
        assert!(reject(&w.route, "user-api", "2", "wisp", &w.wisp).is_err());
    }

    #[test]
    fn a_locked_contract_cannot_be_rejected() {
        let w = world();
        propose_user_api(&w);
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        assert!(reject(&w.route, "user-api", "1", "josh", &w.josh).is_err());
    }

    #[test]
    fn pending_locks_are_the_proposed_ones_only() {
        let w = world();
        propose_user_api(&w);
        propose(
            &w.route,
            &w.fang,
            "billing-api",
            "1",
            "",
            None,
            user_response(),
        )
        .unwrap();
        lock(&w.route, "billing-api", "1", "josh", &w.josh).unwrap();
        // A forged proposal is not pending either.
        let forged = InterfaceContract {
            name: "ghost".into(),
            version: "1".into(),
            description: String::new(),
            request: None,
            response: user_response(),
            proposed_by: "wisp".into(),
            proposed_at: Utc::now(),
            signature: "00".into(),
            lock: None,
        };
        crate::atomic_json(&contract_path(&w.route, "ghost", "1"), &forged).unwrap();
        let pending = pending_locks(&w.route).unwrap();
        assert_eq!(
            pending
                .iter()
                .map(InterfaceContract::reference)
                .collect::<Vec<_>>(),
            vec!["user-api@1"]
        );
    }

    // --- orders on a contract -----------------------------------------------------------

    #[test]
    fn an_order_waits_until_its_contract_is_locked() {
        let w = world();
        let order = contract_order("t-1", "user-api", Some(Side::Consumes));
        // Missing.
        assert_eq!(
            hold_reason(&w.route, &order).unwrap(),
            "waiting for contract user-api@1 to be locked (it has not been proposed yet)"
        );
        // Proposed.
        propose_user_api(&w);
        let reason = hold_reason(&w.route, &order).unwrap();
        assert!(
            reason.starts_with("waiting for contract user-api@1 to be locked"),
            "{reason}"
        );
        assert!(reason.contains("proposed"), "{reason}");
        // Locked.
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        assert!(hold_reason(&w.route, &order).is_none());
        // No interface, no hold.
        assert!(hold_reason(&w.route, &contract_order("t-2", "x", None)).is_none());
    }

    #[test]
    fn a_provider_result_must_fit_the_locked_response() {
        let w = world();
        propose_user_api(&w);
        let provider = InterfaceRef {
            name: "user-api".into(),
            version: "1".into(),
            side: Side::Provides,
        };
        let good = json!({
            "output": "done",
            "response": { "user": { "id": 7, "name": "ada" } },
            "request": { "id": 7 }
        });
        // Not locked: nothing to check against, and that is itself a violation.
        let before = provider_violations(&w.route, &provider, &good);
        assert!(before[0].contains("not locked"), "{before:?}");

        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        assert!(provider_violations(&w.route, &provider, &good).is_empty());

        let wrong_type = json!({ "response": { "user": { "id": "7", "name": "ada" } } });
        assert_eq!(
            provider_violations(&w.route, &provider, &wrong_type),
            vec!["result.response.user.id: expected integer, got string"]
        );
        let missing_field = json!({ "response": { "user": { "id": 7 } } });
        assert_eq!(
            provider_violations(&w.route, &provider, &missing_field),
            vec!["result.response.user.name: missing required key"]
        );
        let no_response = json!({ "output": "done" });
        let found = provider_violations(&w.route, &provider, &no_response);
        assert!(
            found[0].starts_with("result.response: missing"),
            "{found:?}"
        );
        let null_response = json!({ "response": null });
        assert!(
            provider_violations(&w.route, &provider, &null_response)[0]
                .starts_with("result.response: missing")
        );
        // The declared request is held to the request shape, when there is one.
        let bad_request = json!({
            "response": { "user": { "id": 7, "name": "ada" } },
            "request": { "id": "seven" }
        });
        assert_eq!(
            provider_violations(&w.route, &provider, &bad_request),
            vec!["result.request.id: expected integer, got string"]
        );
    }

    #[test]
    fn a_provider_results_mismatch_blocks_it_through_the_task_contract_check() {
        let w = world();
        propose_user_api(&w);
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        issue(
            &w,
            contract_order("t-provide", "user-api", Some(Side::Provides)),
        );
        crate::claim_order(&w.route, "t-provide", "fang").unwrap();

        let submit = |revision: u32, payload: Value| {
            let mut result = crate::TaskResult {
                order_id: "t-provide".into(),
                agent: "fang".into(),
                revision,
                submitted_at: Utc::now(),
                payload,
                signed_by: None,
                signature: None,
            };
            w.fang.sign_result(&mut result);
            crate::submit_result(&w.route, &result).unwrap();
            crate::read_task(&w.route, "t-provide").unwrap()
        };

        // No result yet: nothing to violate.
        let task = crate::read_task(&w.route, "t-provide").unwrap();
        assert!(task.contract_violations_in(&w.route).is_none());

        let bad = submit(
            1,
            json!({ "output": "x", "response": { "user": { "id": "7" } } }),
        );
        let found = bad.contract_violations_in(&w.route).unwrap();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("result.response.user"), "{found:?}");

        let good = submit(
            2,
            json!({ "output": "x", "response": { "user": { "id": 7, "name": "a" } } }),
        );
        assert_eq!(good.contract_violations_in(&w.route), Some(Vec::new()));
        // The plain check knows nothing of interfaces, as before.
        assert!(good.contract_violations().is_none());
    }

    #[test]
    fn a_provider_also_answers_to_the_orders_own_result_contract() {
        let w = world();
        propose_user_api(&w);
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();
        let mut order = contract_order("t-both", "user-api", Some(Side::Provides));
        order.result_contract = Some(crate::contract::ResultContract {
            required: vec!["summary".into()],
            schema: None,
        });
        issue(&w, order);
        crate::claim_order(&w.route, "t-both", "fang").unwrap();
        let mut result = crate::TaskResult {
            order_id: "t-both".into(),
            agent: "fang".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "response": { "user": { "id": 1, "name": "a" } } }),
            signed_by: None,
            signature: None,
        };
        w.fang.sign_result(&mut result);
        crate::submit_result(&w.route, &result).unwrap();
        let task = crate::read_task(&w.route, "t-both").unwrap();
        assert_eq!(
            task.contract_violations_in(&w.route),
            Some(vec!["summary".to_string()])
        );
    }

    #[test]
    fn a_consumer_is_given_the_locked_shapes_and_a_provider_the_way_to_report() {
        let w = world();
        propose_user_api(&w);
        let consumer = contract_order("t-ui", "user-api", Some(Side::Consumes));
        let provider = contract_order("t-api", "user-api", Some(Side::Provides));
        assert!(
            prompt_block(&w.route, &consumer).is_none(),
            "not locked yet"
        );
        lock(&w.route, "user-api", "1", "josh", &w.josh).unwrap();

        let text = prompt_block(&w.route, &consumer).unwrap();
        assert!(text.contains("user-api@1"), "{text}");
        assert!(text.contains("consumes"), "{text}");
        assert!(text.contains("Request shape"), "{text}");
        assert!(text.contains("Response shape"), "{text}");
        assert!(text.contains("\"integer\""), "{text}");
        assert!(text.contains("Do not invent fields"), "{text}");

        let text = prompt_block(&w.route, &provider).unwrap();
        assert!(text.contains("provides"), "{text}");
        assert!(text.contains("\"response\""), "{text}");

        assert!(prompt_block(&w.route, &contract_order("t-x", "x", None)).is_none());
    }

    #[test]
    fn the_orders_on_each_side_are_listed_for_a_reviewer() {
        let w = world();
        propose_user_api(&w);
        issue(
            &w,
            contract_order("t-api", "user-api", Some(Side::Provides)),
        );
        issue(&w, contract_order("t-ui", "user-api", Some(Side::Consumes)));
        issue(
            &w,
            contract_order("t-ui2", "user-api", Some(Side::Consumes)),
        );
        issue(
            &w,
            contract_order("t-other", "billing-api", Some(Side::Provides)),
        );
        issue(&w, contract_order("t-plain", "x", None));
        // A forged order that merely names the contract is not listed.
        crate::issue_order(
            &w.route,
            &contract_order("t-forged", "user-api", Some(Side::Provides)),
        )
        .unwrap();

        let found = orders_for_interface(&w.route, "user-api", "1").unwrap();
        let ids = |orders: &[Order]| orders.iter().map(|o| o.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&found.providers), vec!["t-api"]);
        let mut consumers = ids(&found.consumers);
        consumers.sort();
        assert_eq!(consumers, vec!["t-ui", "t-ui2"]);
        assert!(
            orders_for_interface(&w.route, "user-api", "2")
                .unwrap()
                .providers
                .is_empty()
        );
    }

    #[test]
    fn the_interface_is_signed_into_the_order() {
        let w = world();
        let mut order = contract_order("t-1", "user-api", Some(Side::Provides));
        w.josh.sign_order(&mut order);
        assert_eq!(
            crate::verify_order(&order, &w.route.agents),
            SignatureCheck::Valid
        );
        // Swap the side after signing: no longer valid.
        order.interface.as_mut().unwrap().side = Side::Consumes;
        assert_eq!(
            crate::verify_order(&order, &w.route.agents),
            SignatureCheck::Invalid
        );
        // Drop it entirely: no longer valid.
        order.interface = None;
        assert_eq!(
            crate::verify_order(&order, &w.route.agents),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn touches_allow_overlap_and_the_schema_are_signed_into_the_order() {
        let w = world();
        let sign = |order: &mut Order| w.josh.sign_order(order);
        let check = |order: &Order| crate::verify_order(order, &w.route.agents);

        let mut touched = crate::overlap::tests::order("t-1", &["src/**"]);
        sign(&mut touched);
        assert_eq!(check(&touched), SignatureCheck::Valid);
        touched.touches.push("docs/**".into());
        assert_eq!(check(&touched), SignatureCheck::Invalid);

        let mut allowed = crate::overlap::tests::order("t-2", &["src/**"]);
        sign(&mut allowed);
        allowed.allow_overlap = true;
        assert_eq!(check(&allowed), SignatureCheck::Invalid);

        let mut schema = crate::overlap::tests::order("t-3", &[]);
        schema.result_contract = Some(crate::contract::ResultContract {
            required: Vec::new(),
            schema: Some(user_response()),
        });
        sign(&mut schema);
        assert_eq!(check(&schema), SignatureCheck::Valid);
        schema.result_contract.as_mut().unwrap().schema = Some(shape(json!({ "type": "object" })));
        assert_eq!(check(&schema), SignatureCheck::Invalid);
        schema.result_contract.as_mut().unwrap().schema = None;
        assert_eq!(check(&schema), SignatureCheck::Invalid);
    }

    #[test]
    fn an_order_with_none_of_the_new_fields_keeps_its_old_signature_bytes() {
        // The payload of an order with no schema, interface, touches or overlap flag is
        // exactly what it was before those fields existed, so orders already in the
        // channel still verify.
        let w = world();
        let mut order = crate::overlap::tests::order("t-old", &[]);
        order.result_contract = Some(crate::contract::ResultContract {
            required: vec!["output".into()],
            schema: None,
        });
        w.josh.sign_order(&mut order);
        let wire = serde_json::to_value(&order).unwrap();
        for key in ["interface", "touches", "allow_overlap"] {
            assert!(wire.get(key).is_none(), "{key} must not appear on the wire");
        }
        assert!(wire["result_contract"].get("schema").is_none());
        let back: Order = serde_json::from_value(wire).unwrap();
        assert_eq!(
            crate::verify_order(&back, &w.route.agents),
            SignatureCheck::Valid
        );
        // And an order written by an older version, with none of those keys at all, parses.
        let old = r#"{"id":"t","project_id":"demo","issued_by":"josh","created_at":"2026-01-01T00:00:00Z","payload":{}}"#;
        let parsed: Order = serde_json::from_str(old).unwrap();
        assert!(parsed.interface.is_none() && parsed.touches.is_empty() && !parsed.allow_overlap);
    }
}

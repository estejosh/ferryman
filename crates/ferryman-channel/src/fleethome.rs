//! The fleet's home: one synced channel, `<root>/fleet/`, for what is true of the whole fleet
//! rather than of one project (ADR 0026).
//!
//! ```text
//! <root>/fleet/                       Syncthing folder id fleet-ferryman; the iroh lane carries it
//!   master.json, agents/, grants/     the channel's own trust: the master, the roster, the admitted
//!   directory/<project>/<machine>.json            where a machine keeps a project (signed by the machine)
//!   directory/<project>/<machine>.override.json   the same, signed by the master, which wins
//!   machines/<machine>.json           version, layout, root, OS, engines, projects served, last seen
//!   notices/<id>.json                 fleet-wide announcements, signed
//!   orders/<id>.json                  fleet-wide orders (the ordinary order format), signed
//!   releases/                         release requests and approvals (read from the old place too)
//!   librarian/README.md               a placeholder; the librarian is designed and not built
//!   local/                            this machine's own part; never synced
//! ```
//!
//! # What counts
//!
//! A file counts only when it is signed, the signature verifies against the key the roster
//! pins, and the signer has standing for it: the master (declared in `master.json`) for
//! anything, or a machine identity the master admitted (`grants/<name>.json`, whose
//! capabilities name `machine:<machine>`) for that machine's own entries and for a
//! `layout-change` or `migration` notice. A Worker-level agent (ADR 0024) never has standing
//! here. Anything else is ignored by the readers, and [`Findings`] says what was ignored so
//! `ferry doctor` can report it.
//!
//! # Paths are data
//!
//! A path read from the directory is text another machine wrote. It is checked
//! ([`safe_path`]) and handed back to a person or a script to use; nothing here opens it,
//! runs it or joins another path to it.
//!
//! # What is never in here
//!
//! No secret. A project's `.env` is recorded as a path and nothing of its contents.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ferry::{Entry, Placement, Root};
use crate::{AgentIdentity, AgentRoute, ProjectRoute, SignatureCheck, canonical_agent_name};

/// The fleet channel's project id, which makes its Syncthing folder id `fleet-ferryman`.
pub const PROJECT: &str = "fleet";
/// The Syncthing folder id.
pub const FOLDER_ID: &str = "fleet-ferryman";

pub const DIRECTORY: &str = "directory";
pub const MACHINES: &str = "machines";
pub const NOTICES: &str = "notices";
pub const ORDERS: &str = "orders";
pub const RELEASES: &str = "releases";
pub const LIBRARIAN: &str = "librarian";

const FORMAT: &str = "ferryman-fleet-v1";
/// The most a fleet file may weigh. A directory entry or a notice is a few hundred bytes.
const MAX_FILE: u64 = 256 * 1024;
/// How stale a machine's `last_seen` may get before it is rewritten with nothing else new.
pub const LAST_SEEN_EVERY: Duration = Duration::minutes(10);

// ---------------------------------------------------------------------------------------
// Where things are

/// The fleet folder of the root `start` sits in, when there is one (a folder that exists).
#[must_use]
pub fn dir_near(start: &Path) -> Option<PathBuf> {
    let root = crate::ferry::find_root_from(start)?;
    let dir = root.fleet_dir();
    dir.is_dir().then_some(dir)
}

/// The fleet channel as a route: a channel-only stand-in, like the one a project with no
/// checkout here has. Its attachment is `fleet/local`, which is machine-local.
#[must_use]
pub fn route(root: &Root) -> ProjectRoute {
    let dir = root.fleet_dir();
    ProjectRoute {
        project_id: PROJECT.to_owned(),
        workspace: root.path.clone(),
        attachment: root.fleet_local(),
        communications: dir.clone(),
        shared_remote: FOLDER_ID.to_owned(),
        git_remote: String::new(),
        git_visibility: String::new(),
        agents: crate::read_agent_roster(&dir).unwrap_or_default(),
    }
}

/// Whether the fleet folder has been made on this machine.
#[must_use]
pub fn exists(root: &Root) -> bool {
    root.fleet_dir().join("master.json").is_file() || root.fleet_dir().join(DIRECTORY).is_dir()
}

/// The fleet's own `.stignore`: what Syncthing must never carry out of the folder. `local`
/// is this machine's part; the rest is what no channel carries.
const STIGNORE: &str =
    "local\nkeys\n*.tmp\n*.key\n*.seed\n*.exe\n*.dll\n*.so\n*.dylib\n*.env\n.env\n";

const LIBRARIAN_README: &str = "# The librarian\n\n\
A place held for the fleet's librarian: the thing that will know what the fleet has learned, \
across projects, and answer for it.\n\n\
It is designed and not built. Nothing reads this folder and nothing should write here yet. \
When it exists, its records will be signed like everything else in the fleet folder, and this \
file will say what they are.\n";

// ---------------------------------------------------------------------------------------
// Paths are data

/// Whether a path written by another machine is fit to hand to a person or a script.
///
/// It must be absolute (a drive path or a rooted one), plain text without control
/// characters, and free of `..`, of a UNC share or device namespace (`\\server`, `//x`,
/// `\\?\`, `\\.\`), of a drive-relative form (`C:x`), of alternate data streams, of the
/// characters Windows forbids, and of reserved device names.
///
/// # Errors
/// Why it is refused.
pub fn safe_path(text: &str) -> Result<PathBuf> {
    if text.is_empty() || text.len() > 1024 {
        bail!("an empty or overlong path");
    }
    if text.chars().any(char::is_control) {
        bail!("a path with a control character in it");
    }
    if text.starts_with("\\\\") || text.starts_with("//") || text.starts_with("\\??\\") {
        bail!("a UNC or device path ({text})");
    }
    let bytes = text.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !(drive || text.starts_with('/')) {
        bail!("not an absolute path ({text})");
    }
    let rest = if drive { &text[2..] } else { text };
    if rest.contains(':') {
        bail!("a colon where only a drive letter may have one ({text})");
    }
    if rest
        .chars()
        .any(|c| matches!(c, '*' | '?' | '<' | '>' | '|' | '"'))
    {
        bail!("a character no path here may carry ({text})");
    }
    for part in rest.split(['/', '\\']) {
        if part == ".." {
            bail!("a path that climbs with .. ({text})");
        }
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(
            stem.as_str(),
            "con"
                | "prn"
                | "aux"
                | "nul"
                | "com1"
                | "com2"
                | "com3"
                | "com4"
                | "com5"
                | "com6"
                | "com7"
                | "com8"
                | "com9"
                | "lpt1"
                | "lpt2"
                | "lpt3"
                | "lpt4"
                | "lpt5"
                | "lpt6"
                | "lpt7"
                | "lpt8"
                | "lpt9"
        ) {
            bail!("a reserved device name ({part})");
        }
    }
    Ok(PathBuf::from(text))
}

// ---------------------------------------------------------------------------------------
// Signed files

/// What every fleet file is: a kind, a name, a body, and a signature over all of them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signed {
    pub format: String,
    /// `entry`, `override`, `machine` or `notice`.
    pub kind: String,
    /// What the file is called, signed so a file cannot be copied under another name:
    /// `<project>/<machine>`, `<machine>` or the notice id.
    pub name: String,
    pub written_at: DateTime<Utc>,
    pub body: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

fn payload(doc: &Signed) -> String {
    format!(
        "{FORMAT}\n{}\n{}\n{}\n{}",
        doc.kind,
        doc.name,
        doc.written_at.to_rfc3339(),
        serde_jcs::to_string(&doc.body).unwrap_or_default()
    )
}

/// Sign a body as `identity`.
#[must_use]
pub fn sign(kind: &str, name: &str, body: Value, identity: &AgentIdentity) -> Signed {
    let mut doc = Signed {
        format: FORMAT.to_owned(),
        kind: kind.to_owned(),
        name: name.to_owned(),
        written_at: Utc::now(),
        body,
        signed_by: None,
        signature: None,
    };
    doc.signature = Some(identity.sign_bytes(payload(&doc).as_bytes()));
    doc.signed_by = Some(identity.name().to_owned());
    doc
}

fn read_signed(path: &Path) -> Option<Signed> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let doc: Signed = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (doc.format == FORMAT).then_some(doc)
}

/// A file that was there and does not count, and why. `ferry doctor` reports these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub path: String,
    pub why: String,
}

/// What a read of the fleet folder ignored.
#[derive(Debug, Clone, Default)]
pub struct Findings {
    pub rejected: Vec<Rejection>,
}

impl Findings {
    fn reject(&mut self, dir: &Path, path: &Path, why: impl Into<String>) {
        self.rejected.push(Rejection {
            path: path
                .strip_prefix(dir)
                .unwrap_or(path)
                .display()
                .to_string()
                .replace('\\', "/"),
            why: why.into(),
        });
    }
}

// ---------------------------------------------------------------------------------------
// Standing

/// Who may say what in the fleet folder, read from the folder itself.
#[derive(Debug, Clone)]
pub struct Trust {
    roster: Vec<AgentRoute>,
    master: Option<String>,
    /// Admitted names, and the machines each speaks for.
    admitted: BTreeMap<String, BTreeSet<String>>,
    workers: BTreeSet<String>,
}

/// How far a signer's word goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// The fleet's master.
    Master,
    /// A machine identity the master admitted, for this machine.
    Machine(String),
}

impl Trust {
    /// Read the fleet folder's roster, master, admissions and levels.
    #[must_use]
    pub fn load(dir: &Path) -> Self {
        let roster = crate::read_agent_roster(dir).unwrap_or_default();
        let master = crate::master::read_master_at(dir, &roster)
            .ok()
            .flatten()
            .filter(|declaration| declaration.project_id == PROJECT)
            .map(|declaration| canonical_agent_name(&declaration.master));
        let stand_in = ProjectRoute {
            project_id: PROJECT.to_owned(),
            workspace: dir.to_path_buf(),
            attachment: dir.join("local"),
            communications: dir.to_path_buf(),
            shared_remote: FOLDER_ID.to_owned(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: roster.clone(),
        };
        let mut admitted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        if master.is_some() {
            for (grant, check) in crate::master::member_grants(&stand_in).unwrap_or_default() {
                if check != SignatureCheck::Valid
                    || crate::master::is_revoked_in(dir, &roster, &grant.grantee)
                {
                    continue;
                }
                // The grant pins the key it was given for; the roster must still say it.
                let name = canonical_agent_name(&grant.grantee);
                let keyed = roster.iter().any(|agent| {
                    canonical_agent_name(&agent.name) == name
                        && agent.public_key.as_deref() == Some(grant.public_key.as_str())
                });
                if !keyed {
                    continue;
                }
                let machines = grant
                    .capabilities
                    .iter()
                    .filter_map(|capability| capability.strip_prefix("machine:"))
                    .map(str::to_ascii_lowercase)
                    .collect::<BTreeSet<_>>();
                admitted.entry(name).or_default().extend(machines);
            }
        }
        let workers = crate::access::worker_agents(dir, PROJECT);
        Self {
            roster,
            master,
            admitted,
            workers,
        }
    }

    /// The master's canonical name, when the folder has one.
    #[must_use]
    pub fn master(&self) -> Option<&str> {
        self.master.as_deref()
    }

    /// The roster, as the readers verify against it.
    #[must_use]
    pub fn roster(&self) -> &[AgentRoute] {
        &self.roster
    }

    /// The names the master admitted, with the machines each speaks for.
    #[must_use]
    pub fn admitted(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.admitted
    }

    /// Whether `name` is a Worker-level agent in the fleet folder.
    #[must_use]
    pub fn is_worker(&self, name: &str) -> bool {
        self.workers.contains(&canonical_agent_name(name))
    }

    /// Whether `identity` may write fleet files at all, and what it is refused for.
    ///
    /// # Errors
    /// A Worker-level agent; or a name nobody has admitted and who is not the master.
    pub fn may_write(&self, identity: &AgentIdentity) -> Result<()> {
        let name = canonical_agent_name(identity.name());
        if self.is_worker(&name) {
            bail!(
                "{} is a Worker-level agent in the fleet folder, and a Worker never writes it \
                 (ADR 0024, ADR 0026)",
                identity.name()
            );
        }
        if self.master.as_deref() != Some(name.as_str()) && !self.admitted.contains_key(&name) {
            bail!(
                "{} is not admitted to the fleet folder, so nothing it wrote would count; the \
                 master runs `ferry fleet admit {} --machine <machine>`",
                identity.name(),
                identity.name()
            );
        }
        Ok(())
    }

    /// The standing of whoever signed `doc`, for something about `machine`, or why none.
    ///
    /// # Errors
    /// The reason it does not count.
    pub fn standing(&self, doc: &Signed, machine: Option<&str>) -> Result<Standing, String> {
        match crate::check_signature(
            doc.signed_by.as_ref(),
            doc.signature.as_ref(),
            &payload(doc),
            &self.roster,
        ) {
            SignatureCheck::Valid => {}
            SignatureCheck::Unsigned => return Err("unsigned".into()),
            SignatureCheck::UnknownSigner => {
                return Err(format!(
                    "signed by {}, who is not on the fleet roster",
                    doc.signed_by.as_deref().unwrap_or("?")
                ));
            }
            SignatureCheck::Invalid => return Err("the signature does not verify".into()),
            SignatureCheck::KeyChanged { .. } => {
                return Err("the signer's key is not the one the roster pinned".into());
            }
        }
        let by = canonical_agent_name(doc.signed_by.as_deref().unwrap_or_default());
        if self.master.as_deref() == Some(by.as_str()) {
            return Ok(Standing::Master);
        }
        if self.workers.contains(&by) {
            return Err(format!("signed by {by}, a Worker-level agent"));
        }
        let Some(speaks_for) = self.admitted.get(&by) else {
            return Err(format!("signed by {by}, whom the master has not admitted"));
        };
        match machine {
            Some(machine) if speaks_for.contains(&machine.to_ascii_lowercase()) => {
                Ok(Standing::Machine(by))
            }
            Some(machine) => Err(format!("{by} is not admitted to speak for {machine}")),
            None => Err(format!("{by} is not the master")),
        }
    }
}

fn atomic(path: &Path, doc: &Signed) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::atomic_json(path, doc).with_context(|| format!("write {}", path.display()))
}

/// The same body, not counting when it was written or when the machine last looked.
fn same_body(a: &Value, b: &Value) -> bool {
    let strip = |value: &Value| {
        let mut value = value.clone();
        if let Some(map) = value.as_object_mut() {
            map.remove("last_seen");
        }
        value
    };
    strip(a) == strip(b)
}

/// Whether the file at `path` already says `body` with a signature that counts, and was
/// written recently enough that it need not be refreshed.
fn current(path: &Path, trust: &Trust, machine: &str, body: &Value, keep_fresh: bool) -> bool {
    let Some(doc) = read_signed(path) else {
        return false;
    };
    if trust.standing(&doc, Some(machine)).is_err() || !same_body(&doc.body, body) {
        return false;
    }
    !(keep_fresh && Utc::now() - doc.written_at > LAST_SEEN_EVERY)
}

// ---------------------------------------------------------------------------------------
// Making the folder, and who is in it

/// What `init` did.
#[derive(Debug, Clone, Default)]
pub struct Init {
    pub dir: PathBuf,
    pub made: Vec<String>,
    pub master: String,
}

/// Make the fleet folder and declare `master` its master. Idempotent. Registers nothing with
/// Syncthing or iroh: the caller does, so this stays something a test can run.
///
/// # Errors
/// The folder already has a different master, or a file cannot be written.
pub fn init(root: &Root, master: &AgentIdentity) -> Result<Init> {
    let dir = root.fleet_dir();
    let mut report = Init {
        dir: dir.clone(),
        master: master.name().to_owned(),
        ..Init::default()
    };
    for sub in [
        DIRECTORY, MACHINES, NOTICES, ORDERS, RELEASES, LIBRARIAN, "local",
    ] {
        let path = if sub == "local" {
            root.fleet_local()
        } else {
            dir.join(sub)
        };
        if !path.is_dir() {
            fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
            report.made.push(format!("{sub}/"));
        }
    }
    let ignore = dir.join(".stignore");
    if !ignore.is_file() {
        fs::write(&ignore, STIGNORE)?;
        report.made.push(".stignore".into());
    }
    let readme = dir.join(LIBRARIAN).join("README.md");
    if !readme.is_file() {
        fs::write(&readme, LIBRARIAN_README)?;
        report.made.push("librarian/README.md".into());
    }
    let route = route(root);
    crate::register_agent_key(
        &route,
        &AgentRoute {
            name: master.name().to_owned(),
            role: "operator".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        master,
    )?;
    let route = self::route(root);
    crate::master::initialize_master(&route, master, master.name())?;
    Ok(report)
}

/// Put this identity on the fleet roster (first key wins), so the master can admit it. It
/// does not admit itself: until the master does, what it writes is ignored.
///
/// # Errors
/// The fleet folder is not here, or the name carries a different key already.
pub fn enrol(root: &Root, identity: &AgentIdentity) -> Result<bool> {
    if !exists(root) {
        bail!(
            "no fleet folder in {} yet (the master runs `ferry fleet init`)",
            root.path.display()
        );
    }
    let route = route(root);
    let name = canonical_agent_name(identity.name());
    if route.agents.iter().any(|agent| {
        canonical_agent_name(&agent.name) == name
            && agent.public_key.as_deref() == Some(identity.public_key_hex().as_str())
    }) {
        return Ok(false);
    }
    crate::register_agent_key(
        &route,
        &AgentRoute {
            name: identity.name().to_owned(),
            role: "worker".into(),
            capabilities: Vec::new(),
            public_key: None,
            encryption_key: None,
        },
        identity,
    )?;
    Ok(true)
}

/// Admit `name` (already on the roster, see [`enrol`]) to speak for `machine`: a grant the
/// master signs, naming the key and `machine:<machine>`.
///
/// # Errors
/// The signer is not the master, or `name` is not on the roster.
pub fn admit(root: &Root, master: &AgentIdentity, name: &str, machine: &str) -> Result<()> {
    let machine = machine.to_ascii_lowercase();
    if !crate::is_safe_component(&machine) {
        bail!("a machine name is letters, digits, '.', '-' and '_'");
    }
    let route = route(root);
    crate::ferry::require_master(&route.communications, PROJECT, master, "admit a machine")?;
    let wanted = canonical_agent_name(name);
    let Some(key) = route
        .agents
        .iter()
        .find(|agent| canonical_agent_name(&agent.name) == wanted)
        .and_then(|agent| agent.public_key.clone())
    else {
        bail!("{name} is not on the fleet roster yet; its worker enrols it when it starts");
    };
    let mut capabilities = vec![format!("machine:{machine}")];
    // Admitting again for a second machine keeps what it already speaks for.
    let trust = Trust::load(&route.communications);
    if let Some(known) = trust.admitted.get(&wanted) {
        capabilities.extend(known.iter().map(|m| format!("machine:{m}")));
        capabilities.sort();
        capabilities.dedup();
    }
    crate::master::grant_member(
        &route,
        master,
        &wanted,
        &key,
        Vec::new(),
        vec!["machine".into()],
        capabilities,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The directory: where a machine keeps a project

/// The paths of one project on one machine. Text, because it crosses operating systems.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paths {
    pub code: Option<String>,
    pub channel: Option<String>,
    pub handins: Option<String>,
    pub data: Option<String>,
    pub env: Option<String>,
    pub work: Option<String>,
    /// A person's own working copies, for information. Never where work happens.
    #[serde(default)]
    pub checkouts: Vec<String>,
}

/// One machine's entry for one project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirBody {
    pub project: String,
    pub machine: String,
    /// The ferry root on that machine.
    pub root: String,
    /// `managed` or `custom`.
    pub placement: String,
    pub layout: u32,
    /// `live` or `archived`.
    pub lifecycle: String,
    pub paths: Paths,
}

fn text(path: &Path) -> String {
    path.display().to_string()
}

/// The entry a machine would publish for `entry`, read from its manifest.
#[must_use]
pub fn dir_body(root: &Root, entry: &Entry, machine: &str) -> DirBody {
    let code = entry
        .repo
        .clone()
        .unwrap_or_else(|| entry.managed_clone_path(root));
    DirBody {
        project: entry.project_id.clone(),
        machine: machine.to_ascii_lowercase(),
        root: text(&root.path),
        placement: match entry.placement_in(root) {
            Placement::Managed => "managed",
            Placement::Custom => "custom",
        }
        .into(),
        layout: root.layout_version(),
        lifecycle: if entry.is_archived() {
            "archived"
        } else {
            "live"
        }
        .into(),
        paths: Paths {
            code: Some(text(&code)),
            channel: Some(text(&entry.channel)),
            handins: Some(text(&entry.handins_path(root))),
            data: Some(text(&entry.data_path(root))),
            env: Some(text(&entry.env_path(root))),
            work: Some(text(&entry.work_path(root))),
            checkouts: entry.human_checkouts.iter().map(|p| text(p)).collect(),
        },
    }
}

fn check_paths(paths: &Paths) -> Result<()> {
    for (_, value) in [
        ("code", &paths.code),
        ("channel", &paths.channel),
        ("handins", &paths.handins),
        ("data", &paths.data),
        ("env", &paths.env),
        ("work", &paths.work),
    ] {
        if let Some(value) = value {
            safe_path(value)?;
        }
    }
    for value in &paths.checkouts {
        safe_path(value)?;
    }
    Ok(())
}

/// What a publish did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Published {
    pub written: Vec<String>,
    pub unchanged: usize,
}

fn machine_ok(machine: &str) -> Result<String> {
    let machine = machine.to_ascii_lowercase();
    if !crate::is_safe_component(&machine) || machine.contains('/') {
        bail!("'{machine}' is not a machine name a fleet file can be filed under");
    }
    Ok(machine)
}

/// Publish `machine`'s directory entries, one per project in the root's manifest, signed by
/// `identity`. A file that already says the same thing is left alone.
///
/// # Errors
/// The folder is not here, `identity` may not write it, or has no standing for `machine`.
pub fn publish_directory(
    root: &Root,
    machine: &str,
    identity: &AgentIdentity,
) -> Result<Published> {
    let machine = machine_ok(machine)?;
    if !exists(root) {
        bail!("no fleet folder in {} yet", root.path.display());
    }
    let dir = root.fleet_dir();
    let trust = Trust::load(&dir);
    trust.may_write(identity)?;
    let mut out = Published::default();
    for entry in root.read().projects {
        if !crate::is_safe_component(&entry.project_id) {
            continue;
        }
        let body = serde_json::to_value(dir_body(root, &entry, &machine))?;
        let path = dir
            .join(DIRECTORY)
            .join(&entry.project_id)
            .join(format!("{machine}.json"));
        if current(&path, &trust, &machine, &body, false) {
            out.unchanged += 1;
            continue;
        }
        let doc = sign(
            "entry",
            &format!("{}/{machine}", entry.project_id),
            body,
            identity,
        );
        if let Err(why) = trust.standing(&doc, Some(&machine)) {
            bail!("{} cannot publish for {machine}: {why}", identity.name());
        }
        atomic(&path, &doc)?;
        out.written.push(format!("{}/{machine}", entry.project_id));
    }
    Ok(out)
}

/// The master's override: where `machine` keeps `project`, whatever the machine says.
///
/// # Errors
/// The signer is not the master, or a path is not fit to record.
pub fn override_directory(
    root: &Root,
    master: &AgentIdentity,
    machine: &str,
    mut body: DirBody,
) -> Result<()> {
    let machine = machine_ok(machine)?;
    body.machine.clone_from(&machine);
    check_paths(&body.paths)?;
    if !crate::is_safe_component(&body.project) {
        bail!("not a project id: {}", body.project);
    }
    let trust = Trust::load(&root.fleet_dir());
    if trust.master() != Some(canonical_agent_name(master.name()).as_str()) {
        bail!("only the fleet's master signs an override");
    }
    let path = root
        .fleet_dir()
        .join(DIRECTORY)
        .join(&body.project)
        .join(format!("{machine}.override.json"));
    let doc = sign(
        "override",
        &format!("{}/{machine}", body.project),
        serde_json::to_value(&body)?,
        master,
    );
    atomic(&path, &doc)
}

/// One entry as read: the body and who vouched for it.
#[derive(Debug, Clone, PartialEq)]
pub struct DirEntry {
    pub body: DirBody,
    pub signed_by: String,
    pub written_at: DateTime<Utc>,
    pub overridden: bool,
}

/// The directory as it counts: project, then machine.
#[derive(Debug, Clone, Default)]
pub struct Directory {
    pub projects: BTreeMap<String, BTreeMap<String, DirEntry>>,
    pub findings: Findings,
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(".sync-conflict-"))
        })
        .collect();
    out.sort();
    out
}

/// Read the directory, keeping what counts and noting what does not.
#[must_use]
pub fn read_directory(root: &Root) -> Directory {
    let dir = root.fleet_dir();
    let base = dir.join(DIRECTORY);
    let mut out = Directory::default();
    if !base.is_dir() {
        return out;
    }
    let trust = Trust::load(&dir);
    let mut projects: Vec<PathBuf> = fs::read_dir(&base)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    projects.sort();
    for folder in projects {
        let project = folder
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for path in json_files(&folder) {
            let file = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            let (machine, is_override) = match file.strip_suffix(".override") {
                Some(machine) => (machine.to_owned(), true),
                None => (file, false),
            };
            let reject = |out: &mut Directory, why: String| out.findings.reject(&dir, &path, why);
            if !crate::is_safe_component(&project) || !crate::is_safe_component(&machine) {
                reject(&mut out, "not a project and machine name".into());
                continue;
            }
            let Some(doc) = read_signed(&path) else {
                reject(&mut out, "not a fleet file".into());
                continue;
            };
            let kind = if is_override { "override" } else { "entry" };
            if doc.kind != kind || doc.name != format!("{project}/{machine}") {
                reject(&mut out, "the file is not what its name says it is".into());
                continue;
            }
            let standing = trust.standing(&doc, Some(&machine));
            let standing = match (standing, is_override) {
                (Ok(Standing::Master), _) => Standing::Master,
                (Ok(machine_standing), false) => machine_standing,
                (Ok(_), true) => {
                    reject(&mut out, "an override only counts from the master".into());
                    continue;
                }
                (Err(why), _) => {
                    reject(&mut out, why);
                    continue;
                }
            };
            let Ok(body) = serde_json::from_value::<DirBody>(doc.body.clone()) else {
                reject(&mut out, "the body is not a directory entry".into());
                continue;
            };
            if body.project != project || !body.machine.eq_ignore_ascii_case(&machine) {
                reject(&mut out, "the body names another project or machine".into());
                continue;
            }
            if let Err(why) =
                check_paths(&body.paths).and_then(|()| safe_path(&body.root).map(|_| ()))
            {
                reject(&mut out, format!("unsafe path: {why}"));
                continue;
            }
            let entry = DirEntry {
                body,
                signed_by: doc.signed_by.clone().unwrap_or_default(),
                written_at: doc.written_at,
                overridden: is_override && standing == Standing::Master,
            };
            let slot = out
                .projects
                .entry(project.clone())
                .or_default()
                .entry(machine.clone());
            match slot {
                std::collections::btree_map::Entry::Vacant(vacant) => {
                    vacant.insert(entry);
                }
                std::collections::btree_map::Entry::Occupied(mut held) => {
                    let beats = (entry.overridden && !held.get().overridden)
                        || (entry.overridden == held.get().overridden
                            && entry.written_at > held.get().written_at);
                    if beats {
                        held.insert(entry);
                    }
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Machines

/// What a machine says about itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineBody {
    pub machine: String,
    pub version: String,
    pub layout: u32,
    pub root: String,
    pub os: String,
    /// The engines its worker runs, one line each.
    #[serde(default)]
    pub engines: Vec<String>,
    /// The projects its worker serves.
    #[serde(default)]
    pub projects: Vec<String>,
    pub last_seen: DateTime<Utc>,
    /// The fleet orders this machine has acted on (the last few).
    #[serde(default)]
    pub orders_done: Vec<String>,
}

/// What the caller knows about the machine; the rest is read from the root.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub version: String,
    pub engines: Vec<String>,
    pub projects: Vec<String>,
}

/// Publish this machine's record. Returns whether anything was written (a record that says
/// the same, seen recently, is left alone).
///
/// # Errors
/// As [`publish_directory`].
pub fn publish_machine(
    root: &Root,
    machine: &str,
    identity: &AgentIdentity,
    facts: &Facts,
) -> Result<bool> {
    let machine = machine_ok(machine)?;
    if !exists(root) {
        bail!("no fleet folder in {} yet", root.path.display());
    }
    let dir = root.fleet_dir();
    let trust = Trust::load(&dir);
    trust.may_write(identity)?;
    let done: Vec<String> = orders_done(root).into_iter().rev().take(20).rev().collect();
    let body = MachineBody {
        machine: machine.clone(),
        version: facts.version.clone(),
        layout: root.layout_version(),
        root: text(&root.path),
        os: std::env::consts::OS.to_owned(),
        engines: facts.engines.clone(),
        projects: facts.projects.clone(),
        last_seen: Utc::now(),
        orders_done: done,
    };
    let body = serde_json::to_value(body)?;
    let path = dir.join(MACHINES).join(format!("{machine}.json"));
    if current(&path, &trust, &machine, &body, true) {
        return Ok(false);
    }
    let doc = sign("machine", &machine, body, identity);
    if let Err(why) = trust.standing(&doc, Some(&machine)) {
        bail!("{} cannot publish for {machine}: {why}", identity.name());
    }
    atomic(&path, &doc)?;
    Ok(true)
}

/// A machine record as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRow {
    pub body: MachineBody,
    pub signed_by: String,
}

/// Every machine record that counts.
#[must_use]
pub fn read_machines(root: &Root) -> (Vec<MachineRow>, Findings) {
    let dir = root.fleet_dir();
    let mut findings = Findings::default();
    let mut rows = Vec::new();
    let trust = Trust::load(&dir);
    for path in json_files(&dir.join(MACHINES)) {
        let name = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(doc) = read_signed(&path) else {
            findings.reject(&dir, &path, "not a fleet file");
            continue;
        };
        if doc.kind != "machine" || doc.name != name || !crate::is_safe_component(&name) {
            findings.reject(&dir, &path, "the file is not what its name says it is");
            continue;
        }
        if let Err(why) = trust.standing(&doc, Some(&name)) {
            findings.reject(&dir, &path, why);
            continue;
        }
        let Ok(body) = serde_json::from_value::<MachineBody>(doc.body.clone()) else {
            findings.reject(&dir, &path, "the body is not a machine record");
            continue;
        };
        if !body.machine.eq_ignore_ascii_case(&name) || safe_path(&body.root).is_err() {
            findings.reject(
                &dir,
                &path,
                "the body names another machine, or an unsafe root",
            );
            continue;
        }
        rows.push(MachineRow {
            body,
            signed_by: doc.signed_by.unwrap_or_default(),
        });
    }
    rows.sort_by(|a, b| a.body.machine.cmp(&b.body.machine));
    (rows, findings)
}

// ---------------------------------------------------------------------------------------
// Notices

pub const NOTICE_KINDS: [&str; 5] = [
    "layout-change",
    "deprecation",
    "update-available",
    "migration",
    "general",
];
pub const SEVERITIES: [&str; 3] = ["info", "warning", "high"];

/// A fleet-wide announcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoticeBody {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub text: String,
    pub issued: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    /// The machine a `layout-change` or `migration` notice is about; the machine's own
    /// identity may sign those, and only those, for itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Kind-specific facts: old and new paths, the version an update names.
    #[serde(default)]
    pub details: Value,
}

impl NoticeBody {
    /// A notice issued now, with an id that sorts by time.
    #[must_use]
    pub fn new(kind: &str, severity: &str, title: &str, text: &str) -> Self {
        let issued = Utc::now();
        Self {
            id: format!("{}-{kind}", issued.format("%Y%m%dT%H%M%S%3fZ")),
            kind: kind.to_owned(),
            severity: severity.to_owned(),
            title: title.to_owned(),
            text: text.to_owned(),
            issued,
            expires: None,
            machine: None,
            details: Value::Null,
        }
    }
}

fn notice_scope(body: &NoticeBody) -> Option<&str> {
    matches!(body.kind.as_str(), "layout-change" | "migration")
        .then_some(body.machine.as_deref())
        .flatten()
}

/// Post a notice. The master may post any; a machine identity may post a `layout-change`
/// or `migration` notice about its own machine.
///
/// # Errors
/// A kind or severity that is not known, a field too long, or no standing.
pub fn post_notice(root: &Root, identity: &AgentIdentity, mut body: NoticeBody) -> Result<String> {
    if !exists(root) {
        bail!("no fleet folder in {} yet", root.path.display());
    }
    if !NOTICE_KINDS.contains(&body.kind.as_str()) {
        bail!("a notice is one of: {}", NOTICE_KINDS.join(", "));
    }
    if !SEVERITIES.contains(&body.severity.as_str()) {
        bail!("a severity is one of: {}", SEVERITIES.join(", "));
    }
    if body.title.len() > 200 || body.text.len() > 4000 || !crate::is_safe_component(&body.id) {
        bail!("a notice has a short title, a text under 4000 bytes and a path-safe id");
    }
    if let Some(machine) = body.machine.take() {
        body.machine = Some(machine_ok(&machine)?);
    }
    let dir = root.fleet_dir();
    let trust = Trust::load(&dir);
    trust.may_write(identity)?;
    let doc = sign("notice", &body.id, serde_json::to_value(&body)?, identity);
    if let Err(why) = trust.standing(&doc, notice_scope(&body)) {
        bail!(
            "{} may not post a {} notice: {why}",
            identity.name(),
            body.kind
        );
    }
    atomic(&dir.join(NOTICES).join(format!("{}.json", body.id)), &doc)?;
    Ok(body.id)
}

/// A notice as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeRow {
    pub body: NoticeBody,
    pub signed_by: String,
    pub expired: bool,
}

/// Every notice that counts, newest first.
#[must_use]
pub fn read_notices(root: &Root) -> (Vec<NoticeRow>, Findings) {
    let dir = root.fleet_dir();
    let trust = Trust::load(&dir);
    let mut findings = Findings::default();
    let mut rows = Vec::new();
    let now = Utc::now();
    for path in json_files(&dir.join(NOTICES)) {
        let name = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(doc) = read_signed(&path) else {
            findings.reject(&dir, &path, "not a fleet file");
            continue;
        };
        if doc.kind != "notice" || doc.name != name {
            findings.reject(&dir, &path, "the file is not what its name says it is");
            continue;
        }
        let Ok(body) = serde_json::from_value::<NoticeBody>(doc.body.clone()) else {
            findings.reject(&dir, &path, "the body is not a notice");
            continue;
        };
        if body.id != name || !NOTICE_KINDS.contains(&body.kind.as_str()) {
            findings.reject(
                &dir,
                &path,
                "the body names another notice, or a kind nobody knows",
            );
            continue;
        }
        if let Err(why) = trust.standing(&doc, notice_scope(&body)) {
            findings.reject(&dir, &path, why);
            continue;
        }
        let expired = body.expires.is_some_and(|at| at <= now);
        rows.push(NoticeRow {
            body,
            signed_by: doc.signed_by.unwrap_or_default(),
            expired,
        });
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.body.issued));
    (rows, findings)
}

fn local_list(root: &Root, name: &str) -> Vec<String> {
    fs::read(root.fleet_local().join(name))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Vec<String>>(&bytes).ok())
        .unwrap_or_default()
}

fn save_local_list(root: &Root, name: &str, list: &[String]) -> Result<()> {
    let path = root.fleet_local().join(name);
    crate::atomic_json(&path, &list).with_context(|| format!("write {}", path.display()))
}

/// The unread, unexpired, high-severity notices.
#[must_use]
pub fn unread_high(root: &Root) -> Vec<NoticeRow> {
    let seen = local_list(root, "notices-seen.json");
    read_notices(root)
        .0
        .into_iter()
        .filter(|row| row.body.severity == "high" && !row.expired && !seen.contains(&row.body.id))
        .collect()
}

/// Remember that these notices have been shown on this machine.
///
/// # Errors
/// The local state cannot be written.
pub fn mark_seen(root: &Root, ids: &[String]) -> Result<()> {
    let mut seen = local_list(root, "notices-seen.json");
    for id in ids {
        if !seen.contains(id) {
            seen.push(id.clone());
        }
    }
    let skip = seen.len().saturating_sub(500);
    save_local_list(root, "notices-seen.json", &seen[skip..])
}

fn version_parts(version: &str) -> Vec<u64> {
    version
        .trim_start_matches('v')
        .split(['.', '-', '+'])
        .map_while(|part| part.parse().ok())
        .collect()
}

/// Whether version `a` is newer than version `b`.
#[must_use]
pub fn newer(a: &str, b: &str) -> bool {
    version_parts(a) > version_parts(b)
}

/// The newest release a live `update-available` notice names that is newer than `current`.
#[must_use]
pub fn newer_release(rows: &[NoticeRow], current: &str) -> Option<String> {
    rows.iter()
        .filter(|row| row.body.kind == "update-available" && !row.expired)
        .filter_map(|row| row.body.details.get("version")?.as_str().map(str::to_owned))
        .filter(|version| newer(version, current))
        .max_by(|a, b| version_parts(a).cmp(&version_parts(b)))
}

// ---------------------------------------------------------------------------------------
// Orders

pub const ORDER_ACTIONS: [&str; 3] = ["update", "migrate", "restart-worker"];

/// Issue a fleet order: the ordinary order, signed by the master, for a machine or for all.
///
/// # Errors
/// The signer is not the master, or the action is not one a fleet order carries.
pub fn issue_order(
    root: &Root,
    master: &AgentIdentity,
    machine: Option<&str>,
    action: &str,
    args: Value,
) -> Result<crate::Order> {
    if !exists(root) {
        bail!("no fleet folder in {} yet", root.path.display());
    }
    if !ORDER_ACTIONS.contains(&action) {
        bail!("a fleet order is one of: {}", ORDER_ACTIONS.join(", "));
    }
    let dir = root.fleet_dir();
    let trust = Trust::load(&dir);
    if trust.master() != Some(canonical_agent_name(master.name()).as_str()) {
        bail!("only the fleet's master issues a fleet order");
    }
    let machine = machine.map(machine_ok).transpose()?;
    let now = Utc::now();
    let mut order = crate::Order {
        id: format!("fleet-{}-{action}", now.format("%Y%m%dT%H%M%S%3fZ")),
        project_id: PROJECT.to_owned(),
        issued_by: master.name().to_owned(),
        assigned_to: machine,
        created_at: now,
        payload: json!({ "fleet": true, "action": action, "args": args }),
        requires_review: false,
        requires_approval: false,
        depends_on: Vec::new(),
        signed_by: None,
        signature: None,
        result_contract: None,
        interface: None,
        touches: Vec::new(),
        needs: None,
        allow_overlap: false,
        priority: None,
    };
    master.sign_order(&mut order);
    crate::atomic_json(&dir.join(ORDERS).join(format!("{}.json", order.id)), &order)?;
    Ok(order)
}

/// The fleet orders this machine has acted on.
#[must_use]
pub fn orders_done(root: &Root) -> Vec<String> {
    local_list(root, "orders-done.json")
}

/// Record that this machine acted on a fleet order, so it never acts twice.
///
/// # Errors
/// The local state cannot be written.
pub fn mark_order_done(root: &Root, id: &str) -> Result<()> {
    let mut done = orders_done(root);
    if !done.iter().any(|known| known == id) {
        done.push(id.to_owned());
    }
    let skip = done.len().saturating_sub(500);
    save_local_list(root, "orders-done.json", &done[skip..])
}

/// The fleet orders for `machine` that count: signed by the master, issued in the
/// master's name, addressed to this machine or to all, and not yet acted on.
#[must_use]
pub fn read_orders_for(root: &Root, machine: &str) -> (Vec<crate::Order>, Findings) {
    let dir = root.fleet_dir();
    let trust = Trust::load(&dir);
    let machine = machine.to_ascii_lowercase();
    let done = orders_done(root);
    let mut findings = Findings::default();
    let mut out = Vec::new();
    for path in json_files(&dir.join(ORDERS)) {
        let name = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        let order = fs::metadata(&path)
            .ok()
            .filter(|meta| meta.is_file() && meta.len() <= MAX_FILE)
            .and_then(|_| fs::read(&path).ok())
            .and_then(|bytes| serde_json::from_slice::<crate::Order>(&bytes).ok());
        let Some(order) = order else {
            findings.reject(&dir, &path, "not an order");
            continue;
        };
        if order.id != name || order.project_id != PROJECT {
            findings.reject(&dir, &path, "the order is not what its name says it is");
            continue;
        }
        if crate::verify_order(&order, trust.roster()) != SignatureCheck::Valid {
            findings.reject(&dir, &path, "unsigned, or the signature does not verify");
            continue;
        }
        let signer = canonical_agent_name(order.signed_by.as_deref().unwrap_or_default());
        if trust.master() != Some(signer.as_str())
            || canonical_agent_name(&order.issued_by) != signer
        {
            findings.reject(&dir, &path, "a fleet order counts only from the master");
            continue;
        }
        let mine = order
            .assigned_to
            .as_deref()
            .is_none_or(|to| to.eq_ignore_ascii_case(&machine));
        if mine && !done.contains(&order.id) {
            out.push(order);
        }
    }
    out.sort_by_key(|order| order.created_at);
    (out, findings)
}

// ---------------------------------------------------------------------------------------
// Where a project is

/// A kind of place a project has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Code,
    Channel,
    Handins,
    Data,
    Env,
}

impl Kind {
    /// Read `code`, `channel`, `handins`, `data` or `env`.
    ///
    /// # Errors
    /// A word that is none of them.
    pub fn parse(word: &str) -> Result<Self> {
        Ok(match word.to_ascii_lowercase().as_str() {
            "code" | "repo" => Self::Code,
            "channel" | "comms" => Self::Channel,
            "handins" | "hand-ins" => Self::Handins,
            "data" => Self::Data,
            "env" => Self::Env,
            other => {
                bail!("'{other}' is not a kind of place; use code, channel, handins, data or env")
            }
        })
    }
}

/// Where one project is on one machine, and how that is known.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Where {
    pub project: String,
    pub machine: String,
    /// `manifest` (this machine's own), `directory` or `override` (the master's word).
    pub source: String,
    pub root: String,
    pub placement: String,
    pub layout: u32,
    pub lifecycle: String,
    pub paths: Paths,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
}

impl Where {
    /// The path of a kind, when the entry has one.
    #[must_use]
    pub fn path(&self, kind: Kind) -> Option<&str> {
        match kind {
            Kind::Code => self.paths.code.as_deref(),
            Kind::Channel => self.paths.channel.as_deref(),
            Kind::Handins => self.paths.handins.as_deref(),
            Kind::Data => self.paths.data.as_deref(),
            Kind::Env => self.paths.env.as_deref(),
        }
    }
}

fn from_body(body: DirBody, source: &str, signed_by: Option<String>) -> Where {
    Where {
        project: body.project,
        machine: body.machine,
        source: source.to_owned(),
        root: body.root,
        placement: body.placement,
        layout: body.layout,
        lifecycle: body.lifecycle,
        paths: body.paths,
        signed_by,
    }
}

/// Where `project` is on `machine` (this machine, `own`, when `None`). This machine's own
/// manifest is the truth for this machine, so a migrate is seen the moment it is done and
/// before anything is published; another machine is known by what its entry says, or what the
/// master's override says in its place.
///
/// # Errors
/// The project is not known on that machine.
pub fn resolve(root: &Root, project: &str, machine: Option<&str>, own: &str) -> Result<Where> {
    let own = own.to_ascii_lowercase();
    let wanted = machine.map_or_else(|| own.clone(), str::to_ascii_lowercase);
    if wanted == own
        && let Some(entry) = root
            .read()
            .projects
            .iter()
            .find(|e| e.project_id == project)
    {
        return Ok(from_body(dir_body(root, entry, &own), "manifest", None));
    }
    let directory = read_directory(root);
    let known = directory.projects.get(project);
    if let Some(found) = known.and_then(|machines| machines.get(&wanted)) {
        let source = if found.overridden {
            "override"
        } else {
            "directory"
        };
        return Ok(from_body(
            found.body.clone(),
            source,
            Some(found.signed_by.clone()),
        ));
    }
    match known {
        Some(machines) => bail!(
            "{project} is not known on {wanted}; the fleet directory has it on: {}",
            machines.keys().cloned().collect::<Vec<_>>().join(", ")
        ),
        None => bail!("{project} is in neither this machine's manifest nor the fleet directory"),
    }
}

/// Every project on every machine the fleet knows of, this machine from its manifest.
#[must_use]
pub fn resolve_all(root: &Root, own: &str) -> Vec<Where> {
    let own = own.to_ascii_lowercase();
    let mut rows: BTreeMap<(String, String), Where> = BTreeMap::new();
    for (project, machines) in read_directory(root).projects {
        for (machine, found) in machines {
            let source = if found.overridden {
                "override"
            } else {
                "directory"
            };
            rows.insert(
                (project.clone(), machine),
                from_body(found.body, source, Some(found.signed_by)),
            );
        }
    }
    for entry in root.read().projects {
        rows.insert(
            (entry.project_id.clone(), own.clone()),
            from_body(dir_body(root, &entry, &own), "manifest", None),
        );
    }
    rows.into_values().collect()
}

/// Everything the readers ignored, for `ferry doctor`.
#[must_use]
pub fn audit(root: &Root, own: &str) -> Findings {
    let mut all = read_directory(root).findings;
    all.rejected.extend(read_machines(root).1.rejected);
    all.rejected.extend(read_notices(root).1.rejected);
    all.rejected.extend(read_orders_for(root, own).1.rejected);
    all
}

// ---------------------------------------------------------------------------------------
// The session hint

pub const HINT_BEGIN: &str = "<!-- ferry:where begin -->";
pub const HINT_END: &str = "<!-- ferry:where end -->";

/// A short, stable block for a session's instructions file. It carries no time and nothing
/// that changes between runs but the paths themselves.
#[must_use]
pub fn hint_block(found: &Where) -> String {
    let mut out = format!("{HINT_BEGIN}\n## Where this project lives\n\n");
    let id = &found.project;
    match found.paths.code.as_deref() {
        Some(code) => out.push_str(&format!(
            "This project (`{id}`) lives at `{code}` on this machine.\n"
        )),
        None => out.push_str(&format!("This project is `{id}`.\n")),
    }
    if let Some(channel) = found.paths.channel.as_deref() {
        out.push_str(&format!("Its channel is `{channel}`.\n"));
    }
    if let Some(data) = found.paths.data.as_deref() {
        out.push_str(&format!("Its machine-local data is `{data}`.\n"));
    }
    out.push_str(&format!(
        "Paths move. If a path fails, ask `ferry where {id}` (add `--kind data` or `--kind channel` \
         for one place) and use what it says. Never hardcode a path.\n{HINT_END}\n"
    ));
    out
}

/// What would be done to one instructions file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintAction {
    Create,
    Append,
    Update,
    Unchanged,
    Refused(String),
}

/// One file's plan.
#[derive(Debug, Clone)]
pub struct HintPlan {
    pub project: String,
    pub file: PathBuf,
    pub action: HintAction,
    new_text: Option<String>,
}

impl HintPlan {
    /// Write the file, when the plan is to. Never stages, commits or pushes.
    ///
    /// # Errors
    /// The file cannot be written.
    pub fn apply(&self) -> Result<bool> {
        let Some(text) = &self.new_text else {
            return Ok(false);
        };
        let parent = self.file.parent().context("a file with no folder")?;
        let temporary = parent.join(format!(".ferry-where-{}.tmp", std::process::id()));
        fs::write(&temporary, text)?;
        fs::rename(&temporary, &self.file)
            .with_context(|| format!("write {}", self.file.display()))?;
        Ok(true)
    }
}

/// Put `block` into `existing`: between its own markers when they are there, at the end
/// when they are not. Nothing outside the markers changes, and the file's line endings are
/// kept.
///
/// # Errors
/// The markers are damaged (one without the other, out of order, or more than once); then
/// nothing is touched.
pub fn place_hint(existing: &str, block: &str) -> Result<String> {
    let crlf = existing.contains("\r\n");
    let block = block.trim_end_matches(['\r', '\n']);
    let block = if crlf {
        block.replace('\n', "\r\n")
    } else {
        block.to_owned()
    };
    let begins = existing.matches(HINT_BEGIN).count();
    let ends = existing.matches(HINT_END).count();
    match (begins, ends) {
        (0, 0) => {
            let eol = if crlf { "\r\n" } else { "\n" };
            let mut out = existing.to_owned();
            if !out.is_empty() {
                if !out.ends_with('\n') {
                    out.push_str(eol);
                }
                out.push_str(eol);
            }
            out.push_str(&block);
            out.push_str(eol);
            Ok(out)
        }
        (1, 1) => {
            let start = existing.find(HINT_BEGIN).unwrap_or_default();
            let end = existing.find(HINT_END).unwrap_or_default();
            if end < start {
                bail!("the end marker comes before the begin marker");
            }
            let tail = end + HINT_END.len();
            Ok(format!(
                "{}{block}{}",
                &existing[..start],
                &existing[tail..]
            ))
        }
        _ => bail!("the ferry:where markers are damaged ({begins} begin, {ends} end)"),
    }
}

const MAX_INSTRUCTIONS: u64 = 1024 * 1024;

fn plan_one(project: &str, file: PathBuf, block: &str, create: bool) -> Option<HintPlan> {
    let plan = |action, new_text| HintPlan {
        project: project.to_owned(),
        file: file.clone(),
        action,
        new_text,
    };
    let meta = fs::symlink_metadata(&file).ok();
    let Some(meta) = meta else {
        return create.then(|| plan(HintAction::Create, Some(block.to_owned())));
    };
    if !meta.is_file() {
        return Some(plan(HintAction::Refused("not a plain file".into()), None));
    }
    if meta.len() > MAX_INSTRUCTIONS {
        return Some(plan(HintAction::Refused("larger than 1 MiB".into()), None));
    }
    let Ok(existing) = fs::read_to_string(&file) else {
        return Some(plan(HintAction::Refused("not UTF-8 text".into()), None));
    };
    match place_hint(&existing, block) {
        Err(why) => Some(plan(HintAction::Refused(why.to_string()), None)),
        Ok(text) if text == existing => Some(plan(HintAction::Unchanged, None)),
        Ok(text) => {
            let action = if existing.contains(HINT_BEGIN) {
                HintAction::Update
            } else {
                HintAction::Append
            };
            Some(plan(action, Some(text)))
        }
    }
}

/// What `write-hints` would do in every clone this machine has: CLAUDE.md (made when it is
/// missing), and AGENTS.md where one exists.
#[must_use]
pub fn hint_plan(root: &Root, own: &str) -> Vec<HintPlan> {
    let mut plans = Vec::new();
    for entry in root.read().projects {
        let found = from_body(dir_body(root, &entry, own), "manifest", None);
        let Some(code) = found.paths.code.as_deref().map(PathBuf::from) else {
            continue;
        };
        if !code.is_dir() {
            continue;
        }
        let block = hint_block(&found);
        for (name, create) in [("CLAUDE.md", true), ("AGENTS.md", false)] {
            if let Some(plan) = plan_one(&entry.project_id, code.join(name), &block, create) {
                plans.push(plan);
            }
        }
    }
    plans
}

// ---------------------------------------------------------------------------------------
// Moving what used to be loose, without deleting it

/// Copy every file under `old` that is not under `new` yet, into `new`. Nothing is
/// overwritten and nothing is deleted. Returns how many files came across.
///
/// # Errors
/// A file cannot be copied.
pub fn copy_forward(old: &Path, new: &Path) -> Result<usize> {
    if !old.is_dir() || old == new {
        return Ok(0);
    }
    let mut copied = 0;
    for item in fs::read_dir(old)?.flatten() {
        let from = item.path();
        let to = new.join(item.file_name());
        let kind = item.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            copied += copy_forward(&from, &to)?;
        } else if !to.exists() {
            fs::create_dir_all(new)?;
            fs::copy(&from, &to).with_context(|| format!("copy {}", from.display()))?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// The release records folder of the fleet in the root `start` sits in, when there is one.
#[must_use]
pub fn releases_dir_near(start: &Path) -> Option<PathBuf> {
    let dir = dir_near(start)?.join(RELEASES);
    dir.is_dir().then_some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::Level;

    struct Fleet {
        _dir: tempfile::TempDir,
        root: Root,
        josh: AgentIdentity,
        beastly: AgentIdentity,
    }

    fn fleet() -> Fleet {
        crate::ferry::isolate_root_search_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        crate::licensing::use_machine_state_dir_per_thread(dir.path().join("state"));
        let root = Root::create_with_layout(&dir.path().join("ferry"), 2).unwrap();
        let josh = AgentIdentity::from_seed("josh", [7u8; 32]);
        let beastly = AgentIdentity::from_seed("beastly-ferry", [11u8; 32]);
        init(&root, &josh).unwrap();
        enrol(&root, &beastly).unwrap();
        admit(&root, &josh, "beastly-ferry", "beastly").unwrap();
        let channel = root.comms_home("demo");
        fs::create_dir_all(&channel).unwrap();
        let repo = root.project_dir("demo").join("repo");
        fs::create_dir_all(&repo).unwrap();
        root.adopt("demo", &channel, Some(&repo)).unwrap();
        Fleet {
            _dir: dir,
            root,
            josh,
            beastly,
        }
    }

    fn entry_path(f: &Fleet, machine: &str) -> PathBuf {
        f.root
            .fleet_dir()
            .join(DIRECTORY)
            .join("demo")
            .join(format!("{machine}.json"))
    }

    fn demo(f: &Fleet) -> Entry {
        f.root
            .read()
            .projects
            .into_iter()
            .find(|e| e.project_id == "demo")
            .unwrap()
    }

    fn facts() -> Facts {
        Facts {
            version: "0.6.1".into(),
            engines: vec!["claude".into()],
            projects: vec!["demo".into()],
        }
    }

    #[test]
    fn the_folder_is_made_once_and_keeps_this_machines_part_out_of_sync() {
        let f = fleet();
        let dir = f.root.fleet_dir();
        for sub in [
            DIRECTORY, MACHINES, NOTICES, ORDERS, RELEASES, LIBRARIAN, "local",
        ] {
            assert!(dir.join(sub).is_dir(), "{sub}");
        }
        assert!(
            fs::read_to_string(dir.join(".stignore"))
                .unwrap()
                .lines()
                .any(|l| l == "local")
        );
        assert!(dir.join(LIBRARIAN).join("README.md").is_file());
        assert!(exists(&f.root));
        // Again changes nothing and does not fail.
        let again = init(&f.root, &f.josh).unwrap();
        assert!(again.made.is_empty(), "{:?}", again.made);
        assert_eq!(Trust::load(&dir).master(), Some("josh"));
        // It is not a project: the manifest does not file it.
        assert!(
            f.root
                .read()
                .projects
                .iter()
                .all(|e| e.project_id != PROJECT)
        );
    }

    #[test]
    fn signed_directory_and_machine_entries_round_trip() {
        let f = fleet();
        let out = publish_directory(&f.root, "beastly", &f.beastly).unwrap();
        assert_eq!(out.written, vec!["demo/beastly".to_owned()]);
        assert_eq!(
            publish_directory(&f.root, "beastly", &f.beastly)
                .unwrap()
                .unchanged,
            1
        );
        assert!(publish_machine(&f.root, "beastly", &f.beastly, &facts()).unwrap());
        assert!(!publish_machine(&f.root, "beastly", &f.beastly, &facts()).unwrap());

        let directory = read_directory(&f.root);
        assert!(
            directory.findings.rejected.is_empty(),
            "{:?}",
            directory.findings.rejected
        );
        let entry = &directory.projects["demo"]["beastly"];
        assert_eq!(entry.signed_by, "beastly-ferry");
        assert!(!entry.overridden);
        let repo = f.root.project_dir("demo").join("repo");
        assert_eq!(entry.body.paths.code.as_deref(), Some(text(&repo).as_str()));
        assert_eq!(
            entry.body.paths.data.as_deref(),
            Some(text(&f.root.project_data("demo")).as_str())
        );
        assert_eq!(entry.body.layout, 2);

        let (machines, findings) = read_machines(&f.root);
        assert!(findings.rejected.is_empty(), "{:?}", findings.rejected);
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].body.version, "0.6.1");
        assert_eq!(machines[0].body.projects, vec!["demo".to_owned()]);
        assert_eq!(machines[0].signed_by, "beastly-ferry");
    }

    #[test]
    fn a_forged_entry_is_ignored_and_reported() {
        let f = fleet();
        publish_directory(&f.root, "beastly", &f.beastly).unwrap();
        publish_machine(&f.root, "beastly", &f.beastly, &facts()).unwrap();
        let path = entry_path(&f, "beastly");
        let good: Signed = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let ignored = |f: &Fleet, why: &str| {
            let directory = read_directory(&f.root);
            assert!(directory.projects.is_empty(), "{why}: it counted");
            assert_eq!(directory.findings.rejected.len(), 1, "{why}");
            directory.findings.rejected[0].why.clone()
        };

        // Edited after signing.
        let mut doc = good.clone();
        doc.body["paths"]["code"] = json!("C:\\evil");
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(ignored(&f, "edited").contains("signature"));

        // Signed by someone the roster has never heard of.
        let mallory = AgentIdentity::from_seed("mallory", [99u8; 32]);
        let body = good.body.clone();
        let doc = sign("entry", "demo/beastly", body.clone(), &mallory);
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(ignored(&f, "stranger").contains("roster"));

        // On the roster, never admitted.
        let nobody = AgentIdentity::from_seed("nobody", [98u8; 32]);
        enrol(&f.root, &nobody).unwrap();
        let doc = sign("entry", "demo/beastly", body.clone(), &nobody);
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(ignored(&f, "unadmitted").contains("not admitted"));

        // Admitted, but for another machine than the one the file claims.
        let doc = sign("entry", "demo/tiny", body.clone(), &f.beastly);
        let tiny = path.with_file_name("tiny.json");
        fs::remove_file(&path).unwrap();
        fs::write(&tiny, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(ignored(&f, "wrong machine").contains("not admitted to speak for"));
        fs::remove_file(&tiny).unwrap();

        // Unsigned.
        let mut doc = good.clone();
        doc.signature = None;
        doc.signed_by = None;
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(ignored(&f, "unsigned").contains("unsigned"));

        // Rightly signed, but a path no machine may be told to use.
        let mut bad = good.body.clone();
        bad["paths"]["code"] = json!("C:\\ferry\\..\\..\\Windows");
        let doc = sign("entry", "demo/beastly", bad, &f.beastly);
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(ignored(&f, "unsafe").contains("unsafe path"));

        // A machine record gets the same treatment.
        let machine = f.root.fleet_dir().join(MACHINES).join("beastly.json");
        let mut doc: Signed = serde_json::from_slice(&fs::read(&machine).unwrap()).unwrap();
        doc.body["version"] = json!("9.9.9");
        fs::write(&machine, serde_json::to_vec(&doc).unwrap()).unwrap();
        let (rows, findings) = read_machines(&f.root);
        assert!(rows.is_empty());
        assert_eq!(findings.rejected.len(), 1);

        // And doctor sees all of it.
        assert_eq!(audit(&f.root, "beastly").rejected.len(), 2);
    }

    #[test]
    fn a_worker_cannot_write_the_fleet_folder() {
        let f = fleet();
        publish_directory(&f.root, "beastly", &f.beastly).unwrap();
        crate::access::set_level(&route(&f.root), &f.josh, "beastly-ferry", Level::Worker).unwrap();

        let refused = |why: anyhow::Error| why.to_string();
        assert!(
            refused(publish_directory(&f.root, "beastly", &f.beastly).unwrap_err())
                .contains("Worker")
        );
        assert!(
            refused(publish_machine(&f.root, "beastly", &f.beastly, &facts()).unwrap_err())
                .contains("Worker")
        );
        let mut notice = NoticeBody::new("layout-change", "high", "moved", "moved");
        notice.machine = Some("beastly".into());
        assert!(refused(post_notice(&f.root, &f.beastly, notice).unwrap_err()).contains("Worker"));

        // A file it signs by hand anyway does not count, and the file it signed before it
        // was a Worker stops counting too.
        let body = serde_json::to_value(dir_body(&f.root, &demo(&f), "beastly")).unwrap();
        let doc = sign("entry", "demo/beastly", body, &f.beastly);
        fs::write(entry_path(&f, "beastly"), serde_json::to_vec(&doc).unwrap()).unwrap();
        let directory = read_directory(&f.root);
        assert!(directory.projects.is_empty());
        assert!(directory.findings.rejected[0].why.contains("Worker"));
    }

    #[test]
    fn where_follows_a_migrate_and_knows_other_machines() {
        let f = fleet();
        publish_directory(&f.root, "beastly", &f.beastly).unwrap();
        let before = resolve(&f.root, "demo", None, "beastly").unwrap();
        assert_eq!(before.source, "manifest");
        let old = text(&f.root.project_dir("demo").join("repo"));
        assert_eq!(before.paths.code.as_deref(), Some(old.as_str()));

        // A migrate moves the clone; the manifest says so before anything is published.
        let moved = f.root.path.join("moved").join("demo");
        f.root
            .update_entry("demo", |entry| entry.repo = Some(moved.clone()))
            .unwrap();
        let after = resolve(&f.root, "demo", None, "beastly").unwrap();
        assert_eq!(after.paths.code.as_deref(), Some(text(&moved).as_str()));
        assert_eq!(
            after.paths.data, before.paths.data,
            "data does not move with the clone"
        );

        // Published again, the directory says the same.
        publish_directory(&f.root, "beastly", &f.beastly).unwrap();
        let listed = read_directory(&f.root).projects["demo"]["beastly"]
            .body
            .paths
            .code
            .clone();
        assert_eq!(listed.as_deref(), Some(text(&moved).as_str()));

        // Another machine is known by its own entry, or the master's override of it.
        let tiny = AgentIdentity::from_seed("tiny-ferry", [12u8; 32]);
        enrol(&f.root, &tiny).unwrap();
        admit(&f.root, &f.josh, "tiny-ferry", "tiny").unwrap();
        let mut body = dir_body(&f.root, &demo(&f), "tiny");
        body.root = "/srv/ferry".into();
        body.paths.code = Some("/srv/ferry/projects/demo/repo".into());
        let doc = sign(
            "entry",
            "demo/tiny",
            serde_json::to_value(&body).unwrap(),
            &tiny,
        );
        atomic(&entry_path(&f, "tiny"), &doc).unwrap();
        let there = resolve(&f.root, "demo", Some("tiny"), "beastly").unwrap();
        assert_eq!(there.source, "directory");
        assert_eq!(
            there.paths.code.as_deref(),
            Some("/srv/ferry/projects/demo/repo")
        );
        assert_eq!(there.signed_by.as_deref(), Some("tiny-ferry"));

        body.paths.code = Some("/mnt/big/demo".into());
        override_directory(&f.root, &f.josh, "tiny", body.clone()).unwrap();
        let there = resolve(&f.root, "demo", Some("tiny"), "beastly").unwrap();
        assert_eq!(there.source, "override");
        assert_eq!(there.paths.code.as_deref(), Some("/mnt/big/demo"));
        assert!(override_directory(&f.root, &f.beastly, "tiny", body).is_err());

        let error = resolve(&f.root, "demo", Some("nowhere"), "beastly")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("beastly") && error.contains("tiny"),
            "{error}"
        );
        assert!(resolve(&f.root, "ghost", None, "beastly").is_err());
        let all = resolve_all(&f.root, "beastly");
        assert_eq!(all.len(), 2);
        assert_eq!(Kind::parse("handins").unwrap(), Kind::Handins);
        assert!(Kind::parse("secrets").is_err());
        assert!(after.path(Kind::Env).is_some());
    }

    #[test]
    fn a_machine_posts_its_own_layout_change_and_nothing_else() {
        let f = fleet();
        let mut moved = NoticeBody::new("layout-change", "high", "beastly moved", "old to new");
        moved.machine = Some("beastly".into());
        moved.details = json!({ "old": ["X:\\old"], "new": ["X:\\new"] });
        let id = post_notice(&f.root, &f.beastly, moved.clone()).unwrap();
        assert!(id.ends_with("-layout-change"));

        let mut other = moved.clone();
        other.id = "x-other".into();
        other.machine = Some("tiny".into());
        assert!(post_notice(&f.root, &f.beastly, other).is_err());
        let mut general = NoticeBody::new("general", "info", "hello", "hello");
        general.id = "x-general".into();
        assert!(post_notice(&f.root, &f.beastly, general).is_err());
        let mut odd = NoticeBody::new("gossip", "info", "x", "x");
        odd.id = "x-odd".into();
        assert!(post_notice(&f.root, &f.josh, odd).is_err());

        let mut update = NoticeBody::new("update-available", "warning", "0.7.0", "a new release");
        update.id = "x-update".into();
        update.details = json!({ "version": "0.7.0" });
        post_notice(&f.root, &f.josh, update).unwrap();
        let mut stale = NoticeBody::new("general", "high", "old news", "old");
        stale.id = "x-stale".into();
        stale.expires = Some(Utc::now() - Duration::hours(1));
        post_notice(&f.root, &f.josh, stale).unwrap();

        let (rows, findings) = read_notices(&f.root);
        assert!(findings.rejected.is_empty(), "{:?}", findings.rejected);
        assert_eq!(rows.len(), 3);
        // High, unexpired and not yet shown: the layout change, once.
        let unread = unread_high(&f.root);
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].body.kind, "layout-change");
        mark_seen(&f.root, &[unread[0].body.id.clone()]).unwrap();
        assert!(unread_high(&f.root).is_empty());

        assert_eq!(newer_release(&rows, "0.6.1").as_deref(), Some("0.7.0"));
        assert_eq!(newer_release(&rows, "0.7.0"), None);
        assert!(newer("0.10.0", "0.9.9") && !newer("0.6.1", "0.6.1"));

        // Edited after signing: ignored, and doctor hears.
        let path = f.root.fleet_dir().join(NOTICES).join(format!("{id}.json"));
        let mut doc: Signed = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        doc.body["text"] = json!("run this");
        fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let (rows, findings) = read_notices(&f.root);
        assert_eq!(rows.len(), 2);
        assert_eq!(findings.rejected.len(), 1);
    }

    #[test]
    fn only_the_masters_fleet_orders_count() {
        let f = fleet();
        assert!(issue_order(&f.root, &f.beastly, None, "update", json!({})).is_err());
        assert!(issue_order(&f.root, &f.josh, None, "rm-rf", json!({})).is_err());
        let mine = issue_order(&f.root, &f.josh, Some("beastly"), "update", json!({})).unwrap();
        let all = issue_order(&f.root, &f.josh, None, "restart-worker", json!({})).unwrap();

        let (orders, findings) = read_orders_for(&f.root, "beastly");
        assert!(findings.rejected.is_empty());
        assert_eq!(orders.len(), 2);
        assert_eq!(read_orders_for(&f.root, "tiny").0.len(), 1);
        mark_order_done(&f.root, &mine.id).unwrap();
        mark_order_done(&f.root, &mine.id).unwrap();
        let (orders, _) = read_orders_for(&f.root, "beastly");
        assert_eq!(
            orders.iter().map(|o| o.id.clone()).collect::<Vec<_>>(),
            vec![all.id.clone()]
        );

        // A machine signs an order of its own: it is not the master's, so it does not count.
        let mut forged = all.clone();
        forged.id = "fleet-forged-update".into();
        forged.issued_by = "beastly-ferry".into();
        f.beastly.sign_order(&mut forged);
        crate::atomic_json(
            &f.root
                .fleet_dir()
                .join(ORDERS)
                .join("fleet-forged-update.json"),
            &forged,
        )
        .unwrap();
        // The master's order, edited.
        let mut edited = all.clone();
        edited.id = "fleet-edited-update".into();
        edited.payload =
            json!({ "fleet": true, "action": "update", "args": { "url": "http://x" } });
        crate::atomic_json(
            &f.root
                .fleet_dir()
                .join(ORDERS)
                .join("fleet-edited-update.json"),
            &edited,
        )
        .unwrap();
        let (orders, findings) = read_orders_for(&f.root, "beastly");
        assert_eq!(orders.len(), 1);
        assert_eq!(findings.rejected.len(), 2);
    }

    #[test]
    fn paths_from_the_directory_are_data_and_the_bad_ones_are_refused() {
        for good in [
            "C:\\ferry\\projects\\demo",
            "/home/josh/ferry",
            "D:/x/y",
            "X:\\ferry\\a b\\c.d",
        ] {
            assert!(safe_path(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "relative\\path",
            "C:\\a\\..\\b",
            "/a/../b",
            "\\\\server\\share\\x",
            "//server/share",
            "\\\\?\\C:\\x",
            "\\\\.\\PhysicalDrive0",
            "C:x",
            "C:\\a\\b:stream",
            "C:\\a\\nul",
            "C:\\a\\COM1.txt",
            "C:\\a\\x*y",
            "/a/b\u{7}",
            "/a/b\nrm -rf /",
        ] {
            assert!(safe_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_hint_writer_touches_only_its_own_markers() {
        let f = fleet();
        let block = hint_block(&from_body(
            dir_body(&f.root, &demo(&f), "beastly"),
            "manifest",
            None,
        ));
        assert!(block.starts_with(HINT_BEGIN) && block.trim_end().ends_with(HINT_END));
        assert!(block.contains("ferry where demo") && block.contains("Never hardcode"));
        assert_eq!(
            block,
            hint_block(&from_body(
                dir_body(&f.root, &demo(&f), "beastly"),
                "manifest",
                None
            ))
        );

        // Markers present: only what is between them changes.
        let existing =
            format!("# Title\n\nKeep this.\n\n{HINT_BEGIN}\nold\n{HINT_END}\n\nAfter.\n");
        let out = place_hint(&existing, &block).unwrap();
        assert!(out.starts_with("# Title\n\nKeep this.\n\n"));
        assert!(out.ends_with("\n\nAfter.\n"));
        assert!(!out.contains("\nold\n"));
        assert_eq!(
            place_hint(&out, &block).unwrap(),
            out,
            "a second run changes nothing"
        );

        // No markers: appended, and everything before it is as it was.
        let plain = "# Notes\nline\n";
        let out = place_hint(plain, &block).unwrap();
        assert!(out.starts_with(plain));
        assert_eq!(out.matches(HINT_BEGIN).count(), 1);
        assert!(place_hint("", &block).unwrap().starts_with(HINT_BEGIN));

        // Windows line endings stay Windows line endings.
        let crlf = format!("# T\r\n\r\n{HINT_BEGIN}\r\nold\r\n{HINT_END}\r\nafter\r\n");
        let out = place_hint(&crlf, &block).unwrap();
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "a bare newline crept in"
        );
        assert!(out.ends_with(&format!("{HINT_END}\r\nafter\r\n")));

        // Damaged markers are refused and nothing is written.
        for broken in [
            format!("a\n{HINT_BEGIN}\nno end\n"),
            format!("a\n{HINT_END}\nno begin\n"),
            format!("{HINT_END}\n{HINT_BEGIN}\n"),
            format!("{HINT_BEGIN}\n{HINT_END}\n{HINT_BEGIN}\n{HINT_END}\n"),
        ] {
            assert!(place_hint(&broken, &block).is_err(), "{broken:?}");
        }
    }

    #[test]
    fn write_hints_plans_first_and_writes_only_what_it_says() {
        let f = fleet();
        let clone = f.root.project_dir("demo").join("repo");
        fs::write(clone.join("AGENTS.md"), "# Agents\nkeep\n").unwrap();
        let plans = hint_plan(&f.root, "beastly");
        let by = |name: &str| plans.iter().find(|p| p.file.ends_with(name)).unwrap();
        assert_eq!(by("CLAUDE.md").action, HintAction::Create);
        assert_eq!(by("AGENTS.md").action, HintAction::Append);
        // Planning wrote nothing.
        assert!(!clone.join("CLAUDE.md").exists());
        assert_eq!(
            fs::read_to_string(clone.join("AGENTS.md")).unwrap(),
            "# Agents\nkeep\n"
        );

        for plan in &plans {
            assert!(plan.apply().unwrap());
        }
        let agents = fs::read_to_string(clone.join("AGENTS.md")).unwrap();
        assert!(agents.starts_with("# Agents\nkeep\n") && agents.contains(HINT_BEGIN));
        assert!(
            fs::read_to_string(clone.join("CLAUDE.md"))
                .unwrap()
                .contains("ferry where demo")
        );
        // Never a commit: there is no repository here to commit to, and nothing asked for one.
        assert!(!clone.join(".git").exists());
        assert!(
            hint_plan(&f.root, "beastly")
                .iter()
                .all(|p| p.action == HintAction::Unchanged)
        );

        // A file with damaged markers is left exactly as it was.
        let damaged = format!("{HINT_BEGIN}\nhalf\n");
        fs::write(clone.join("CLAUDE.md"), &damaged).unwrap();
        let plans = hint_plan(&f.root, "beastly");
        assert!(matches!(
            by_name(&plans, "CLAUDE.md").action,
            HintAction::Refused(_)
        ));
        assert!(!by_name(&plans, "CLAUDE.md").apply().unwrap());
        assert_eq!(
            fs::read_to_string(clone.join("CLAUDE.md")).unwrap(),
            damaged
        );
    }

    fn by_name<'a>(plans: &'a [HintPlan], name: &str) -> &'a HintPlan {
        plans.iter().find(|p| p.file.ends_with(name)).unwrap()
    }

    #[test]
    fn copying_forward_never_overwrites_or_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old");
        let new = dir.path().join("new");
        fs::create_dir_all(old.join("sub")).unwrap();
        fs::create_dir_all(&new).unwrap();
        fs::write(old.join("a.pub"), "old-a").unwrap();
        fs::write(old.join("b.pub"), "old-b").unwrap();
        fs::write(old.join("sub").join("c.pub"), "old-c").unwrap();
        fs::write(new.join("a.pub"), "new-a").unwrap();
        assert_eq!(copy_forward(&old, &new).unwrap(), 2);
        assert_eq!(fs::read_to_string(new.join("a.pub")).unwrap(), "new-a");
        assert_eq!(fs::read_to_string(new.join("b.pub")).unwrap(), "old-b");
        assert_eq!(
            fs::read_to_string(new.join("sub").join("c.pub")).unwrap(),
            "old-c"
        );
        assert!(old.join("a.pub").is_file() && old.join("b.pub").is_file());
        assert_eq!(copy_forward(&old, &new).unwrap(), 0);
        assert_eq!(copy_forward(&dir.path().join("none"), &new).unwrap(), 0);
    }
}

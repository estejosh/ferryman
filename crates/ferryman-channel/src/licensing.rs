//! Counting a fleet against the free allowance, and saying so.
//!
//! # What this does not do
//!
//! It does not stop anything. Exceeding the allowance prints a notice and reports a
//! count; work continues. A licensing check that breaks someone's fleet at 3am costs
//! more goodwill than the licence revenue it protects, and the [`LICENSE`] says
//! plainly that continuing to run is not the same as being permitted to.
//!
//! It also does not read anything of yours. The only values that leave a machine are
//! the registered email addresses and three integers - see `PRIVACY.md`, which is part
//! of the licence terms rather than marketing copy. Nothing in this module can reach a
//! task, a message, a prompt, a result, or a file name, and that is enforced by the
//! type of [`CheckIn`]: there is no field for it to go in.
//!
//! # Why the records live in the synced folder
//!
//! A fleet has no server, so no machine can be asked how big the fleet is. Each machine
//! publishes one record about itself, every machine can read all of them, and the count
//! is the same answer everywhere. One writer per path, like everything else here, so a
//! second machine joining cannot conflict with the first.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{ProjectRoute, is_safe_component};

/// Seats in the free allowance.
pub const FREE_SEATS: usize = 2;
/// Computers in the free allowance.
pub const FREE_COMPUTERS: usize = 2;
/// Mobile devices in the free allowance.
pub const FREE_MOBILE_DEVICES: usize = 2;

/// What kind of thing a device is, in the licence's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    /// Runs the Software or an Agent. Counts against the Computer limit.
    Computer,
    /// Reviews and approves only, and runs neither. Counts against the Mobile limit.
    Mobile,
}

impl DeviceKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_lowercase().as_str() {
            "computer" | "pc" => Ok(Self::Computer),
            "mobile" | "phone" | "tablet" => Ok(Self::Mobile),
            other => bail!("device kind must be 'computer' or 'mobile', not '{other}'"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Computer => "computer",
            Self::Mobile => "mobile",
        }
    }
}

/// One machine's own description of itself.
///
/// Deliberately thin. It carries what the licence is counted in and nothing else - no
/// hostname, no hardware id, no network address - because every extra field here is a
/// field that ends up in a check-in and has to be justified to a sceptical reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Random, generated once on this machine. Not derived from the hardware.
    pub id: String,
    pub kind: DeviceKind,
    /// The human responsible for this machine. Distinct addresses are how Seats are
    /// counted: the licence counts people, and this is the only signal of a person.
    pub operator_email: String,
    pub registered_at: DateTime<Utc>,
}

/// The fleet, counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetCount {
    pub seats: usize,
    pub computers: usize,
    pub mobile_devices: usize,
}

impl FleetCount {
    /// Whether the deployment is beyond the free allowance.
    ///
    /// Each limit is checked on its own. They do not pool: three Computers and no phone
    /// is over, even though it is fewer devices than two of each.
    #[must_use]
    pub fn over_limit(&self) -> bool {
        self.seats > FREE_SEATS
            || self.computers > FREE_COMPUTERS
            || self.mobile_devices > FREE_MOBILE_DEVICES
    }

    /// Which limits are exceeded, in words a person can act on.
    #[must_use]
    pub fn exceeded(&self) -> Vec<String> {
        let mut over = Vec::new();
        if self.seats > FREE_SEATS {
            over.push(format!(
                "{} seats (free tier allows {FREE_SEATS})",
                self.seats
            ));
        }
        if self.computers > FREE_COMPUTERS {
            over.push(format!(
                "{} computers (free tier allows {FREE_COMPUTERS})",
                self.computers
            ));
        }
        if self.mobile_devices > FREE_MOBILE_DEVICES {
            over.push(format!(
                "{} phones/tablets (free tier allows {FREE_MOBILE_DEVICES})",
                self.mobile_devices
            ));
        }
        over
    }
}

fn devices_dir(route: &ProjectRoute) -> PathBuf {
    route.communications.join("devices")
}

/// Where this machine remembers its own id. Local, never synced.
fn device_id_path(attachment: &Path) -> PathBuf {
    attachment.join("device.json")
}

/// Where this *machine's* identity lives, outside any one project.
///
/// The id used to be stored per attachment, so enabling three projects on one computer
/// minted three device ids and the fleet counted one machine as three. That number
/// decides free-tier eligibility, and no output could tell "two computers" from "this
/// computer, enabled twice".
///
/// `None` when no per-user directory can be determined, in which case the caller falls
/// back to the per-attachment file - a machine with no home directory should still work,
/// and over-counting is a far better failure than refusing to run.
fn machine_id_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("FERRYMAN_STATE_DIR") {
        return Some(PathBuf::from(explicit).join("device.json"));
    }
    if cfg!(windows) {
        return std::env::var("LOCALAPPDATA")
            .ok()
            .map(|local| PathBuf::from(local).join("Ferryman").join("device.json"));
    }
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return Some(PathBuf::from(state).join("ferryman").join("device.json"));
    }
    std::env::var("HOME").ok().map(|home| {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("ferryman")
            .join("device.json")
    })
}

fn read_local_device(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let existing: LocalDevice = serde_json::from_str(&text).ok()?;
    is_safe_component(&existing.id).then_some(existing.id)
}

fn write_local_device(path: &Path, id: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(&LocalDevice { id: id.to_string() })?,
    )
    .with_context(|| format!("write {}", path.display()))
}

#[derive(Serialize, Deserialize)]
struct LocalDevice {
    id: String,
}

/// This machine's id, generated once and kept.
///
/// Random rather than derived from the hardware: a hardware fingerprint would identify
/// the machine to the Licensor, which is more than counting requires and more than
/// `PRIVACY.md` promises.
pub fn device_id(attachment: &Path) -> Result<String> {
    device_id_with(attachment, machine_id_path())
}

/// The same, with the machine-wide location given rather than discovered. Exists so the
/// tests can exercise the real logic without reading or writing the identity of the
/// machine running them.
#[cfg(test)]
fn device_id_with_machine_file(attachment: &Path, machine: &Path) -> Result<String> {
    device_id_with(attachment, Some(machine.to_path_buf()))
}

fn device_id_with(attachment: &Path, machine: Option<PathBuf>) -> Result<String> {
    let per_project = device_id_path(attachment);

    // The machine-wide file is the answer whenever it exists.
    if let Some(path) = &machine
        && let Some(id) = read_local_device(path)
    {
        // Keep the per-project copy in step so an older `ferry` on the same machine
        // reports the same identity rather than minting a second one.
        if read_local_device(&per_project).as_deref() != Some(id.as_str()) {
            let _ = write_local_device(&per_project, &id);
        }
        return Ok(id);
    }

    // Adopt an id this project already had rather than renaming the machine. A machine
    // that has been counted for weeks should not become a new computer because it was
    // upgraded.
    if let Some(id) = read_local_device(&per_project) {
        if let Some(path) = &machine {
            let _ = write_local_device(path, &id);
        }
        return Ok(id);
    }

    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    let id = hex::encode(bytes);
    if let Some(path) = &machine {
        let _ = write_local_device(path, &id);
    }
    write_local_device(&per_project, &id)?;
    Ok(id)
}

/// Publish this machine's record so the rest of the fleet can count it.
pub fn register_device(route: &ProjectRoute, record: &DeviceRecord) -> Result<PathBuf> {
    if !is_safe_component(&record.id) {
        bail!("device id must be a path-safe identifier")
    }
    if !looks_like_email(&record.operator_email) {
        bail!(
            "'{}' does not look like an email address",
            record.operator_email
        )
    }
    let path = devices_dir(route).join(format!("{}.json", record.id));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
    fs::rename(&temporary, &path)?;
    Ok(path)
}

/// Every machine that has registered on this channel.
pub fn read_devices(route: &ProjectRoute) -> Result<Vec<DeviceRecord>> {
    let dir = devices_dir(route);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut devices = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // One unreadable record must not hide the rest, or a corrupt file would quietly
        // shrink the count and report a fleet as compliant when it is not.
        if let Ok(text) = fs::read_to_string(&path)
            && let Ok(record) = serde_json::from_str::<DeviceRecord>(&text)
        {
            devices.push(record);
        }
    }
    devices.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(devices)
}

/// Count the fleet from its published records.
#[must_use]
pub fn count(devices: &[DeviceRecord]) -> FleetCount {
    let seats: BTreeSet<&str> = devices
        .iter()
        .map(|d| d.operator_email.trim())
        .filter(|e| !e.is_empty())
        .collect();
    FleetCount {
        seats: seats.len(),
        computers: devices
            .iter()
            .filter(|d| d.kind == DeviceKind::Computer)
            .count(),
        mobile_devices: devices
            .iter()
            .filter(|d| d.kind == DeviceKind::Mobile)
            .count(),
    }
}

/// The addresses registered on this channel, in a stable order.
#[must_use]
pub fn registered_emails(devices: &[DeviceRecord]) -> Vec<String> {
    devices
        .iter()
        .map(|d| d.operator_email.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// A stable id for the deployment as a whole.
///
/// The smallest device id, which every machine computes identically from the same
/// files - the same trick as the oldest claim winning a task. That avoids a
/// "who allocates the id" race with no server to allocate it, and costs nothing,
/// because the id only needs to correlate two check-ins from one fleet.
#[must_use]
pub fn deployment_id(devices: &[DeviceRecord]) -> Option<String> {
    devices.iter().map(|d| d.id.clone()).min()
}

/// Exactly what leaves a machine. There is no other field, by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckIn {
    pub deployment_id: String,
    pub emails: Vec<String>,
    pub seats: usize,
    pub computers: usize,
    pub mobile_devices: usize,
    pub over_limit: bool,
    pub version: String,
    pub sent_at: DateTime<Utc>,
}

/// Build the check-in for this channel's current state.
pub fn check_in(route: &ProjectRoute, version: &str) -> Result<Option<CheckIn>> {
    let devices = read_devices(route)?;
    let Some(deployment_id) = deployment_id(&devices) else {
        // Nothing registered yet: there is nothing to report and nobody to report it
        // about. Sending an empty ping would be data collection with no purpose.
        return Ok(None);
    };
    let counted = count(&devices);
    Ok(Some(CheckIn {
        deployment_id,
        emails: registered_emails(&devices),
        seats: counted.seats,
        computers: counted.computers,
        mobile_devices: counted.mobile_devices,
        over_limit: counted.over_limit(),
        version: version.to_string(),
        sent_at: Utc::now(),
    }))
}

/// The notice shown when a deployment is beyond the free allowance.
///
/// Written to be read by someone who is probably not cheating - most over-limit fleets
/// are an honest third laptop - so it says what is over, what it costs, and does not
/// threaten.
#[must_use]
pub fn over_limit_notice(counted: &FleetCount) -> String {
    let mut notice = String::from(
        "\n  ---------------------------------------------------------------\n  \
         This deployment is beyond Ferryman's free tier.\n",
    );
    for line in counted.exceeded() {
        notice.push_str(&format!("    - {line}\n"));
    }
    notice.push_str(
        "  Agents are always unlimited and never count.\n  \
         Ferryman keeps working. To license it, see COMMERCIAL.md.\n  \
         ---------------------------------------------------------------\n",
    );
    notice
}

/// Cheap sanity check, not validation.
///
/// Deliberately loose: rejecting a real address because it fails somebody's regex is a
/// worse failure than accepting a fake one, since the address exists to make contact
/// possible rather than to prove identity.
fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains(char::is_whitespace)
}

#[cfg(test)]
mod device_identity {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ferryman-devid-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The bug: the id lived per attachment, so enabling three projects on one computer
    /// minted three ids and the fleet counted one machine as three.
    #[test]
    fn two_projects_on_one_machine_share_one_id() {
        let root = temp("shared");
        let state = root.join("state");
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();

        // Point the machine-wide location at a temp dir rather than the real one, so the
        // test neither reads nor writes the developer's own device identity.
        let first = device_id_with_machine_file(&a, &state.join("device.json")).unwrap();
        let second = device_id_with_machine_file(&b, &state.join("device.json")).unwrap();
        assert_eq!(first, second, "one machine must count as one computer");
    }

    /// The upgrade path. A machine already registered under a per-project id must keep
    /// it: becoming a "new computer" on upgrade would inflate the count it just fixed.
    #[test]
    fn an_existing_project_id_is_adopted_not_replaced() {
        let root = temp("adopt");
        let state = root.join("state");
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        write_local_device(&device_id_path(&project), "0123456789abcdef").unwrap();

        let id = device_id_with_machine_file(&project, &state.join("device.json")).unwrap();
        assert_eq!(
            id, "0123456789abcdef",
            "an upgrade must not rename the machine"
        );
        assert_eq!(
            read_local_device(&state.join("device.json")).as_deref(),
            Some("0123456789abcdef"),
            "and the id should be promoted so other projects agree"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, kind: DeviceKind, email: &str) -> DeviceRecord {
        DeviceRecord {
            id: id.into(),
            kind,
            operator_email: email.into(),
            registered_at: Utc::now(),
        }
    }

    #[test]
    fn agents_never_count_only_machines_and_people_do() {
        // The headline promise: twenty agents on two computers is still free.
        let fleet = vec![
            device("a1", DeviceKind::Computer, "jo@example.com"),
            device("a2", DeviceKind::Computer, "jo@example.com"),
        ];
        let counted = count(&fleet);
        assert_eq!(counted.seats, 1);
        assert_eq!(counted.computers, 2);
        assert!(!counted.over_limit());
    }

    #[test]
    fn the_limits_do_not_pool() {
        // Three computers and no phone is over, even though it is fewer than the four
        // devices the old wording allowed. This is the whole point of the rewrite.
        let fleet = vec![
            device("a1", DeviceKind::Computer, "jo@example.com"),
            device("a2", DeviceKind::Computer, "jo@example.com"),
            device("a3", DeviceKind::Computer, "jo@example.com"),
        ];
        let counted = count(&fleet);
        assert!(counted.over_limit());
        assert_eq!(counted.exceeded().len(), 1);
        assert!(counted.exceeded()[0].contains("computers"));
    }

    #[test]
    fn two_of_each_is_within_the_free_tier() {
        let fleet = vec![
            device("a1", DeviceKind::Computer, "jo@example.com"),
            device("a2", DeviceKind::Computer, "sam@example.com"),
            device("b1", DeviceKind::Mobile, "jo@example.com"),
            device("b2", DeviceKind::Mobile, "sam@example.com"),
        ];
        let counted = count(&fleet);
        assert_eq!(counted.seats, 2);
        assert_eq!(counted.computers, 2);
        assert_eq!(counted.mobile_devices, 2);
        assert!(!counted.over_limit());
    }

    #[test]
    fn seats_are_people_not_machines() {
        // Four machines, three humans: over on seats, not on computers.
        let fleet = vec![
            device("a1", DeviceKind::Computer, "jo@example.com"),
            device("a2", DeviceKind::Computer, "sam@example.com"),
            device("b1", DeviceKind::Mobile, "pat@example.com"),
        ];
        let counted = count(&fleet);
        assert_eq!(counted.seats, 3);
        assert!(counted.over_limit());
        assert!(counted.exceeded()[0].contains("seats"));
    }

    #[test]
    fn every_machine_computes_the_same_deployment_id() {
        // No server allocates it, so the rule has to be one every reader agrees on.
        let one = vec![
            device("zz", DeviceKind::Computer, "jo@example.com"),
            device("aa", DeviceKind::Computer, "jo@example.com"),
        ];
        let other = vec![
            device("aa", DeviceKind::Computer, "jo@example.com"),
            device("zz", DeviceKind::Computer, "jo@example.com"),
        ];
        assert_eq!(deployment_id(&one), deployment_id(&other));
        assert_eq!(deployment_id(&one).unwrap(), "aa");
    }

    #[test]
    fn a_check_in_carries_counts_and_nothing_else() {
        // If this test needs updating because a field was added, that field also needs
        // adding to PRIVACY.md before it ships.
        let fleet = vec![device("a1", DeviceKind::Computer, "jo@example.com")];
        let counted = count(&fleet);
        let payload = CheckIn {
            deployment_id: deployment_id(&fleet).unwrap(),
            emails: registered_emails(&fleet),
            seats: counted.seats,
            computers: counted.computers,
            mobile_devices: counted.mobile_devices,
            over_limit: counted.over_limit(),
            version: "0.3.0".into(),
            sent_at: Utc::now(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "computers",
                "deployment_id",
                "emails",
                "mobile_devices",
                "over_limit",
                "seats",
                "sent_at",
                "version"
            ]
        );
    }

    #[test]
    fn an_empty_fleet_reports_nothing() {
        assert_eq!(deployment_id(&[]), None);
    }

    #[test]
    fn addresses_are_checked_loosely_but_not_ignored() {
        assert!(looks_like_email("jo@example.com"));
        assert!(looks_like_email("jo+tag@sub.example.co.uk"));
        assert!(!looks_like_email("jo"));
        assert!(!looks_like_email("jo@localhost"));
        assert!(!looks_like_email("jo @example.com"));
        assert!(!looks_like_email(""));
    }

    #[test]
    fn the_notice_says_what_is_over_and_that_agents_are_free() {
        let counted = FleetCount {
            seats: 1,
            computers: 5,
            mobile_devices: 0,
        };
        let notice = over_limit_notice(&counted);
        assert!(notice.contains("5 computers"));
        assert!(notice.contains("Agents are always unlimited"));
        assert!(notice.contains("keeps working"));
    }
}

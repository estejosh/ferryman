//! The `[iroh]` section of the ferry root's `ferry.toml`: machine-local, never synced.
//!
//! ```toml
//! [iroh]
//! enabled = true
//! # Which relay carries traffic when two machines cannot see each other. Three shapes:
//! #
//! #  (a) our own relay (pinned): `relay_url`, optionally more in `relays`, in order. The
//! #      first is the primary. Public relays are NOT used unless you opt in below.
//! #  (b) iroh's default public relays: `public_relays = true`, and nothing else about
//! #      relays. It needs no server, no certificate and no token, but it is a choice you
//! #      make: saying nothing about relays never means public relays.
//! #  (c) direct only: `direct_only = true`, or saying nothing at all. No relay; machines
//! #      must reach each other.
//! # public_relays = true
//! relay_url = "https://162.35.10.46"
//! # relays = ["https://relay-two.example"]      # more of our own, after relay_url
//! # fallback_public_relays = true               # with a custom relay: n0's defaults too
//! # The relay's self-signed certificate, pinned: this exact certificate and no other.
//! relay_cert_sha256 = "49:32:08:E4:...:C0:D1"
//! # Optional, and entirely optional: a relay that wants no token needs no file. The
//! # file holds the relay's access token and nothing else. It is read, never printed,
//! # and never belongs in a channel or in this file.
//! # relay_token_file = "<machine state>/iroh-relay.token"
//! # Optional; the relay's QUIC address-discovery port (UDP). Default 443.
//! # relay_quic_port = 443
//! # Minutes without a good sync (or with an error) before the lane raises a warning.
//! # alert_after_minutes = 15
//! # Peers that come and go (a laptop) and must never raise an alert: agent names, or the
//! # start of an endpoint id. Every other peer is expected to be on all the time.
//! # intermittent_peers = ["laptop-agent"]
//! ```
//!
//! # Why the token is a path and not a value
//!
//! `ferry.toml` is read by people and copied into backups, and `rootconfig` already
//! refuses a credential in it for that reason. The token is a secret only in the sense
//! that it keeps strangers from using our relay's bandwidth, but it is still a secret, so
//! it lives in a file of its own, owner-only, in the machine state directory. It is never
//! required: with no file the lane connects without one, which is all the public relays
//! and any relay that is not gated ask for.
//!
//! # Why a pin and not a CA
//!
//! The relay has no domain on purpose, so no public CA will sign for it, and trusting a
//! self-signed certificate by turning verification off would trust every certificate. A
//! SHA-256 of the one certificate it serves is the narrowest thing that can be trusted.
//! The pin covers our own relays only. A public relay (when the fallback is on) is checked
//! against the public CAs as always. Without a pin, every relay must present a certificate
//! a public CA signed.
//!
//! A section that is missing, or `enabled = false`, is the lane off: exactly what every
//! machine did before it existed. A section that cannot be used is the lane off too, with
//! a note that says why, rather than a worker that will not start.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// The token file's name in the machine state directory, when `relay_token_file` is unset.
pub const DEFAULT_TOKEN_FILE: &str = "iroh-relay.token";

/// The relay's QUIC address-discovery port when none is configured. Ours serves it on
/// UDP 443, beside HTTPS on TCP 443, so one firewall rule covers both.
pub const DEFAULT_QUIC_PORT: u16 = 443;

/// Minutes a peer may go without a good sync, or the relay without a connection, before
/// the lane says so, when `alert_after_minutes` is unset.
pub const DEFAULT_ALERT_MINUTES: u64 = 15;

/// Which relays the lane may use, decided from the configuration alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPlan {
    /// iroh's own public relays. No pin, no token: the default for a new user.
    Public,
    /// Our relays, in order, the first being the primary. `fallback_public` adds the public
    /// relays, used only while none of ours can be reached.
    Custom {
        urls: Vec<String>,
        fallback_public: bool,
    },
    /// No relay at all.
    Direct,
}

/// A relay the master put in the fleet's signed relay list (see `FLEET_SETUP`/`IROH_LANE`),
/// as the lane needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetRelayEntry {
    pub url: String,
    /// The certificate the master vouched for. `None`: a public CA must vouch for it.
    pub pin: Option<[u8; 32]>,
}

fn same_relay(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// What `[iroh]` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohConfig {
    pub enabled: bool,
    /// The primary relay of ours (the first of [`Self::relays`]). `None`: none of ours.
    pub relay_url: Option<String>,
    /// Every relay of ours, in order, the primary first.
    pub relays: Vec<String>,
    /// With a relay of ours: also use iroh's public relays when ours cannot be reached.
    pub fallback_public_relays: bool,
    /// No relay at all, public or ours.
    pub direct_only: bool,
    /// With no relay of ours named and none in the fleet's list: use iroh's public relays.
    /// Never implied; without it, no relay named means no relay.
    pub public_relays: bool,
    pub relay_cert_sha256: Option<[u8; 32]>,
    pub relay_token_file: Option<PathBuf>,
    pub relay_quic_port: u16,
    /// Minutes before a silent peer or an unreachable relay is raised as a warning.
    pub alert_after_minutes: u64,
    /// Days a honoured tombstone is kept before compaction drops it and records how far
    /// back the channel's deletions reach.
    pub tombstone_days: u32,
    /// Peers that come and go (a laptop): agent names, or the start of an endpoint id. The
    /// lane never raises an alert about them. Every other peer is expected to be on all the
    /// time, as a machine with a worker service is.
    pub intermittent_peers: Vec<String>,
    /// Relays from the fleet's master-signed list, in its order, after [`Self::relays`].
    /// Not read from `ferry.toml`: [`Self::with_fleet_relays`] fills it.
    pub fleet_relays: Vec<FleetRelayEntry>,
    /// What was wrong with the section, if anything.
    pub notes: Vec<String>,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_url: None,
            relays: Vec::new(),
            fallback_public_relays: false,
            direct_only: false,
            public_relays: false,
            relay_cert_sha256: None,
            relay_token_file: None,
            relay_quic_port: DEFAULT_QUIC_PORT,
            alert_after_minutes: DEFAULT_ALERT_MINUTES,
            tombstone_days: ferryman_channel::tombstone::DEFAULT_TOMBSTONE_DAYS,
            intermittent_peers: Vec::new(),
            fleet_relays: Vec::new(),
            notes: Vec::new(),
        }
    }
}

impl IrohConfig {
    /// Add the fleet's relay list after the relays this machine names itself. A relay
    /// already named in `ferry.toml` stays as `ferry.toml` has it (and its pin); the rest
    /// follow in the master's order. With `direct_only` they are ignored.
    #[must_use]
    pub fn with_fleet_relays(mut self, list: Vec<FleetRelayEntry>) -> Self {
        if self.direct_only {
            return self;
        }
        self.fleet_relays = list
            .into_iter()
            .filter(|entry| !self.relays.iter().any(|own| same_relay(own, &entry.url)))
            .collect();
        self
    }

    /// Enabled, with no relay named anywhere and public relays not asked for: the lane runs
    /// relay-less, which is worth saying.
    #[must_use]
    pub fn relayless_for_want_of_a_relay(&self) -> bool {
        self.enabled
            && !self.direct_only
            && !self.public_relays
            && self.relays.is_empty()
            && self.fleet_relays.is_empty()
    }

    /// Whether `url` is one this machine's own `ferry.toml` names (not one that came from
    /// the fleet's list). Only those get the access token.
    #[must_use]
    pub fn is_own_relay(&self, url: &str) -> bool {
        self.relays.iter().any(|own| same_relay(own, url))
    }

    /// Every relay of ours in order of preference: this machine's own, then the fleet's.
    #[must_use]
    pub fn all_relays(&self) -> Vec<String> {
        let mut all = self.relays.clone();
        all.extend(self.fleet_relays.iter().map(|entry| entry.url.clone()));
        all
    }

    /// Read `[iroh]` from `<root>/ferry.toml`. Never fails; problems become notes and
    /// leave the lane off.
    #[must_use]
    pub fn load(root: &Path) -> Self {
        let file = root.join("ferry.toml");
        let Ok(text) = std::fs::read_to_string(&file) else {
            return Self::default();
        };
        Self::parse(
            &text,
            ferryman_channel::licensing::machine_state_dir().as_deref(),
        )
    }

    /// The parsing half of [`Self::load`], with the machine directory given.
    #[must_use]
    pub fn parse(text: &str, machine_dir: Option<&Path>) -> Self {
        let mut config = Self::default();
        let table: toml::Table = match text.parse() {
            Ok(table) => table,
            Err(error) => {
                config
                    .notes
                    .push(format!("ferry.toml is not valid TOML: {error}"));
                return config;
            }
        };
        let Some(section) = table.get("iroh").and_then(toml::Value::as_table) else {
            return config;
        };
        config.enabled = section
            .get("enabled")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        config.direct_only = section
            .get("direct_only")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        config.fallback_public_relays = section
            .get("fallback_public_relays")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        config.public_relays = section
            .get("public_relays")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        match section.get("intermittent_peers") {
            None => {}
            Some(toml::Value::Array(items)) => {
                config.intermittent_peers = items
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_owned)
                    .collect();
            }
            Some(_) => config
                .notes
                .push("[iroh] intermittent_peers is not a list of names".into()),
        }
        // `relay_url` is the primary and `relays` the rest, in order; one list, no repeats.
        let mut relays: Vec<String> = Vec::new();
        if let Some(url) = section.get("relay_url").and_then(toml::Value::as_str) {
            relays.push(url.to_owned());
        }
        match section.get("relays") {
            None => {}
            Some(toml::Value::Array(items)) => {
                for item in items {
                    match item.as_str() {
                        Some(url) if !relays.iter().any(|have| have == url) => {
                            relays.push(url.to_owned());
                        }
                        Some(_) => {}
                        None => config
                            .notes
                            .push("[iroh] relays holds something that is not a URL".into()),
                    }
                }
            }
            Some(_) => config
                .notes
                .push("[iroh] relays is not a list of URLs".into()),
        }
        if let Some(pin) = section
            .get("relay_cert_sha256")
            .and_then(toml::Value::as_str)
        {
            match parse_fingerprint(pin) {
                Ok(pin) => config.relay_cert_sha256 = Some(pin),
                Err(error) => config
                    .notes
                    .push(format!("[iroh] relay_cert_sha256: {error}")),
            }
        }
        config.relay_token_file = section
            .get("relay_token_file")
            .and_then(toml::Value::as_str)
            .map(PathBuf::from)
            .or_else(|| machine_dir.map(|dir| dir.join(DEFAULT_TOKEN_FILE)));
        if let Some(port) = section.get("relay_quic_port") {
            match port.as_integer().and_then(|p| u16::try_from(p).ok()) {
                Some(port) => config.relay_quic_port = port,
                None => config
                    .notes
                    .push("[iroh] relay_quic_port is not a port number".into()),
            }
        }
        if let Some(minutes) = section.get("alert_after_minutes") {
            match minutes
                .as_integer()
                .and_then(|m| u64::try_from(m).ok())
                .filter(|m| *m > 0)
            {
                Some(minutes) => config.alert_after_minutes = minutes,
                None => config
                    .notes
                    .push("[iroh] alert_after_minutes is not a positive number".into()),
            }
        }
        if let Some(days) = section.get("tombstone_days") {
            match days
                .as_integer()
                .and_then(|d| u32::try_from(d).ok())
                .filter(|d| *d > 0)
            {
                Some(days) => config.tombstone_days = days,
                None => config
                    .notes
                    .push("[iroh] tombstone_days is not a positive number".into()),
            }
        }
        for url in &relays {
            if !url.starts_with("https://") {
                config.notes.push(format!(
                    "[iroh] relay '{url}' is not https://; the lane stays off"
                ));
                config.enabled = false;
            }
        }
        if !relays.is_empty()
            && section.contains_key("relay_cert_sha256")
            && config.relay_cert_sha256.is_none()
        {
            // A pin that was meant and could not be read must not fall back to
            // trusting public CAs: the lane stays off until it is fixed.
            config.enabled = false;
        }
        if config.direct_only && !relays.is_empty() {
            config
                .notes
                .push("[iroh] direct_only = true, so the relays listed are not used".into());
            relays.clear();
        }
        config.relay_url = relays.first().cloned();
        config.relays = relays;
        config
    }

    /// Which relays this configuration allows.
    ///
    /// - `direct_only`: none.
    /// - a relay of ours named (in `ferry.toml` or the fleet's list): ours, in order, plus
    ///   the public ones only when `fallback_public_relays` is set.
    /// - nothing named: iroh's public relays only if `public_relays = true`; otherwise no
    ///   relay at all. It fails closed: an empty or unreadable list never turns into a
    ///   public relay carrying the fleet's traffic.
    #[must_use]
    pub fn relay_plan(&self) -> RelayPlan {
        if self.direct_only {
            RelayPlan::Direct
        } else if self.relays.is_empty() && self.fleet_relays.is_empty() {
            if self.public_relays {
                RelayPlan::Public
            } else {
                RelayPlan::Direct
            }
        } else {
            RelayPlan::Custom {
                urls: self.all_relays(),
                fallback_public: self.fallback_public_relays,
            }
        }
    }

    /// One line for `status`: what relays the lane may use.
    #[must_use]
    pub fn describe_relays(&self) -> String {
        match self.relay_plan() {
            RelayPlan::Direct if !self.direct_only && !self.public_relays => {
                "none (no relay is named; `public_relays = true` would use iroh's public relays)"
                    .into()
            }
            RelayPlan::Direct => "none (direct only)".into(),
            RelayPlan::Public => "iroh's public relays (public_relays = true)".into(),
            RelayPlan::Custom {
                urls,
                fallback_public,
            } => format!(
                "{}{}",
                urls.join(", then "),
                if fallback_public {
                    ", then iroh's public relays if none of ours answers"
                } else {
                    ""
                }
            ),
        }
    }

    /// The relay's access token, read from its file. `None` when there is no file: the
    /// token is optional, and a lane with none connects without one.
    ///
    /// # Errors
    /// The file exists and cannot be read, or holds nothing.
    pub fn token(&self) -> Result<Option<String>> {
        let Some(path) = &self.relay_token_file else {
            return Ok(None);
        };
        if !path.is_file() {
            return Ok(None);
        }
        let token = std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?
            .trim()
            .to_owned();
        if token.is_empty() {
            bail!("{} is empty", path.display());
        }
        Ok(Some(token))
    }
}

/// `AB:CD:...` or plain hex, 32 bytes, as `openssl x509 -fingerprint -sha256` prints it.
///
/// # Errors
/// Not 64 hex digits once the colons are gone.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    let plain: String = text
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    let Ok(bytes) = hex::decode(&plain) else {
        bail!("'{text}' is not a hex SHA-256 fingerprint");
    };
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("a SHA-256 fingerprint is 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fleets_relays_follow_our_own_in_the_masters_order() {
        let list = vec![
            FleetRelayEntry {
                url: "https://162.35.10.46/".into(),
                pin: None,
            },
            FleetRelayEntry {
                url: "https://b.example/".into(),
                pin: Some([1; 32]),
            },
        ];
        let only_fleet = IrohConfig {
            enabled: true,
            ..IrohConfig::default()
        }
        .with_fleet_relays(list.clone());
        assert_eq!(
            only_fleet.relay_plan(),
            RelayPlan::Custom {
                urls: vec!["https://162.35.10.46/".into(), "https://b.example/".into()],
                fallback_public: false,
            },
            "no relay of our own named: the fleet's list is the plan, not iroh's public relays"
        );
        // One already in ferry.toml is not repeated, and keeps its place (first).
        let both = IrohConfig {
            enabled: true,
            relays: vec!["https://162.35.10.46".into()],
            ..IrohConfig::default()
        }
        .with_fleet_relays(list.clone());
        assert_eq!(
            both.all_relays(),
            vec!["https://162.35.10.46", "https://b.example/"]
        );
        assert_eq!(both.fleet_relays.len(), 1);
        // No relays at all means none, whatever the fleet lists.
        let direct = IrohConfig {
            enabled: true,
            direct_only: true,
            ..IrohConfig::default()
        }
        .with_fleet_relays(list);
        assert_eq!(direct.relay_plan(), RelayPlan::Direct);
        assert!(direct.fleet_relays.is_empty());
        // An empty list changes nothing, and nothing is not the public relays.
        let nothing = IrohConfig::default().with_fleet_relays(Vec::new());
        assert_eq!(nothing.relay_plan(), RelayPlan::Direct);
        let opted_in = IrohConfig {
            public_relays: true,
            ..IrohConfig::default()
        }
        .with_fleet_relays(Vec::new());
        assert_eq!(opted_in.relay_plan(), RelayPlan::Public);
    }

    const PIN: &str = "49:32:08:E4:6F:B8:E3:9B:FD:F2:8D:B8:0F:8C:33:F9:\
                       9F:2A:57:A0:A1:71:B3:52:4A:9D:11:67:AD:BD:C0:D1";

    #[test]
    fn no_section_is_the_lane_off() {
        let config = IrohConfig::parse("[git]\nremote_template = \"x/{project}\"\n", None);
        assert!(!config.enabled);
        assert!(config.notes.is_empty());
    }

    #[test]
    fn a_full_section_is_read_and_the_token_defaults_to_the_machine_directory() {
        let text = format!(
            "[iroh]\nenabled = true\nrelay_url = \"https://162.35.10.46\"\n\
             relay_cert_sha256 = \"{PIN}\"\n"
        );
        let config = IrohConfig::parse(&text, Some(Path::new("/state")));
        assert!(config.enabled, "{:?}", config.notes);
        assert_eq!(config.relay_url.as_deref(), Some("https://162.35.10.46"));
        assert_eq!(config.relay_cert_sha256.unwrap()[0], 0x49);
        assert_eq!(
            config.relay_token_file,
            Some(Path::new("/state").join(DEFAULT_TOKEN_FILE))
        );
        assert_eq!(config.relay_quic_port, 443);
        assert_eq!(config.alert_after_minutes, DEFAULT_ALERT_MINUTES);
    }

    #[test]
    fn a_pin_that_cannot_be_read_keeps_the_lane_off() {
        let text = "[iroh]\nenabled = true\nrelay_url = \"https://162.35.10.46\"\n\
                    relay_cert_sha256 = \"49:32\"\n";
        let config = IrohConfig::parse(text, None);
        assert!(!config.enabled);
        assert_eq!(config.notes.len(), 1);
    }

    #[test]
    fn a_plain_http_relay_keeps_the_lane_off() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nrelay_url = \"http://162.35.10.46\"\n",
            None,
        );
        assert!(!config.enabled);
    }

    #[test]
    fn the_token_is_read_from_its_file_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DEFAULT_TOKEN_FILE), "s3cret\n").unwrap();
        let config = IrohConfig::parse("[iroh]\nenabled = true\n", Some(dir.path()));
        assert_eq!(config.token().unwrap().as_deref(), Some("s3cret"));
    }

    #[test]
    fn no_token_file_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let config = IrohConfig::parse("[iroh]\nenabled = true\n", Some(dir.path()));
        assert_eq!(config.token().unwrap(), None);
        let none = IrohConfig::parse("[iroh]\nenabled = true\n", None);
        assert_eq!(none.token().unwrap(), None);
    }

    #[test]
    fn no_relay_named_is_no_relay_and_public_relays_need_an_explicit_opt_in() {
        let config = IrohConfig::parse("[iroh]\nenabled = true\n", None);
        assert!(config.enabled);
        assert_eq!(config.relay_plan(), RelayPlan::Direct);
        assert!(config.relayless_for_want_of_a_relay());
        assert!(config.describe_relays().contains("public_relays = true"));
        assert_eq!(config.relay_url, None);
        let opted = IrohConfig::parse("[iroh]\nenabled = true\npublic_relays = true\n", None);
        assert_eq!(opted.relay_plan(), RelayPlan::Public);
        assert!(!opted.relayless_for_want_of_a_relay());
    }

    #[test]
    fn only_relays_named_in_ferry_toml_are_ours_for_the_token() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nrelay_url = \"https://a.example\"\n",
            None,
        )
        .with_fleet_relays(vec![FleetRelayEntry {
            url: "https://listed.example/".into(),
            pin: None,
        }]);
        assert!(config.is_own_relay("https://a.example"));
        assert!(config.is_own_relay("https://a.example/"));
        assert!(!config.is_own_relay("https://listed.example/"));
    }

    #[test]
    fn intermittent_peers_are_read() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nintermittent_peers = [\"laptop\"]\n",
            None,
        );
        assert_eq!(config.intermittent_peers, vec!["laptop".to_owned()]);
    }

    #[test]
    fn a_pinned_relay_of_ours_is_custom_only_by_default() {
        let text = format!(
            "[iroh]\nenabled = true\nrelay_url = \"https://162.35.10.46\"\n\
             relay_cert_sha256 = \"{PIN}\"\n"
        );
        let config = IrohConfig::parse(&text, None);
        assert_eq!(
            config.relay_plan(),
            RelayPlan::Custom {
                urls: vec!["https://162.35.10.46".into()],
                fallback_public: false
            }
        );
    }

    #[test]
    fn public_relays_are_a_fallback_only_when_asked_for() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nrelay_url = \"https://a.example\"\n\
             fallback_public_relays = true\n",
            None,
        );
        assert_eq!(
            config.relay_plan(),
            RelayPlan::Custom {
                urls: vec!["https://a.example".into()],
                fallback_public: true
            }
        );
        assert!(config.describe_relays().contains("public relays"));
    }

    #[test]
    fn the_relay_list_is_ordered_primary_first_without_repeats() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nrelay_url = \"https://a.example\"\n\
             relays = [\"https://b.example\", \"https://a.example\", \"https://c.example\"]\n",
            None,
        );
        assert_eq!(
            config.relays,
            [
                "https://a.example",
                "https://b.example",
                "https://c.example"
            ]
        );
        assert_eq!(config.relay_url.as_deref(), Some("https://a.example"));
    }

    #[test]
    fn a_list_alone_makes_its_first_entry_the_primary() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nrelays = [\"https://b.example\", \"https://c.example\"]\n",
            None,
        );
        assert_eq!(config.relay_url.as_deref(), Some("https://b.example"));
        assert_eq!(config.relays.len(), 2);
    }

    #[test]
    fn one_plain_http_relay_in_the_list_keeps_the_lane_off() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\nrelays = [\"https://b.example\", \"http://c.example\"]\n",
            None,
        );
        assert!(!config.enabled);
    }

    #[test]
    fn direct_only_is_no_relay_and_ignores_a_list() {
        let config = IrohConfig::parse(
            "[iroh]\nenabled = true\ndirect_only = true\nrelay_url = \"https://a.example\"\n",
            None,
        );
        assert!(config.enabled);
        assert_eq!(config.relay_plan(), RelayPlan::Direct);
        assert_eq!(config.relay_url, None);
        assert_eq!(config.notes.len(), 1);
    }

    #[test]
    fn the_alert_threshold_is_configurable_and_must_be_positive() {
        let config = IrohConfig::parse("[iroh]\nenabled = true\nalert_after_minutes = 5\n", None);
        assert_eq!(config.alert_after_minutes, 5);
        let bad = IrohConfig::parse("[iroh]\nenabled = true\nalert_after_minutes = 0\n", None);
        assert_eq!(bad.alert_after_minutes, DEFAULT_ALERT_MINUTES);
        assert_eq!(bad.notes.len(), 1);
    }
}

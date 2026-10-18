//! The `[iroh]` section of the ferry root's `ferry.toml`: machine-local, never synced.
//!
//! ```toml
//! [iroh]
//! enabled = true
//! relay_url = "https://162.35.10.46"
//! # The relay's self-signed certificate, pinned: this exact certificate and no other.
//! relay_cert_sha256 = "49:32:08:E4:...:C0:D1"
//! # Optional; this is the default. The file holds the relay's access token and nothing
//! # else. It is read, never printed, and never belongs in a channel or in this file.
//! # relay_token_file = "<machine state>/iroh-relay.token"
//! # Optional; the relay's QUIC address-discovery port (UDP). Default 443.
//! # relay_quic_port = 443
//! ```
//!
//! # Why the token is a path and not a value
//!
//! `ferry.toml` is read by people and copied into backups, and `rootconfig` already
//! refuses a credential in it for that reason. The token is a secret only in the sense
//! that it keeps strangers from using our relay's bandwidth, but it is still a secret, so
//! it lives in a file of its own, owner-only, in the machine state directory.
//!
//! # Why a pin and not a CA
//!
//! The relay has no domain on purpose, so no public CA will sign for it, and trusting a
//! self-signed certificate by turning verification off would trust every certificate. A
//! SHA-256 of the one certificate it serves is the narrowest thing that can be trusted.
//! Without a pin, the relay must present a certificate a public CA signed.
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

/// What `[iroh]` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IrohConfig {
    pub enabled: bool,
    /// `None`: no relay, direct connections only.
    pub relay_url: Option<String>,
    pub relay_cert_sha256: Option<[u8; 32]>,
    pub relay_token_file: Option<PathBuf>,
    pub relay_quic_port: u16,
    /// What was wrong with the section, if anything.
    pub notes: Vec<String>,
}

impl IrohConfig {
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
        let mut config = Self {
            relay_quic_port: DEFAULT_QUIC_PORT,
            ..Self::default()
        };
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
        config.relay_url = section
            .get("relay_url")
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
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
        if let Some(url) = &config.relay_url {
            if !url.starts_with("https://") {
                config.notes.push(format!(
                    "[iroh] relay_url '{url}' is not https://; the lane stays off"
                ));
                config.enabled = false;
            } else if section.contains_key("relay_cert_sha256")
                && config.relay_cert_sha256.is_none()
            {
                // A pin that was meant and could not be read must not fall back to
                // trusting public CAs: the lane stays off until it is fixed.
                config.enabled = false;
            }
        }
        config
    }

    /// The relay's access token, read from its file. `None` when there is no file.
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
}

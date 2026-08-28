//! `deadman.toml` — every knob of ferry-deadman is driven by this optional
//! per-repo file; CLI flags merely override individual values.
//!
//! Parsing rules:
//! - missing keys fall back to sane defaults (see [`Config::default`]),
//! - **unknown keys produce a warning, never an error** (forward compat),
//! - malformed TOML or wrong value types are [`Error::BadInput`].

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

/// Canonical location of the config inside a repo.
pub fn config_path(repo: &Path) -> PathBuf {
    repo.join("deadman.toml")
}

/// A parsed config plus diagnostics about keys we did not recognise.
#[derive(Debug)]
pub struct Loaded {
    pub path: PathBuf,
    pub config: Config,
    /// True when an actual file was read (vs all-defaults fallback).
    pub present: bool,
    /// Dotted paths of keys present in the file but unknown to this version.
    pub unknown_keys: Vec<String>,
}

/// Load and parse `<repo>/deadman.toml` (or an explicit override path).
///
/// Unknown keys are collected as warnings; the caller prints them.
pub fn load(explicit: Option<&Path>, repo: &Path) -> Result<Loaded> {
    let path: PathBuf = match explicit {
        Some(p) => p.to_path_buf(),
        None => config_path(repo),
    };
    if !path.exists() {
        return Ok(Loaded {
            path,
            config: Config::default(),
            present: false,
            unknown_keys: Vec::new(),
        });
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::BadInput(format!("cannot read {}: {e}", path.display())))?;
    let (config, unknown_keys) =
        parse(&text).map_err(|e| Error::BadInput(format!("{} is invalid: {e}", path.display())))?;
    Ok(Loaded {
        path,
        config,
        present: true,
        unknown_keys,
    })
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Which beacon enforces the timelock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconSetting {
    /// Deterministic offline fake chain — for drills and tests ONLY.
    Simulate,
    /// Base URL of any drand HTTP API serving the quicknet chain.
    Url(String),
}

impl Default for BeaconSetting {
    fn default() -> Self {
        BeaconSetting::Url(String::new())
    }
}

impl<'de> Deserialize<'de> for BeaconSetting {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("drand") {
            return Ok(BeaconSetting::Url(String::new()));
        }
        if t.eq_ignore_ascii_case("simulate") || t.eq_ignore_ascii_case("sim") {
            return Ok(BeaconSetting::Simulate);
        }
        if t.starts_with("http://") || t.starts_with("https://") {
            return Ok(BeaconSetting::Url(t.to_string()));
        }
        Err(serde::de::Error::custom(format!(
            "beacon must be \"simulate\" or an http(s) drand endpoint URL, got {t:?}"
        )))
    }
}

/// How a successor identifies. `key` may be absent: the name alone then forms
/// a (weaker, name-derived) commitment in headers and audit output.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct SuccessorCfg {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub key: String,
}

/// A replacement for the built-in bundle→tar.gz archiver. Whatever it
/// produces must end up as ONE file at `$FERRY_DEADMAN_OUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveCmd {
    /// Executed via `sh -c`, with cwd set to the repo.
    Shell(String),
    /// Executed directly (argv[0] + args), with cwd set to the repo.
    Argv(Vec<String>),
}

impl ArchiveCmd {
    /// Normalised argv used for execution and persistence in state.
    pub fn argv(&self) -> Vec<String> {
        match self {
            ArchiveCmd::Shell(s) => vec!["sh".into(), "-c".into(), s.clone()],
            ArchiveCmd::Argv(v) => v.clone(),
        }
    }

    pub fn display(&self) -> String {
        self.argv().join(" ")
    }
}

impl<'de> Deserialize<'de> for ArchiveCmd {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::One(s) => ArchiveCmd::Shell(s),
            Raw::Many(v) => {
                if v.is_empty() {
                    return Err(serde::de::Error::custom(
                        "archive.command array must not be empty",
                    ));
                }
                ArchiveCmd::Argv(v)
            }
        })
    }
}

/// `[archive]` section: replacement archiver settings.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct ArchiveSection {
    #[serde(default)]
    pub command: Option<ArchiveCmd>,
}

/// Which events count as a heartbeat beyond an explicit `heartbeat` call.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeartbeatSource {
    /// The explicit `ferry-deadman heartbeat` command (always honoured).
    Manual,
    /// ANY successful ferry-deadman invocation against the repo re-arms.
    AnyCli,
}

/// Commands run around lifecycle events. Failures are warnings, never fatal.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct NotifyCfg {
    #[serde(default)]
    pub arm: Option<String>,
    #[serde(default)]
    pub rearm: Option<String>,
    #[serde(default)]
    pub trigger: Option<String>,
}

/// The whole schema. Every field optional; see `TEMPLATE`.
///
/// NOTE: deliberately NOT `deny_unknown_fields` — unknown keys must be
/// warnings (collected by [`collect_unknown`]), never errors.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default, rename = "beacon")]
    pub beacon: Option<BeaconSetting>,
    #[serde(default)]
    pub include_secrets: bool,
    /// Extra globs archived beside the git bundle (docs, secrets, whatever).
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub successors: Vec<SuccessorCfg>,
    #[serde(default)]
    pub archive: ArchiveSection,
    #[serde(default)]
    pub heartbeat: HeartbeatSection,
    #[serde(default)]
    pub notify: NotifyCfg,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct HeartbeatSection {
    #[serde(default)]
    pub sources: Vec<HeartbeatSource>,
}

/// Parse config text, returning the config plus dotted paths of unknown keys.
pub fn parse(text: &str) -> std::result::Result<(Config, Vec<String>), String> {
    let table: toml::Table = text
        .parse()
        .map_err(|e| format!("TOML syntax error: {e}"))?;
    let mut unknown = Vec::new();
    collect_unknown(&table, &[], &mut unknown);
    let config: Config = toml::from_str(text).map_err(|e| format!("value error: {e}"))?;
    Ok((config, unknown))
}

fn collect_unknown(table: &toml::Table, prefix: &[&str], out: &mut Vec<String>) {
    // Known child schemas: table name -> allowed sub-keys.
    const NESTED: &[(&str, &[&str])] = &[
        ("archive", &["command"]),
        ("heartbeat", &["sources"]),
        ("notify", &["arm", "rearm", "trigger"]),
    ];
    const TOP_KNOWN: &[&str] = &[
        "window",
        "beacon",
        "include_secrets",
        "include",
        "successors",
        "archive",
        "heartbeat",
        "notify",
    ];

    for (k, v) in table {
        let dotted = if prefix.is_empty() {
            (*k).to_string()
        } else {
            format!("{}.{}", prefix.join("."), k)
        };
        let known = match prefix.split_last() {
            None => TOP_KNOWN.contains(&k.as_str()),
            Some((&parent, _)) => match parent {
                // [[successors]] element tables are handled here; the
                // array itself is recursed below.
                "successors" => matches!(k.as_str(), "name" | "key"),
                _ => NESTED
                    .iter()
                    .filter(|(p, _)| *p == parent)
                    .any(|(_, subs)| subs.contains(&k.as_str())),
            },
        };
        if !known {
            // Warn once at the top of an unknown subtree.
            out.push(dotted);
            continue;
        }
        match (k.as_str(), v) {
            ("successors", toml::Value::Array(items)) => {
                for item in items {
                    if let toml::Value::Table(t) = item {
                        collect_unknown(t, &["successors"], out);
                    }
                }
            }
            (_, toml::Value::Table(inner))
                if !prefix.is_empty() || NESTED.iter().any(|(p, _)| *p == k.as_str()) =>
            {
                let mut next = prefix.to_vec();
                next.push(k);
                collect_unknown(inner, &next, out);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Template written by `init`
// ---------------------------------------------------------------------------

/// Fully commented starter config: nothing is active until the user edits it.
pub const TEMPLATE: &str = r#"# deadman.toml — ferry-deadman succession settings
# Every setting is optional; delete what you don't need. CLI flags override
# anything written here. Docs: https://github.com/estejosh/ferryman

## Silence window before the archive becomes decryptable. Accepts
## s/m/h/d/w units, compound values like "1d12h".
#window = "30d"

## Beacon enforcing the timelock:
##   "simulate"          deterministic OFFLINE chain — drills/tests ONLY,
##                       provides NO real protection
##   "https://api.drand.sh"   any drand HTTP endpoint serving quicknet
#beacon = "https://api.drand.sh"

## Beyond the git bundle you may archive working-tree files. Globs are
## gitignore-style, matched against repo-relative paths.
#include = [
#  "docs/**",
#  ".env*",
#  "*.key",
#]

## Additionally sweep conventional secret locations (.env*, *.key, *.pem,
## secrets/**, .secrets/**).
#include_secrets = false

## One entry per successor; EACH gets its own independently sealed copy.
## `key` is optional: a file path or inline hex used as an identity
## commitment in the artifact header (the timelock itself is keyed to the
## beacon, not to this value).
#[[successors]]
#name = "ada"
#key = "~/keys/ada.pub"

#[[successors]]
#name = "grace"
#key = "~/keys/grace.pub"   # inline hex works here too

## Replace the built-in `git bundle --all` + tar.gz archiver with any
## command producing ONE file at $FERRY_DEADMAN_OUT (cwd = repo root).
## Either a shell line…
#archive.command = "./make-release-bundle.sh"
## …or an argv vector.
#archive.command = ["tar", "czf", "$FERRY_DEADMAN_OUT", ".git", "docs"]

## Which events count as a heartbeat:
##   "manual"   explicit `ferry-deadman heartbeat` (always honoured)
##   "any-cli"  any ferry-deadman invocation re-arms the switch
#heartbeat.sources = ["manual"]

## Arbitrary commands run on lifecycle events (via sh -c, cwd = repo).
## Exposes $FERRY_DEADMAN_EVENT, $FERRY_DEADMAN_REPO, $FERRY_DEADMAN_ROUND,
## $FERRY_DEADMAN_UNLOCK_AT. Hook failures are warnings, never fatal.
#[notify]
#arm = "say 'deadman armed'"
#rearm = "curl -fsS -m 5 https://example.test/alive"
#trigger = "mail -s 'project handed over' ada@example.test < NOTICE"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_file_absent_or_empty() {
        let (c, u) = parse("").unwrap();
        assert!(u.is_empty());
        assert_eq!(c, Config::default());
    }

    #[test]
    fn parses_every_documented_key() {
        let text = r#"
window = "14d"
beacon = "simulate"
include_secrets = true
include = ["docs/**", "*.key"]
archive.command = "./bundle.sh"
heartbeat.sources = ["manual", "any-cli"]
[notify]
arm = "echo armed"
rearm = "echo rearmed"
trigger = "echo triggered"
[[successors]]
name = "ada"
key = "ada.pub"
[[successors]]
name = "grace"
"#;
        let (c, unknown) = parse(text).unwrap();
        assert!(unknown.is_empty(), "{unknown:?}");
        assert_eq!(c.window.as_deref(), Some("14d"));
        assert_eq!(c.beacon, Some(BeaconSetting::Simulate));
        assert!(c.include_secrets);
        assert_eq!(c.include.len(), 2);
        assert_eq!(
            c.archive.command,
            Some(ArchiveCmd::Shell("./bundle.sh".into()))
        );
        assert_eq!(
            c.heartbeat.sources,
            vec![HeartbeatSource::Manual, HeartbeatSource::AnyCli]
        );
        assert_eq!(c.notify.arm.as_deref(), Some("echo armed"));
        assert_eq!(c.successors.len(), 2);
        assert_eq!(c.successors[1].key, "");
    }

    #[test]
    fn beacon_url_and_aliases() {
        for (raw, want) in [
            (
                "https://api.drand.sh",
                BeaconSetting::Url("https://api.drand.sh".into()),
            ),
            ("drand", BeaconSetting::Url(String::new())),
            ("SIM", BeaconSetting::Simulate),
        ] {
            let text = format!("beacon = {raw:?}");
            let (c, _) = parse(&text).unwrap();
            assert_eq!(c.beacon, Some(want));
        }
        let err = parse("beacon = \"ftp://nope\"").unwrap_err();
        assert!(err.contains("simulate"), "{err}");
    }

    #[test]
    fn archive_command_accepts_argv_form() {
        let (c, _) = parse("archive.command = [\"tar\", \"czf\", \"out\"]").unwrap();
        assert_eq!(
            c.archive.command,
            Some(ArchiveCmd::Argv(vec![
                "tar".into(),
                "czf".into(),
                "out".into()
            ]))
        );
        assert!(parse("archive.command = []").is_err());
    }

    #[test]
    fn unknown_keys_warn_but_do_not_error() {
        let text = r#"
windo = "30d"
totally_new = 42
[notif]
arm = "x"
[[successors]]
name = "a"
nick = "b"
"#;
        let (c, unknown) = parse(text).unwrap();
        assert_eq!(c.window, None);
        // Unknown subtrees warn once at their root; collection order is
        // alphabetical because TOML tables iterate sorted.
        let mut got = unknown.clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                "notif".to_string(),
                "successors.nick".to_string(),
                "totally_new".to_string(),
                "windo".to_string(),
            ]
        );
        assert_eq!(unknown.len(), 4);
    }

    #[test]
    fn malformed_toml_is_a_clean_parse_error() {
        assert!(parse("window = ").is_err());
        assert!(parse("[[").is_err());
        assert!(parse("window = 12").is_err()); // wrong type
    }

    #[test]
    fn template_parses_as_all_defaults() {
        let (c, unknown) = parse(TEMPLATE).unwrap();
        assert_eq!(c, Config::default());
        assert!(unknown.is_empty());
    }

    #[test]
    fn heartbeat_sources_reject_garbage() {
        assert!(parse("heartbeat.sources = [\"telepathy\"]").is_err());
    }
}

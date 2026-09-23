//! Pre-flight checks for one project: is this machine actually ready to run a
//! task?
//!
//! # Why this exists
//!
//! Between `ferry enable` and the first task there was nothing that verified the
//! setup end to end. A missing engine binary, an unparseable config or a key
//! that never made it onto the roster surfaced only when a worker claimed a task
//! and failed mid-flight - the slowest, most confusing possible feedback, and
//! the reason a novice concludes "Ferryman is broken" when the fix is one line
//! in `agent.toml`.
//!
//! Every check here states its remedy, not merely its symptom: the whole point
//! is that the CLI knows the answer and should not make the operator discover
//! it. The checks are read-only; nothing here claims a task, touches Syncthing
//! configuration, or prints anything from `credentials.json` beyond whether it
//! exists.
//!
//! Nothing in here prints either - it returns data, and the caller decides how a
//! person or a program reads it.

use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::agent::AgentConfig;

/// One readiness check, and what to do about it when it fails.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable machine-readable name, e.g. `"engine_on_path"`.
    pub name: &'static str,
    /// Whether this check passed.
    pub ok: bool,
    /// What was found, or the remedy when it was not.
    pub detail: String,
    /// Whether a failure here means the machine cannot run work. Informational
    /// checks (Syncthing, credentials) can fail and the machine still works -
    /// locally, at least - so they must not be allowed to fail the report.
    pub required: bool,
}

/// The full readiness picture for one project.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub project: String,
    pub checks: Vec<Check>,
    /// Computed, not stored, so it cannot disagree with `checks`: whether every
    /// required check passed. Informational checks do not count - a machine
    /// without Syncthing can still run tasks against its own channel. Part of
    /// the JSON so a caller never re-derives it and gets a different answer.
    pub ready: bool,
}

/// Resolve a command the way a shell would, close enough for a warning.
///
/// A bare name is searched along `paths`; a name carrying a separator is taken
/// as a path relative to the current directory. On Windows a bare name without
/// an extension also tries the platform executable suffix, because `command =
/// "claude"` means `claude.exe` there. On Unix the bit that makes a file
/// executable is checked too - a non-executable match is not a match, which is
/// exactly the surprise a novice cannot diagnose on their own.
///
/// Returns where it was found, or `None` when it is not there. Never an error:
/// "cannot even read your PATH" is reported as not-found by the caller, which
/// is what it means for practical purposes.
pub fn find_in_paths<I>(command: &str, paths: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    let suffix = std::env::consts::EXE_SUFFIX;
    let candidates: Vec<String> = if suffix.is_empty() || Path::new(command).extension().is_some() {
        vec![command.to_string()]
    } else {
        vec![command.to_string(), format!("{command}{suffix}")]
    };
    if command.contains('/') || command.contains('\\') {
        return candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| is_executable(path));
    }
    paths
        .into_iter()
        .flat_map(|dir| {
            candidates
                .iter()
                .map(move |name| dir.join(name))
                .collect::<Vec<_>>()
        })
        .find(|path| is_executable(path))
}

/// [`find_in_paths`] against the process's own `PATH`.
#[must_use]
pub fn find_on_path(command: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    find_in_paths(command, std::env::split_paths(&paths))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

fn check(name: &'static str, ok: bool, required: bool, detail: String) -> Check {
    Check {
        name,
        ok,
        detail,
        required,
    }
}

/// Run every check against the project containing `start`.
///
/// Deliberately infallible: a doctor that refuses to run is no use at all. Each
/// failing prerequisite marks the checks that depend on it as skipped rather
/// than inventing failures for them.
pub fn examine(start: &Path) -> Report {
    let mut checks = Vec::new();

    let route = match ferryman_channel::route_for(start) {
        Ok(route) => route,
        Err(error) => {
            checks.push(check(
                "channel",
                false,
                true,
                format!(
                    "no Ferryman channel found above {} - run 'ferry enable' \
                     in the project directory first ({error})",
                    start.display()
                ),
            ));
            return Report {
                project: String::new(),
                ready: false,
                checks,
            };
        }
    };
    checks.push(check(
        "channel",
        true,
        true,
        route.communications.display().to_string(),
    ));

    let config = match AgentConfig::load(&route.attachment) {
        Ok(config) => config,
        Err(error) => {
            checks.push(check(
                "agent_config",
                false,
                true,
                format!(
                    "{error:#} - 'ferry enable' again; it is idempotent and will not \
                         overwrite a config you edited"
                ),
            ));
            // Everything left needs the config; say so instead of guessing.
            for (name, why) in [
                ("engine_on_path", "the agent config is unreadable"),
                ("signing_key", "the agent name is unknown"),
                ("roster", "the agent name is unknown"),
                ("credentials_file", "not checked"),
                ("syncthing", "not checked"),
            ] {
                checks.push(Check {
                    name,
                    ok: false,
                    detail: format!("skipped: {why}"),
                    required: false,
                });
            }
            return Report {
                project: route.project_id,
                ready: false,
                checks,
            };
        }
    };
    checks.push(check(
        "agent_config",
        true,
        true,
        format!(
            "runs '{}' with review = '{}'",
            config.command,
            config.review.as_str()
        ),
    ));

    // The single most common first-task failure: the engine is not installed,
    // or is named differently on this machine (on WSL, `claude` on PATH is
    // often the Windows install, which a Linux worker cannot use).
    //
    // # Why a sandboxed agent gets a different answer
    //
    // This check resolves `command` on the HOST's PATH. For a bare runner that is the
    // right question, because the host is where the engine will run. For a container
    // runner it is the wrong question entirely: the engine has to exist inside the
    // IMAGE, and the host PATH says nothing about that.
    //
    // Answering it anyway is worse than not checking. A sandboxed worker whose image
    // lacks the engine printed `ok engine_on_path` while every single task failed to
    // start - the operator's first diagnostic confidently confirming the thing that was
    // broken. `doctor` is the first command a new operator runs, and a check that can be
    // confidently wrong costs more than a check that admits what it cannot see.
    //
    // So under a container runner this reports the runtime instead, which is the part
    // this machine genuinely can answer, and says plainly that the engine is the image's
    // business.
    if config.runner.is_sandboxed() {
        let runtime = config.runner.runtime();
        let image = config.runner.image().unwrap_or("");
        if find_on_path(runtime).is_some() {
            checks.push(check(
                "engine_on_path",
                true,
                true,
                format!(
                    "'{}' runs inside {runtime} ({image}), so the engine has to be in that \
                     image - this machine's PATH cannot tell you whether it is. \
                     '{runtime}' itself resolves here.",
                    config.command
                ),
            ));
        } else {
            checks.push(check(
                "engine_on_path",
                false,
                true,
                format!(
                    "'{runtime}' is NOT on this machine's PATH, and '{}' is configured to \
                     run inside {runtime} ({image}) - every task would fail to start. \
                     Install {runtime}, or clear 'sandbox' in {}",
                    config.command,
                    AgentConfig::path(&route.attachment).display()
                ),
            ));
        }
    } else if find_on_path(&config.command).is_some() {
        checks.push(check(
            "engine_on_path",
            true,
            true,
            format!("'{}' resolves on this machine", config.command),
        ));
    } else {
        checks.push(check(
            "engine_on_path",
            false,
            true,
            format!(
                "'{}' is NOT on this machine's PATH - every task would fail to start. \
                 Install it, or edit 'command' in {}",
                config.command,
                AgentConfig::path(&route.attachment).display()
            ),
        ));
    }

    let key_path = route
        .attachment
        .join("keys")
        .join(format!("{}.key", config.agent));
    if key_path.exists() {
        checks.push(check(
            "signing_key",
            true,
            true,
            "this machine signs as the agent it is configured as".to_string(),
        ));
    } else {
        checks.push(check(
            "signing_key",
            false,
            true,
            format!(
                "{} is missing - run 'ferry enable' again; it creates a key only when \
                 there is not one, never replacing an existing identity",
                key_path.display()
            ),
        ));
    }

    let rostered = ferryman_channel::read_agent_roster(&route.communications)
        .map(|roster| roster.iter().any(|a| a.name == config.agent))
        .unwrap_or(false);
    if rostered {
        checks.push(check(
            "roster",
            true,
            true,
            format!("'{}' is known to the fleet", config.agent),
        ));
    } else {
        checks.push(check(
            "roster",
            false,
            true,
            format!(
                "'{}' is not in the roster - peers would report UnknownSigner for \
                 everything this machine writes. Run 'ferry enable' to register it",
                config.agent
            ),
        ));
    }

    // Present or absent, never contents. What is IN credentials.json is none of
    // a diagnostic's business.
    let credentials = route.attachment.join("credentials.json");
    checks.push(check(
        "credentials_file",
        credentials.exists(),
        false,
        if credentials.exists() {
            "present; listed variables are passed to the engine, all other secret-looking \
             environment is scrubbed"
                .to_string()
        } else {
            format!(
                "absent. Cloud engines need their API key to survive the environment scrub: \
                 put {{\"ENV_VAR_NAME\": \"...\"}} in {} - see docs/ENGINE_SETUP.md",
                credentials.display()
            )
        },
    ));

    // Best-effort and bounded: the probe has a hard timeout inside the channel
    // crate. Unavailable is normal on a first machine and never blocks local
    // work, so this is informational.
    match ferryman_channel::syncthing_health() {
        Ok(health) => {
            let connected = health.peers.iter().filter(|p| p.connected).count();
            let shared = ferryman_channel::syncthing_folder_device_ids(&route)
                .map(|ids| ids.len())
                .unwrap_or(0);
            checks.push(check(
                "syncthing",
                true,
                false,
                format!(
                    "{} at {}; {} device(s) paired, {connected} connected; this folder shared with {shared}",
                    if health.managed { "managed instance" } else { "reachable" },
                    health.api_base,
                    health.peers.len(),
                ),
            ));

            // A reachable daemon and a paired device count say nothing about whether
            // this folder is actually syncing. A folder whose `.stfolder` marker is
            // missing sits in `error` and moves nothing in either direction, and the
            // only place that shows is `/rest/db/status`. Reporting the daemon alone as
            // `ok` is how doctor came to say ready while sync was completely dead.
            if let Some(folder) = ferryman_channel::syncthing_channel_state(&route) {
                let moving = folder.is_moving();
                let ours = folder.syncs(&route.communications);
                checks.push(check(
                    "syncthing_folder",
                    moving && ours,
                    false,
                    if !ours {
                        // The id is registered, and may well be perfectly healthy - on
                        // somebody else's directory. This project then syncs nothing
                        // while the state reads idle, which is the missing-marker
                        // failure one level up and just as quiet.
                        format!(
                            "folder {} is {} but Syncthing is syncing {}, not this project's \
                             channel at {} - nothing this project writes leaves the machine; \
                             `ferry channel syncthing on` re-points it here",
                            folder.folder_id,
                            folder.state,
                            folder.registered_path,
                            route.communications.display(),
                        )
                    } else if moving {
                        format!("folder {} is {}", folder.folder_id, folder.state)
                    } else {
                        format!(
                            "folder {} is {}{} - nothing syncs in either direction until this \
                             clears; `ferry channel syncthing on` re-registers it",
                            folder.folder_id,
                            if folder.state.is_empty() {
                                "in an unknown state"
                            } else {
                                &folder.state
                            },
                            if folder.error.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", folder.error)
                            },
                        )
                    },
                ));
            }
        }
        Err(err) => checks.push(check(
            "syncthing",
            false,
            false,
            format!(
                "{err} - the channel still works on this machine, but nothing crosses to \
                 others until Syncthing is running{}",
                if ferryman_channel::syncthing_managed_configured() {
                    "; ferry doctor --fix starts it"
                } else {
                    ""
                }
            ),
        )),
    }

    // Open grants are fine alone. With a second person on the roster they mean
    // "anyone who can write the folder may name their own role" (ADR 0014).
    let operators = ferryman_channel::read_agent_roster(&route.communications)
        .map(|roster| roster.iter().filter(|a| a.role == "operator").count())
        .unwrap_or(0);
    if !route.requires_grants() && operators > 1 {
        checks.push(check(
            "grants",
            false,
            false,
            format!(
                "open, with {operators} operators on the roster - set grants = \"required\" \
                 in bridge.toml (inviting from the dashboard does this)"
            ),
        ));
    }
    match ferryman_channel::master::read_master(&route) {
        Ok(Some(declaration)) => {
            checks.push(check("master", true, false, declaration.master.clone()))
        }
        Ok(None) => checks.push(check(
            "master",
            false,
            false,
            "no master declared - run 'ferry enable' on the orchestrator machine, or \
             'ferry enable --master' anywhere, to declare one"
                .to_string(),
        )),
        Err(err) => checks.push(check("master", false, false, format!("{err:#}"))),
    }

    // Version skew across the fleet, in both directions.
    //
    // This reported only the machines behind THIS one, reasoning that the stale machine
    // misbehaves first and is never the one you are sitting at. The second half is false,
    // and its falseness is silent: a machine that is itself behind read "no registered
    // machine is behind it" and concluded it was current. The check reassured precisely
    // the machine that needed telling, and a machine four versions back sat there for
    // weeks being told it was fine.
    //
    // Being behind is also the more actionable half. "Some other machine is stale" is a
    // note to go and find someone; "you are stale" is a command you can run where you are
    // standing, so it leads.
    let fleet: Vec<(String, String)> = ferryman_channel::licensing::read_devices(&route)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| Some((d.id, d.ferry_version?)))
        .collect();
    let (level, detail) = version_skew(env!("CARGO_PKG_VERSION"), &fleet);
    checks.push(check("versions", level, false, detail));

    let ready = checks.iter().all(|check| !check.required || check.ok);
    Report {
        project: route.project_id,
        ready,
        checks,
    }
}

/// What the `versions` check should say, given this machine's version and what every
/// registered machine reports. `fleet` is `(device id, version)`.
///
/// A free function rather than inline, because the defect it replaced was a *sentence* -
/// a stale machine being told "no registered machine is behind it" - and a sentence is
/// only catchable by asserting on the sentence. Inline, it needed a whole channel and a
/// device roster to exercise, which is why nothing exercised it.
fn version_skew(mine: &str, fleet: &[(String, String)]) -> (bool, String) {
    use ferryman_channel::licensing::version_is_older;
    let behind: Vec<String> = fleet
        .iter()
        .filter(|(_, version)| version_is_older(version, mine))
        .map(|(id, version)| format!("{} ({version})", &id[..id.len().min(8)]))
        .collect();
    // The newest version anyone reports, when it beats ours.
    let newer = fleet
        .iter()
        .map(|(_, version)| version.as_str())
        .filter(|version| version_is_older(mine, version))
        .fold(None::<&str>, |best, version| match best {
            Some(best) if !version_is_older(best, version) => Some(best),
            _ => Some(version),
        });
    let detail = match (newer, behind.is_empty()) {
        (Some(newest), true) => {
            format!("this machine {mine} is BEHIND the fleet's {newest} - run 'ferry update' here")
        }
        (Some(newest), false) => format!(
            "this machine {mine} is BEHIND the fleet's {newest} - run 'ferry update' here; \
             and behind this machine: {}",
            behind.join(", ")
        ),
        (None, false) => format!(
            "this machine {mine}; behind: {} - run 'ferry update' there",
            behind.join(", ")
        ),
        (None, true) => format!("this machine {mine}; every registered machine is level with it"),
    };
    (newer.is_none() && behind.is_empty(), detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(id, version)| ((*id).to_string(), (*version).to_string()))
            .collect()
    }

    /// The defect, reproduced: grouchly on 0.5.10 beside beastly on 0.5.11 was told
    /// nothing was wrong, because the check only ever looked downhill.
    #[test]
    fn a_machine_that_is_itself_behind_is_told_so() {
        let (level, detail) = version_skew("0.5.10", &fleet(&[("8799dfe2f32dc7aa", "0.5.11")]));
        assert!(!level);
        assert!(detail.contains("BEHIND"), "{detail}");
        assert!(detail.contains("0.5.11"), "{detail}");
        assert!(
            detail.contains("here"),
            "the remedy runs on this machine, not another: {detail}"
        );
    }

    /// Both directions at once. Neither report may swallow the other.
    #[test]
    fn a_machine_in_the_middle_hears_about_both_sides() {
        let (level, detail) = version_skew(
            "0.5.10",
            &fleet(&[
                ("newer0001111aaaa", "0.5.12"),
                ("older0002222bbbb", "0.5.9"),
            ]),
        );
        assert!(!level);
        assert!(detail.contains("0.5.12"), "{detail}");
        // Named by the first eight of its device id, the way the listing has always
        // shortened them - long enough to pick a machine out, short enough to read.
        assert!(detail.contains("older000 (0.5.9)"), "{detail}");
        assert!(!detail.contains("older0002222bbbb"), "{detail}");
    }

    /// The newest wins, not merely the first one seen.
    #[test]
    fn the_furthest_ahead_is_the_one_named() {
        let (_, detail) = version_skew(
            "0.5.9",
            &fleet(&[("a", "0.5.10"), ("b", "0.6.0"), ("c", "0.5.11")]),
        );
        assert!(detail.contains("0.6.0"), "{detail}");
        assert!(!detail.contains("0.5.10"), "{detail}");
    }

    /// The old behaviour, preserved: someone else is stale and the remedy is over there.
    #[test]
    fn a_machine_ahead_of_a_stale_peer_still_points_at_the_peer() {
        let (level, detail) = version_skew("0.5.11", &fleet(&[("5695598bdb", "0.5.10")]));
        assert!(!level);
        assert!(detail.contains("5695598b (0.5.10)"), "{detail}");
        assert!(detail.contains("there"), "{detail}");
        assert!(!detail.contains("BEHIND"), "{detail}");
    }

    /// A level fleet says so plainly, and no longer claims something it cannot know.
    #[test]
    fn a_level_fleet_is_reported_as_level() {
        let (level, detail) = version_skew("0.5.11", &fleet(&[("a", "0.5.11"), ("b", "0.5.11")]));
        assert!(level);
        assert!(detail.contains("level"), "{detail}");
        let (alone, _) = version_skew("0.5.11", &fleet(&[]));
        assert!(alone);
    }

    fn tempdir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "ferryman-doctor-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_bare_command_is_found_along_the_given_directories() {
        let dir = tempdir("found");
        let binary = dir.join("ferryman-fake-engine");
        std::fs::write(&binary, "#!/bin/sh\n").unwrap();
        make_executable(&binary);

        assert_eq!(
            find_in_paths("ferryman-fake-engine", [dir.clone()]),
            Some(binary)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_executable_match_is_not_found() {
        let dir = tempdir("notexec");
        std::fs::write(dir.join("ferryman-inert"), "data").unwrap();
        assert_eq!(find_in_paths("ferryman-inert", [dir]), None);
    }

    #[cfg(windows)]
    #[test]
    fn the_platform_executable_suffix_is_tried() {
        let dir = tempdir("found");
        let binary = dir.join(format!(
            "ferryman-fake-engine{}",
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::write(&binary, b"MZ").unwrap();
        assert_eq!(find_in_paths("ferryman-fake-engine", [dir]), Some(binary));
    }

    #[test]
    fn a_missing_command_is_reported_as_not_found() {
        assert_eq!(
            find_in_paths("definitely-not-an-engine-9x7", [tempdir("empty")]),
            None
        );
    }

    #[test]
    fn a_separated_name_is_taken_as_a_path_not_searched() {
        // Relative to the current directory, not searched along the directories
        // given: pointing command at ./vendor/engine must keep working.
        let dir = tempdir("sep");
        std::fs::write(dir.join("marker"), "").unwrap();
        #[cfg(unix)]
        make_executable(&dir.join("marker"));
        let marker = dir.join("marker");
        let found = find_in_paths(&marker.display().to_string(), [tempdir("elsewhere")]);
        // An absolute path outside PATH is still resolved directly.
        assert_eq!(found.as_deref(), Some(marker.as_path()));
    }

    #[test]
    fn an_unenabled_directory_reports_one_channel_failure_and_nothing_else() {
        let dir = tempdir("nochannel");
        let report = examine(&dir);
        assert_eq!(report.checks.len(), 1);
        assert!(!report.ready);
        assert_eq!(report.checks[0].name, "channel");
    }

    /// The check that used to be confidently wrong.
    ///
    /// A container-run agent's engine lives in the IMAGE, so the host PATH cannot answer
    /// the question. It used to answer anyway, and a sandboxed worker whose image lacked
    /// the engine got a green `engine_on_path` while every task failed to start.
    #[test]
    fn a_sandboxed_agent_is_not_told_its_engine_is_fine_because_the_host_has_one() {
        let dir = crate::enable::tests_support::enabled_project("ferryman-no-such-engine-8b2");
        let config = dir.join(".ferryman").join("agent.toml");
        let text = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            text.replace("sandbox = \"\"", "sandbox = \"podman:example/image\""),
        )
        .unwrap();

        let engine = examine(&dir)
            .checks
            .into_iter()
            .find(|c| c.name == "engine_on_path")
            .unwrap();

        // Whichever way it lands - podman present or absent on the machine running the
        // tests - it must never claim the engine itself is fine, and it must name the
        // image so the operator knows where to look.
        assert!(
            engine.detail.contains("example/image"),
            "{:?}",
            engine.detail
        );
        assert!(
            !engine.detail.contains("resolves on this machine"),
            "the host PATH cannot vouch for an engine inside a container: {:?}",
            engine.detail
        );
    }

    #[test]
    fn an_enabled_project_with_a_missing_engine_is_not_ready_and_says_what_to_do() {
        let dir = crate::enable::tests_support::enabled_project("ferryman-no-such-engine-9x7");
        let report = examine(&dir);
        assert!(!report.ready, "{:?}", report.checks);

        let engine = report
            .checks
            .iter()
            .find(|c| c.name == "engine_on_path")
            .unwrap();
        assert!(!engine.ok);
        assert!(engine.detail.contains("agent.toml"), "{:?}", engine.detail);
    }
}

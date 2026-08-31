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
    match ferryman_channel::syncthing_peers() {
        Ok(peers) => checks.push(check(
            "syncthing",
            true,
            false,
            format!("reachable; {} device(s) paired", peers.len()),
        )),
        Err(_) => checks.push(check(
            "syncthing",
            false,
            false,
            "not reachable - the channel still works on this machine, but nothing \
             crosses to others until Syncthing is installed and running"
                .to_string(),
        )),
    }

    let ready = checks.iter().all(|check| !check.required || check.ok);
    Report {
        project: route.project_id,
        ready,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

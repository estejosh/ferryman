//! Heavy orders through the machine's snifrig queue (ADR 0028).
//!
//! PENDING SNIFRIG AGREEMENT. The order fields (`needs.heavy`, `needs.hints`) and the
//! command lines below are a proposal; snifrig has not confirmed the names or what its
//! can-i-start check means. So the whole path is behind `snifrig_heavy = true` in
//! `agent.toml`, which defaults to off, and even then it only engages when
//! a `snifrig` binary is on PATH AND that binary answers `snifrig can-i-start --help`
//! successfully. Today's snifrig has no such subcommand, so today everything runs directly,
//! exactly as before.
//!
//! Snifrig only wraps process start. No work content moves, and the command is the same
//! command the worker would have run.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ferryman_channel::ProjectRoute;
use ferryman_channel::work::{ExplicitNeeds, ResourceHints};

/// The `agent.toml` key that turns this on. Default off.
pub const CONFIG_KEY: &str = "snifrig_heavy";

/// How an order's command will be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunVia {
    Direct,
    Snifrig,
}

impl RunVia {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Snifrig => "snifrig",
        }
    }
}

/// Whether `agent.toml` text switches the heavy path on.
#[must_use]
pub fn enabled_in(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        key.trim() == CONFIG_KEY
            && matches!(
                value.trim().trim_matches('"').to_ascii_lowercase().as_str(),
                "true" | "yes" | "on" | "1"
            )
    })
}

/// Whether this machine's agent config enables the heavy path.
#[must_use]
pub fn enabled(attachment: &Path) -> bool {
    std::fs::read_to_string(attachment.join("agent.toml")).is_ok_and(|text| enabled_in(&text))
}

/// The `snifrig` binary on PATH, if there is one.
#[must_use]
pub fn snifrig_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let names: &[&str] = if cfg!(windows) {
        &["snifrig.exe", "snifrig.cmd", "snifrig.bat"]
    } else {
        &["snifrig"]
    };
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
}

/// Whether the snifrig on this machine has the can-i-start check the proposal relies on.
#[must_use]
pub fn has_can_i_start(snifrig: &Path) -> bool {
    Command::new(snifrig)
        .args(["can-i-start", "--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The arguments the can-i-start check is given for these hints.
#[must_use]
pub fn check_args(hints: &ResourceHints) -> Vec<String> {
    let mut args = vec!["can-i-start".to_string()];
    for (flag, value) in [
        ("--cores", hints.cores),
        ("--ram-gb", hints.ram_gb),
        ("--gpu-mem-gb", hints.gpu_mem_gb),
        ("--expected-minutes", hints.expected_minutes),
    ] {
        if let Some(value) = value {
            args.push(flag.to_string());
            args.push(value.to_string());
        }
    }
    args
}

/// `snifrig run --name <order> -- <binary> <args...>`
#[must_use]
pub fn wrapped(
    snifrig: &Path,
    order_id: &str,
    binary: &str,
    args: &[String],
) -> (String, Vec<String>) {
    let mut out = vec![
        "run".to_string(),
        "--name".to_string(),
        order_id.to_string(),
        "--".to_string(),
        binary.to_string(),
    ];
    out.extend(args.iter().cloned());
    (snifrig.to_string_lossy().into_owned(), out)
}

/// The decision, with everything it depends on passed in.
#[must_use]
pub fn decide(
    enabled: bool,
    needs: Option<&ExplicitNeeds>,
    snifrig: Option<&Path>,
    can_i_start_exists: impl FnOnce(&Path) -> bool,
    order_id: &str,
    binary: String,
    args: Vec<String>,
) -> (String, Vec<String>, RunVia) {
    let heavy = needs.is_some_and(|needs| needs.heavy);
    if let (true, true, Some(snifrig)) = (enabled, heavy, snifrig)
        && can_i_start_exists(snifrig)
    {
        let (binary, args) = wrapped(snifrig, order_id, &binary, &args);
        return (binary, args, RunVia::Snifrig);
    }
    (binary, args, RunVia::Direct)
}

/// What the worker calls just before it starts an order's command.
#[must_use]
pub fn plan(
    route: &ProjectRoute,
    order_id: &str,
    binary: String,
    args: Vec<String>,
) -> (String, Vec<String>, RunVia) {
    if !enabled(&route.attachment) {
        return (binary, args, RunVia::Direct);
    }
    let needs = ferryman_channel::read_task(route, order_id)
        .ok()
        .and_then(|task| task.order.needs);
    let snifrig = snifrig_on_path();
    decide(
        true,
        needs.as_ref(),
        snifrig.as_deref(),
        has_can_i_start,
        order_id,
        binary,
        args,
    )
}

/// Which way an order would run here, for `ferry_orders show`.
#[must_use]
pub fn run_via(route: &ProjectRoute, needs: Option<&ExplicitNeeds>) -> RunVia {
    if !enabled(&route.attachment) || !needs.is_some_and(|needs| needs.heavy) {
        return RunVia::Direct;
    }
    match snifrig_on_path() {
        Some(path) if has_can_i_start(&path) => RunVia::Snifrig,
        _ => RunVia::Direct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heavy() -> ExplicitNeeds {
        ExplicitNeeds {
            heavy: true,
            hints: Some(ResourceHints {
                cores: Some(8),
                ..ResourceHints::default()
            }),
            ..ExplicitNeeds::default()
        }
    }

    #[test]
    fn the_flag_defaults_off_and_reads_true() {
        assert!(!enabled_in(""));
        assert!(!enabled_in("snifrig_heavy = false\n"));
        assert!(enabled_in("command = \"claude\"\nsnifrig_heavy = true\n"));
    }

    #[test]
    fn a_heavy_order_with_snifrig_and_the_check_runs_through_the_queue() {
        let snifrig = PathBuf::from("/bin/snifrig");
        let (binary, args, via) = decide(
            true,
            Some(&heavy()),
            Some(&snifrig),
            |_| true,
            "ord-1",
            "claude".into(),
            vec!["-p".into(), "go".into()],
        );
        assert_eq!(via, RunVia::Snifrig);
        assert_eq!(binary, "/bin/snifrig");
        assert_eq!(args, ["run", "--name", "ord-1", "--", "claude", "-p", "go"]);
    }

    #[test]
    fn everything_else_runs_directly() {
        let snifrig = PathBuf::from("/bin/snifrig");
        let direct = |enabled, needs: Option<&ExplicitNeeds>, snifrig: Option<&Path>, check| {
            decide(
                enabled,
                needs,
                snifrig,
                |_| check,
                "o",
                "claude".into(),
                Vec::new(),
            )
            .2
        };
        assert_eq!(
            direct(false, Some(&heavy()), Some(&snifrig), true),
            RunVia::Direct
        );
        assert_eq!(direct(true, None, Some(&snifrig), true), RunVia::Direct);
        assert_eq!(
            direct(true, Some(&ExplicitNeeds::default()), Some(&snifrig), true),
            RunVia::Direct
        );
        assert_eq!(direct(true, Some(&heavy()), None, true), RunVia::Direct);
        assert_eq!(
            direct(true, Some(&heavy()), Some(&snifrig), false),
            RunVia::Direct
        );
    }

    #[test]
    fn hints_become_check_flags_and_are_validated() {
        let hints = ResourceHints {
            cores: Some(8),
            ram_gb: Some(16),
            gpu_mem_gb: None,
            expected_minutes: Some(45),
        };
        assert_eq!(
            check_args(&hints),
            [
                "can-i-start",
                "--cores",
                "8",
                "--ram-gb",
                "16",
                "--expected-minutes",
                "45"
            ]
        );
        assert!(hints.validate().is_ok());
        assert!(
            ResourceHints {
                cores: Some(0),
                ..ResourceHints::default()
            }
            .validate()
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fake_snifrig_shim_is_found_and_probed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("snifrig");
        std::fs::write(&shim, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(has_can_i_start(&shim));
        let missing = dir.path().join("nothing");
        assert!(!has_can_i_start(&missing));
        let bad = dir.path().join("bad");
        std::fs::write(&bad, "#!/bin/sh\nexit 2\n").unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!has_can_i_start(&bad));
    }
}

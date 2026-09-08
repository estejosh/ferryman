//! Supervising the Ferryman-managed Syncthing instance.
//!
//! Ferryman can run its own Syncthing, separate from any the person already uses, so a
//! fleet's folders never mix with a household's. That instance has a known home
//! ([`ferryman_channel::syncthing_managed_home`]) and nothing else on the machine starts
//! it, so Ferryman has to: `ferry syncthing start`, `ferry doctor --fix`, and the agent
//! loop when it notices the process is gone.
//!
//! Stopping goes through Syncthing's own shutdown endpoint, never a kill: a kill in the
//! middle of an index write is how a folder ends up needing a rescan.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use ferryman_channel::{SyncthingHealth, syncthing_health, syncthing_managed_home};

/// How long to wait for a freshly started Syncthing to answer its API.
const START_DEADLINE: Duration = Duration::from_secs(20);

/// Where the `syncthing` binary is, if anywhere.
///
/// PATH first. On Windows the winget install lands under the per-user WinGet packages
/// directory and never touches PATH, so that is searched too - the version in the
/// directory name changes on every update, so it is matched by prefix, newest last.
#[must_use]
pub fn find_binary() -> Option<PathBuf> {
    if let Some(found) = crate::doctor::find_on_path("syncthing") {
        return Some(found);
    }
    if cfg!(windows) {
        let mut found = Vec::new();
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let packages = Path::new(&local)
                .join("Microsoft")
                .join("WinGet")
                .join("Packages");
            if let Ok(entries) = std::fs::read_dir(packages) {
                for entry in entries.flatten() {
                    if !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("Syncthing.Syncthing_")
                    {
                        continue;
                    }
                    if let Ok(inner) = std::fs::read_dir(entry.path()) {
                        for dir in inner.flatten() {
                            let exe = dir.path().join("syncthing.exe");
                            if exe.is_file() {
                                found.push(exe);
                            }
                        }
                    }
                }
            }
        }
        if let Ok(program_files) = std::env::var("ProgramFiles") {
            let exe = Path::new(&program_files)
                .join("Syncthing")
                .join("syncthing.exe");
            if exe.is_file() {
                found.push(exe);
            }
        }
        found.sort();
        return found.pop();
    }
    for candidate in ["/usr/local/bin/syncthing", "/opt/homebrew/bin/syncthing"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Whether the managed instance is answering right now.
#[must_use]
pub fn managed_running() -> bool {
    syncthing_health().is_ok_and(|h| h.managed)
}

/// Start the managed instance if it is not already answering, and wait until it is.
///
/// Creates the managed home on first run (`syncthing generate`), so a machine that has
/// never had one gets one with no default folder and its GUI on loopback. Returns the
/// health reading once the API answers.
pub fn start() -> Result<SyncthingHealth> {
    if let Ok(health) = syncthing_health()
        && health.managed
    {
        return Ok(health);
    }
    let Some(home) = syncthing_managed_home() else {
        bail!("cannot work out where the managed Syncthing should live on this platform");
    };
    let Some(binary) = find_binary() else {
        bail!(
            "Syncthing is not installed; get it from https://syncthing.net/downloads/ \
             (winget install Syncthing.Syncthing on Windows) and run this again"
        );
    };
    if !home.join("config.xml").is_file() {
        std::fs::create_dir_all(&home)
            .with_context(|| format!("create {}", home.display()))?;
        let generated = Command::new(&binary)
            .arg("generate")
            .arg("--home")
            .arg(&home)
            .arg("--no-default-folder")
            .arg("--gui-address=127.0.0.1:0")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .context("run syncthing generate")?;
        if !generated.status.success() {
            bail!(
                "syncthing generate failed: {}",
                String::from_utf8_lossy(&generated.stderr).trim()
            );
        }
    }
    spawn_detached(&binary, &home)?;
    let started = Instant::now();
    while started.elapsed() < START_DEADLINE {
        thread::sleep(Duration::from_millis(500));
        if let Ok(health) = syncthing_health()
            && health.managed
        {
            return Ok(health);
        }
    }
    bail!(
        "started Syncthing from {} with home {} but it did not answer within {}s",
        binary.display(),
        home.display(),
        START_DEADLINE.as_secs()
    )
}

/// Ask the managed instance to shut down. Refuses to touch a Syncthing that is not the
/// managed one: that is the person's own, and Ferryman has no business stopping it.
pub fn stop() -> Result<()> {
    let health = syncthing_health().context("read Syncthing")?;
    if !health.managed {
        bail!(
            "the Syncthing answering at {} is not the Ferryman-managed one; not stopping it",
            health.api_base
        );
    }
    ferryman_channel::syncthing_shutdown()
}

fn spawn_detached(binary: &Path, home: &Path) -> Result<()> {
    let mut command = Command::new(binary);
    command
        .arg("serve")
        .arg("--home")
        .arg(home)
        .arg("--no-browser")
        .arg("--no-restart")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW: outlives the
        // ferry process that started it and never flashes a console.
        command.creation_flags(0x0000_0008 | 0x0000_0200 | 0x0800_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A new session so a Ctrl-C to ferry does not take Syncthing with it.
        // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
        unsafe {
            command.pre_exec(|| {
                libc_setsid();
                Ok(())
            });
        }
    }
    command
        .spawn()
        .with_context(|| format!("start {}", binary.display()))?;
    Ok(())
}

#[cfg(unix)]
fn libc_setsid() {
    unsafe extern "C" {
        fn setsid() -> i32;
    }
    // SAFETY: plain libc call with no arguments.
    unsafe {
        setsid();
    }
}

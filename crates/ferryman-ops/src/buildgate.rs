//! One build at a time per machine, for everything the worker starts.
//!
//! An engine is a model with a shell. Give three of them three orders on one machine and
//! each runs `cargo test --workspace` in its own checkout, all at once, and the person at
//! that machine loses it. Asking the engines to queue is a rule they can forget; this is
//! the worker doing it for them.
//!
//! The worker puts a small folder first on every engine's PATH. In it, `cargo` is this
//! same `ferry` binary under another name. Started as `cargo`, ferry takes the machine's
//! build slot (a lock file in machine state), waiting for it if another build has it,
//! then runs the real `cargo` with the same arguments and gives back its exit code. The
//! slot is let go when that build ends, however it ends, because the operating system
//! drops the lock with the process.
//!
//! A build started inside a build (a build script that runs cargo) does not wait for the
//! slot its parent already holds.

use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use fs2::FileExt;

/// The tools that take the build slot. Named by what the engine types.
pub const TOOLS: &[&str] = &["cargo"];

/// Set on a gated build, so a build it starts goes straight through.
pub const HELD: &str = "FERRYMAN_BUILD_SLOT_HELD";

/// The PATH the engine had before the gate folder was put in front of it.
pub const REAL_PATH: &str = "FERRYMAN_GATE_REAL_PATH";

/// Machine state for the gate: `<machine state>/build-gate`.
#[must_use]
pub fn dir() -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("build-gate"))
}

/// The gated tool this process was started as, if any (`cargo`, `cargo.exe`).
#[must_use]
pub fn invoked_as() -> Option<&'static str> {
    let first = std::env::args_os().next()?;
    tool_named(Path::new(&first))
}

fn tool_named(path: &Path) -> Option<&'static str> {
    let stem = path.file_stem()?.to_str()?.to_ascii_lowercase();
    TOOLS.iter().copied().find(|tool| *tool == stem)
}

/// The folder of gated tools for an engine's PATH, made or refreshed from this binary.
/// When it cannot be made, the worker runs engines as before and says so.
///
/// # Errors
/// The folder or a link in it could not be written.
pub fn shim_dir() -> anyhow::Result<PathBuf> {
    let bin = dir()
        .ok_or_else(|| anyhow::anyhow!("no per-user state directory on this machine"))?
        .join("bin");
    std::fs::create_dir_all(&bin)?;
    let me = std::env::current_exe()?;
    let size = std::fs::metadata(&me)?.len();
    for tool in TOOLS {
        let shim = bin.join(format!("{tool}{}", std::env::consts::EXE_SUFFIX));
        if std::fs::metadata(&shim).is_ok_and(|meta| meta.len() == size) {
            continue;
        }
        // A shim in use cannot be replaced on Windows; the old one still gates, so a
        // failed refresh is not a reason to run ungated.
        if shim.exists() && std::fs::remove_file(&shim).is_err() {
            continue;
        }
        if std::fs::hard_link(&me, &shim).is_err() {
            std::fs::copy(&me, &shim)?;
        }
    }
    Ok(bin)
}

/// `PATH` for an engine: the gate folder first, then what it had.
#[must_use]
pub fn engine_path(shims: &Path, original: Option<&OsString>) -> Option<OsString> {
    let mut dirs = vec![shims.to_path_buf()];
    if let Some(original) = original {
        dirs.extend(std::env::split_paths(original));
    }
    std::env::join_paths(dirs).ok()
}

/// The real `tool` on `path`, skipping the gate folder and anything that is this binary.
fn real_tool(tool: &str, path: &OsString, shims: Option<&Path>) -> Option<PathBuf> {
    let me = std::env::current_exe()
        .ok()
        .and_then(|me| me.canonicalize().ok());
    let shims = shims.and_then(|dir| dir.canonicalize().ok());
    let names: Vec<String> = if cfg!(windows) {
        vec![
            format!("{tool}.exe"),
            format!("{tool}.cmd"),
            format!("{tool}.bat"),
        ]
    } else {
        vec![tool.to_string()]
    };
    std::env::split_paths(path)
        .filter(|dir| shims.is_none() || dir.canonicalize().ok() != shims)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| {
            candidate.is_file()
                && (me.is_none() || candidate.canonicalize().ok() != me)
                && !same_size_as_me(candidate)
        })
}

/// A copied shim is not the same file as this binary but is still this binary.
fn same_size_as_me(candidate: &Path) -> bool {
    let Ok(me) = std::env::current_exe() else {
        return false;
    };
    match (std::fs::metadata(&me), std::fs::metadata(candidate)) {
        (Ok(a), Ok(b)) => a.len() == b.len() && tool_named(candidate).is_some(),
        _ => false,
    }
}

/// How many jobs one build gets when the caller did not say: most of the machine, not all.
fn default_jobs() -> usize {
    let cpus = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
    (cpus - cpus / 4).max(1)
}

/// Run as `tool`: take the slot, run the real one, give back its exit code.
#[must_use]
pub fn run_gated(tool: &str) -> ExitCode {
    let path = std::env::var_os(REAL_PATH)
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_default();
    let shims = dir().map(|dir| dir.join("bin"));
    let Some(real) = real_tool(tool, &path, shims.as_deref()) else {
        eprintln!("ferry: no real {tool} found on PATH behind the build gate");
        return ExitCode::from(127);
    };
    let slot = if std::env::var_os(HELD).is_some() {
        None
    } else {
        match take_slot() {
            Ok(slot) => slot,
            Err(error) => {
                eprintln!("ferry: build slot unavailable ({error}); building without it");
                None
            }
        }
    };
    let mut command = Command::new(&real);
    command
        .args(std::env::args_os().skip(1))
        .env("PATH", &path)
        .env_remove(REAL_PATH)
        .env(HELD, "1");
    if tool == "cargo" && std::env::var_os("CARGO_BUILD_JOBS").is_none() {
        command.env("CARGO_BUILD_JOBS", default_jobs().to_string());
    }
    let status = command.status();
    drop(slot);
    match status {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from),
        Err(error) => {
            eprintln!("ferry: could not start {}: {error}", real.display());
            ExitCode::from(127)
        }
    }
}

/// The machine's build slot, waiting for it if it is taken. `None` with no state dir.
fn take_slot() -> std::io::Result<Option<File>> {
    let Some(dir) = dir() else {
        return Ok(None);
    };
    std::fs::create_dir_all(&dir)?;
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("build.lock"))?;
    if file.try_lock_exclusive().is_err() {
        eprintln!("ferry: another build has this machine's build slot; waiting for it");
        file.lock_exclusive()?;
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_is_known_by_its_name_with_or_without_exe() {
        assert_eq!(tool_named(Path::new("/x/cargo")), Some("cargo"));
        assert_eq!(tool_named(Path::new("C:/x/Cargo.exe")), Some("cargo"));
        assert_eq!(tool_named(Path::new("/x/ferry")), None);
    }

    #[test]
    fn the_gate_folder_goes_first_and_nothing_is_lost() {
        let original = std::env::join_paths(["/usr/bin", "/bin"]).unwrap();
        let path = engine_path(Path::new("/state/build-gate/bin"), Some(&original)).unwrap();
        let dirs: Vec<_> = std::env::split_paths(&path).collect();
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/state/build-gate/bin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin")
            ]
        );
    }

    #[test]
    fn the_real_tool_is_found_behind_the_gate_folder() {
        let root = tempfile::tempdir().unwrap();
        let shims = root.path().join("shims");
        let real = root.path().join("real");
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        let name = if cfg!(windows) { "cargo.exe" } else { "cargo" };
        std::fs::write(shims.join(name), b"gate").unwrap();
        std::fs::write(real.join(name), b"the real one").unwrap();
        let path = std::env::join_paths([&shims, &real]).unwrap();
        assert_eq!(
            real_tool("cargo", &path, Some(&shims)),
            Some(real.join(name))
        );
    }

    #[test]
    fn a_second_build_waits_for_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("build.lock");
        let open = || {
            File::options()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock)
                .unwrap()
        };
        let first = open();
        first.try_lock_exclusive().unwrap();
        assert!(open().try_lock_exclusive().is_err());
        drop(first);
        assert!(open().try_lock_exclusive().is_ok());
    }
}

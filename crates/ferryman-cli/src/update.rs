//! Keeping `ferry` current, because an install that drifts is an install that lies.
//!
//! # Why this exists
//!
//! The updater that was already here updates *Bridge git checkouts*. Nothing ever
//! updated the binary, so an install quietly stayed on whatever version it was first
//! given. The machine that wrote this was running 0.4.0 against a fleet on 0.5.4 - four
//! minor versions of fixes, on the operator's own box, silently. That is how an hour goes
//! into debugging something that was fixed weeks ago.
//!
//! # What it will and will not do
//!
//! It replaces the binary on disk and says so. It never replaces a *running* process:
//! a worker in the middle of a task is not interrupted, and the new version takes effect
//! the next time it starts. Swapping the executable out from under a running fleet to
//! save one restart is not a trade worth making.
//!
//! # What the check actually proves
//!
//! The archive is verified against the `.sha256` published beside it. That is an
//! integrity check - it catches a truncated download, a proxy that mangled the bytes, a
//! half-written file. It is **not** a signature: the checksum comes from the same place
//! as the archive, so it proves nothing about a compromised release host. Release *tags*
//! are GPG-signed and verifiable (see `docs/RELEASE_PROCESS.md`); the binaries are not,
//! and this says so rather than implying a guarantee it cannot make.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const REPO: &str = "estejosh/ferryman";

/// The release target this build is for.
///
/// Derived from `cfg!` rather than a build script, so it cannot silently disagree with
/// what was actually compiled.
#[must_use]
pub fn target_triple() -> Option<&'static str> {
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => return None,
    })
}

fn archive_name(target: &str) -> String {
    if target.contains("windows") {
        format!("ferry-{target}.zip")
    } else {
        format!("ferry-{target}.tar.gz")
    }
}

/// What the newest published release is called, e.g. `v0.5.4`.
///
/// Uses the API rather than following the `releases/latest` redirect, because the answer
/// wanted here is the version *name* - and reporting "you are current" by comparing a
/// download URL to itself is how a broken check passes forever.
pub async fn latest_release() -> Result<String> {
    let response = reqwest::Client::builder()
        .user_agent(concat!("ferry/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(20))
        .build()?
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .send()
        .await
        .context("ask GitHub for the latest release")?;
    if !response.status().is_success() {
        bail!(
            "GitHub answered {} asking for the latest release",
            response.status()
        );
    }
    let body: serde_json::Value = response.json().await.context("read the release listing")?;
    body["tag_name"]
        .as_str()
        .map(ToString::to_string)
        .context("the latest release has no tag name")
}

/// This build's version, as a release tag would spell it.
#[must_use]
pub fn running_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// A version as numbers, for comparing. Anything after a `-` is a pre-release suffix and
/// is ignored: `0.5.5-rc1` and `0.5.5` are the same release for this purpose.
fn parts(version: &str) -> Vec<u64> {
    version
        .trim()
        .trim_start_matches('v')
        .split('-')
        .next()
        .unwrap_or_default()
        .split('.')
        .map(|piece| piece.parse().unwrap_or(0))
        .collect()
}

/// Whether `latest` is NEWER than what is running.
///
/// # Why this is a comparison and not an inequality
///
/// It was an inequality first, and running it caught the bug in one sentence: a build of
/// main reported "available v0.5.4" against its own v0.5.5 and offered to install it.
/// Harmless as a message, and not harmless at all in [`keep_current`], which would have
/// silently DOWNGRADED every developer build and every machine running ahead of a tag -
/// including, at that moment, the entire fleet.
///
/// Newer only. A machine ahead of the latest release is told so and left alone.
#[must_use]
pub fn is_newer(latest: &str) -> bool {
    parts(latest) > parts(env!("CARGO_PKG_VERSION"))
}

/// Whether the running build is ahead of the newest published release, which is what a
/// build from source looks like.
#[must_use]
pub fn is_ahead(latest: &str) -> bool {
    parts(env!("CARGO_PKG_VERSION")) > parts(latest)
}

async fn fetch(url: &str) -> Result<Vec<u8>> {
    let response = reqwest::Client::builder()
        .user_agent(concat!("ferry/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(180))
        .build()?
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetch {url}"))?;
    if !response.status().is_success() {
        bail!("{url} answered {}", response.status());
    }
    Ok(response.bytes().await?.to_vec())
}

/// Download the release for this platform, verify it, and put it where `ferry` runs from.
///
/// Returns the version installed.
pub async fn apply(tag: &str) -> Result<String> {
    let Some(target) = target_triple() else {
        bail!(
            "no published build for {} on {} - update by building from source",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    };
    let archive = archive_name(target);
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");

    let bytes = fetch(&format!("{base}/{archive}")).await?;
    let sums = fetch(&format!("{base}/{archive}.sha256"))
        .await
        .context("fetch the checksum; refusing to install an unverified binary")?;

    // The published file is `<hex>  <name>`, as sha256sum writes it.
    let expected = String::from_utf8_lossy(&sums)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let actual = hex::encode(Sha256::digest(&bytes));
    if expected.is_empty() || expected != actual {
        bail!(
            "{archive} does not match its published checksum - refusing to install it. \
             This is what a truncated or tampered download looks like; try again, and if \
             it persists do not force it."
        );
    }

    // Our own staging directory rather than a crate: `tempfile` is only a dev-dependency
    // in this crate, and pulling it into the shipped binary to hold three files for four
    // seconds is not a trade worth making.
    let staging = std::env::temp_dir().join(format!("ferryman-update-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&staging).context("make a staging directory")?;
    let staging = Staging(staging);
    let archive_path = staging.path().join(&archive);
    std::fs::write(&archive_path, &bytes).context("write the downloaded archive")?;

    // `tar` reads both .tar.gz and .zip, and ships with Windows 10 and later as well as
    // macOS and Linux - so one code path covers every platform we publish for, with no
    // archive crate to keep current.
    let status = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&archive_path)
        .arg("-C")
        .arg(staging.path())
        .status()
        .context("run tar to unpack the release")?;
    if !status.success() {
        bail!("could not unpack {archive}")
    }

    let binary = if cfg!(windows) { "ferry.exe" } else { "ferry" };
    let unpacked = staging.path().join(format!("ferry-{target}")).join(binary);
    if !unpacked.is_file() {
        bail!("{} is not in the archive", unpacked.display())
    }

    let destination = std::env::current_exe().context("find where ferry is installed")?;
    install_over(&unpacked, &destination)?;
    Ok(tag.to_string())
}

/// A staging directory that removes itself, so a failed update does not leave a copy of
/// the archive lying in the temp directory forever.
struct Staging(PathBuf);

impl Staging {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Put the new binary where the old one is.
///
/// Windows will not let a running executable be deleted or overwritten, so the old one is
/// renamed aside first - which Windows *does* allow, even while it is running. The
/// leftover is removed on the next update rather than immediately, because the process
/// that would delete it is the one still executing from it.
fn install_over(new: &Path, destination: &Path) -> Result<()> {
    let previous = with_suffix(destination, ".old");
    // Any leftover from a previous update is no longer running, so this is where it goes.
    let _ = std::fs::remove_file(&previous);

    if destination.exists() {
        std::fs::rename(destination, &previous).with_context(|| {
            format!(
                "move the current binary aside ({}). If it is running elsewhere, stop it \
                 and try again.",
                destination.display()
            )
        })?;
    }
    if let Err(error) = std::fs::copy(new, destination) {
        // Put it back rather than leaving the machine with no ferry at all.
        let _ = std::fs::rename(&previous, destination);
        return Err(error).with_context(|| format!("install into {}", destination.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("make {} executable", destination.display()))?;
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// How often an unattended install looks for a new release.
const CHECK_EVERY_HOURS: i64 = 6;

/// Where the last check is remembered, so a restart loop cannot turn "check for updates"
/// into a request every few seconds.
fn stamp_path() -> Option<PathBuf> {
    ferryman_channel::licensing::machine_state_dir().map(|dir| dir.join("last-update-check"))
}

fn checked_recently() -> bool {
    let Some(path) = stamp_path() else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(then) = text.trim().parse::<chrono::DateTime<chrono::Utc>>() else {
        return false;
    };
    (chrono::Utc::now() - then).num_hours() < CHECK_EVERY_HOURS
}

fn remember_check() {
    if let Some(path) = stamp_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, chrono::Utc::now().to_rfc3339());
    }
}

/// Keep this install current, on the way into a long-running command.
///
/// # Why it applies rather than nags
///
/// A notice that an update is available is a notice somebody has to act on, and the
/// machine that prompted this was four minor versions behind precisely because nothing
/// ever forced the issue. So it installs.
///
/// # Why that is safe to do unattended
///
/// It only ever replaces the binary on DISK. The process that ran it carries on with the
/// code it already has, and every worker in flight finishes the task it is holding. The
/// new version takes effect at the next start, which for an agent loop is minutes away
/// and for a person is whenever they next run something.
///
/// Best-effort throughout: a machine with no network, a rate-limited API, a release that
/// does not cover this platform - none of those are reasons to refuse to start the work
/// somebody actually asked for. It says what happened and gets out of the way.
///
/// Set `FERRYMAN_NO_AUTO_UPDATE=1` to turn it off entirely.
pub async fn keep_current() {
    if std::env::var("FERRYMAN_NO_AUTO_UPDATE").is_ok_and(|v| !v.is_empty() && v != "0") {
        return;
    }
    if checked_recently() {
        return;
    }
    remember_check();

    let Ok(latest) = latest_release().await else {
        return;
    };
    if !is_newer(&latest) {
        return;
    }
    match apply(&latest).await {
        Ok(installed) => {
            println!("  updated ferry to {installed}; it takes effect when this restarts");
        }
        Err(error) => {
            // Worth one line and no more. The command the operator ran is the point.
            println!("  could not update to {latest}: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_platform_has_a_published_build() {
        assert!(
            target_triple().is_some(),
            "the release matrix should cover the platform the tests run on"
        );
    }

    #[test]
    fn windows_ships_a_zip_and_everything_else_a_tarball() {
        assert_eq!(
            archive_name("x86_64-pc-windows-msvc"),
            "ferry-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(
            archive_name("aarch64-apple-darwin"),
            "ferry-aarch64-apple-darwin.tar.gz"
        );
    }

    #[test]
    fn the_running_version_is_spelled_the_way_a_tag_is() {
        let running = running_version();
        assert!(running.starts_with('v'));
        assert!(
            !is_newer(&running),
            "a build must not think itself out of date"
        );
    }

    /// The bug that replacing an inequality with a comparison fixes. A build of main is
    /// AHEAD of the latest tag, and an inequality read that as "different, so update" -
    /// which in the unattended path would have quietly DOWNGRADED every machine running
    /// ahead of a release, the whole fleet included.
    #[test]
    fn a_build_ahead_of_the_latest_release_is_never_downgraded() {
        assert!(!is_newer("v0.0.1"), "an older release is not an update");
        assert!(is_ahead("v0.0.1"));

        assert!(is_newer("v999.0.0"), "a newer release is an update");
        assert!(!is_ahead("v999.0.0"));
    }

    #[test]
    fn versions_compare_by_number_and_not_by_text() {
        // Why this cannot be string comparison: "0.5.10" sorts before "0.5.9".
        assert!(parts("v0.5.10") > parts("0.5.9"));
        assert!(parts("v1.0.0") > parts("v0.99.99"));
        // A pre-release suffix is not part of the ordering here.
        assert_eq!(parts("v0.5.5-rc1"), parts("0.5.5"));
        // Nonsense sorts low rather than panicking.
        assert!(parts("v0.5.5") > parts("not-a-version"));
    }

    /// The whole point of the swap: the old binary is moved rather than deleted, because
    /// Windows will not let a running executable be removed - and a failed copy must not
    /// leave the machine with no `ferry` at all.
    #[test]
    fn installing_keeps_the_old_binary_until_the_next_update() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("ferry");
        std::fs::write(&destination, b"old").unwrap();
        let new = dir.path().join("staged");
        std::fs::write(&new, b"new").unwrap();

        install_over(&new, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new");
        assert_eq!(
            std::fs::read(with_suffix(&destination, ".old")).unwrap(),
            b"old"
        );
    }

    #[test]
    fn installing_where_nothing_is_yet_simply_writes_it() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("ferry");
        let new = dir.path().join("staged");
        std::fs::write(&new, b"new").unwrap();

        install_over(&new, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new");
    }
}

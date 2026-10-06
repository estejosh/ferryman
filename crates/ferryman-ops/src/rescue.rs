//! Break-glass: a live terminal on one of your own machines, from anywhere, for as long as
//! a person on that machine keeps it open.
//!
//! The channel is how machines normally talk, and when the channel itself is what broke
//! there is nothing left to fix it with. This is the way back in. It is built so that it
//! does not exist until it is needed:
//!
//! - Nothing runs and nothing listens. `ferry rescue open` fetches upterm the first time
//!   it is used (checksum-verified), and the session lives only while that command runs.
//! - Both sides need a person. The machine being rescued approves every join in its own
//!   terminal (upterm without `--accept`), and only keys published by your own machines
//!   with `ferry rescue key` may even ask.
//! - Every connection is outbound, through upterm's relay, so it works behind any NAT and
//!   opens no port. The relay carries an SSH session it cannot read.
//! - It ends when the person closes it, or at the time limit, whichever is first.
//!
//! Keys and the join line travel in the fleet folder Syncthing already shares between
//! your machines. The join line grants nothing on its own: it needs a published key AND
//! the person on the other side saying yes.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where rescue keys and open sessions live: inside the fleet folder, so they reach the
/// other machines the way everything else between them does.
pub fn rescue_dir() -> Result<PathBuf> {
    ferryman_channel::licensing::fleet_dir()
        .map(|dir| dir.join("rescue"))
        .context("no fleet folder on this machine; run `ferry enable` once first")
}

/// One machine's open rescue session, as the other machines see it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub machine: String,
    /// The `ssh ...` line upterm printed for this session.
    pub ssh: String,
    pub opened_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Session {
    #[must_use]
    pub fn expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// This machine's rescue key, created on first use. Its public half is published to
/// `rescue/allowed/<machine>.pub` so the machines you might rescue will let it ask to join.
pub fn ensure_key(machine: &str) -> Result<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .context("no home directory")?;
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh)?;
    let key = ssh.join("ferryman_rescue_ed25519");
    if !key.is_file() {
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C"])
            .arg(format!("ferryman-rescue@{machine}"))
            .arg("-f")
            .arg(&key)
            .status()
            .context("run ssh-keygen (it ships with OpenSSH)")?;
        if !status.success() {
            bail!("ssh-keygen could not create {}", key.display());
        }
    }
    let public = std::fs::read_to_string(key.with_extension("pub"))
        .with_context(|| format!("read {}.pub", key.display()))?;
    // Not `keys`: the fleet folder's .stignore keeps any directory called `keys` on this
    // machine, which is right for private keys and silently wrong for these.
    let keys = rescue_dir()?.join("allowed");
    std::fs::create_dir_all(&keys)?;
    std::fs::write(
        keys.join(format!("{machine}.pub")),
        public.trim().to_string() + "\n",
    )?;
    Ok(key)
}

/// Every published rescue key except this machine's own: who may ask to join here.
pub fn authorized_keys(rescue: &Path, machine: &str) -> Result<Vec<(String, String)>> {
    let mut keys = Vec::new();
    let Ok(entries) = std::fs::read_dir(rescue.join("allowed")) else {
        return Ok(keys);
    };
    for entry in entries {
        let path = entry?.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".pub"))
        else {
            continue;
        };
        if name.eq_ignore_ascii_case(machine) || name.contains(".sync-conflict-") {
            continue;
        }
        let line = std::fs::read_to_string(&path)?.trim().to_string();
        if line.starts_with("ssh-") {
            keys.push((name.to_string(), line));
        }
    }
    keys.sort();
    Ok(keys)
}

/// Where this machine keeps its own copy of who may ask to join.
fn local_cache() -> Result<PathBuf> {
    Ok(ferryman_channel::licensing::machine_state_dir()
        .context("no per-user state directory")?
        .join("rescue")
        .join("allowed_keys"))
}

/// Read a cache file of `name<TAB>key` lines.
fn read_cache(path: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (name, key) = l.split_once('\t')?;
            key.starts_with("ssh-")
                .then(|| (name.to_string(), key.to_string()))
        })
        .collect()
}

/// Merge `published` into the cache at `path`, keeping every key ever seen, and return
/// the merged set. The cache is what makes rescue work when sync does not: keys are
/// copied here whenever the fleet folder is readable, so on the day it is not, this
/// machine still knows who may ask.
pub fn merge_cache(path: &Path, published: &[(String, String)]) -> Result<Vec<(String, String)>> {
    let mut all = read_cache(path);
    for (name, key) in published {
        if let Some(slot) = all.iter_mut().find(|(n, _)| n == name) {
            slot.1.clone_from(key);
        } else {
            all.push((name.clone(), key.clone()));
        }
    }
    all.sort();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        path,
        all.iter()
            .map(|(n, k)| format!("{n}\t{k}\n"))
            .collect::<String>(),
    )?;
    Ok(all)
}

/// Copy the keys your other machines published into this machine's own cache. Cheap
/// and silent; the worker calls it on every start so the cache stays current while
/// sync is healthy.
pub fn cache_keys(machine: &str) -> Result<Vec<(String, String)>> {
    let published = rescue_dir()
        .and_then(|dir| authorized_keys(&dir, machine))
        .unwrap_or_default();
    let mut merged = merge_cache(&local_cache()?, &published)?;
    merged.retain(|(n, _)| !n.eq_ignore_ascii_case(machine));
    Ok(merged)
}

/// The `ssh ...` line from `upterm session current`'s output.
#[must_use]
pub fn ssh_line(session_output: &str) -> Option<String> {
    session_output.lines().find_map(|line| {
        let at = line.find("ssh ")?;
        let rest = line[at..].trim();
        rest.contains('@').then(|| rest.to_string())
    })
}

/// The SHA-256 a published `checksums.txt` gives for `asset`.
#[must_use]
pub fn checksum_for(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        (name == asset).then(|| hash.to_lowercase())
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(std::fs::read(path)?)))
}

/// The upterm binary: on PATH, or the copy fetched for this user on first use.
pub fn upterm_binary() -> Result<PathBuf> {
    let exe = if cfg!(windows) {
        "upterm.exe"
    } else {
        "upterm"
    };
    if let Some(found) = crate::doctor::find_on_path("upterm") {
        return Ok(found);
    }
    let into = ferryman_channel::licensing::machine_state_dir()
        .context("no per-user directory to put upterm in")?
        .join("upterm");
    let binary = into.join(exe);
    if binary.is_file() {
        return Ok(binary);
    }
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "windows" => "windows",
        "macos" => "darwin",
        other => bail!("upterm publishes no build for {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("upterm publishes no build for {other}"),
    };
    let asset = format!("upterm_{os}_{arch}.tar.gz");
    let base = "https://github.com/owenthereal/upterm/releases/latest/download";
    std::fs::create_dir_all(&into)?;
    eprintln!("fetching upterm for this rescue (first use only): {base}/{asset}");
    let archive = into.join(&asset);
    let sums = into.join("checksums.txt");
    for (url, to) in [
        (format!("{base}/{asset}"), &archive),
        (format!("{base}/checksums.txt"), &sums),
    ] {
        let ok = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(to)
            .arg(&url)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            bail!("could not download {url}");
        }
    }
    let want = checksum_for(&std::fs::read_to_string(&sums)?, &asset)
        .with_context(|| format!("{asset} is not listed in upterm's checksums.txt"))?;
    if sha256_file(&archive)? != want {
        let _ = std::fs::remove_file(&archive);
        let _ = std::fs::remove_file(&sums);
        bail!("upterm download failed its checksum; nothing was installed");
    }
    let ok = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(&into)
        .status()
        .is_ok_and(|s| s.success());
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&sums);
    if !ok || !binary.is_file() {
        bail!("could not unpack upterm into {}", into.display());
    }
    Ok(binary)
}

/// Open a rescue session on this machine and hold it until the person here closes it or
/// `minutes` pass. Runs in this terminal: the person here sees who asks to join and says
/// yes or no to each.
pub fn open(machine: &str, minutes: u64) -> Result<()> {
    // From this machine's own cache, topped up from the fleet folder if it is readable.
    // Never from the fleet folder alone: rescue is for when sync may be what broke.
    let keys = cache_keys(machine)?;
    if keys.is_empty() {
        bail!(
            "this machine has never seen a rescue key from your other machines, so nobody \
             could join. Set it up ahead of time, while sync works: run `ferry rescue key` on \
             the machine you will connect from, then `ferry rescue status` here"
        );
    }
    let upterm = upterm_binary()?;
    let state = ferryman_channel::licensing::machine_state_dir()
        .context("no per-user state directory")?
        .join("rescue");
    std::fs::create_dir_all(&state)?;
    let allowed = state.join("authorized_keys");
    std::fs::write(
        &allowed,
        keys.iter()
            .map(|(_, k)| format!("{k}\n"))
            .collect::<String>(),
    )?;
    let info = state.join("session.txt");
    let _ = std::fs::remove_file(&info);

    // The shell the session runs writes the join line first. `upterm session current`
    // only works inside the session, where upterm sets its admin socket.
    let mut host = Command::new(&upterm);
    host.arg("host")
        .arg("--authorized-keys")
        .arg(&allowed)
        .arg("--");
    if cfg!(windows) {
        host.args([
            "powershell".to_string(),
            "-NoLogo".to_string(),
            "-NoExit".to_string(),
            "-Command".to_string(),
            format!(
                "& '{}' session current | Out-File -Encoding utf8 '{}'",
                upterm.display(),
                info.display()
            ),
        ]);
    } else {
        host.args([
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "'{}' session current > '{}' 2>&1; exec \"${{SHELL:-bash}}\"",
                upterm.display(),
                info.display()
            ),
        ]);
    }
    println!();
    println!("rescue session for {machine}, open for at most {minutes} minute(s).");
    println!(
        "may ask to join: {}",
        keys.iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("you approve each join here. type `exit` to close it.");
    println!();
    let mut child = host
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("start upterm")?;

    let opened = Utc::now();
    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    // Publishing the join line to the fleet folder is a convenience for when sync works.
    // The line is also printed here, for the person on this machine to read or text to
    // the person helping, which works when nothing else does.
    let published = rescue_dir()
        .ok()
        .map(|dir| dir.join("sessions"))
        .filter(|dir| std::fs::create_dir_all(dir).is_ok())
        .map(|dir| dir.join(format!("{machine}.json")));
    let mut announced = false;
    let timed_out = loop {
        if !announced
            && let Some(ssh) = std::fs::read_to_string(&info)
                .ok()
                .as_deref()
                .and_then(ssh_line)
        {
            let session = Session {
                machine: machine.to_string(),
                ssh,
                opened_at: opened,
                expires_at: opened
                    + chrono::Duration::minutes(i64::try_from(minutes).unwrap_or(30)),
            };
            eprintln!("\n================ RESCUE JOIN LINE ================");
            eprintln!("give this to the person helping you (text, phone, anything):\n");
            eprintln!("  ferry rescue join \"{}\"", session.ssh);
            eprintln!("\nit is useless without their key and your yes.");
            eprintln!("==================================================\n");
            if let Some(path) = &published {
                let _ = std::fs::write(path, serde_json::to_vec_pretty(&session)?);
            }
            announced = true;
        }
        if child.try_wait()?.is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break true;
        }
        thread::sleep(Duration::from_millis(500));
    };
    // The join line is gone the moment the session is, on every machine.
    if let Some(path) = &published {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::remove_file(&info);
    let _ = std::fs::remove_file(&allowed);
    if timed_out {
        println!("\nrescue session closed: the {minutes}-minute limit was reached");
    } else {
        println!("rescue session closed.");
    }
    Ok(())
}

/// Join another machine's open rescue session from here.
///
/// `target` is either the join line the person on that machine gave you (works with no
/// sync at all), or a machine name, looked up in the fleet folder when sync is working.
pub fn join(target: &str, this_machine: &str) -> Result<()> {
    let ssh = if let Some(line) = ssh_line(target).or_else(|| {
        // Pasted without the leading `ssh`: `TOKEN@uptermd.upterm.dev`.
        (target.contains('@') && !target.contains(char::is_whitespace))
            .then(|| format!("ssh {target}"))
    }) {
        line
    } else {
        let path = rescue_dir()?
            .join("sessions")
            .join(format!("{target}.json"));
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "no join line for {target} here. The person on {target} runs `ferry rescue \
                 open`, which prints a join line; paste it: ferry rescue join \"<that line>\""
            )
        })?;
        let session: Session = serde_json::from_slice(&bytes)?;
        if session.expired(Utc::now()) {
            bail!("{target}'s rescue session has expired; ask for a new one");
        }
        session.ssh
    };
    let machine = target;
    let key = ensure_key(this_machine)?;
    let mut args: Vec<&str> = ssh.split_whitespace().collect();
    if args.first() == Some(&"ssh") {
        args.remove(0);
    }
    println!(
        "joining {}. The person there has to approve you; wait for them.",
        if machine.contains('@') {
            "the session"
        } else {
            machine
        }
    );
    let status = Command::new("ssh")
        .arg("-i")
        .arg(&key)
        .args(["-o", "IdentitiesOnly=yes"])
        .args(&args)
        .status()
        .context("run ssh")?;
    if !status.success() {
        bail!("the rescue session ended or refused the join");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_join_line_is_found_in_session_output() {
        let out = "=== SESSION\nCommand:        bash\nSSH Command:    ssh AbC123:xyz@uptermd.upterm.dev\nAuthorized Keys: ...\n";
        assert_eq!(
            ssh_line(out).as_deref(),
            Some("ssh AbC123:xyz@uptermd.upterm.dev")
        );
        assert_eq!(ssh_line("nothing here"), None);
        assert_eq!(ssh_line("ssh is not a session"), None);
    }

    #[test]
    fn a_machine_does_not_authorize_itself_or_conflict_copies() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("allowed");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("beastly.pub"), "ssh-ed25519 AAAA beastly\n").unwrap();
        std::fs::write(keys.join("grouchly.pub"), "ssh-ed25519 BBBB grouchly\n").unwrap();
        std::fs::write(keys.join("phone.pub"), "not a key\n").unwrap();
        std::fs::write(
            keys.join("x.sync-conflict-20260101-000000-ABC.pub"),
            "ssh-ed25519 CCCC x\n",
        )
        .unwrap();
        let got = authorized_keys(dir.path(), "grouchly").unwrap();
        assert_eq!(
            got,
            vec![(
                "beastly".to_string(),
                "ssh-ed25519 AAAA beastly".to_string()
            )]
        );
        assert!(
            authorized_keys(&dir.path().join("none"), "grouchly")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_checksum_is_read_for_the_exact_asset() {
        let sums = "aa11  upterm_linux_amd64.tar.gz\nBB22  upterm_linux_amd64.deb\ncc33 *upterm_windows_amd64.tar.gz\n";
        assert_eq!(
            checksum_for(sums, "upterm_linux_amd64.tar.gz").as_deref(),
            Some("aa11")
        );
        assert_eq!(
            checksum_for(sums, "upterm_windows_amd64.tar.gz").as_deref(),
            Some("cc33")
        );
        assert_eq!(checksum_for(sums, "upterm_darwin_arm64.tar.gz"), None);
    }

    #[test]
    fn the_cache_keeps_keys_after_the_fleet_folder_stops_providing_them() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("rescue").join("allowed_keys");
        let first = vec![(
            "beastly".to_string(),
            "ssh-ed25519 AAAA beastly".to_string(),
        )];
        assert_eq!(merge_cache(&cache, &first).unwrap(), first);
        // Sync broke: nothing published is readable. The cache still knows beastly.
        assert_eq!(merge_cache(&cache, &[]).unwrap(), first);
        // A rotated key replaces the old one; a new machine is added.
        let later = vec![
            (
                "beastly".to_string(),
                "ssh-ed25519 BBBB beastly".to_string(),
            ),
            ("laptop".to_string(), "ssh-ed25519 CCCC laptop".to_string()),
        ];
        assert_eq!(merge_cache(&cache, &later).unwrap(), later);
    }

    #[test]
    fn a_session_expires_at_its_limit() {
        let now = Utc::now();
        let s = Session {
            machine: "grouchly".into(),
            ssh: "ssh t@uptermd.upterm.dev".into(),
            opened_at: now,
            expires_at: now + chrono::Duration::minutes(30),
        };
        assert!(!s.expired(now));
        assert!(s.expired(now + chrono::Duration::minutes(30)));
    }
}

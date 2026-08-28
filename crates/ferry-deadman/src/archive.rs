//! Archive construction and recovery.
//!
//! Default archiver: `git bundle --all` (+ optional secret files and user
//! globs) packed into one deterministic-entry tar.gz.
//!
//! A user-configured replacement archiver (`archive.command` in deadman.toml)
//! may produce ANY single file; recovery then proves integrity by hash alone
//! instead of by bundle verification.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use globset::GlobSet;

use crate::beacon::{create_bundle, hex_digest, path_to_str, run_git};
use crate::config::ArchiveCmd;
use crate::error::{Error, Result};

const MAX_EXTRA_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_EXTRA_BYTES: u64 = 128 * 1024 * 1024;
const BUNDLE_ENTRY: &str = "repo.bundle";
const EXTRA_PREFIX: &str = "extra/";
/// Work-tree directories never walked for extra files.
const SKIP_DIRS: &[&str] = &[".git", ".deadman", "node_modules", "target"];

/// A repo-relative path spelled the way the archive and the config both mean it:
/// `/` separated, whatever the host uses.
///
/// Windows hands back `docs\deep\runbook.md` from `strip_prefix`, and three things
/// downstream assume `/`. The include globs are gitignore-style and `/` separated, so
/// `include = ["docs/**"]` matched nothing at all on Windows and the files were left
/// out of the archive without a word - the worst shape a bug can take in a tool whose
/// job is to still have your files in ten years. `included_extras` is a record a
/// successor reads on some other machine, so it must not describe the same archive
/// two ways. And a tar entry name is POSIX by specification: a backslash in one is
/// part of the file name, not a directory separator, so an archive sealed on Windows
/// would restore as files with backslashes in their names.
fn rel_slashes(rel: &Path) -> String {
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Everything needed to seal copies of an archive.
#[derive(Debug)]
pub struct BuiltArchive {
    /// The single sealed-then-recoverable payload (tar.gz or custom blob).
    pub payload: Vec<u8>,
    pub bundle_sha256: Option<String>,
    pub archive_sha256: String,
    pub head_sha256: Option<String>,
    pub included_extras: Vec<String>,
    pub warnings: Vec<String>,
}

/// Knobs controlling how the payload is produced.
#[derive(Debug, Default)]
pub struct ArchiveOptions<'a> {
    pub include_secrets: bool,
    pub include_globs: &'a [String],
    pub archive_command: Option<&'a ArchiveCmd>,
}

/// Produce the one-file payload per the configured options.
pub fn build_archive(repo: &Path, opts: &ArchiveOptions<'_>) -> Result<BuiltArchive> {
    let head = crate::beacon::git_head(repo)?;
    if let Some(cmd) = opts.archive_command {
        return run_custom_archive(repo, cmd, head);
    }

    let scratch = tempfile::Builder::new()
        .prefix("ferry-deadman-build-")
        .tempdir_in(std::env::temp_dir())
        .map_err(|e| Error::Other(format!("cannot create temp dir: {e}")))?;
    let bundle_path = scratch.path().join("bundle.out");
    let bundle_sha = create_bundle(repo, &bundle_path)?;

    // Gather optional extras from the work tree.
    let mut extras: BTreeSet<PathBuf> = BTreeSet::new();
    let mut warnings = Vec::new();
    if opts.include_secrets {
        collect_secret_files(repo, &mut extras, &mut warnings);
    }
    if !opts.include_globs.is_empty() {
        collect_glob_matches(repo, opts.include_globs, &mut extras, &mut warnings)?;
    }

    let mut payload = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut payload, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        append_file(&mut builder, scratch.path(), "bundle.out", BUNDLE_ENTRY)?;
        for rel in &extras {
            let abs = repo.join(rel);
            let meta = std::fs::metadata(&abs)
                .map_err(|e| Error::Other(format!("cannot stat {}: {e}", abs.display())))?;
            if !meta.is_file() || meta.len() > MAX_EXTRA_FILE_BYTES {
                continue;
            }
            let name = format!("{EXTRA_PREFIX}{}", rel_slashes(rel));
            append_file(&mut builder, repo, path_to_str(rel)?, &name)?;
        }
        let enc = builder
            .into_inner()
            .map_err(|e| Error::Other(format!("tar finish failed: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Other(format!("gzip finish failed: {e}")))?;
    }
    Ok(BuiltArchive {
        archive_sha256: hex_digest(&payload),
        payload,
        bundle_sha256: Some(bundle_sha),
        head_sha256: head,
        included_extras: extras.iter().map(|p| rel_slashes(p)).collect(),
        warnings,
    })
}

/// Run the user's archiver. Contract (documented in README + template):
/// cwd = repo root, `$FERRY_DEADMAN_REPO` = repo root, `$FERRY_DEADMAN_OUT`
/// = path of the single file the command must produce.
fn run_custom_archive(repo: &Path, cmd: &ArchiveCmd, head: Option<String>) -> Result<BuiltArchive> {
    let scratch = tempfile::Builder::new()
        .prefix("ferry-deadman-custom-")
        .tempdir_in(std::env::temp_dir())
        .map_err(|e| Error::Other(format!("cannot create temp dir: {e}")))?;
    let out_path = scratch.path().join("archive.bin");
    let argv = cmd.argv();
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| Error::BadInput("archive.command must not be empty".into()))?;

    let status = std::process::Command::new(program)
        .args(args)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .env("FERRY_DEADMAN_REPO", repo)
        .env("FERRY_DEADMAN_OUT", &out_path)
        .status()
        .map_err(|e| Error::Other(format!("cannot run archive.command {:?}: {e}", program)))?;
    if !status.success() {
        return Err(Error::Other(format!(
            "archive.command exited with {status}"
        )));
    }
    let payload = std::fs::read(&out_path).map_err(|_| {
        Error::BadInput(format!(
            "archive.command did not produce the expected single file at {}",
            out_path.display()
        ))
    })?;
    Ok(BuiltArchive {
        archive_sha256: hex_digest(&payload),
        payload,
        bundle_sha256: None,
        head_sha256: head,
        included_extras: Vec::new(),
        warnings: vec![
            "custom archive command in effect: recovery verifies the payload by hash only"
                .to_string(),
        ],
    })
}

fn append_file(
    builder: &mut tar::Builder<flate2::write::GzEncoder<&mut Vec<u8>>>,
    base: &Path,
    rel: &str,
    entry_name: &str,
) -> Result<()> {
    let abs = base.join(rel);
    let mut f = std::fs::File::open(&abs)
        .map_err(|e| Error::Other(format!("cannot open {}: {e}", abs.display())))?;
    let mut header = tar::Header::new_gnu();
    let meta = f.metadata()?;
    header.set_size(meta.len());
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, entry_name, &mut f)
        .map_err(|e| Error::Other(format!("tar append {entry_name} failed: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// extra-file collection
// ---------------------------------------------------------------------------

/// Conventional secret locations, relative to the work-tree root.
/// Deterministic on purpose so tests can assert against it.
const SECRET_FILES: &[&str] = &[".env", ".env.local", ".env.production", ".env.development"];
const SECRET_EXT_PREFIXES: &[&str] = &[".env."];
const SECRET_EXTENSIONS: &[&str] = &["pem", "key"];
const SECRET_DIRS: &[&str] = &["secrets", ".secrets"];

fn collect_secret_files(repo: &Path, out: &mut BTreeSet<PathBuf>, warnings: &mut Vec<String>) {
    let mut total: u64 = 0;
    let push_candidate =
        |rel: PathBuf, out: &mut BTreeSet<PathBuf>, total: &mut u64, warnings: &mut Vec<String>| {
            if out.contains(&rel) {
                return;
            }
            let abs = repo.join(&rel);
            match std::fs::metadata(&abs) {
                Ok(meta) if meta.is_file() => {
                    if *total + meta.len() > MAX_TOTAL_EXTRA_BYTES {
                        warnings.push(format!(
                            "skipped {} (total extra-size limit reached)",
                            rel.display()
                        ));
                        return;
                    }
                    *total += meta.len();
                    out.insert(rel);
                }
                _ => {}
            }
        };

    for name in SECRET_FILES {
        push_candidate(PathBuf::from(name), out, &mut total, warnings);
    }
    // *.key / *.pem at the root only (avoid walking the whole tree).
    if let Ok(entries) = std::fs::read_dir(repo) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let lower = name.to_ascii_lowercase();
            let is_env_prefixed = SECRET_EXT_PREFIXES.iter().any(|p| lower.starts_with(p));
            let has_secret_ext = SECRET_EXTENSIONS
                .iter()
                .any(|ext| lower.ends_with(&format!(".{ext}")));
            if (is_env_prefixed || has_secret_ext) && entry.path().is_file() {
                push_candidate(PathBuf::from(name), out, &mut total, warnings);
            }
        }
    }
    // secrets/ directories.
    for dir in SECRET_DIRS {
        collect_dir_recursive(&repo.join(dir), dir, out, &mut total, warnings);
    }
}

fn collect_dir_recursive(
    abs: &Path,
    rel_prefix: &str,
    out: &mut BTreeSet<PathBuf>,
    total: &mut u64,
    warnings: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(abs) else {
        return;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        let rel = format!("{rel_prefix}/{fname}");
        let path = entry.path();
        if path.is_file() {
            let candidate = PathBuf::from(&rel);
            if !out.contains(&candidate) {
                match std::fs::metadata(&path) {
                    Ok(m)
                        if m.len() <= MAX_EXTRA_FILE_BYTES
                            && *total + m.len() <= MAX_TOTAL_EXTRA_BYTES =>
                    {
                        *total += m.len();
                        out.insert(candidate);
                    }
                    Ok(m) => {
                        warnings.push(format!("skipped {rel} (size {} bytes over limit)", m.len()))
                    }
                    Err(_) => {}
                }
            }
        } else if path.is_dir() && !SKIP_DIRS.contains(&fname) {
            collect_dir_recursive(&path, &rel, out, total, warnings);
        }
    }
}

/// Match gitignore-style globs against repo-relative paths. Patterns without
/// a `/` match against the basename at any depth (like .gitignore).
fn collect_glob_matches(
    repo: &Path,
    globs: &[String],
    out: &mut BTreeSet<PathBuf>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut full_builder = globset::GlobSetBuilder::new();
    let mut base_builder = globset::GlobSetBuilder::new();
    for (i, g) in globs.iter().enumerate() {
        if g.trim().is_empty() {
            return Err(Error::BadInput(format!(
                "include glob #{i} is empty (did you mean \"**\"?)"
            )));
        }
        let full_glob = globset::GlobBuilder::new(g.trim())
            .literal_separator(true)
            .build()
            .map_err(|e| Error::BadInput(format!("bad include glob {g:?}: {e}")))?;
        full_builder.add(full_glob);
        if !g.contains('/') {
            // Gitignore-style: bare patterns match basenames at any depth.
            let base_glob = globset::Glob::new(g.trim())
                .map_err(|e| Error::BadInput(format!("bad include glob {g:?}: {e}")))?;
            base_builder.add(base_glob);
        }
    }
    let full_set = full_builder
        .build()
        .map_err(|e| Error::BadInput(format!("bad include globs: {e}")))?;
    let base_set = base_builder
        .build()
        .map_err(|e| Error::BadInput(format!("bad include globs: {e}")))?;

    let mut total: u64 = 0;
    walk_for_globs(repo, repo, &full_set, &base_set, out, &mut total, warnings);
    Ok(())
}

fn walk_for_globs(
    repo: &Path,
    dir: &Path,
    full_set: &GlobSet,
    base_set: &GlobSet,
    out: &mut BTreeSet<PathBuf>,
    total: &mut u64,
    warnings: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(repo) else {
            continue;
        };
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let rel_str = rel_slashes(rel);
        if path.is_dir() {
            if !SKIP_DIRS.contains(&fname) {
                walk_for_globs(repo, &path, full_set, base_set, out, total, warnings);
            }
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let matched =
            full_set.is_match(rel_str.as_str()) || base_set.is_match(std::path::Path::new(fname));
        if !matched || out.contains(rel) {
            continue;
        }
        match std::fs::metadata(&path) {
            Ok(m)
                if m.len() <= MAX_EXTRA_FILE_BYTES && *total + m.len() <= MAX_TOTAL_EXTRA_BYTES =>
            {
                *total += m.len();
                out.insert(rel.to_path_buf());
            }
            Ok(m) => warnings.push(format!(
                "skipped {} ({} bytes exceeds per-file limit)",
                rel.display(),
                m.len()
            )),
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// recovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryKind {
    /// Standard ferry-deadman tar.gz carrying a verified git bundle.
    BundleTarGz,
    /// A tar.gz without a repo.bundle inside (custom archiver).
    PlainTarGz,
    /// An opaque single file produced by a custom archiver.
    Opaque,
}

#[derive(Debug)]
pub struct RecoveryReport {
    pub kind: RecoveryKind,
    /// Directory the payload was unpacked into (`dest` itself).
    pub recovered_root: PathBuf,
    pub bundle_path: Option<PathBuf>,
    pub bundle_sha256: Option<String>,
    pub refs: Vec<String>,
    pub clone_head: Option<String>,
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// Recover a decrypted payload into `dest` (created fresh).
///
/// - tar.gz payloads are unpacked; a contained `repo.bundle` is additionally
///   verified (`git bundle verify`) and cloned to prove usability end-to-end.
/// - opaque payloads are written as `recovered-archive.bin`.
pub fn recover_payload(payload: &[u8], dest: &Path) -> Result<RecoveryReport> {
    std::fs::create_dir_all(dest)?;
    if !is_gzip(payload) {
        let bin = dest.join("recovered-archive.bin");
        std::fs::write(&bin, payload)?;
        return Ok(RecoveryReport {
            kind: RecoveryKind::Opaque,
            recovered_root: dest.to_path_buf(),
            bundle_path: None,
            bundle_sha256: None,
            refs: Vec::new(),
            clone_head: None,
        });
    }

    let gz = flate2::read::GzDecoder::new(payload);
    let archive = tar::Archive::new(gz);
    let mut bundle_path: Option<PathBuf> = None;
    unpack_tar(archive, dest, &mut bundle_path)?;

    if bundle_path.is_none() {
        return Ok(RecoveryReport {
            kind: RecoveryKind::PlainTarGz,
            recovered_root: dest.to_path_buf(),
            bundle_path: None,
            bundle_sha256: None,
            refs: Vec::new(),
            clone_head: None,
        });
    }
    let bundle_path = bundle_path.expect("checked above");
    let bundle_sha = hex_digest(&std::fs::read(&bundle_path)?);

    let scratch = tempfile::Builder::new()
        .prefix("ferry-deadman-verify-")
        .tempdir_in(std::env::temp_dir())
        .map_err(|e| Error::Other(format!("cannot create verify dir: {e}")))?;
    let refs = crate::beacon::verify_bundle(&bundle_path, scratch.path())?;

    // Clone into a sibling directory to prove usability end-to-end.
    let clone_dir = dest.join("recovered-repo");
    let bundle_str = path_to_str(&bundle_path)?.to_string();
    let clone_out = run_git(
        Some(dest),
        &["clone", "--quiet", &bundle_str, path_to_str(&clone_dir)?],
    );
    let clone_head = match clone_out {
        Ok(_) => run_git(Some(&clone_dir), &["rev-parse", "HEAD"])
            .ok()
            .map(|s| s.trim().to_string()),
        Err(_) => None,
    };

    Ok(RecoveryReport {
        kind: RecoveryKind::BundleTarGz,
        recovered_root: dest.to_path_buf(),
        bundle_path: Some(bundle_path),
        bundle_sha256: Some(bundle_sha),
        refs,
        clone_head,
    })
}

fn unpack_tar<R: Read>(
    archive: tar::Archive<R>,
    dest: &Path,
    bundle_path: &mut Option<PathBuf>,
) -> Result<()> {
    let mut archive = archive;
    archive.set_preserve_permissions(false);
    for entry in archive
        .entries()
        .map_err(|e| Error::Corrupt(format!("archive is not readable tar.gz: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| Error::Corrupt(format!("archive entry unreadable: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| Error::Corrupt(format!("bad entry path: {e}")))?
            .into_owned();
        // Safety: reject anything that escapes the destination or is not a plain file.
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
            || path.is_absolute()
        {
            return Err(Error::Corrupt(format!(
                "archive contains unsafe path {path:?}"
            )));
        }
        match entry.header().entry_type() {
            tar::EntryType::Regular => {}
            _ => {
                return Err(Error::Corrupt(format!(
                    "unexpected non-file entry {path:?}"
                )));
            }
        }
        let target = dest.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Corrupt(format!("failed to read entry {path:?}: {e}")))?;
        std::fs::write(&target, &bytes)?;
        if path == Path::new(BUNDLE_ENTRY) {
            *bundle_path = Some(target);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport;

    #[test]
    fn a_recorded_path_is_slash_separated_on_every_host() {
        // The archive, the manifest and the include globs all speak `/`. This is the
        // only place that is decided, and it is decided the same way on Windows as
        // anywhere else - the alternative was `include = ["docs/**"]` matching nothing
        // there, silently, which the CI run that caught it demonstrated.
        let rel: PathBuf = ["docs", "deep", "runbook.md"].iter().collect();
        assert_eq!(rel_slashes(&rel), "docs/deep/runbook.md");
        assert_eq!(rel_slashes(Path::new(".env")), ".env");
        assert_eq!(rel_slashes(Path::new("")), "");
    }

    #[test]
    fn builds_and_recovers_roundtrip_with_secrets_and_globs() {
        let ctx = testsupport::repo_fixture("fdm-archive");
        let marker = ctx.repo().join("secrets");
        std::fs::create_dir_all(&marker).unwrap();
        std::fs::write(marker.join("api.token"), "hunter2").unwrap();
        std::fs::write(ctx.repo().join(".env"), "DB_PASS=x").unwrap();
        std::fs::create_dir_all(ctx.repo().join("docs/deep")).unwrap();
        std::fs::write(ctx.repo().join("docs/deep/runbook.md"), "# run").unwrap();

        let globs = vec!["docs/**".to_string()];
        let built = build_archive(
            ctx.repo(),
            &ArchiveOptions {
                include_secrets: true,
                include_globs: &globs,
                archive_command: None,
            },
        )
        .unwrap();
        assert!(!built.bundle_sha256.as_deref().unwrap().is_empty());
        assert!(
            built
                .included_extras
                .contains(&String::from("secrets/api.token"))
        );
        assert!(built.included_extras.contains(&String::from(".env")));
        assert!(
            built
                .included_extras
                .contains(&String::from("docs/deep/runbook.md"))
        );
        assert_eq!(built.archive_sha256, hex_digest(&built.payload));

        let tmp = tempfile::tempdir().unwrap();
        let report = recover_payload(&built.payload, tmp.path()).unwrap();
        assert_eq!(report.kind, RecoveryKind::BundleTarGz);
        assert_eq!(
            report.bundle_sha256.as_deref(),
            built.bundle_sha256.as_deref()
        );
        assert!(report.refs.iter().any(|r| r.contains("refs/heads/main")));
        assert_eq!(
            report.clone_head.as_deref(),
            ctx.head.as_deref(),
            "cloned HEAD must equal original HEAD"
        );

        let recovered_env = std::fs::read_to_string(tmp.path().join("extra/.env")).unwrap();
        assert_eq!(recovered_env, "DB_PASS=x");
        let recovered_token =
            std::fs::read_to_string(tmp.path().join("extra/secrets/api.token")).unwrap();
        assert_eq!(recovered_token, "hunter2");
        let runbook =
            std::fs::read_to_string(tmp.path().join("extra/docs/deep/runbook.md")).unwrap();
        assert_eq!(runbook, "# run");
    }

    #[test]
    fn custom_archive_produces_opaque_but_hashverifiable_payload() {
        let ctx = testsupport::repo_fixture("fdm-custom");
        let cmd = ArchiveCmd::Shell("cp hello.txt \"$FERRY_DEADMAN_OUT\"".into());
        let built = build_archive(
            ctx.repo(),
            &ArchiveOptions {
                include_secrets: false,
                include_globs: &[],
                archive_command: Some(&cmd),
            },
        )
        .unwrap();
        assert!(built.bundle_sha256.is_none());
        let tmp = tempfile::tempdir().unwrap();
        let report = recover_payload(&built.payload, tmp.path()).unwrap();
        assert_eq!(report.kind, RecoveryKind::Opaque);
        let got = std::fs::read(tmp.path().join("recovered-archive.bin")).unwrap();
        assert_eq!(got, b"hello from fdm-custom\n");
        assert_eq!(hex_digest(&got), built.archive_sha256);
    }

    #[test]
    fn failing_custom_archive_is_a_clean_error() {
        let ctx = testsupport::repo_fixture("fdm-custom-fail");
        let cmd = ArchiveCmd::Shell("exit 3".into());
        let err = build_archive(
            ctx.repo(),
            &ArchiveOptions {
                include_secrets: false,
                include_globs: &[],
                archive_command: Some(&cmd),
            },
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("exited"));
    }

    #[test]
    fn rejects_traversal_entries() {
        // Hand-craft a tar entry named "../evil.txt" (tar::Builder refuses to
        // create one, so we build the ustar header manually).
        let mut raw: Vec<u8> = Vec::new();
        let mut header = [0u8; 512];
        header[..11].copy_from_slice(b"../evil.txt");
        header[100..108].copy_from_slice(b"0000644\x00");
        header[108..116].copy_from_slice(b"0000000\x00");
        header[116..124].copy_from_slice(b"0000000\x00");
        header[124..136].copy_from_slice(b"00000000003\x00"); // size 3
        header[136..148].copy_from_slice(b"00000000000\x00"); // mtime
        header[156] = b'0'; // regular file
        header[257..263].copy_from_slice(b"ustar\x00");
        header[148..156].copy_from_slice(b"        "); // checksum placeholder
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        let chk = format!("{:06o}\x00 ", sum);
        header[148..156].copy_from_slice(chk.as_bytes());
        raw.extend_from_slice(&header);
        raw.extend_from_slice(b"pwn");
        raw.resize(raw.len() + 509, 0); // pad data block to 512

        // wrap in gzip since recover expects gz
        let mut gz_bytes = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::fast());
            std::io::Write::write_all(&mut enc, &raw).unwrap();
            enc.finish().unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        assert!(recover_payload(&gz_bytes, tmp.path()).is_err());
    }
}

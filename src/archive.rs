//! Archive construction and recovery: git bundle (+ optional secret files)
//! packed into a tar.gz.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::beacon::{create_bundle, hex_digest, path_to_str, run_git};
use crate::error::{Error, Result};

const MAX_EXTRA_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_EXTRA_BYTES: u64 = 128 * 1024 * 1024;
const BUNDLE_ENTRY: &str = "repo.bundle";
const EXTRA_PREFIX: &str = "extra/";

/// Everything needed to seal an archive.
#[derive(Debug)]
pub struct BuiltArchive {
    pub tar_gz: Vec<u8>,
    pub bundle_sha256: String,
    pub archive_sha256: String,
    pub head_sha256: Option<String>,
    pub included_extras: Vec<String>,
    pub warnings: Vec<String>,
}

/// Build `git bundle --all`, optionally add conventional secret files, and
/// compress everything into a deterministic-entry tar.gz.
pub fn build_archive(repo: &Path, include_secrets: bool) -> Result<BuiltArchive> {
    let scratch = tempfile::Builder::new()
        .prefix("ferry-deadman-build-")
        .tempdir_in(std::env::temp_dir())
        .map_err(|e| Error::Other(format!("cannot create temp dir: {e}")))?;
    let bundle_path = scratch.path().join("bundle.out");
    let bundle_sha = create_bundle(repo, &bundle_path)?;
    let head = crate::beacon::git_head(repo)?;

    // Gather optional extras from the work tree.
    let mut extras: BTreeSet<PathBuf> = BTreeSet::new();
    let mut warnings = Vec::new();
    if include_secrets {
        collect_secret_files(repo, &mut extras, &mut warnings);
    }

    let mut tar_bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        append_file(&mut builder, scratch.path(), "bundle.out", BUNDLE_ENTRY)?;
        for rel in &extras {
            let abs = repo.join(rel);
            let meta = std::fs::metadata(&abs)
                .map_err(|e| Error::Other(format!("cannot stat {}: {e}", abs.display())))?;
            if !meta.is_file() {
                continue;
            }
            if meta.len() > MAX_EXTRA_FILE_BYTES {
                warnings.push(format!(
                    "skipped {} ({} bytes exceeds per-file limit)",
                    rel.display(),
                    meta.len()
                ));
                continue;
            }
            let name = format!("{EXTRA_PREFIX}{}", rel.display());
            append_file(&mut builder, repo, path_to_str(rel)?, &name)?;
        }
        let enc = builder
            .into_inner()
            .map_err(|e| Error::Other(format!("tar finish failed: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Other(format!("gzip finish failed: {e}")))?;
    }
    Ok(BuiltArchive {
        archive_sha256: hex_digest(&tar_bytes),
        tar_gz: tar_bytes,
        bundle_sha256: bundle_sha,
        head_sha256: head,
        included_extras: extras.iter().map(|p| p.display().to_string()).collect(),
        warnings,
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
    // secrets/ directories, one level of recursion guard via walk.
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
        } else if path.is_dir() && fname != ".git" && fname != "node_modules" && fname != "target" {
            collect_dir_recursive(&path, &rel, out, total, warnings);
        }
    }
}

#[derive(Debug)]
pub struct RecoveryReport {
    pub bundle_path: PathBuf,
    pub bundle_sha256: String,
    pub refs: Vec<String>,
    pub clone_head: Option<String>,
}

/// Extract a decrypted tar.gz into `dest` (created fresh), then prove the
/// bundle is intact: verify + list refs + clone.
pub fn extract_and_verify(tar_gz: &[u8], dest: &Path) -> Result<RecoveryReport> {
    std::fs::create_dir_all(dest)?;
    let gz = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(false);

    let mut bundle_path: Option<PathBuf> = None;
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
            bundle_path = Some(target.clone());
        }
    }

    let bundle_path =
        bundle_path.ok_or_else(|| Error::Corrupt("archive does not contain repo.bundle".into()))?;
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
        Ok(_) => {
            let head = run_git(Some(&clone_dir), &["rev-parse", "HEAD"]).ok();
            head.map(|s| s.trim().to_string())
        }
        Err(_) => None,
    };

    Ok(RecoveryReport {
        bundle_path,
        bundle_sha256: bundle_sha,
        refs,
        clone_head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport;

    #[test]
    fn builds_and_recovers_roundtrip_with_secrets() {
        let ctx = testsupport::repo_fixture("fdm-archive");
        let marker = ctx.repo().join("secrets");
        std::fs::create_dir_all(&marker).unwrap();
        std::fs::write(marker.join("api.token"), "hunter2").unwrap();
        std::fs::write(ctx.repo().join(".env"), "DB_PASS=x").unwrap();

        let built = build_archive(ctx.repo(), true).unwrap();
        assert!(!built.bundle_sha256.is_empty());
        assert!(
            built
                .included_extras
                .contains(&String::from("secrets/api.token"))
        );
        assert!(built.included_extras.contains(&String::from(".env")));
        assert_eq!(built.archive_sha256, hex_digest(&built.tar_gz));

        let tmp = tempfile::tempdir().unwrap();
        let report = extract_and_verify(&built.tar_gz, tmp.path()).unwrap();
        assert_eq!(report.bundle_sha256, built.bundle_sha256);
        assert!(report.refs.iter().any(|r| r.contains("refs/heads/main")));
        assert!(report.clone_head.is_some());
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

        // wrap in gzip since extract expects gz
        let mut gz_bytes = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::fast());
            std::io::Write::write_all(&mut enc, &raw).unwrap();
            enc.finish().unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        assert!(extract_and_verify(&gz_bytes, tmp.path()).is_err());
    }
}

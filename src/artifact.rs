//! The sealed artifact container: `<repo>/.deadman/sealed-archive.tlock`.
//!
//! ```text
//! magic   b"FDM1"
//! u32 LE  header length
//! bytes   header (JSON, not secret)
//! bytes   key blob  (timelock-encrypted archive key)
//! bytes   payload   nonce(12) || AES-256-GCM(tar.gz archive)
//! ```

use std::io::{Read, Write as _};
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::error::{Error, Result};
use crate::state::Mode;

pub const MAGIC: &[u8; 4] = b"FDM1";
pub const FORMAT: &str = "ferry-deadman/v1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactHeader {
    pub format: String,
    pub mode: Mode,
    #[serde(default)]
    pub beacon_url: Option<String>,
    #[serde(default)]
    pub chain_hash: Option<String>,
    pub unlock_round: u64,
    pub period_secs: u64,
    pub genesis_unix: i64,
    pub created_unix: i64,
    /// Identity commitment of the successor this copy is sealed for.
    pub successor_fingerprint: String,
    #[serde(default)]
    pub successor_name: Option<String>,
    /// sha256 of the git bundle inside the archive (None when a custom
    /// archiver produced a payload without one).
    #[serde(default)]
    pub bundle_sha256: Option<String>,
    /// sha256 of the tar.gz payload (before encryption).
    pub archive_sha256: String,
    /// HEAD commit at seal time, when the repo had one.
    #[serde(default)]
    pub head_sha256: Option<String>,
}

#[derive(Debug)]
pub struct SealedArtifact {
    pub header: ArtifactHeader,
    pub key_blob: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

/// Encrypt the archive and serialize a complete artifact.
pub fn build_artifact(
    header: ArtifactHeader,
    master_key: &[u8; 32],
    key_blob: Vec<u8>,
    archive_tar_gz: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    crate::tlock::fill_random(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| Error::Other("aes key init failed".into()))?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce_bytes), archive_tar_gz)
        .map_err(|_| Error::Other("aes-gcm payload seal failed".into()))?;

    let header_json = serde_json::to_vec(&header)?;
    if header_json.len() > u32::MAX as usize {
        return Err(Error::Other("header impossibly large".into()));
    }
    let mut out = Vec::with_capacity(4 + 4 + header_json.len() + key_blob.len() + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&key_blob);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse an artifact without touching crypto.
pub fn parse_artifact(bytes: &[u8]) -> Result<SealedArtifact> {
    if bytes.len() < 8 || &bytes[0..4] != MAGIC {
        return Err(Error::Corrupt(
            "not a ferry-deadman artifact (bad magic)".into(),
        ));
    }
    let hdr_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let cursor = 8usize.checked_add(hdr_len).ok_or_else(corrupt)?;
    if cursor > bytes.len() || hdr_len == 0 {
        return Err(corrupt());
    }
    let header: ArtifactHeader = serde_json::from_slice(&bytes[8..cursor])
        .map_err(|e| Error::Corrupt(format!("artifact header is invalid JSON: {e}")))?;
    if header.format != FORMAT {
        return Err(Error::Corrupt(format!(
            "artifact format {:?} not supported by this version ({FORMAT})",
            header.format
        )));
    }
    let rest = &bytes[cursor..];
    // drand blob: 1+128; sim blob: 1+12+32+16
    let min_key = match header.mode {
        Mode::Drand => 1 + 96 + 16 + 16,
        Mode::Sim => 1 + 12 + 32 + 16,
    };
    if rest.len() < min_key + 12 + 16 {
        return Err(corrupt());
    }
    let key_blob = rest[..min_key].to_vec();
    let payload = &rest[min_key..];
    let nonce = payload[..12].to_vec();
    let mut encrypted_payload = nonce;
    encrypted_payload.extend_from_slice(&payload[12..]);
    Ok(SealedArtifact {
        header,
        key_blob,
        encrypted_payload,
    })
}

/// Decrypt the payload with the recovered master key; returns the tar.gz bytes.
pub fn decrypt_payload(master_key: &[u8; 32], encrypted_payload: &[u8]) -> Result<Vec<u8>> {
    if encrypted_payload.len() < 12 + 16 {
        return Err(corrupt());
    }
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| Error::Other("aes key init failed".into()))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&encrypted_payload[..12]);
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, &encrypted_payload[12..])
        .map_err(|_| {
            Error::Corrupt(
                "payload authentication failed — artifact was tampered with or truncated".into(),
            )
        })
}

fn corrupt() -> Error {
    Error::Corrupt("sealed archive is malformed".into())
}

/// Atomic file write: temp file in the same directory, then rename over target.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::BadInput(format!("{} has no parent directory", path.display())))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read a whole file, mapping missing paths to a friendly error.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)
        .map_err(|e| Error::BadInput(format!("cannot read {}: {e}", path.display())))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::Beacon;

    fn sample_header(unlock_round: u64) -> ArtifactHeader {
        ArtifactHeader {
            format: FORMAT.into(),
            mode: Mode::Sim,
            beacon_url: None,
            chain_hash: None,
            unlock_round,
            period_secs: 1,
            genesis_unix: 1_000,
            created_unix: 2_000,
            successor_fingerprint: "sha256:deadbeef".into(),
            successor_name: None,
            bundle_sha256: Some("aa".repeat(32)),
            archive_sha256: "bb".repeat(32),
            head_sha256: None,
        }
    }

    #[test]
    fn artifact_roundtrip_and_tamper_detection() {
        let beacon = Beacon::sim(10_000);
        let round = beacon.unlock_round(10_000, 3);
        let (master, key_blob) = crate::tlock::seal_master_key(&beacon, round).unwrap();
        let archive = b"pretend-tar-gz-bytes".to_vec();

        let bytes =
            build_artifact(sample_header(round), &master, key_blob.clone(), &archive).unwrap();
        let parsed = parse_artifact(&bytes).unwrap();
        assert_eq!(parsed.header.unlock_round, round);
        assert_eq!(parsed.key_blob, key_blob);

        // tamper with one payload byte → auth failure
        let mut bad = bytes.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let parsed_bad = parse_artifact(&bad).unwrap();
        assert!(decrypt_payload(&master, &parsed_bad.encrypted_payload).is_err());

        // honest roundtrip works
        let got = decrypt_payload(&master, &parsed.encrypted_payload).unwrap();
        assert_eq!(got, archive);
    }

    #[test]
    fn rejects_garbage_magic() {
        assert!(parse_artifact(b"NOPE").is_err());
        assert!(parse_artifact(&[]).is_err());
        assert!(parse_artifact(b"FDM1\x99\x00\x00\x00junkjunkjunk").is_err());
    }

    #[test]
    fn atomic_write_replaces() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x.bin");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        // no stray temp files
        let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{self, Error, Result};

/// drand quicknet: unchained BLS (keys G2 / signatures G1, RFC 9380 hashing).
/// This is the chain tlock is designed for; round signatures exist only after
/// their round time, which is what makes the timelock work.
pub const QUICKNET_CHAIN_HASH: &str =
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// Mirrors tried in order when no explicit --beacon URL is given.
pub const DEFAULT_BEACON_BASES: &[&str] = &["https://api.drand.sh", "https://drand.cloudflare.com"];

/// Simulation beacon period: one round per second.
pub const SIM_PERIOD_SECS: u64 = 1;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(HTTP_TIMEOUT))
        .build()
        .new_agent()
}

/// Tolerant view of drand chain-info JSON (v1 and v2 field names).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    #[serde(alias = "chain_hash")]
    pub hash: String,
    pub public_key: String,
    pub period: u64,
    pub genesis_time: i64,
    #[serde(alias = "schemeID")]
    pub scheme: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimParams {
    /// Unix seconds at which the simulated chain's round 1 begins.
    pub anchor_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandParams {
    pub base_url: String,
    pub chain_hash: String,
    pub info: ChainInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Beacon {
    Sim(SimParams),
    Drand(DrandParams),
}

impl Beacon {
    /// Build a simulation beacon anchored at `anchor_unix`.
    pub fn sim(anchor_unix: i64) -> Self {
        Beacon::Sim(SimParams { anchor_unix })
    }

    /// Fetch live chain info from the first mirror that answers.
    pub fn fetch_default_drand() -> Result<(String, ChainInfo)> {
        for base in DEFAULT_BEACON_BASES {
            match fetch_chain_info(base, QUICKNET_CHAIN_HASH) {
                Ok(info) => return Ok(((*base).to_string(), info)),
                Err(e) => eprintln!("warning: beacon mirror {base} unavailable: {e}"),
            }
        }
        Err(Error::Other(
            "no drand mirror reachable; pass --beacon <url> or use --simulate".into(),
        ))
    }

    /// Build a drand beacon, verifying that the endpoint really serves the
    /// expected chain.
    pub fn drand(base_url: &str, chain_hash: &str) -> Result<Self> {
        let info = fetch_chain_info(base_url, chain_hash)?;
        if !info.hash.eq_ignore_ascii_case(chain_hash) {
            return Err(Error::BadInput(format!(
                "endpoint {} serves chain {} but expected {}",
                base_url,
                info.hash,
                chain_hash.to_ascii_lowercase()
            )));
        }
        if !info.scheme.contains("unchained") || !info.scheme.contains("rfc9380") {
            return Err(Error::BadInput(format!(
                "chain scheme {:?} is not supported (need an unchained rfc9380 chain such as quicknet)",
                info.scheme
            )));
        }
        Ok(Beacon::Drand(DrandParams {
            base_url: base_url.trim_end_matches('/').to_string(),
            chain_hash: chain_hash.to_ascii_lowercase(),
            info,
        }))
    }

    pub fn period_secs(&self) -> u64 {
        match self {
            Beacon::Sim(_) => SIM_PERIOD_SECS,
            Beacon::Drand(p) => p.info.period.max(1),
        }
    }

    pub fn genesis_unix(&self) -> i64 {
        match self {
            Beacon::Sim(p) => p.anchor_unix,
            Beacon::Drand(p) => p.info.genesis_time,
        }
    }

    /// The round that is "current" at unix time `t` (round 1 starts at genesis).
    pub fn round_at(&self, t: i64) -> u64 {
        let period = self.period_secs() as i64;
        let elapsed = t - self.genesis_unix();
        if elapsed < 0 {
            return 1;
        }
        (elapsed / period) as u64 + 1
    }

    /// Unix time at which round `r` begins (its signature becomes available).
    pub fn round_time(&self, r: u64) -> i64 {
        self.genesis_unix() + ((r.saturating_sub(1)) as i64) * self.period_secs() as i64
    }

    /// The unlock round for a window measured from `now`.
    pub fn unlock_round(&self, now: i64, window_secs: u64) -> u64 {
        self.round_at(now + window_secs as i64)
    }

    /// Blocking fetch of a round signature. Returns:
    /// - `Ok(sig)` once available,
    /// - [`Error::Locked`] if it cannot exist yet (`max_wait` elapsed or sim gate hit),
    /// - `Err` for network/protocol problems worth surfacing immediately.
    ///
    /// For simulation the signature is a pure function of the round number and
    /// the gate is enforced here, so tests stay deterministic and offline.
    pub fn wait_for_signature(&self, round: u64, max_wait: Duration) -> Result<Vec<u8>> {
        let deadline = std::time::Instant::now() + max_wait;
        loop {
            let available_at = error::from_unix(self.round_time(round));
            if std::time::SystemTime::now() >= available_at {
                match self {
                    Beacon::Sim(_) => return Ok(sim_signature(round)),
                    Beacon::Drand(p) => {
                        // 404: round not published yet, keep polling.
                        if let Some(sig) = fetch_round_signature(p, round)? {
                            return Ok(sig);
                        }
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Locked {
                    round,
                    at: available_at,
                });
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - std::time::Instant::now()));
        }
    }
}

/// Deterministic fake beacon signature: pure function of the round number.
/// It carries NO secrecy — simulate mode enforces the timelock by policy
/// (the gate in [`Beacon::wait_for_signature`]), not by mathematics.
pub fn sim_signature(round: u64) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update(b"ferry-deadman/sim-chain/v1");
    h.update(round.to_le_bytes());
    h.finalize().to_vec()
}

fn http_get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T> {
    let resp = agent()
        .get(url)
        .call()
        .map_err(|e| Error::other(format!("GET {url} failed: {e}")))?;
    let body: T = resp
        .into_body()
        .read_json()
        .map_err(|e| Error::other(format!("invalid JSON from {url}: {e}")))?;
    Ok(body)
}

pub fn fetch_chain_info(base_url: &str, chain_hash: &str) -> Result<ChainInfo> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{base}/{chain_hash}/info");
    http_get_json::<ChainInfo>(&url)
}

/// `Ok(None)` means "not published yet" (HTTP 404).
fn fetch_round_signature(p: &DrandParams, round: u64) -> Result<Option<Vec<u8>>> {
    let url = format!("{}/{}/public/{round}", p.base_url, p.chain_hash);
    let resp = match agent().get(&url).call() {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(404)) => return Ok(None),
        Err(e) => return Err(Error::other(format!("GET {url} failed: {e}"))),
    };
    #[derive(Deserialize)]
    struct SigResp {
        #[serde(default)]
        round: u64,
        signature: String,
    }
    let body: SigResp = resp
        .into_body()
        .read_json()
        .map_err(|e| Error::other(format!("invalid JSON from {url}: {e}")))?;
    let sig = hex::decode(body.signature.trim())
        .map_err(|_| Error::other(format!("beacon returned non-hex signature at {url}")))?;
    if sig.len() != 48 && sig.len() != 96 {
        return Err(Error::other(format!(
            "beacon returned a signature of unexpected size {} at {url}",
            sig.len()
        )));
    }
    let _ = body.round;
    Ok(Some(sig))
}

// ---------------------------------------------------------------------------
// git helpers shared by archive building and verification
// ---------------------------------------------------------------------------

/// Run `git` with arguments, returning stdout; stderr is folded into errors.
pub fn run_git(cwd: Option<&Path>, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new("git");
    if let Some(dir) = cwd {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never");
    let out = cmd
        .output()
        .map_err(|e| Error::other(format!("failed to spawn git: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(Error::GitFailed {
            args: args.join(" "),
            stderr: format!("{}{}", stdout.trim(), stderr.trim()),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// True if `path` is inside a git work tree / repository.
pub fn is_git_repo(path: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--git-dir"])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// HEAD commit id, or `None` on an unborn branch (no commits yet).
pub fn git_head(repo: &Path) -> Result<Option<String>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(["rev-parse", "HEAD"]);
    let out = cmd
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::other(format!("failed to spawn git: {e}")))?;
    if out.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ))
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("unknown revision") || stderr.contains("ambiguous argument") {
            Ok(None)
        } else {
            Err(Error::other(format!(
                "git rev-parse HEAD failed in {}: {}",
                repo.display(),
                stderr.trim()
            )))
        }
    }
}

/// Create `git bundle --all` at `out_path`, returning its sha256 hex digest.
pub fn create_bundle(repo: &Path, out_path: &Path) -> Result<String> {
    let bundle_str = path_to_str(out_path)?;
    run_git(Some(repo), &["bundle", "create", bundle_str, "--all"]).map_err(|e| {
        Error::Other(format!(
            "git bundle failed (does the repo have at least one commit?): {e}"
        ))
    })?;
    let bytes = std::fs::read(out_path)?;
    Ok(hex_digest(&bytes))
}

/// sha256 hex digest of `bytes`.
pub fn hex_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Verify a bundle in an empty scratch repo and list its refs.
pub fn verify_bundle(bundle: &Path, scratch: &Path) -> Result<Vec<String>> {
    let bundle_str = path_to_str(bundle)?;
    run_git(Some(scratch), &["init", "--quiet"])?;
    run_git(Some(scratch), &["bundle", "verify", bundle_str])?;
    let heads = run_git(Some(scratch), &["bundle", "list-heads", bundle_str])?;
    Ok(heads
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

pub fn path_to_str(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| Error::BadInput(format!("path {} is not valid UTF-8", p.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_signature_is_deterministic_and_sized() {
        let a = sim_signature(42);
        let b = sim_signature(42);
        let c = sim_signature(43);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn round_math_sim() {
        let b = Beacon::sim(1_000);
        assert_eq!(b.period_secs(), 1);
        assert_eq!(b.round_at(999), 1); // before genesis clamps to 1
        assert_eq!(b.round_at(1_000), 1);
        assert_eq!(b.round_at(1_001), 2);
        assert_eq!(b.round_at(2_000), 1001);
        assert_eq!(b.round_time(1), 1_000);
        assert_eq!(b.round_time(42), 1_041);
        // window of 10s from t=1000 lands in round 11 (rounds are 1s apart)
        assert_eq!(b.unlock_round(1_000, 10), 11);
        assert_eq!(b.round_time(b.unlock_round(1_000, 10)), 1_010);
    }
}

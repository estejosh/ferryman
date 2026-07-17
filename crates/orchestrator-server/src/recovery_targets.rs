//! Recovery-target boundary.  Providers are deliberately inert until a project
//! names and approves a target in `bridge-project.toml` and a matching consent
//! manifest has been approved.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use async_trait::async_trait;
use sha2::Digest;

#[derive(Debug, Clone)]
pub struct Receipt {
    pub target: String,
    pub remote_id: String,
    pub sha256: String,
}

#[async_trait]
pub trait RecoveryTarget: Send + Sync {
    fn name(&self) -> &str;
    async fn availability(&self) -> Result<()>;
    async fn upload_pack(&self, manifest_hash: &str, bundle: &[u8]) -> Result<Receipt>;
    async fn download_pack(&self, remote_id: &str) -> Result<Vec<u8>>;
    async fn verify_remote_hash(&self, receipt: &Receipt) -> Result<()>;
    async fn record_receipt(&self, receipt: &Receipt) -> Result<()>;
}

#[derive(Clone)]
pub struct FilesystemTarget {
    pub name: String,
    pub root: PathBuf,
}
#[async_trait]
impl RecoveryTarget for FilesystemTarget {
    fn name(&self) -> &str {
        &self.name
    }
    async fn availability(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.root).await?;
        Ok(())
    }
    async fn upload_pack(&self, manifest_hash: &str, bundle: &[u8]) -> Result<Receipt> {
        self.availability().await?;
        let path = self.root.join(format!("{manifest_hash}.obpack"));
        tokio::fs::write(&path, bundle).await?;
        Ok(Receipt {
            target: self.name.clone(),
            remote_id: path.to_string_lossy().into_owned(),
            sha256: manifest_hash.into(),
        })
    }
    async fn download_pack(&self, remote_id: &str) -> Result<Vec<u8>> {
        tokio::fs::read(remote_id).await.map_err(Into::into)
    }
    async fn verify_remote_hash(&self, receipt: &Receipt) -> Result<()> {
        let bytes = self.download_pack(&receipt.remote_id).await?;
        let actual = hex::encode(sha2::Sha256::digest(bytes));
        if actual != receipt.sha256 {
            bail!("remote recovery hash mismatch")
        };
        Ok(())
    }
    async fn record_receipt(&self, receipt: &Receipt) -> Result<()> {
        tokio::fs::write(
            self.root.join(format!("{}.receipt", receipt.sha256)),
            format!("{}\n", receipt.remote_id),
        )
        .await?;
        Ok(())
    }
}

/// Google Drive, MEGA, and private Git implementations must be configured with
/// a credential/key reference and an approved target. These fail closed instead
/// of accepting raw credentials or sending an unverified blob.
pub struct DisabledExternalTarget {
    pub provider: String,
}
#[async_trait]
impl RecoveryTarget for DisabledExternalTarget {
    fn name(&self) -> &str {
        &self.provider
    }
    async fn availability(&self) -> Result<()> {
        bail!(
            "{} recovery target is disabled or not configured",
            self.provider
        )
    }
    async fn upload_pack(&self, _: &str, _: &[u8]) -> Result<Receipt> {
        self.availability().await?;
        unreachable!()
    }
    async fn download_pack(&self, _: &str) -> Result<Vec<u8>> {
        self.availability().await?;
        unreachable!()
    }
    async fn verify_remote_hash(&self, _: &Receipt) -> Result<()> {
        self.availability().await
    }
    async fn record_receipt(&self, _: &Receipt) -> Result<()> {
        self.availability().await
    }
}

pub fn is_named_target_policy(policy: &str, target: &str) -> bool {
    policy
        .lines()
        .any(|line| line.trim() == format!("\"{target}\", ").trim_end_matches(' '))
        || policy.contains(&format!("\"{target}\""))
}
pub fn target_path(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

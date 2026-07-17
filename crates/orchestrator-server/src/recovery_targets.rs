//! Recovery-target boundary.  Providers are deliberately inert until a project
//! names and approves a target in `bridge-project.toml` and a matching consent
//! manifest has been approved.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::Serialize;
use sha2::Digest;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
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

/// A private Git repository is a portability target, not a project repository.
/// It receives only already-encrypted bundles and their authenticated manifests.
#[derive(Clone)]
pub struct GitRecoveryTarget {
    pub repository: String,
    pub branch: String,
    pub work_root: PathBuf,
}
impl GitRecoveryTarget {
    async fn checkout(&self) -> Result<PathBuf> {
        tokio::fs::create_dir_all(&self.work_root).await?;
        let directory = self.work_root.join(Uuid::new_v4().to_string());
        git(
            &self.work_root,
            &[
                "clone",
                &self.repository,
                directory.to_string_lossy().as_ref(),
            ],
        )
        .await?;
        let remote_branch = format!("origin/{}", self.branch);
        if git(
            &directory,
            &["checkout", "-B", &self.branch, &remote_branch],
        )
        .await
        .is_err()
        {
            git(&directory, &["checkout", "-B", &self.branch]).await?;
        }
        git(
            &directory,
            &["config", "user.name", "Orchestrator Bridge Recovery"],
        )
        .await?;
        git(
            &directory,
            &["config", "user.email", "recovery@orchestrator-bridge.local"],
        )
        .await?;
        Ok(directory)
    }
    pub async fn upload_pack_and_manifest(
        &self,
        sha256: &str,
        bundle: &[u8],
        manifest: &[u8],
    ) -> Result<Receipt> {
        let checkout = self.checkout().await?;
        let packs = checkout.join("packs");
        tokio::fs::create_dir_all(&packs).await?;
        tokio::fs::write(packs.join(format!("{sha256}.obpack")), bundle).await?;
        tokio::fs::write(packs.join(format!("{sha256}.manifest.json")), manifest).await?;
        git(&checkout, &["add", "packs"]).await?;
        let _ = git(
            &checkout,
            &["commit", "-m", &format!("bridge recovery {sha256}")],
        )
        .await;
        git(
            &checkout,
            &["push", "origin", &format!("HEAD:{}", self.branch)],
        )
        .await?;
        Ok(Receipt {
            target: "private_git".into(),
            remote_id: sha256.into(),
            sha256: sha256.into(),
        })
    }
}
#[async_trait]
impl RecoveryTarget for GitRecoveryTarget {
    fn name(&self) -> &str {
        "private_git"
    }
    async fn availability(&self) -> Result<()> {
        git(&self.work_root, &["ls-remote", &self.repository])
            .await
            .map(|_| ())
    }
    async fn upload_pack(&self, sha256: &str, bundle: &[u8]) -> Result<Receipt> {
        self.upload_pack_and_manifest(sha256, bundle, b"{}").await
    }
    async fn download_pack(&self, remote_id: &str) -> Result<Vec<u8>> {
        let checkout = self.checkout().await?;
        tokio::fs::read(checkout.join("packs").join(format!("{remote_id}.obpack")))
            .await
            .map_err(Into::into)
    }
    async fn verify_remote_hash(&self, receipt: &Receipt) -> Result<()> {
        let bytes = self.download_pack(&receipt.remote_id).await?;
        if hex::encode(sha2::Sha256::digest(bytes)) != receipt.sha256 {
            bail!("private Git recovery hash mismatch")
        };
        Ok(())
    }
    async fn record_receipt(&self, _: &Receipt) -> Result<()> {
        Ok(())
    }
}

async fn git(directory: &Path, args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(directory)
        .output()
        .await?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::process::Command;

    #[tokio::test]
    async fn private_git_target_round_trips_an_encrypted_blob() {
        let root = std::env::temp_dir().join(format!("bridge-git-target-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let repository = root.join("recovery.git");
        assert!(
            Command::new("git")
                .args(["init", "--bare", repository.to_string_lossy().as_ref()])
                .status()
                .unwrap()
                .success()
        );
        let target = GitRecoveryTarget {
            repository: repository.to_string_lossy().into_owned(),
            branch: "bridge/recovery".into(),
            work_root: root.join("work"),
        };
        let bundle = b"opaque encrypted bundle";
        let hash = hex::encode(sha2::Sha256::digest(bundle));
        let receipt = target
            .upload_pack_and_manifest(&hash, bundle, b"{\"format\":\"test\"}")
            .await
            .unwrap();
        target.verify_remote_hash(&receipt).await.unwrap();
        assert_eq!(target.download_pack(&hash).await.unwrap(), bundle);
    }
}

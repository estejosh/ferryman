use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use orchestrator_core::{AgentPersistence, Project};

pub fn project_directory(root: &Path, project_id: &str) -> Result<PathBuf> {
    let slug = slug(project_id);
    if slug.is_empty() {
        bail!("project id must contain letters or numbers")
    }
    Ok(root.join(slug))
}

/// Creates a local-only Git repository. The bridge never sets a remote or calls a
/// hosting provider, so it cannot accidentally create a public repository.
pub fn provision_private_repository(
    root: &Path,
    project_id: &str,
    project_name: &str,
) -> Result<PathBuf> {
    let directory = project_directory(root, project_id)?;
    fs::create_dir_all(directory.join(".orchestrator/agents"))?;
    if !directory.join(".git").exists() {
        let status = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&directory)
            .status()
            .context("run git init")?;
        if !status.success() {
            bail!("git init failed for {}", directory.display())
        }
    }
    let remote = Command::new("git")
        .args(["remote"])
        .current_dir(&directory)
        .output()
        .context("inspect Git remotes")?;
    if !remote.stdout.is_empty() {
        bail!("refusing workspace with a configured remote; bridge repositories stay local/private")
    }
    let note = directory.join(".orchestrator/REPOSITORY.md");
    if !note.exists() {
        fs::write(
            &note,
            format!(
                "# Private local repository\n\n- Project: {project_name}\n- Project ID: {project_id}\n- Device: {}\n- Naming convention: `{}`\n\nThis repository was created by Orchestrator Bridge. It has no remote by design. The bridge must never publish it or add a remote automatically. On another device, the same project ID creates the same local directory name and a new private local Git repository.\n",
                device_id(),
                slug(project_id)
            ),
        )?;
    }
    let manifest = directory.join("bridge-project.toml");
    if !manifest.exists() {
        fs::write(
            &manifest,
            format!(
                "# Orchestrator Bridge project policy. Keep this file in the private local repository.\nformat = \"orchestrator-bridge-project/v1\"\nproject_id = \"{project_id}\"\nproject_name = {project_name:?}\nretention = \"retained-artifacts-only\"\nartifact_quota_bytes = 104857600\nallowed_capabilities = []\n\n[portability]\n# External targets receive only opaque encrypted continuity packs.\nrecovery_order = [\"local\", \"network\", \"google_drive\", \"mega\", \"private_git\"]\npreapproved_encrypted_pack_fallback = false\napproved_targets = []\n\n[github]\n# Draft PR delivery only; never configure a default-branch push here.\ndraft_pr_only = true\nrecovery_branch = \"bridge/recovery\"\n\n[updates]\n# Each project must opt in before a system-wide Bridge update touches its metadata.\nopt_in = false\ncompatibility = \"minor\"\n",
                project_name = project_name
            ),
        )?;
    }
    Ok(directory)
}

pub fn write_agent_profile(
    project: &Project,
    role: &str,
    description: &str,
    persistence: &AgentPersistence,
) -> Result<(String, PathBuf)> {
    let name = format!("{}-{}", slug(&project.id), slug(role));
    if name.ends_with('-') {
        bail!("agent role must contain letters or numbers")
    }
    let path = PathBuf::from(&project.workspace_path)
        .join(".orchestrator/agents")
        .join(format!("{name}.md"));
    if !path.exists() {
        let lifecycle = match persistence {
            AgentPersistence::Temporal => "temporal",
            AgentPersistence::Permanent => "permanent",
        };
        fs::write(
            &path,
            format!(
                "# {name}\n\n- Project: {} (`{}`)\n- Role: {role}\n- Lifecycle: {lifecycle}\n\n## Purpose\n\n{description}\n\n## Orchestrator instructions\n\nUse this agent only for the stated role. A **temporal** agent is created for a bounded job or workflow and may be retired when that work finishes. A **permanent** agent is retained as project infrastructure and may be reused by future orchestrators. Read this profile before assigning work; preserve the project/role-derived name rather than inventing a generic agent label.\n",
                project.name, project.id
            ),
        )?;
    }
    Ok((name, path))
}

pub fn select_artifact_root(local: PathBuf, _network: Option<PathBuf>) -> PathBuf {
    // Network disks are recovery targets, never the preferred artifact root.
    // A local write is authoritative; a recovery pack can fall back to a named
    // network target only when local pack storage is unavailable and policy has
    // approved that target.
    local
}
fn slug(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
fn device_id() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-device".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn naming_is_project_and_role_derived() {
        assert_eq!(slug("Home Studio"), "home-studio");
        assert_eq!(slug("QA / Safety"), "qa-safety");
    }
}

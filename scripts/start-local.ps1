param(
  [string]$DataRoot = "$PSScriptRoot\..\.data",
  [string]$RecoveryGitRepository = 'https://github.com/estejosh/orchestrator-bridge-recovery.git'
)

$ErrorActionPreference = 'Stop'
$reference = 'keychain:OrchestratorBridge:recovery'
$env:ORCHESTRATOR_RECOVERY_KEY_REFERENCE = $reference

try {
  cargo run -p orchestrator-cli --bin orchestrator-key -- verify | Out-Null
} catch {
  Write-Host 'Creating your local recovery key in Windows Credential Manager...'
  cargo run -p orchestrator-cli --bin orchestrator-key -- bootstrap
}

Write-Host 'Starting a local-only Bridge. Nothing is exposed to the internet.'
cargo run -p orchestrator-server -- --database "$DataRoot\bridge.db" --artifacts "$DataRoot\artifacts" --workspace-root "$DataRoot\projects" --memory-root "$DataRoot\memory" --recovery-root "$DataRoot\recovery" --recovery-git-repository "$RecoveryGitRepository"

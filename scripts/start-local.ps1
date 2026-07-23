param(
  [string]$DataRoot = "$PSScriptRoot\..\.data",
  [string]$RecoveryGitRepository = 'https://github.com/estejosh/ferryman-recovery.git'
)

$ErrorActionPreference = 'Stop'
$reference = 'keychain:Ferryman:recovery'
$env:FERRYMAN_RECOVERY_KEY_REFERENCE = $reference

try {
  cargo run -p ferryman-cli --bin ferryman-key -- verify | Out-Null
} catch {
  Write-Host 'Creating your local recovery key in Windows Credential Manager...'
  cargo run -p ferryman-cli --bin ferryman-key -- bootstrap
}

Write-Host 'Starting a local-only Bridge. Nothing is exposed to the internet.'
cargo run -p ferryman-server -- --database "$DataRoot\bridge.db" --artifacts "$DataRoot\artifacts" --workspace-root "$DataRoot\projects" --memory-root "$DataRoot\memory" --recovery-root "$DataRoot\recovery" --recovery-git-repository "$RecoveryGitRepository"

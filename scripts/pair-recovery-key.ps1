param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('Export', 'Import')]
  [string]$Mode,
  [string]$Path = "$env:USERPROFILE\Desktop\bridge-recovery-pairing.obkey"
)

$ErrorActionPreference = 'Stop'

if ($Mode -eq 'Export') {
  Write-Host 'This makes an encrypted pairing file. The passphrase is requested securely and is never saved.'
  cargo run -p orchestrator-cli --bin orchestrator-key -- pairing-export --output $Path
  Write-Host 'Copy that one encrypted file to the second trusted machine. Do not send the passphrase with it.'
} else {
  Write-Host 'Enter the passphrase used on the first machine. The recovery key will be stored in Windows Credential Manager.'
  cargo run -p orchestrator-cli --bin orchestrator-key -- pairing-import --input $Path
}

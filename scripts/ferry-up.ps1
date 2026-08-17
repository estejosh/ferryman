# Get Ferryman current and this repository attached, in one command.
#
#   irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/ferry-up.ps1 | iex
#   .\ferry-up.ps1 -Email you@example.com
#
# The Windows half of `ferry-up.sh`; the reasoning is in that file. Kept as a separate
# script rather than a shim because there is no `sh` on a default Windows install -
# which is not a hypothetical here: hardcoding `sh` is a bug this project has now
# shipped twice and fixed twice.

[CmdletBinding()]
param(
    [string]$Email = $env:FERRYMAN_EMAIL,
    [switch]$NoEnable
)

$ErrorActionPreference = 'Stop'
function Say  { param([string]$m) Write-Host "ferry-up: $m" }
function Warn { param([string]$m) Write-Warning "ferry-up: $m" }

# ---------------------------------------------------------------- before

# Recorded before anything changes: "did my identity survive?" cannot be answered
# afterwards from memory.
$beforeVersion = try { (& ferry --version 2>&1 | Out-String).Trim() } catch { 'not installed' }
if ([string]::IsNullOrWhiteSpace($beforeVersion)) { $beforeVersion = 'not installed' }

function Get-KeyFingerprints {
    if (-not (Test-Path .ferryman\keys)) { return $null }
    # Fingerprints only. The key itself never leaves the machine and must not be logged.
    Get-ChildItem .ferryman\keys\*.key -ErrorAction SilentlyContinue |
        ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash.Substring(0, 16) } |
        Sort-Object
}
$beforeKeys = Get-KeyFingerprints

Say "before: $beforeVersion"

# ---------------------------------------------------------------- install

Say 'installing or updating ferry...'
Invoke-RestMethod https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | Invoke-Expression

if (-not (Get-Command ferry -ErrorAction SilentlyContinue)) {
    throw 'ferry is still not on PATH; open a new shell (the installer updates PATH for new sessions) and re-run'
}

$afterVersion = (& ferry --version 2>&1 | Out-String).Trim()
Say "after:  $afterVersion"
if ($beforeVersion -eq $afterVersion -and $beforeVersion -ne 'not installed') {
    # Worth saying out loud: the previous release reported an identical version string
    # before and after a day of changes, so "nothing appears to have happened" was
    # indistinguishable from "nothing happened".
    Say 'the version and commit are unchanged, so this machine was already current'
}

# ---------------------------------------------------------------- attach

if (-not $NoEnable) {
    if (Test-Path .ferryman\bridge.toml) {
        Say 'this repository is already attached; leaving its configuration alone'
    }
    elseif ([string]::IsNullOrWhiteSpace($Email)) {
        Warn 'this repository is not attached, and no email was given'
        Warn 'run:  .\ferry-up.ps1 -Email you@example.com   (or set FERRYMAN_EMAIL)'
    }
    else {
        Say "attaching this repository as $(Split-Path -Leaf (Get-Location))..."
        # `enable` never prompts and is safe to run twice.
        & ferry enable --email $Email
    }
}

# ---------------------------------------------------------------- after

if (Test-Path .ferryman\bridge.toml) {
    Write-Host ''
    Say 'where this repository stands:'
    & ferry channel status
    Write-Host ''
    & ferry channel agents
    Write-Host ''
    # The check that matters after an upgrade: a new binary that cannot verify
    # signatures written by the old one is exactly what this exists to catch.
    Say 'signature check on every artifact (all should read Valid):'
    & ferry channel tasks
    Write-Host ''
}

$afterKeys = Get-KeyFingerprints
if ($beforeKeys) {
    if (($beforeKeys -join ',') -eq ($afterKeys -join ',')) {
        Say 'signing key unchanged (upgrading never rotates one)'
    }
    else {
        # Loud, and stop. A changed key means every artifact this machine published
        # stops verifying elsewhere, and recovering is a restore, not a retry.
        Warn ''
        Warn '*** THE SIGNING KEY CHANGED. STOP. ***'
        Warn 'Every artifact this machine published will now fail to verify elsewhere.'
        Warn 'Restore .ferryman\keys from a backup before running anything else, and'
        Warn 'please report this: https://github.com/estejosh/ferryman/issues'
        exit 1
    }
}

@'
next:
  ferry agent run        # this machine does work
  ferry agent review     # this machine judges results
  ferry soak             # a report to paste into an issue while we soak-test

Run this same command on every machine in the fleet, then compare the commit in
`ferry --version`. If they differ, they are not running the same Ferryman.
'@ | Write-Host

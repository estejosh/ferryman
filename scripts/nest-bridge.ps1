#requires -version 5
<#
.SYNOPSIS
  Set up a full, self-contained Ferryman bridge nested inside a project repo.
.DESCRIPTION
  Creates <Project>\.ferryman\ which:
    - runs its own Ferryman server + SQLite data from inside the project,
    - is its OWN git repo (the bridge sub-project is versioned independently),
    - is gitignored by the parent project so it never pollutes the main repo.
  This unblocks agents that are sandboxed to their project directory and cannot
  reach a sibling bridge checkout.
.EXAMPLE
  powershell -File scripts\nest-bridge.ps1 -Project C:\code\myproject -Port 8791
#>
param(
  [string]$Project = (Get-Location).Path,
  [int]$Port = 8787,
  [string]$ProjectSlug = 'demo'
)
$ErrorActionPreference = 'Stop'
$DirName = '.ferryman'
$Bridge  = Join-Path $Project $DirName

# 1) parent repo ignores the nested bridge
git -C $Project rev-parse --git-dir *> $null
if ($LASTEXITCODE -eq 0) {
  $gi = Join-Path $Project '.gitignore'
  $entry = "/$DirName/"
  $present = (Test-Path $gi) -and ((Get-Content $gi -ErrorAction SilentlyContinue) -contains $entry)
  if (-not $present) {
    Add-Content -Path $gi -Value "`r`n# Ferryman nested bridge (its own git repo; not part of this project)`r`n$entry"
    Write-Host "gitignore: added $entry to $gi"
  }
} else {
  Write-Host "note: $Project is not a git repo; skipped parent .gitignore step"
}

# 2) bridge folder + data dir + its own git repo
New-Item -ItemType Directory -Force -Path (Join-Path $Bridge '.data') | Out-Null
if (-not (Test-Path (Join-Path $Bridge '.git'))) {
  git -C $Bridge init -q
  Write-Host "git: initialized bridge sub-repo at $Bridge"
}

# 3) the bridge's own .gitignore (runtime state stays out of the sub-repo)
@"
# Runtime state - never committed to the bridge sub-repo
.data/
*.log
bin/
target/
"@ | Set-Content -Path (Join-Path $Bridge '.gitignore') -Encoding ascii

# 4) config
@"
# Ferryman nested bridge
endpoint = "http://127.0.0.1:$Port"
project  = "$ProjectSlug"
# All state lives under .data\ in this folder.
"@ | Set-Content -Path (Join-Path $Bridge 'bridge.toml') -Encoding ascii

# 5) start helper (port baked in; override the binary with $env:FERRYMAN_BIN)
$start = @'
#requires -version 5
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin  = if ($env:FERRYMAN_BIN) { $env:FERRYMAN_BIN } else { 'ferryman-server' }
& $bin `
  --database       (Join-Path $here '.data\bridge.db') `
  --artifacts      (Join-Path $here '.data\artifacts') `
  --workspace-root (Join-Path $here '.data\projects') `
  --memory-root    (Join-Path $here '.data\bridge-memory') `
  --recovery-root  (Join-Path $here '.data\recovery') `
  --listen '127.0.0.1:__PORT__'
'@ -replace '__PORT__', $Port
$start | Set-Content -Path (Join-Path $Bridge 'start.ps1') -Encoding ascii

# 6) short README inside the bridge
@"
# Nested Ferryman bridge

This folder is a self-contained Ferryman bridge for the parent project.
It is its own git repo and is gitignored by the parent, so it never pollutes
the main project's history.

- Start:  powershell -File start.ps1   (needs ferryman-server on PATH or `$env:FERRYMAN_BIN)
- API:    http://127.0.0.1:$Port
- State:  everything under .data\ (gitignored here too)

See the Ferryman repo docs/NESTED_BRIDGE.md for the full model.
"@ | Set-Content -Path (Join-Path $Bridge 'README.md') -Encoding ascii

# attribution notice (Ferryman Source-Available License, section 5)
@"
This project uses Ferryman (https://github.com/estejosh/ferryman),
licensed under the Ferryman Source-Available License.
"@ | Set-Content -Path (Join-Path $Bridge 'NOTICE.md') -Encoding ascii

Write-Host ""
Write-Host "Nested bridge ready: $Bridge  (API http://127.0.0.1:$Port)"
Write-Host "Next: cd `"$Bridge`"; powershell -File start.ps1"

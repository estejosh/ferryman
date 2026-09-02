<#
.SYNOPSIS
Remove Ferryman from this machine.

.DESCRIPTION
Deliberately conservative about three things, because getting any of them wrong is
worse than leaving a file behind:

  - Your OPERATOR IDENTITY is never deleted without -Identity. It is sealed under a
    password nothing else holds a copy of, and if you uninstall to reinstall you want it
    to still be there. A disk cleaner deleting one is what taught us this.
  - Your CHANNELS are never deleted. They are the coordination history for real work,
    they live inside your projects, and Syncthing would carry the deletion to every
    other machine in the fleet.
  - Nothing outside Ferryman's own directories is touched. Syncthing is not ours.

.PARAMETER Identity
Also remove your operator identity and its spare copy. There is no undo except your
24-word recovery phrase.

.PARAMETER DryRun
List what would be removed, and remove nothing.
#>
[CmdletBinding()]
param(
    [switch]$Identity,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host "ferryman: $m" }

$state  = Join-Path $env:LOCALAPPDATA 'Ferryman'
$refuge = Join-Path $env:USERPROFILE  '.ferryman'
$binDir = if ($env:FERRYMAN_BINDIR) { $env:FERRYMAN_BINDIR } else { Join-Path $env:LOCALAPPDATA 'Ferryman\bin' }

$targets = @()
if (Test-Path (Join-Path $binDir 'ferry.exe')) { $targets += (Join-Path $binDir 'ferry.exe') }
if (Test-Path $state)  { $targets += $state }
if ($Identity -and (Test-Path $refuge)) { $targets += $refuge }

if (-not $targets) { Say "nothing to remove - Ferryman is not installed here"; return }

# A running dashboard or worker holds ferry.exe open, and a delete that half-succeeds is
# worse than one that refuses. Say so rather than failing with a locked-file error.
$running = Get-Process -Name ferry -ErrorAction SilentlyContinue
if ($running -and -not $DryRun) {
    Say "ferry is still running (pid $($running.Id -join ', ')). Stop it first, then run this again."
    return
}

foreach ($t in $targets) {
    if ($DryRun) { Say "would remove $t" }
    else { Remove-Item -Recurse -Force $t; Say "removed $t" }
}

if (-not $Identity -and (Test-Path $refuge)) {
    Say "kept your operator identity in $refuge - re-run with -Identity to remove it too"
}
Say "your project channels (.ferryman inside each project) were not touched"

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Workspace,
  [switch]$Json
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
  param(
    [ValidateSet('PASS','WARN','FAIL')][string]$Level,
    [string]$Check,
    [string]$Detail
  )
  $results.Add([pscustomobject]@{
    level = $Level
    check = $Check
    detail = $Detail
  })
}

function Invoke-GitRead {
  param([string]$Directory, [string[]]$Arguments)
  $output = (& git -C $Directory @Arguments 2>&1) -join "`n"
  return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output.Trim() }
}

function Get-SafeTree {
  param([string]$Root)
  $pending = [System.Collections.Generic.Stack[string]]::new()
  $pending.Push($Root)
  while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    foreach ($entry in Get-ChildItem -LiteralPath $directory -Force) {
      $entry
      if ($entry.PSIsContainer -and
          -not ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and
          $entry.Name -ne '.git') {
        $pending.Push($entry.FullName)
      }
    }
  }
}

$workspacePath = [System.IO.Path]::GetFullPath($Workspace)
if (-not (Test-Path -LiteralPath $workspacePath -PathType Container)) {
  Add-Result FAIL workspace "Workspace does not exist: $workspacePath"
} else {
  Add-Result PASS workspace $workspacePath
}

$attachment = Join-Path $workspacePath '.ferryman'
$communications = Join-Path $attachment 'ferryman'
$mainGit = Join-Path $workspacePath '.git'

if (Test-Path -LiteralPath $mainGit) {
  $mainRemote = Invoke-GitRead $workspacePath @('config','--get','remote.origin.url')
  Add-Result PASS main_remote $(if ($mainRemote.Output) { $mainRemote.Output } else { '(none)' })
  $ignored = Invoke-GitRead $workspacePath @('check-ignore','-q','.ferryman')
  if ($ignored.ExitCode -eq 0) {
    Add-Result PASS main_ignore '/.ferryman/ is ignored by the main project'
  } else {
    Add-Result FAIL main_ignore '/.ferryman/ is not ignored by the main project'
  }
} else {
  Add-Result WARN main_git 'Workspace is not a Git checkout'
}

if (-not (Test-Path -LiteralPath $attachment -PathType Container)) {
  Add-Result WARN attachment 'No .ferryman attachment exists'
  $safeEntries = @()
} else {
  Add-Result PASS attachment $attachment
  $safeEntries = @(Get-SafeTree $attachment)
  $reparsePoints = @($safeEntries |
    Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
  if ($reparsePoints.Count -eq 0) {
    Add-Result PASS reparse_points 'No reparse points or symlinks under .ferryman'
  } else {
    Add-Result FAIL reparse_points (($reparsePoints.FullName | Sort-Object) -join '; ')
  }
}

if (Test-Path -LiteralPath (Join-Path $attachment 'token') -PathType Leaf) {
  Add-Result PASS outer_token 'Outer token exists; contents were not read'
} else {
  Add-Result WARN outer_token 'Outer token is absent; hub registration may be deferred'
}

if (-not (Test-Path -LiteralPath (Join-Path $communications '.git'))) {
  Add-Result WARN inner_git 'Portable communications Git checkout is absent'
} else {
  $innerRemote = Invoke-GitRead $communications @('config','--get','remote.origin.url')
  $scanOwner = $env:FERRYMAN_CHANNEL_GIT_OWNER
  $scanSuffix = if ($env:FERRYMAN_CHANNEL_GIT_SUFFIX) { $env:FERRYMAN_CHANNEL_GIT_SUFFIX } else { '-ferryman' }
  $expectedPattern = '^https://github\.com/' + [regex]::Escape($scanOwner) + '/[A-Za-z0-9._-]+' + [regex]::Escape($scanSuffix) + '(?:\.git)?$'
  if (-not $innerRemote.Output) {
    # No upstream at all is the Syncthing-only channel, not a failure.
    Add-Result PASS inner_remote '(none; Syncthing-only)'
  } elseif (-not $scanOwner) {
    Add-Result FAIL inner_remote "$($innerRemote.Output) (set FERRYMAN_CHANNEL_GIT_OWNER to pin the expected owner)"
  } elseif ($innerRemote.ExitCode -eq 0 -and $innerRemote.Output -match $expectedPattern) {
    Add-Result PASS inner_remote $innerRemote.Output
  } else {
    Add-Result FAIL inner_remote $innerRemote.Output
  }
  $innerStatus = Invoke-GitRead $communications @('status','--porcelain','--untracked-files=all')
  if ($innerStatus.ExitCode -ne 0) {
    Add-Result FAIL inner_status $innerStatus.Output
  } elseif ($innerStatus.Output) {
    Add-Result WARN inner_status $innerStatus.Output
  } else {
    Add-Result PASS inner_status 'Portable repository is clean'
  }
}

foreach ($forbidden in @('token','runtime')) {
  $path = Join-Path $communications $forbidden
  if (Test-Path -LiteralPath $path) {
    Add-Result FAIL "inner_$forbidden" "Forbidden portable path exists: $path"
  } else {
    Add-Result PASS "inner_$forbidden" "No portable $forbidden path"
  }
}

if (Test-Path -LiteralPath $communications -PathType Container) {
  $suspicious = @($safeEntries |
    Where-Object {
      -not $_.PSIsContainer -and
      $_.FullName.StartsWith($communications, [System.StringComparison]::OrdinalIgnoreCase) -and
      $_.Name -match '(^\.env(?:\.|$)|token|secret|credential|password|\.sqlite3?$|\.db$|\.lock$)'
    })
  if ($suspicious.Count -eq 0) {
    Add-Result PASS portable_names 'No suspicious portable filenames'
  } else {
    Add-Result FAIL portable_names (($suspicious.FullName | Sort-Object) -join '; ')
  }
}

$standard = Join-Path $communications 'STANDARD.toml'
if (Test-Path -LiteralPath $standard -PathType Leaf) {
  $revisionLine = Get-Content -LiteralPath $standard |
    Where-Object { $_ -match '^revision\s*=\s*\d+\s*$' } |
    Select-Object -First 1
  $revision = if ($revisionLine -match '(\d+)') { [int]$Matches[1] } else { 0 }
  if ($revision -eq 2) {
    Add-Result PASS standard_revision 'Ferryman project standard revision 2'
  } elseif ($revision -gt 2) {
    Add-Result FAIL standard_revision "Project revision $revision is newer than this Ferryman checkout"
  } else {
    Add-Result WARN standard_revision "Project revision $revision needs update to revision 2"
  }
} else {
  Add-Result WARN standard_revision 'STANDARD.toml is missing; project needs a standard update'
}

if ($Json) {
  $results | ConvertTo-Json -Depth 4
} else {
  $results | Format-Table -AutoSize
}

if ($results.Where({ $_.level -eq 'FAIL' }).Count -gt 0) {
  exit 2
}

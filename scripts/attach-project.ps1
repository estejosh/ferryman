[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][string]$Workspace,
  [Parameter(Mandatory)][string]$Project,
  [Parameter(Mandatory)][string]$SharedRemote,
  # Optional: omit for a Syncthing-only channel with no Git rung at all.
  [string]$GitRemote = '',
  [string]$AdoptFrom,
  [string]$Hub = 'http://127.0.0.1:8796',
  [string]$WslDistribution = 'Ubuntu',
  [ValidateSet('unmanaged','single-agent','multi-agent')]
  [string]$IntegrationMode = 'unmanaged',
  [string[]]$Participant = @(),
  [switch]$UpdateStandard,
  [switch]$DryRun,
  [switch]$SkipMegaRegistration,
  [switch]$SkipHubRegistration
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked {
  param([string]$Program, [string[]]$Arguments, [string]$WorkingDirectory)
  if ($DryRun) {
    Write-Host "DRY-RUN: $Program $($Arguments -join ' ') [cwd=$WorkingDirectory]"
    return ''
  }
  $previousPreference = $ErrorActionPreference
  $locationPushed = $false
  try {
    Push-Location -LiteralPath $WorkingDirectory
    $locationPushed = $true
    # Windows PowerShell promotes native stderr (including harmless Git progress)
    # to a terminating NativeCommandError when the script preference is Stop.
    $ErrorActionPreference = 'Continue'
    $output = & $Program @Arguments 2>&1
    $exitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousPreference
    if ($locationPushed) { Pop-Location }
  }
  if ($exitCode -ne 0) { throw "$Program failed: $output" }
  return ($output -join "`n")
}

function Write-NewText {
  param([string]$Path, [string]$Content)
  if (Test-Path -LiteralPath $Path) {
    $existing = Get-Content -LiteralPath $Path -Raw
    if ($existing -ne $Content) {
      throw "Refusing to overwrite existing file: $Path"
    }
    Write-Host "OK existing: $Path"
    return
  }
  if ($DryRun) { Write-Host "DRY-RUN: create $Path"; return }
  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Write-ManagedText {
  param([string]$Path, [string]$Content)
  if ((Test-Path -LiteralPath $Path) -and $UpdateStandard) {
    $existing = Get-Content -LiteralPath $Path -Raw
    if ($existing -eq $Content) {
      Write-Host "OK current standard: $Path"
      return
    }
    if ($DryRun) {
      Write-Host "DRY-RUN: update Ferryman-managed standard file $Path"
      return
    }
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
    Write-Host "UPDATED standard file: $Path"
    return
  }
  Write-NewText -Path $Path -Content $Content
}

function Normalize-GitRemote {
  param([string]$Remote)
  return ($Remote.Trim().ToLowerInvariant() -replace '\.git$','')
}

function Convert-ParticipantRoutes {
  $seenNames = @{ 'project-inbox' = $true }
  $routes = @(
    @{
      name = 'project-inbox'
      role = 'project'
      capabilities = @('messages.receive')
    }
  )
  foreach ($specification in $Participant) {
    $fields = $specification.Split('|')
    if ($fields.Count -lt 2 -or $fields.Count -gt 3) {
      throw "Participant must use name|role|capability1,capability2: $specification"
    }
    $name = $fields[0].Trim()
    $role = $fields[1].Trim()
    if ($name -in @('.','..') -or $role -in @('.','..') -or
        $name -notmatch '^[A-Za-z0-9._-]+$' -or $role -notmatch '^[A-Za-z0-9._-]+$') {
      throw "Participant name and role must be path-safe: $specification"
    }
    if ($seenNames.ContainsKey($name)) {
      throw "Participant names must be unique and cannot replace project-inbox: $name"
    }
    $seenNames[$name] = $true
    $capabilities = if ($fields.Count -eq 3 -and -not [string]::IsNullOrWhiteSpace($fields[2])) {
      @($fields[2].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else { @() }
    $routes += @{
      name = $name
      role = $role
      capabilities = $capabilities
    }
  }
  return @($routes)
}

$workspacePath = [System.IO.Path]::GetFullPath($Workspace)
if (-not (Test-Path -LiteralPath $workspacePath -PathType Container)) {
  throw "Workspace does not exist: $workspacePath"
}
$attachment = Join-Path $workspacePath '.ferryman'
$communications = Join-Path $attachment 'ferryman'
$gitSuffix = if ($env:FERRYMAN_CHANNEL_GIT_SUFFIX) { $env:FERRYMAN_CHANNEL_GIT_SUFFIX } else { '-ferryman' }
$expectedName = "$Project$gitSuffix"
$channelOwner = $env:FERRYMAN_CHANNEL_GIT_OWNER
$participantRoutes = @(Convert-ParticipantRoutes)
if ($Project -in @('.','..') -or $Project -notmatch '^[A-Za-z0-9._-]+$') {
  throw 'Project must be a path-safe identifier'
}
# Pinning the channel to a canonical location stops a tampered or mistaken mapping from
# redirecting a private channel somewhere else. Fail closed: a remote that cannot be
# pinned is refused rather than accepted unpinned. An absent remote is the
# Syncthing-only channel and is valid.
if ($GitRemote) {
  if (-not $channelOwner) {
    throw 'A Git remote was supplied but FERRYMAN_CHANNEL_GIT_OWNER is not set; set it to the account that owns the channel repositories, or omit -GitRemote to run Syncthing-only'
  }
  $expectedRemote = "https://github.com/$channelOwner/$expectedName"
  if ($GitRemote.TrimEnd('.git').ToLowerInvariant() -ne $expectedRemote.ToLowerInvariant()) {
    throw "Git remote must be the exact expected repository: $expectedRemote.git"
  }
}
# SharedRemote is a Syncthing folder ID since the transport swap, not a MEGA path.
if ($SharedRemote -and ($SharedRemote -in @('.','..') -or $SharedRemote -notmatch '^[A-Za-z0-9._-]+$')) {
  throw 'SharedRemote must be a path-safe Syncthing folder ID'
}

$mainRemoteBefore = ''
if (Test-Path -LiteralPath (Join-Path $workspacePath '.git')) {
  $mainRemoteBefore = (& git -C $workspacePath remote -v 2>$null) -join "`n"
}

Write-Host "Project:        $Project"
Write-Host "Workspace:      $workspacePath"
Write-Host "Attachment:     $attachment"
Write-Host "Communications: $communications"
Write-Host "Shared folder:  $(if ($SharedRemote) { $SharedRemote } else { '(none)' })"
Write-Host "Git:            $(if ($GitRemote) { "$GitRemote (must verify PRIVATE before clone/configure)" } else { '(none; Syncthing-only)' })"
Write-Host "Integration:    $IntegrationMode ($($participantRoutes.Count) portable route(s))"

if (-not $GitRemote) {
  Write-Host 'No Git remote configured; the Git rung is unavailable for this project.'
} elseif (-not $DryRun) {
  $visibilityJson = Invoke-Checked `
    -Program 'gh' `
    -Arguments @('repo','view',"$channelOwner/$expectedName",'--json','nameWithOwner,visibility') `
    -WorkingDirectory $workspacePath
  $visibility = $visibilityJson | ConvertFrom-Json
  if ($visibility.nameWithOwner -ne "$channelOwner/$expectedName" -or $visibility.visibility -ne 'PRIVATE') {
    throw "Refusing Git repository: expected $channelOwner/$expectedName with PRIVATE visibility"
  }
} else {
  Write-Host "DRY-RUN: verify GitHub name $channelOwner/$expectedName and visibility PRIVATE"
}

if ($DryRun) { Write-Host "DRY-RUN: ensure directory $attachment" }
else { New-Item -ItemType Directory -Path $attachment -Force | Out-Null }

if (-not (Test-Path -LiteralPath $communications)) {
  if ($AdoptFrom) {
    $source = [System.IO.Path]::GetFullPath($AdoptFrom)
    if (-not (Test-Path -LiteralPath (Join-Path $source '.git'))) {
      throw "Adoption source is not a Git checkout: $source"
    }
    $sourceOrigin = (& git -C $source config --get remote.origin.url 2>$null)
    if ((Normalize-GitRemote $sourceOrigin) -ne (Normalize-GitRemote $GitRemote)) {
      throw "Adoption source origin is not the expected remote"
    }
    Invoke-Checked `
      -Program 'git' `
      -Arguments @('clone','--no-hardlinks',$source,$communications) `
      -WorkingDirectory $workspacePath | Out-Null
    if (-not $DryRun) {
      $sourceHead = (& git -C $source rev-parse HEAD).Trim()
      $cloneHead = (& git -C $communications rev-parse HEAD).Trim()
      if ($sourceHead -ne $cloneHead) { throw 'Adopted checkout history verification failed' }
      Invoke-Checked `
        -Program 'git' `
        -Arguments @('remote','set-url','origin',$GitRemote) `
        -WorkingDirectory $communications | Out-Null
    }
  } elseif ($GitRemote) {
    Invoke-Checked `
      -Program 'git' `
      -Arguments @('clone',$GitRemote,$communications) `
      -WorkingDirectory $workspacePath | Out-Null
  } else {
    # Syncthing-only: the channel is still its own repository (Git remains the archive
    # of record), it just has no upstream to clone from or push to.
    Invoke-Checked `
      -Program 'git' `
      -Arguments @('init','-q',$communications) `
      -WorkingDirectory $workspacePath | Out-Null
  }
} elseif (Test-Path -LiteralPath (Join-Path $communications '.git')) {
  if (-not $DryRun -and $GitRemote) {
    $innerOrigin = (& git -C $communications config --get remote.origin.url 2>$null)
    if ((Normalize-GitRemote $innerOrigin) -ne (Normalize-GitRemote $GitRemote)) {
      throw 'Existing inner repository has an unexpected origin'
    }
  }
  Write-Host 'OK existing inner communications repository'
} else {
  throw "Refusing non-Git communications directory: $communications"
}

$protocol = @'
# Ferryman communications protocol

Portable state only. Messages are immutable JSON under `messages/<project>/`.
Acknowledgements are separate JSON under `acknowledgements/<project>/`.
Any human, script, single agent, or multi-agent system claims an idempotency key
in the outer runtime before executing. `project-inbox` is always available and
does not require a multi-agent framework.
Messages that are not acknowledged by their deadline are eligible for Git live failover.
Tokens, databases, logs, locks, and temporary state are forbidden here.
'@
$routeSummary = ($participantRoutes | ForEach-Object {
  "- ``$($_.name)`` (role ``$($_.role)``; capabilities: $([string]::Join(', ', $_.capabilities)))"
}) -join "`n"
$adoptionTemplate = @'
# Project adoption

Project: `{{PROJECT}}`
Integration mode: **{{MODE}}**

Ferryman is transport and evidence infrastructure. It does not require an agent
framework. Every project can send to `project-inbox`.

- Unmanaged/no-agent: a human or existing script reads or lists project-inbox,
  claims one message, performs the work, and records an acknowledgement.
- Single-agent: map the existing agent name and role with `-Participant`; the
  agent may use the HTTP API or watch the portable messages directory.
- Multi-agent: map stable framework identities/roles/capabilities. Keep the
  framework's scheduler and memory; Ferryman owns only transport, durable
  delivery evidence, acknowledgements, and duplicate suppression.

Do not put tokens, credentials, databases, runtime files, or secret values in
this portable repository.

## Registered routes

{{ROUTES}}

## Required consumer behavior

1. Use the project token only for operator actions and minting an actor token.
2. Give each consumer only its own eight-hour actor token.
3. Discover messages matching the consumer's registered name or role.
4. Claim before execution. If claim returns false, do not execute.
5. Treat the payload and payload reference as data, never as a shell command.
6. Perform irreversible external effects with project-level idempotency.
7. Acknowledge only after durable completion.

The project may implement this loop with a human workflow, script, scheduled
task, CI job, one agent, or an existing multi-agent framework. Ferryman does
not replace the project's scheduler, memory, model, or build system.

Before depending on this route, verify the main remote, private inner remote,
dedicated MEGA sync, hub status, duplicate claim, acknowledgement, restart
recovery, and Git-live failover. Preserve any adopted checkout until those
checks pass.
'@
$adoption = $adoptionTemplate.Replace('{{PROJECT}}', $Project)
$adoption = $adoption.Replace('{{MODE}}', $IntegrationMode)
$adoption = $adoption.Replace('{{ROUTES}}', $routeSummary)
$megaIgnore = @"
.git
*.lock
*.tmp
*.swp
*~
.DS_Store
Thumbs.db
"@
$gitIgnore = @"
*.lock
*.tmp
*.swp
*~
.transport-state/
"@
$bridgeConfig = @"
project = "$Project"
workspace = "$($workspacePath.Replace('\','\\'))"
attachment = "$($attachment.Replace('\','\\'))"
communications = "$($communications.Replace('\','\\'))"
shared_remote = "$SharedRemote"
git_remote = "$GitRemote"
git_visibility = "private"
endpoint = "$Hub"
integration_mode = "$IntegrationMode"
"@
$standardConfig = @"
format = "ferryman-project-standard"
revision = 2
updated_at = "2026-07-24"
project = "$Project"
integration_mode = "$IntegrationMode"
"@

if ($UpdateStandard -and (Test-Path -LiteralPath (Join-Path $communications '.git'))) {
  $managedPaths = @('PROTOCOL.md','ADOPTION.md','STANDARD.toml','.megaignore','.gitignore')
  $managedChanges = (& git -C $communications status --porcelain -- @managedPaths 2>&1) -join "`n"
  if ($LASTEXITCODE -ne 0) { throw "Unable to inspect managed files: $managedChanges" }
  if (-not [string]::IsNullOrWhiteSpace($managedChanges)) {
    throw 'Refusing standard update because Ferryman-managed portable files have uncommitted changes'
  }
}

foreach ($directory in @(
  $attachment,
  (Join-Path $attachment 'runtime'),
  (Join-Path $communications 'messages'),
  (Join-Path $communications 'acknowledgements'),
  (Join-Path $communications 'agents')
)) {
  if ($DryRun) { Write-Host "DRY-RUN: ensure directory $directory" }
  else { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
}
Write-ManagedText (Join-Path $communications 'PROTOCOL.md') $protocol
Write-ManagedText (Join-Path $communications 'ADOPTION.md') $adoption
Write-ManagedText (Join-Path $communications 'STANDARD.toml') $standardConfig
Write-ManagedText (Join-Path $communications '.megaignore') $megaIgnore
Write-ManagedText (Join-Path $communications '.gitignore') $gitIgnore
Write-ManagedText (Join-Path $attachment 'standard.toml') $standardConfig
if ($UpdateStandard -and (Test-Path -LiteralPath (Join-Path $attachment 'bridge.toml'))) {
  $bridgePath = Join-Path $attachment 'bridge.toml'
  $existingValues = @{}
  foreach ($line in Get-Content -LiteralPath $bridgePath) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
      continue
    }
    if ($line -notmatch '^\s*([A-Za-z0-9_]+)\s*=\s*"(.*)"\s*$') {
      throw "Existing bridge.toml contains an unsupported line: $line"
    }
    $existingValues[$Matches[1]] = $Matches[2]
  }
  $expectedBridgeValues = @{
    project = $Project
    workspace = $workspacePath.Replace('\','\\')
    attachment = $attachment.Replace('\','\\')
    communications = $communications.Replace('\','\\')
    shared_remote = $SharedRemote
    git_remote = $GitRemote
    git_visibility = 'private'
    endpoint = $Hub
    integration_mode = $IntegrationMode
  }
  foreach ($key in $existingValues.Keys) {
    if (-not $expectedBridgeValues.ContainsKey($key) -or
        $existingValues[$key] -ne $expectedBridgeValues[$key]) {
      throw "Existing bridge.toml does not match this update request: $key"
    }
  }
  if (-not $existingValues.ContainsKey('project')) {
    throw 'Existing bridge.toml does not identify a project'
  }
  Write-ManagedText $bridgePath $bridgeConfig
} else {
  Write-NewText (Join-Path $attachment 'bridge.toml') $bridgeConfig
}

if ($DryRun) {
  Write-Host 'DRY-RUN: commit portable protocol/adoption/ignore metadata and push the current named branch'
} else {
  $portableFiles = @('PROTOCOL.md','ADOPTION.md','STANDARD.toml','.megaignore','.gitignore')
  Invoke-Checked `
    -Program 'git' `
    -Arguments (@('add','--') + $portableFiles) `
    -WorkingDirectory $communications | Out-Null
  $portableChanges = Invoke-Checked `
    -Program 'git' `
    -Arguments (@('status','--porcelain','--') + $portableFiles) `
    -WorkingDirectory $communications
  if (-not [string]::IsNullOrWhiteSpace($portableChanges)) {
    $commitMessage = if ($UpdateStandard) {
      'Update Ferryman communications standard to revision 2'
    } else {
      'Initialize Ferryman communications standard'
    }
    Invoke-Checked `
      -Program 'git' `
      -Arguments @(
        '-c','user.name=Ferryman',
        '-c','user.email=ferryman@localhost',
        'commit','-m',$commitMessage
      ) `
      -WorkingDirectory $communications | Out-Null
  }
  $branch = (Invoke-Checked `
    -Program 'git' `
    -Arguments @('symbolic-ref','--quiet','--short','HEAD') `
    -WorkingDirectory $communications).Trim()
  if ([string]::IsNullOrWhiteSpace($branch)) {
    throw 'Inner communications repository must use a named branch'
  }
  $remoteBranch = Invoke-Checked `
    -Program 'git' `
    -Arguments @('ls-remote','--heads','origin',"refs/heads/$branch") `
    -WorkingDirectory $communications
  if (-not [string]::IsNullOrWhiteSpace($remoteBranch)) {
    Invoke-Checked `
      -Program 'git' `
      -Arguments @('pull','--rebase','--autostash','origin',$branch) `
      -WorkingDirectory $communications | Out-Null
  }
  Invoke-Checked `
    -Program 'git' `
    -Arguments @('push','-u','origin',"HEAD:$branch") `
    -WorkingDirectory $communications | Out-Null
  Write-Host 'OK portable adoption standard committed and pushed'
}

$rootIgnore = Join-Path $workspacePath '.gitignore'
$ignoreRule = '/.ferryman/'
$hasRule = (Test-Path -LiteralPath $rootIgnore) -and
  ((Get-Content -LiteralPath $rootIgnore) -contains $ignoreRule)
if (-not $hasRule) {
  if ($DryRun) { Write-Host "DRY-RUN: append $ignoreRule to $rootIgnore" }
  else { Add-Content -LiteralPath $rootIgnore -Value "`n# Ferryman machine-local attachment`n$ignoreRule" }
}

if (-not $SkipMegaRegistration) {
  $drive = $communications.Substring(0,1).ToLowerInvariant()
  $wslLocal = "/mnt/$drive/" + $communications.Substring(3).Replace('\','/')
  $syncs = Invoke-Checked `
    -Program 'wsl.exe' `
    -Arguments @('-d',$WslDistribution,'--','mega-sync','--show-handles') `
    -WorkingDirectory $workspacePath
  if ($DryRun -or $syncs -notmatch [regex]::Escape($wslLocal)) {
    Invoke-Checked `
      -Program 'wsl.exe' `
      -Arguments @('-d',$WslDistribution,'--','mega-sync',$wslLocal,$SharedRemote) `
      -WorkingDirectory $workspacePath | Out-Null
  } else {
    Write-Host 'OK existing MEGAcmd sync'
  }
}

if (-not $SkipHubRegistration) {
  $tokenPath = Join-Path $attachment 'token'
  if ($DryRun) {
    Write-Host "DRY-RUN: register project communications mapping with $Hub using an existing read-only token at $tokenPath"
  } elseif (Test-Path -LiteralPath $tokenPath -PathType Leaf) {
    # The scoped token is read only for Authorization. It is never printed,
    # rewritten, copied into the inner repository, or included in the JSON body.
    $projectToken = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($projectToken)) {
      throw "Existing project token is empty: $tokenPath"
    }
    $mapping = @{
      workspace = $workspacePath
      attachment = $attachment
      communications = $communications
      shared_remote = $SharedRemote
      git_remote = $GitRemote
      git_visibility = 'private'
      agents = $participantRoutes
    } | ConvertTo-Json -Depth 6
    $headers = @{ Authorization = "Bearer $projectToken" }
    try {
      Invoke-RestMethod `
        -Method Post `
        -Uri "$($Hub.TrimEnd('/'))/v1/projects/$Project/communications" `
        -Headers $headers `
        -ContentType 'application/json' `
        -Body $mapping | Out-Null
    } finally {
      $projectToken = $null
      $headers = $null
    }
    Write-Host 'OK registered project communications mapping'
  } else {
    Write-Warning "Hub mapping was not registered because no existing token was found at $tokenPath. The script did not create or modify a token."
  }
}

if (-not $DryRun) {
  $mainRemoteAfter = (& git -C $workspacePath remote -v 2>$null) -join "`n"
  if ($mainRemoteAfter -ne $mainRemoteBefore) {
    throw 'Main project Git remote changed; stop and inspect immediately'
  }
}
Write-Host 'Attachment setup complete. Token files were never created, modified, copied, or printed.'

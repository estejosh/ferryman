# Ferryman: join a project from an invite code, on Windows.
#
#   irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/join.ps1 | iex; ferry-join <code>
#
# Installs ferry if it is not here (the same install.ps1 every release uses), then hands
# the code to `ferry team invite accept`, which does the rest: Syncthing, the channel,
# your identity. Everything it asks for, it asks on this screen. Nothing else to run.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ferry-join {
    param([Parameter(Mandatory = $true)][string]$Code)
    $bin = if ($env:FERRYMAN_BINDIR) { $env:FERRYMAN_BINDIR } else { Join-Path $env:LOCALAPPDATA 'Ferryman\bin' }
    $ferry = Join-Path $bin 'ferry.exe'
    if (-not (Test-Path $ferry)) {
        $onPath = Get-Command ferry -ErrorAction SilentlyContinue
        if ($onPath) { $ferry = $onPath.Source }
    }
    if (-not (Test-Path $ferry)) {
        Write-Host 'Installing Ferryman...'
        Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1')
        if (-not (Test-Path $ferry)) { throw "ferry was not installed at $ferry; see the messages above" }
    }
    & $ferry team invite accept $Code
    if ($LASTEXITCODE -ne 0) { throw 'joining did not finish; read the message above and run the same line again' }
}

if ($MyInvocation.InvocationName -ne '.' -and $args.Count -ge 1) {
    ferry-join -Code $args[0]
} else {
    Write-Host 'Ferryman join is loaded. Now run:  ferry-join <code>'
}

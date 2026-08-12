<#
Ferryman installer for Windows.

  irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | iex

Why this exists: the documented alternatives were `npm install -g ferryman-cli` and
`curl -fsSL ... | sh`. On a clean Windows machine there is no POSIX shell - `sh` is not
a command - so the fallback could not run at all, and a Windows user following the
instructions had no working path. This was found by following our own install
instructions on a clean machine, and it failed at step one.

Like install.sh, it verifies the checksum before installing. Piping a script from the
internet into a shell already asks for trust; running an unverified binary afterwards
would be asking twice.

It installs for the current user and never asks for administrator rights: an agent
running unattended cannot answer a UAC prompt.
#>

[CmdletBinding()]
param(
    # Pin a release, e.g. "v0.3.1". Defaults to the newest.
    [string]$Version = $(if ($env:FERRYMAN_VERSION) { $env:FERRYMAN_VERSION } else { 'latest' }),
    [string]$BinDir  = $(if ($env:FERRYMAN_BINDIR) { $env:FERRYMAN_BINDIR } else { Join-Path $env:LOCALAPPDATA 'Ferryman\bin' })
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # a progress bar makes this ~10x slower
$repo = 'estejosh/ferryman'

function Say([string]$m) { Write-Host "ferryman: $m" }

if ([Environment]::Is64BitOperatingSystem -eq $false) {
    throw "ferryman: no prebuilt binary for 32-bit Windows. Build it with: cargo install --git https://github.com/$repo ferryman-cli"
}

if ($Version -eq 'latest') {
    $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'ferryman-installer' }
    $Version = $release.tag_name
}
Say "installing $Version"

$asset = 'ferry-x86_64-pc-windows-msvc.zip'
$base  = "https://github.com/$repo/releases/download/$Version"
$work  = Join-Path ([System.IO.Path]::GetTempPath()) ("ferryman-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $work | Out-Null

try {
    $zip = Join-Path $work $asset
    Invoke-WebRequest "$base/$asset" -OutFile $zip
    Invoke-WebRequest "$base/$asset.sha256" -OutFile "$zip.sha256"

    # The published .sha256 is "<hash>  <filename>"; only the hash is needed.
    $want = ((Get-Content "$zip.sha256" -Raw) -split '\s+')[0].ToLower()
    $got  = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($want -ne $got) {
        throw "ferryman: checksum mismatch for $asset`n  expected $want`n  got      $got`nNot installing."
    }
    Say 'checksum verified'

    Expand-Archive $zip -DestinationPath (Join-Path $work 'x') -Force
    $exe = Get-ChildItem (Join-Path $work 'x') -Recurse -Filter 'ferry.exe' | Select-Object -First 1
    if (-not $exe) { throw "ferryman: $asset did not contain ferry.exe" }

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    Copy-Item $exe.FullName (Join-Path $BinDir 'ferry.exe') -Force
    Say "installed to $BinDir\ferry.exe"

    # Add to PATH for future shells, and to this one, so the next line of a script works.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$BinDir", 'User')
        Say 'added to your PATH (new terminals will see it)'
    }
    if ($env:Path -notlike "*$BinDir*") { $env:Path = "$env:Path;$BinDir" }

    & (Join-Path $BinDir 'ferry.exe') --version
    Say "next: cd into your project and run  ferry enable --email you@example.com"
    Say 'ferryman needs Syncthing running to reach other machines: https://syncthing.net/downloads/'
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

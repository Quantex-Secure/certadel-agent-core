#requires -Version 7
<#
.SYNOPSIS
  Downloads the Pebble + pebble-challtestsrv binaries plus the test TLS
  cert/key into tests/.pebble/ so the integration test fixture can spin
  Pebble up as a local ACME server. No Docker required.

.DESCRIPTION
  Resolves the latest stable Pebble release from the GitHub API, picks the
  asset matching the current OS/arch, and downloads:

    - pebble             (Windows: pebble.exe)
    - pebble-challtestsrv (Windows: pebble-challtestsrv.exe)
    - test cert.pem + key.pem (sourced from the Pebble repo)

  All files land in tests/.pebble/ (which is gitignored). Re-running is
  idempotent — already-present files are skipped.

.PARAMETER Tag
  Override the release tag — e.g. "v2.6.0". Defaults to "latest".

.PARAMETER Force
  Re-download even if files already exist.
#>
[CmdletBinding()]
param(
    [string] $Tag = "latest",
    [switch] $Force
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$dest = Join-Path $repoRoot "tests/.pebble"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$os = if ($IsWindows -or [System.Environment]::OSVersion.Platform -eq 'Win32NT') { "windows" }
      elseif ($IsLinux) { "linux" }
      elseif ($IsMacOS) { "darwin" }
      else { throw "Unsupported OS" }
$ext = if ($os -eq "windows") { ".exe" } else { "" }

Write-Host "Resolving Pebble release ($Tag) for $os-amd64..." -ForegroundColor Cyan
$apiUrl = if ($Tag -eq "latest") {
    "https://api.github.com/repos/letsencrypt/pebble/releases/latest"
} else {
    "https://api.github.com/repos/letsencrypt/pebble/releases/tags/$Tag"
}

$release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "acme-manager-pebble-fetch" }
$tagName = $release.tag_name
Write-Host "Using Pebble $tagName" -ForegroundColor Cyan

$assets = $release.assets

# Modern Pebble releases (GoReleaser) ship each binary inside a per-OS/arch
# archive rather than as a bare executable — e.g. "pebble-windows-amd64.zip"
# containing "pebble-windows-amd64/windows/amd64/pebble.exe". A .zip is published
# for every platform, so we always use Expand-Archive (cross-platform in pwsh 7)
# and avoid needing tar. Cast a moderately wide net on the separator.
$pebbleAsset = $assets | Where-Object {
    $_.name -match "^pebble[_-]$os[-_]amd64\.zip$"
} | Select-Object -First 1

$challAsset = $assets | Where-Object {
    $_.name -match "^pebble-challtestsrv[_-]$os[-_]amd64\.zip$"
} | Select-Object -First 1

if (-not $pebbleAsset) {
    Write-Host "Available assets:" -ForegroundColor Yellow
    $assets | ForEach-Object { Write-Host "  $($_.name)" }
    throw "Couldn't find a pebble .zip asset matching $os-amd64 in $tagName"
}
if (-not $challAsset) {
    throw "Couldn't find a pebble-challtestsrv .zip asset matching $os-amd64 in $tagName"
}

# Downloads an archive asset, extracts it, and copies the named binary (found
# recursively — GoReleaser nests it under <os>/<arch>/) to $dest/$TargetName.
function Save-BinaryFromArchive {
    param([string] $Url, [string] $BinaryName, [string] $TargetName)
    $target = Join-Path $dest $TargetName
    if ((Test-Path $target) -and -not $Force) {
        Write-Host "  ✓ $TargetName already present" -ForegroundColor Green
        return
    }
    Write-Host "  ↓ $TargetName" -ForegroundColor Cyan
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) "$([System.Guid]::NewGuid().ToString('N')).zip"
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmpZip -UseBasicParsing
        Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force
        $binary = Get-ChildItem -Path $tmpDir -Recurse -File -Filter $BinaryName | Select-Object -First 1
        if (-not $binary) {
            throw "Archive from $Url did not contain '$BinaryName'"
        }
        Copy-Item -Path $binary.FullName -Destination $target -Force
        if (-not $IsWindows) {
            chmod +x $target
        }
    }
    finally {
        Remove-Item -Path $tmpZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Save-BinaryFromArchive -Url $pebbleAsset.browser_download_url -BinaryName "pebble$ext" -TargetName "pebble$ext"
Save-BinaryFromArchive -Url $challAsset.browser_download_url  -BinaryName "pebble-challtestsrv$ext" -TargetName "pebble-challtestsrv$ext"

# Pebble's bundled test cert/key — needed for the ACME endpoint to serve HTTPS.
$certUrl = "https://raw.githubusercontent.com/letsencrypt/pebble/$tagName/test/certs/localhost/cert.pem"
$keyUrl  = "https://raw.githubusercontent.com/letsencrypt/pebble/$tagName/test/certs/localhost/key.pem"

function Save-TextFile {
    param([string] $Url, [string] $TargetName)
    $target = Join-Path $dest $TargetName
    if ((Test-Path $target) -and -not $Force) {
        Write-Host "  ✓ $TargetName already present" -ForegroundColor Green
        return
    }
    Write-Host "  ↓ $TargetName" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Url -OutFile $target -UseBasicParsing
}

Save-TextFile -Url $certUrl -TargetName "cert.pem"
Save-TextFile -Url $keyUrl  -TargetName "key.pem"

Write-Host ""
Write-Host "Pebble $tagName installed at $dest" -ForegroundColor Green
Write-Host "Integration tests will pick this up automatically." -ForegroundColor Green

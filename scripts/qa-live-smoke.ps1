$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$bin = if ($env:UGRANT_BIN) { $env:UGRANT_BIN } else { Join-Path $repoRoot "zig-out/bin/ugrant.exe" }
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ugrant-smoke-" + [guid]::NewGuid().ToString("N"))
$homeDir = Join-Path $tmpRoot "home"

function Assert-Contains {
  param(
    [string]$Haystack,
    [string]$Needle
  )

  if (-not $Haystack.Contains($Needle)) {
    throw "Expected output to contain '$Needle' but got:`n$Haystack"
  }
}

function Log-Step {
  param([string]$Message)
  Write-Host "`n==> $Message"
}

try {
  New-Item -ItemType Directory -Path $homeDir -Force | Out-Null
  [Environment]::SetEnvironmentVariable('HOME', $null, 'Process')
  $env:USERPROFILE = $homeDir

  Remove-Item Env:UGRANT_TEST_PLATFORM_STORE_AVAILABLE -ErrorAction SilentlyContinue
  Remove-Item Env:UGRANT_TEST_PLATFORM_STORE_SECRET -ErrorAction SilentlyContinue

  Log-Step "init insecure-keyfile in isolated USERPROFILE"
  & $bin init --backend insecure-keyfile --allow-insecure-keyfile | Out-Null
  $statusOut = & $bin status | Out-String
  Assert-Contains $statusOut "initialized: yes"
  Assert-Contains $statusOut "backend: insecure-keyfile"
  Assert-Contains $statusOut "security_mode: degraded"

  $doctorOut = & $bin doctor | Out-String
  Assert-Contains $doctorOut "config:"
  Assert-Contains $doctorOut "state_dir:"

  Log-Step "add a real profile record without live oauth"
  & $bin profile add --name qa-smoke --service google-imap --client-id qa-client-id --client-secret qa-client-secret | Out-Null
  $profileList = & $bin profile list | Out-String
  Assert-Contains $profileList "qa-smoke"

  Log-Step "rekey into platform-secure-store test backend"
  $env:UGRANT_TEST_PLATFORM_STORE_AVAILABLE = "1"
  $env:UGRANT_TEST_PLATFORM_STORE_SECRET = "ci-platform-secret"
  & $bin rekey --backend platform-secure-store | Out-Null
  $statusOut = & $bin status | Out-String
  Assert-Contains $statusOut "backend: platform-secure-store"
  Assert-Contains $statusOut "security_mode: normal"

  $doctorOut = & $bin doctor | Out-String
  Assert-Contains $doctorOut "config:"
  Assert-Contains $doctorOut "state_dir:"

  Log-Step "rekey back to insecure-keyfile"
  & $bin rekey --allow-insecure-keyfile | Out-Null
  $statusOut = & $bin status | Out-String
  Assert-Contains $statusOut "backend: insecure-keyfile"
  Assert-Contains $statusOut "security_mode: degraded"

  Log-Step "live smoke passed"
}
finally {
  Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

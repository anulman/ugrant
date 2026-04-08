$ErrorActionPreference = "Stop"

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ugrant-manual-qa-" + [guid]::NewGuid().ToString("N"))
$homeDir = Join-Path $tmpRoot "home"
$localAppData = Join-Path $homeDir "AppData\Local"
$bin = Join-Path $localAppData "Programs\ugrant\bin\ugrant.exe"

function Step {
  param([string]$Message)
  Write-Host "`n### $Message"
}

try {
  New-Item -ItemType Directory -Path $homeDir -Force | Out-Null
  New-Item -ItemType Directory -Path $localAppData -Force | Out-Null
  [Environment]::SetEnvironmentVariable('HOME', $null, 'Process')
  $env:USERPROFILE = $homeDir
  $env:LOCALAPPDATA = $localAppData

  Step "Fresh install into isolated USERPROFILE/LOCALAPPDATA"
  Invoke-RestMethod https://www.ugrant.sh/install.ps1 | Invoke-Expression
  & $bin status

  Step "Initialize and inspect live state"
  & $bin init --backend insecure-keyfile --allow-insecure-keyfile
  & $bin status
  & $bin doctor

  Step "Add a profile record and verify it exists"
  & $bin profile add --name qa-smoke --service google-imap --client-id qa-client-id --client-secret qa-client-secret
  & $bin profile list

  Step "Reinstall over the existing binary"
  Invoke-RestMethod https://www.ugrant.sh/install.ps1 | Invoke-Expression
  & $bin status

  Step "Repair a clobbered install"
  Set-Content -Path $bin -Value 'broken' -Encoding ascii
  Invoke-RestMethod https://www.ugrant.sh/install.ps1 | Invoke-Expression
  & $bin status

  @"

Manual checks to record:
- Did install succeed in the isolated temp profile?
- In the same window, could you run the full installed path immediately?
- After opening a fresh PowerShell window, did bare `ugrant` resolve on PATH?
- Did reinstall overwrite the existing binary cleanly?
- Did the repair step replace a broken binary with a working one?
"@ | Write-Host
}
finally {
  Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Atomic Red Team: Invoke-AtomicRedTeam module + atomics in C:\AtomicRedTeam.
# Defender stays on; only the framework folder is excluded so its files are not quarantined.
# Whether Defender is on or off during an emulation run is a separate, recorded decision.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$root = "C:\AtomicRedTeam"

New-Item $root -ItemType Directory -Force | Out-Null
if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
  Add-MpPreference -ExclusionPath $root
}

if (-not (Test-Path "$root\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1")) {
  # PowerShell Gallery prerequisites (powershell-yaml is pulled by the installer)
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  # powershell-yaml is a required module of Invoke-AtomicRedTeam; install it AllUsers so any
  # account (e.g. Administrator over SSH during runs) can load the module, not just the installer.
  Install-Module powershell-yaml -Scope AllUsers -Force
  Invoke-Expression (Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing).Content
  Install-AtomicRedTeam -getAtomics -InstallPath $root -Force
}

# Load the module for every PowerShell session (used over WinRM and SSH)
$profileLine = "Import-Module '$root\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force; `$PSDefaultParameterValues = @{'Invoke-AtomicTest:PathToAtomicsFolder'='$root\atomics'}"
$allUsers = $PROFILE.AllUsersAllHosts
New-Item (Split-Path $allUsers) -ItemType Directory -Force | Out-Null
if (-not (Test-Path $allUsers) -or -not (Select-String -Path $allUsers -SimpleMatch $root -Quiet)) {
  Add-Content $allUsers $profileLine
}

# Evidence: versions for the report
Import-Module "$root\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$info = [ordered]@{
  installed_utc     = (Get-Date).ToUniversalTime().ToString("o")
  module_version    = (Get-Module Invoke-AtomicRedTeam).Version.ToString()
  technique_folders = (Get-ChildItem "$root\atomics" -Directory -Filter "T*").Count
}
$info | ConvertTo-Json | Set-Content "$root\art-version.json"
Get-Content "$root\art-version.json"

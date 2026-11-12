# YARA rules for on-demand and scheduled osquery scans (osquery "yara" table, sigfile column).
# Rule set: YARA Forge "Core" (curated public rules, high accuracy, low false positives), pinned release.
param([string]$Release = "20261108")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$dir = "C:\ProgramData\yara"
$rules = "$dir\yara-forge-core.yar"

New-Item $dir -ItemType Directory -Force | Out-Null
$tmp = "$dir\core-$Release.zip"
curl.exe -fsSL -o $tmp "https://github.com/YARAHQ/yara-forge/releases/download/$Release/yara-forge-rules-core.zip"
if ($LASTEXITCODE -ne 0) { throw "download failed ($LASTEXITCODE)" }
Expand-Archive $tmp "$dir\core-$Release" -Force
Copy-Item "$dir\core-$Release\packages\core\yara-rules-core.yar" $rules -Force
Remove-Item $tmp, "$dir\core-$Release" -Recurse -Force

# Only SYSTEM and Administrators: osquery runs as SYSTEM; rules should not be user-writable
icacls $dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

$info = [ordered]@{
  ruleset    = "YARA Forge core"
  release    = $Release
  file       = $rules
  sha256     = (Get-FileHash $rules -Algorithm SHA256).Hash
  rule_count = (Select-String -Path $rules -Pattern '^(private |global )?rule ' ).Count
  installed_utc = (Get-Date).ToUniversalTime().ToString("o")
}
$info | ConvertTo-Json | Set-Content "$dir\ruleset.json"
Get-Content "$dir\ruleset.json"

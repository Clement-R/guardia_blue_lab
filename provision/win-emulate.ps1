# Adversary-emulation run harness. Runs an Atomic Red Team plan (CSV) in sequence,
# records T0/T1 and a per-test execution log, and pauses between tests so alerts can be
# attributed to a test by time window. Run over SSH from the siem VM (see emulation/README.md):
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\AtomicRedTeam\win-emulate.ps1 -Plan evilcorp -RunId run-ec-1 [-GetPrereqs] [-Resolve]
#
# This does NOT take snapshots or resync the clock: do that from the host before/after
# (see emulation/README.md), so the harness stays a pure, repeatable executor.
param(
  [Parameter(Mandatory)][string]$Plan,           # plan name (CSV at C:\AtomicRedTeam\plans\<plan>.csv) or a full path
  [Parameter(Mandatory)][string]$RunId,
  [string]$Atomics = "C:\AtomicRedTeam\atomics",
  [int]$PauseSeconds = 20,
  [switch]$GetPrereqs,                            # fetch prerequisites before the timed run (do this on a separate pass)
  [switch]$Resolve                                # only resolve/validate GUIDs against the installed atomics, then exit
)
$ErrorActionPreference = "Stop"
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

$planPath = if (Test-Path $Plan) { $Plan } else { "C:\AtomicRedTeam\plans\$Plan.csv" }
$tests = Import-Csv $planPath
$out = "C:\AtomicRedTeam\results\$RunId"
New-Item $out -ItemType Directory -Force | Out-Null

# Resolve GUIDs from the atomics YAML (authoritative), filtered to Windows tests. Atomics test
# numbers drift between releases, so the plan is keyed by GUID; this validates them and fills blanks.
function Get-WinAtomics($tech) {
  $yf = Join-Path $Atomics "$tech\$tech.yaml"
  if (-not (Test-Path $yf)) { return @() }
  try { $doc = ConvertFrom-Yaml (Get-Content $yf -Raw) } catch { return @() }
  @($doc.atomic_tests | Where-Object { $_.supported_platforms -contains 'windows' })
}
foreach ($t in $tests) {
  $wa = Get-WinAtomics $t.Technique
  if (-not $t.TestGuid -and $t.NameHint) {
    $m = $wa | Where-Object { $_.name -like "*$($t.NameHint)*" } | Select-Object -First 1
    if ($m) { $t.TestGuid = $m.auto_generated_guid }
  }
  $t | Add-Member Resolved ([bool](@($wa.auto_generated_guid) -contains $t.TestGuid)) -Force
}
$tests | Select-Object Order, Technique, Tactic, TestGuid, Resolved, Name | Format-Table -Auto | Out-String | Tee-Object "$out\plan-resolved.txt"
$unres = $tests | Where-Object { -not $_.Resolved }
if ($unres) {
  Write-Warning "Unresolved tests. Available Windows atomics for each (pick a GUID):"
  foreach ($u in $unres) {
    "`n== $($u.Order) $($u.Technique) ($($u.Name)) ==" | Tee-Object "$out\plan-resolved.txt" -Append
    Get-WinAtomics $u.Technique | ForEach-Object { "  {0}  {1}" -f $_.auto_generated_guid, $_.name } | Tee-Object "$out\plan-resolved.txt" -Append
  }
}
if ($Resolve) { exit 0 }

if ($GetPrereqs) {
  foreach ($t in $tests | Where-Object Resolved) {
    Invoke-AtomicTest $t.Technique -TestGuids $t.TestGuid -GetPrereqs -PathToAtomicsFolder $Atomics
  }
  Write-Host "Prerequisites fetched. Snapshot the VM (art-primed) before the timed run."
  exit 0
}

# --- Timed run ---
Start-Transcript -Path "$out\$RunId-transcript.txt" | Out-Null
$exec = "$out\$RunId-execlog.csv"
"T0 (UTC): $((Get-Date).ToUniversalTime().ToString('o'))" | Tee-Object "$out\$RunId-markers.txt"
foreach ($t in $tests | Where-Object Resolved) {
  "{0} start (UTC): {1}  {2} {3}" -f $t.Order, (Get-Date).ToUniversalTime().ToString('o'), $t.Technique, $t.Name | Tee-Object "$out\$RunId-markers.txt" -Append
  Invoke-AtomicTest $t.Technique -TestGuids $t.TestGuid -PathToAtomicsFolder $Atomics -ExecutionLogPath $exec
  Start-Sleep -Seconds $PauseSeconds
}
"T1 (UTC): $((Get-Date).ToUniversalTime().ToString('o'))" | Tee-Object "$out\$RunId-markers.txt" -Append
Stop-Transcript | Out-Null
Write-Host "Done. Evidence in $out (markers, execlog, transcript). Copy it off the VM before reverting."

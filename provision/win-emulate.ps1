# Adversary-emulation run harness. Runs an Atomic Red Team plan (CSV) in sequence,
# records T0/T1 and a per-test execution log, and pauses between tests so alerts can be
# attributed to a test by time window. Run over SSH from the siem VM (see emulation/README.md):
#   pwsh C:\AtomicRedTeam\win-emulate.ps1 -Plan evilcorp -RunId run-ec-1 [-GetPrereqs] [-Resolve]
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

# Resolve: for any row missing a TestGuid, find it by matching the Name against the installed atomics.
# Atomics test numbers drift between releases, so the plan is keyed by GUID; this fills blanks and flags bad ones.
foreach ($t in $tests) {
  $avail = Invoke-AtomicTest $t.Technique -ShowDetailsBrief -PathToAtomicsFolder $Atomics 2>$null
  if (-not $t.TestGuid) {
    $m = $avail | Where-Object { $_ -like "*$($t.NameHint)*" } | Select-Object -First 1
    if ($m -and $m -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $t.TestGuid = $Matches[1] }
  }
  $t | Add-Member Resolved ([bool]($avail -match [regex]::Escape($t.TestGuid))) -Force
}
$tests | Select-Object Order, Technique, Tactic, TestGuid, Resolved, Name | Format-Table -Auto | Out-String | Tee-Object "$out\plan-resolved.txt"
if ($tests | Where-Object { -not $_.Resolved }) { Write-Warning "Some tests did not resolve on this atomics version (see above)." }
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

# Adversary emulation — runs and scoring

Two runs, one per adversary, on `dc01`:
- **run-ec** — Evil Corp / Indrik Spider (G0119), plan `evilcorp-plan.csv`
- **run-ws** — Wizard Spider (G0102), plan `wizardspider-plan.csv`

The Evil Corp plan reuses the reference build's verified Atomic GUIDs where the chains overlap,
so run 1 is directly comparable to the instructor reference. The Wizard Spider plan adds
Active-Directory techniques (Kerberoasting, domain/DC discovery, NTDS dump) that the single-host
reference put out of scope; several GUIDs are left blank and resolved on the box (atomics test
numbers drift between releases, so plans are keyed by GUID and name hint).

## Outcome scale (per test; technique success recorded separately)

| Outcome | Definition |
|---|---|
| Alerted | At least one visible (non building-block) alert attributable to the test |
| Building-block only | Only building-block alerts (hidden from the default Alerts view) |
| Telemetry only | No alert, but raw events of the activity exist in at least one source |
| Not observed | No alert and no raw events |
| Not executed | The test failed to run (error, missing prerequisite) |

Time to detect = first visible alert creation time − test start time.

## Attribution

A test's window runs from its start time (execlog / markers) to the next test's start; the last
window ends at T1. Alerts map by the triggering event time (`kibana.alert.original_time`), not
alert creation time. Framework noise (the harness's own `whoami`/host-info, WinRM/SSH execution
rules, provisioning `curl` downloads) is excluded before scoring.

## Procedure (per run)

On the host:
1. `vagrant snapshot restore dc art-primed --no-provision`
2. `vagrant winrm dc -c 'w32tm /resync /force; w32tm /stripchart /computer:pool.ntp.org /samples:2 /dataonly'` — proceed only if offset < 1 s
3. `vagrant ssh siem -c 'sudo bash /vagrant/scripts/health.sh 3 10'` — confirm no late rules / no breaker trips before starting
4. Run the plan over SSH to the DC (session 0: sshd -> cmd -> powershell), e.g.:
   `ssh Administrator@10.77.77.20 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\AtomicRedTeam\win-emulate.ps1 -Plan evilcorp -RunId run-ec-1'`
5. Note T0/T1 from `C:\AtomicRedTeam\results\<RunId>\<RunId>-markers.txt`, then pull the evidence
   off the DC: `scripts/pull-evidence.sh <RunId>` (scp over SSH -> `evidence/<RunId>/`). Do this
   **before** restoring the snapshot — the results live only on the VM.
6. Wait T1 + 15 min (beyond the Sigma 13-min lookback), then score:
   `vagrant ssh siem -c 'sudo bash /vagrant/scripts/score-run.sh C:\AtomicRedTeam\results\<RunId>\<RunId>-execlog.csv <T0> <T1>'`

Preparation (once): install atomics and fetch prerequisites, then snapshot:
   `vagrant provision dc --provision-with art`
   `ssh Administrator@10.77.77.20 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\AtomicRedTeam\win-emulate.ps1 -Plan evilcorp -RunId prep -GetPrereqs'`
   `ssh Administrator@10.77.77.20 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\AtomicRedTeam\win-emulate.ps1 -Plan wizardspider -RunId prep -GetPrereqs'`
   `vagrant snapshot save dc art-primed`

## Defender decision

Record whether Microsoft Defender is on or off for the runs. The reference disabled it to measure
detection without prevention. Keeping it in **Detect/audit** (not block) is an alternative that
preserves detection measurement while showing what a defended host would flag; decide and document.

## Rules of engagement

Lab only. Exfiltration tests (Rclone) point at a lab-internal target; nothing leaves the lab.
No real encryption. Snapshot before each run; revert after.

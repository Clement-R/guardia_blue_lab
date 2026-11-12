# Host telemetry: advanced audit policy (DC-oriented), DCSync audit SACL, PowerShell logging,
# event channels and log sizes, Sysmon with sysmon-modular. Safe to re-run.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Windows PowerShell 5.1 downloads are very slow with the progress bar
New-Item C:\lab -ItemType Directory -Force | Out-Null   # evidence files go here

# --- 1. Advanced audit policy ---
# Subcategory settings win over legacy category settings; 4688 carries the command line
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty $lsa SCENoApplyLegacyAuditPolicy 1 -Type DWord
$p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item $p -Force | Out-Null
Set-ItemProperty $p ProcessCreationIncludeCmdLine_Enabled 1 -Type DWord

auditpol /backup /file:C:\lab\auditpol-before.csv | Out-Null
if ($LASTEXITCODE -ne 0) { throw "auditpol backup failed" }
$audit = @(
  # subcategory,                        success, failure
  @("Process Creation",                     $true,  $false),
  @("Process Termination",                  $true,  $false),
  @("Logon",                                $true,  $true),
  @("Logoff",                               $true,  $false),
  @("Special Logon",                        $true,  $false),
  @("Other Logon/Logoff Events",            $true,  $true),
  @("Account Lockout",                      $false, $true),
  @("User Account Management",              $true,  $true),
  @("Security Group Management",            $true,  $false),
  @("Computer Account Management",          $true,  $false),
  @("Other Object Access Events",           $true,  $false),
  @("Security System Extension",            $true,  $false),
  @("Audit Policy Change",                  $true,  $true),
  @("Authentication Policy Change",         $true,  $false),
  @("Filtering Platform Connection",        $false, $true),
  @("DPAPI Activity",                       $true,  $true),
  @("Kerberos Authentication Service",      $true,  $true),
  @("Kerberos Service Ticket Operations",   $true,  $true),
  @("Credential Validation",                $true,  $true),
  @("Directory Service Access",             $true,  $true),
  @("Directory Service Changes",            $true,  $false)
)
foreach ($a in $audit) {
  $s = if ($a[1]) { "enable" } else { "disable" }
  $f = if ($a[2]) { "enable" } else { "disable" }
  auditpol /set /subcategory:"$($a[0])" /success:$s /failure:$f | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($a[0])" }
}

# --- 2. SACL on the domain root: replication rights used => 4662 (DCSync) ---
Import-Module ActiveDirectory
$dn = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:$dn" -Audit
$everyone = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$rights = @(
  "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
  "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
  "89e95b76-444d-4c62-991a-0facbeda640c"   # DS-Replication-Get-Changes-In-Filtered-Set
)
$existing = $acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
  ForEach-Object { $_.ObjectType.Guid }
foreach ($g in $rights) {
  if ($existing -notcontains $g) {
    $acl.AddAuditRule((New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
      $everyone, "ExtendedRight", "Success", [guid]$g)))
  }
}
Set-Acl "AD:$dn" $acl

# --- 3. PowerShell logging: script block, module (all), transcription ---
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item "$ps\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "$ps\ScriptBlockLogging" EnableScriptBlockLogging 1 -Type DWord
New-Item "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty "$ps\ModuleLogging" EnableModuleLogging 1 -Type DWord
Set-ItemProperty "$ps\ModuleLogging\ModuleNames" "*" "*"
New-Item "$ps\Transcription" -Force | Out-Null
Set-ItemProperty "$ps\Transcription" EnableTranscripting 1 -Type DWord
Set-ItemProperty "$ps\Transcription" EnableInvocationHeader 1 -Type DWord
Set-ItemProperty "$ps\Transcription" OutputDirectory "C:\PowerShellTranscripts"
New-Item C:\PowerShellTranscripts -ItemType Directory -Force | Out-Null

# --- 4. Log sizes and extra channels ---
wevtutil sl Security /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864
$extraChannels = @(
  "Microsoft-Windows-TaskScheduler/Operational",
  "Microsoft-Windows-Bits-Client/Operational",
  "Microsoft-Windows-CodeIntegrity/Operational",
  "Microsoft-Windows-WMI-Activity/Operational",
  "Microsoft-Windows-WinRM/Operational",
  "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
  "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
  "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
  "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
  "Microsoft-Windows-Kernel-PnP/Configuration",
  "Microsoft-Windows-DNSServer/Audit",
  "Microsoft-Windows-GroupPolicy/Operational"
)
foreach ($c in $extraChannels) {
  cmd /c "wevtutil sl `"$c`" /e:true /ms:33554432" 2>$null
  if ($LASTEXITCODE -ne 0) { Write-Warning "channel not enabled (may be absent on this host): $c" }
}

# --- 5. Sysmon with the sysmon-modular default configuration ---
$dir = "C:\lab\sysmon"
New-Item $dir -ItemType Directory -Force | Out-Null
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile "$dir\Sysmon.zip" -UseBasicParsing
Expand-Archive "$dir\Sysmon.zip" $dir -Force
# sysmon-modular publishes generated configs as releases (same release as the reference build)
Invoke-WebRequest https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig.xml `
  -OutFile "$dir\sysmonconfig.xml" -UseBasicParsing
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  & "$dir\Sysmon64.exe" -accepteula -c "$dir\sysmonconfig.xml"
} else {
  & "$dir\Sysmon64.exe" -accepteula -i "$dir\sysmonconfig.xml"
}
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:67108864

# --- 6. Evidence: effective policy after a Group Policy refresh ---
gpupdate /force | Out-Null
auditpol /get /category:* | Out-File C:\lab\auditpol-after.txt -Encoding utf8
Get-Content C:\lab\auditpol-after.txt
(Get-Acl "AD:$dn" -Audit).Audit | Where-Object { $rights -contains $_.ObjectType.Guid } |
  Format-Table IdentityReference, AuditFlags, ObjectType
Get-Service Sysmon64 | Format-Table Name, Status

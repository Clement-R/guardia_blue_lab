# After promotion: wait for AD, restrict DNS to the lab NIC and forward to libvirt's resolver,
# and give the DC (the domain's root time source) an external NTP source.
param(
  [string]$Ip = "10.77.77.20",
  [string]$Forwarder = "10.77.77.1",
  [string]$NtpPeers = "pool.ntp.org,0x8"
)
$ErrorActionPreference = "Stop"

# AD Web Services takes a few minutes after the first boot as a DC
for ($i = 0; $i -lt 60; $i++) {
  try { Import-Module ActiveDirectory; Get-ADDomain | Out-Null; break } catch { Start-Sleep 10 }
}
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode | Format-List

dnscmd /ResetListenAddresses $Ip | Out-Null
Set-DnsServerForwarder -IPAddress $Forwarder
Restart-Service DNS
Resolve-DnsName artifacts.elastic.co -Type A | Where-Object Type -eq 'A' | Select-Object -First 1 | Format-Table Name, IPAddress

# --- Time: the PDC emulator is the domain's time root, so it needs an external source.
# Accurate time matters for detection (rule lookbacks, time to detect) and must be
# resynchronised after every snapshot revert: w32tm /resync /force
w32tm /config /manualpeerlist:"$NtpPeers" /syncfromflags:manual /reliable:yes /update | Out-Null
Restart-Service w32time
Start-Sleep 5
w32tm /resync /force | Out-Null
w32tm /query /source
w32tm /stripchart /computer:($NtpPeers -split ",")[0] /samples:2 /dataonly

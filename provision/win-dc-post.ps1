# After promotion: wait for AD, then restrict DNS to the lab NIC and forward to libvirt's resolver.
param(
  [string]$Ip = "10.77.77.20",
  [string]$Forwarder = "10.77.77.1"
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

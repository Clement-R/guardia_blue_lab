# Static IP on the lab NIC, then promote a new forest lab.local. Vagrant reboots afterwards.
param(
  [string]$Ip = "10.77.77.20",
  [string]$Gateway = "10.77.77.1",
  [string]$Mac = "52-54-00-77-77-20",
  [string]$Domain = "lab.local",
  [string]$NetBios = "LAB"
)
$ErrorActionPreference = "Stop"

# --- Lab NIC: static IP, DNS on itself ---
$nic = Get-NetAdapter | Where-Object MacAddress -eq $Mac
if (-not $nic) { throw "Lab NIC with MAC $Mac not found" }
if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Ip -ErrorAction SilentlyContinue)) {
  Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
  Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Ip -PrefixLength 24 | Out-Null
}
Rename-NetAdapter -Name $nic.Name -NewName "lab" -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceAlias "lab" -ServerAddresses @("127.0.0.1")

# The other NIC is Vagrant's management network: keep it out of the domain's DNS
Get-NetAdapter | Where-Object MacAddress -ne $Mac | ForEach-Object {
  Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $false
}

# --- Promotion (skipped if already a DC) ---
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
  Write-Host "Already a domain controller of $((Get-CimInstance Win32_ComputerSystem).Domain), skipping promotion"
  exit 0
}
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

# Random DSRM password: lab only, not needed afterwards
$dsrm = ConvertTo-SecureString ([guid]::NewGuid().ToString() + "aA1!") -AsPlainText -Force
Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBios -InstallDns `
  -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion -Force | Out-Null
Write-Host "Forest $Domain created; Vagrant reboots the VM now"

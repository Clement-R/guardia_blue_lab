# Trust the lab CA, then install Elastic Agent and enrol it into Fleet, with certificate verification.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Windows PowerShell 5.1 downloads are very slow with the progress bar
$lab     = "C:\lab"
$version = (Get-Content "$lab\stack-version" -Raw).Trim()
$token   = (Get-Content "$lab\enrollment-token" -Raw).Trim()
$fleet   = (Get-Content "$lab\fleet-url" -Raw).Trim()

Import-Certificate -FilePath "$lab\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

if (Get-Service "Elastic Agent" -ErrorAction SilentlyContinue) {
  Write-Host "Elastic Agent already installed"
  & "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
  exit 0
}

$name = "elastic-agent-$version-windows-x86_64"
Invoke-WebRequest "https://artifacts.elastic.co/downloads/beats/elastic-agent/$name.zip" `
  -OutFile "$lab\$name.zip" -UseBasicParsing
Expand-Archive "$lab\$name.zip" $lab -Force

& "$lab\$name\elastic-agent.exe" install --non-interactive `
  --url=$fleet --enrollment-token=$token --certificate-authorities="$lab\ca.crt"
if ($LASTEXITCODE -ne 0) { throw "elastic-agent install failed ($LASTEXITCODE)" }

Start-Sleep 30
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status

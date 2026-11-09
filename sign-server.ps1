param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$VpsIp,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$SshKey
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir = Join-Path $ScriptDir "certs"

if (!(Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
}

$CaKey = Join-Path $CertsDir "ca.key"
$CaCrt = Join-Path $CertsDir "ca.crt"
$ServerKey = Join-Path $CertsDir "server.key"
$ServerCsr = Join-Path $CertsDir "server.csr"
$ServerCrt = Join-Path $CertsDir "server.crt"

if (!(Test-Path $CaKey) -or !(Test-Path $CaCrt)) {
    Write-Error "CA certificates not found in $CertsDir. Run scripts/generate_ca_and_clients.py first!"
    exit 1
}

Write-Host "[*] 1. Generating server key and CSR for IP: $VpsIp..."
openssl req -newkey rsa:2048 -nodes -keyout $ServerKey -out $ServerCsr -subj "/CN=$VpsIp"

Write-Host "[*] 2. Signing server certificate with local CA and SAN=IP:$VpsIp..."
$ExtFile = [System.IO.Path]::GetTempFileName()
Set-Content -Path $ExtFile -Value "subjectAltName=IP:$VpsIp"

openssl x509 -req -in $ServerCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $ServerCrt -days 365 -extfile $ExtFile

Remove-Item -Path $ExtFile, $ServerCsr -ErrorAction SilentlyContinue

Write-Host "[*] 3. Uploading certificates to VPS via scp..."
scp -i $SshKey -o StrictHostKeyChecking=no $ServerCrt $ServerKey $CaCrt "ubuntu@${VpsIp}:/tmp/"

Write-Host "[*] 4. Moving certs to /etc/nginx/certs/ and reloading Nginx..."
$RemoteCmd = "sudo mkdir -p /etc/nginx/certs && sudo mv /tmp/server.crt /tmp/server.key /tmp/ca.crt /etc/nginx/certs/ && sudo chown -R root:root /etc/nginx/certs && sudo chmod 644 /etc/nginx/certs/server.crt /etc/nginx/certs/ca.crt && sudo chmod 600 /etc/nginx/certs/server.key && sudo nginx -t && sudo systemctl reload nginx"
ssh -i $SshKey -o StrictHostKeyChecking=no "ubuntu@$VpsIp" $RemoteCmd

Write-Host "[+] Done! Server certificate deployed and active for https://$VpsIp/"

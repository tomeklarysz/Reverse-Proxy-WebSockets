#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <VPS_PUBLIC_IP> <SSH_KEY_PATH>"
    echo "Example: $0 3.120.15.20 ~/.ssh/MyKeyPairPutty.pem"
    exit 1
fi

VPS_IP="$1"
SSH_KEY="$2"
CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"

mkdir -p "$CERTS_DIR"

if [ ! -f "$CERTS_DIR/ca.key" ] || [ ! -f "$CERTS_DIR/ca.crt" ]; then
    echo "[-] Error: CA certificates not found in $CERTS_DIR. Run generate-ca-and-clients first!"
    exit 1
fi

echo "[*] 1. Generating server key and CSR for IP: $VPS_IP..."
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.csr" \
    -subj "/CN=$VPS_IP"

echo "[*] 2. Signing server certificate with local CA and SAN=IP:$VPS_IP..."
EXT_FILE=$(mktemp)
echo "subjectAltName=IP:$VPS_IP" > "$EXT_FILE"

openssl x509 -req \
    -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/server.crt" \
    -days 365 \
    -extfile "$EXT_FILE"

rm -f "$EXT_FILE" "$CERTS_DIR/server.csr"

echo "[*] 3. Uploading certificates to VPS (/tmp -> /etc/nginx/certs/)..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "$CERTS_DIR/server.crt" "$CERTS_DIR/server.key" "$CERTS_DIR/ca.crt" \
    "ubuntu@$VPS_IP:/tmp/"

echo "[*] 4. Moving certs and reloading Nginx on VPS..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@$VPS_IP" "
    sudo mkdir -p /etc/nginx/certs
    sudo mv /tmp/server.crt /tmp/server.key /tmp/ca.crt /etc/nginx/certs/
    sudo chown -R root:root /etc/nginx/certs
    sudo chmod 644 /etc/nginx/certs/server.crt /etc/nginx/certs/ca.crt
    sudo chmod 600 /etc/nginx/certs/server.key
    sudo nginx -t && sudo systemctl reload nginx
    echo '[+] Nginx reloaded successfully with new certificates!'
"

echo "[+] Done! Server certificate deployed and active for https://$VPS_IP/"

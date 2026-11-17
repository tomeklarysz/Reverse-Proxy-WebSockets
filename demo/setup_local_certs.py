#!/usr/bin/env python3
"""Create a separate CA + certificates for the local Docker replica of the VPS.

Writes everything to demo/certs (ignored by git), so the team's certs/ used
for the real VPS are never touched:
  ca.crt / ca.key         - local demo Root CA
  agent.crt / agent.key   - agent mTLS identity
  client.crt / client.key / client.p12 - browser identity (password: client123)
  server.crt / server.key - Nginx certificate for 127.0.0.1 / localhost
"""
import os
import subprocess
import sys

DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(DEMO_DIR)
CERTS_DIR = os.path.join(DEMO_DIR, "certs")


# Minimal OpenSSL config. Some openssl builds on Windows (e.g. the one bundled with
# Strawberry Perl) point to a non-existent default openssl.cnf and "openssl req" fails.
OPENSSL_CNF = """[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no
[req_dn]
CN = placeholder
[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"""


def use_minimal_openssl_conf(directory):
    """Point OPENSSL_CONF to a minimal config unless the user already set a valid one."""
    if os.path.isfile(os.environ.get("OPENSSL_CONF", "")):
        return
    path = os.path.join(directory, "openssl-minimal.cnf")
    with open(path, "w") as f:
        f.write(OPENSSL_CNF)
    os.environ["OPENSSL_CONF"] = path


def run(cmd):
    print(f"[*] {' '.join(cmd)}")
    subprocess.check_call(cmd)


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    use_minimal_openssl_conf(CERTS_DIR)   # inherited by generate_ca_and_clients.py too
    run([sys.executable, os.path.join(PROJECT_ROOT, "scripts", "generate_ca_and_clients.py"), "--certs-dir", CERTS_DIR])

    key, csr, crt, ext = (os.path.join(CERTS_DIR, n) for n in ("server.key", "server.csr", "server.crt", "server.ext"))
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1"])
    with open(ext, "w") as f:
        f.write("subjectAltName=IP:127.0.0.1,DNS:localhost\n")
    run(["openssl", "x509", "-req", "-in", csr, "-CA", os.path.join(CERTS_DIR, "ca.crt"),
         "-CAkey", os.path.join(CERTS_DIR, "ca.key"), "-CAcreateserial", "-out", crt, "-days", "30", "-extfile", ext])
    os.remove(csr)
    os.remove(ext)
    print(f"\n[+] Local demo certificates ready in {CERTS_DIR}")


if __name__ == "__main__":
    main()

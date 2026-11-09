#!/usr/bin/env python3
"""Generate Root CA, Agent client certificates, and Browser PKCS#12 client certificates for mTLS."""

import argparse
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CERTS_DIR = os.path.join(PROJECT_ROOT, "certs")


def run_cmd(cmd):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.check_call(cmd)


def generate(certs_dir, client_pass):
    os.makedirs(certs_dir, exist_ok=True)

    ca_key = os.path.join(certs_dir, "ca.key")
    ca_crt = os.path.join(certs_dir, "ca.crt")
    agent_key = os.path.join(certs_dir, "agent.key")
    agent_csr = os.path.join(certs_dir, "agent.csr")
    agent_crt = os.path.join(certs_dir, "agent.crt")
    client_key = os.path.join(certs_dir, "client.key")
    client_csr = os.path.join(certs_dir, "client.csr")
    client_crt = os.path.join(certs_dir, "client.crt")
    client_p12 = os.path.join(certs_dir, "client.p12")

    # 1. Root Certificate Authority (CA)
    if not os.path.exists(ca_key) or not os.path.exists(ca_crt):
        print("\n--- 1. Generating Root CA (ca.key, ca.crt) ---")
        run_cmd([
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-days", "3650", "-nodes",
            "-keyout", ca_key, "-out", ca_crt,
            "-subj", "/CN=ReverseProxy-Root-CA/O=AcademicPoC/OU=SecureComm"
        ])
    else:
        print("\n--- 1. Root CA already exists, reusing ca.key and ca.crt ---")

    # 2. Agent Identity (mTLS certificate for agent.py)
    print("\n--- 2. Generating Agent Certificate (agent.key, agent.crt) ---")
    run_cmd([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", agent_key, "-out", agent_csr,
        "-subj", "/CN=ReverseProxy-Local-Agent/O=AcademicPoC"
    ])
    run_cmd([
        "openssl", "x509", "-req", "-in", agent_csr,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-out", agent_crt, "-days", "365"
    ])
    if os.path.exists(agent_csr):
        os.remove(agent_csr)

    # 3. Browser Client Identity (mTLS certificate for user browser: client.p12)
    print("\n--- 3. Generating Browser Client Certificate (client.p12) ---")
    run_cmd([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", client_key, "-out", client_csr,
        "-subj", "/CN=ReverseProxy-Browser-Client/O=AcademicPoC"
    ])
    run_cmd([
        "openssl", "x509", "-req", "-in", client_csr,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-out", client_crt, "-days", "365"
    ])
    if os.path.exists(client_csr):
        os.remove(client_csr)

    # Convert browser client cert to PKCS#12 bundle (.p12)
    run_cmd([
        "openssl", "pkcs12", "-export",
        "-out", client_p12,
        "-inkey", client_key,
        "-in", client_crt,
        "-certfile", ca_crt,
        "-passout", f"pass:{client_pass}"
    ])

    print("\n" + "=" * 60)
    print("[+] All identity certificates generated successfully!")
    print(f"[*] Directory: {certs_dir}")
    print("    - ca.crt           -> Public CA certificate (copied to VPS / loaded by client)")
    print("    - ca.key           -> Private CA key (KEEP LOCAL & SECRET)")
    print("    - agent.crt / key  -> Agent mTLS certificate and private key")
    print(f"    - client.p12       -> Browser certificate (Password: '{client_pass}')")
    print("=" * 60)
    print("[*] To import client.p12 into browser:")
    print("    - Windows: Double-click client.p12 -> Current User -> Personal Store")
    print("    - macOS: Double-click client.p12 -> Add to Keychain -> login")
    print("    - Firefox: Settings -> Privacy & Security -> View Certificates -> Your Certificates -> Import")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Generate CA, Agent, and Client certificates for mTLS")
    parser.add_argument("--certs-dir", default=CERTS_DIR, help="Directory to save certificates")
    parser.add_argument("--password", default="client123", help="Export password for client.p12")
    args = parser.parse_args()

    generate(args.certs_dir, args.password)


if __name__ == "__main__":
    main()

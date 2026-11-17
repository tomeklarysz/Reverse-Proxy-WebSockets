"""Authentication demo: who can open the tunnel and who cannot.

Tries to connect to the tunnel endpoint (Nginx with mTLS -> vps.py) in several ways
and prints a table. Layers that are demonstrated:
  1. mTLS (Nginx)        - client must present a certificate signed by our CA
  2. Bearer token (vps.py) - second, independent factor (defense in depth)
  3. Origin check (vps.py) - browser connections are refused (CSWSH)
  4. Server authentication (agent) - the agent refuses a fake server (MITM),
     unless verification is disabled with --insecure

Usage:
  python security_tests/demo_auth.py --url wss://127.0.0.1:8443/ws-tunnel --certs demo/certs   # local Docker replica
  python security_tests/demo_auth.py --url wss://<VPS_IP>/ws-tunnel --certs certs              # real VPS
The token is taken from --token or the TUNNEL_TOKEN environment variable.

Note: the "valid credentials" case briefly replaces a running agent's tunnel;
the agent reconnects automatically within ~2 s.
Exit code: 0 = every case behaved as expected, 1 = something did not.
"""
import argparse
import asyncio
import os
import ssl
import subprocess
import sys
import tempfile

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import InvalidStatus

rows = []

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


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def make_rogue_pki(tmp):
    """A CA that is NOT ours, with a client cert and a server cert for 127.0.0.1 - what an attacker can make."""
    use_minimal_openssl_conf(tmp)
    ca_key, ca_crt = os.path.join(tmp, "rogue-ca.key"), os.path.join(tmp, "rogue-ca.crt")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", ca_key, "-out", ca_crt,
            "-subj", "/CN=Attacker-CA")
    ext = os.path.join(tmp, "san.ext")
    with open(ext, "w") as f:
        f.write("subjectAltName=IP:127.0.0.1,DNS:localhost\n")
    paths = {}
    for name in ("client", "server"):
        key, csr, crt = (os.path.join(tmp, f"rogue-{name}.{e}") for e in ("key", "csr", "crt"))
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", f"/CN=Attacker-{name}")
        openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-out", crt,
                "-days", "1", "-extfile", ext)
        paths[name] = (crt, key)
    return paths


def client_ctx(ca=None, cert=None, verify=True):
    """Same TLS setup as agent.py."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.load_verify_locations(cafile=ca)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert:
        ctx.load_cert_chain(*cert)
    return ctx


async def try_connect(url, ctx, token=None, origin=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with connect(url, ssl=ctx, additional_headers=headers, origin=origin, open_timeout=10):
            return True, "connected (HTTP 101)"
    except InvalidStatus as e:
        body = e.response.body.decode(errors="replace")
        hint = ""
        if "No required SSL certificate" in body:
            hint = " - Nginx: no client certificate"
        elif "SSL certificate error" in body:
            hint = " - Nginx: certificate not signed by our CA"
        return False, f"HTTP {e.response.status_code}{hint}"
    except ssl.SSLCertVerificationError as e:
        return False, f"TLS: {e.verify_message}"
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return False, f"TLS/connection error: {e.__class__.__name__}"


def record(case, who, accepted, result, expect_accepted):
    ok = accepted == expect_accepted
    rows.append((case, who, "ACCEPTED" if accepted else "REJECTED", result, "OK" if ok else "UNEXPECTED"))


async def fake_server_case(ca, agent_cert, token, rogue, verify):
    """An attacker's server (e.g. DNS spoofing / evil Wi-Fi) pretending to be the VPS."""
    captured = []

    def steal(connection, request):
        captured.append(request.headers.get("Authorization", ""))

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(*rogue["server"])
    async with serve(lambda ws: ws.wait_closed(), "127.0.0.1", 0, ssl=srv_ctx, process_request=steal) as srv:
        port = srv.sockets[0].getsockname()[1]
        accepted, result = await try_connect(f"wss://127.0.0.1:{port}/ws-tunnel",
                                             client_ctx(ca, agent_cert, verify=verify), token)
    if captured and captured[0]:
        stolen = captured[0].removeprefix("Bearer ")
        result += f"; attacker captured token {stolen[:6]}..."
    return accepted, result


async def main(args):
    ca = os.path.join(args.certs, "ca.crt")
    agent_cert = (os.path.join(args.certs, "agent.crt"), os.path.join(args.certs, "agent.key"))
    for path in (ca, *agent_cert):
        if not os.path.isfile(path):
            print(f"[X] Missing {path} - generate certificates first (see README).")
            return 2
    if not args.token:
        print("[X] No token - set TUNNEL_TOKEN or pass --token.")
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        rogue = make_rogue_pki(tmp)
        good = client_ctx(ca, agent_cert)
        url, tok = args.url, args.token

        print(f"Target: {url}\n")
        record("1", "stolen token, NO client certificate", *await try_connect(url, client_ctx(ca), tok), False)
        record("2", "stolen token, certificate from attacker's CA",
               *await try_connect(url, client_ctx(ca, rogue["client"]), tok), False)
        record("3", "valid certificate, no token", *await try_connect(url, good), False)
        record("4", "valid certificate, wrong token", *await try_connect(url, good, "wrong-token-123"), False)
        record("5", "valid cert + token, from a browser (Origin)",
               *await try_connect(url, good, tok, origin="https://evil.example"), False)
        record("6", "valid certificate + valid token (agent)", *await try_connect(url, good, tok), True)
        record("7", "agent -> FAKE server (MITM), verification ON",
               *await fake_server_case(ca, agent_cert, tok, rogue, verify=True), False)
        record("8", "agent -> FAKE server, --insecure (verification OFF)",
               *await fake_server_case(ca, agent_cert, tok, rogue, verify=False), True)

    widths = [max(len(str(r[i])) for r in rows + [("#", "Who connects", "Result", "Details", "Check")]) for i in range(5)]
    header = ("#", "Who connects", "Result", "Details", "Check")
    line = "+".join("-" * (w + 2) for w in widths)
    print(line)
    print("|".join(f" {h:<{w}} " for h, w in zip(header, widths)))
    print(line)
    for r in rows:
        print("|".join(f" {c:<{w}} " for c, w in zip(r, widths)))
    print(line)
    print("\nCase 8 is expected to succeed: it shows why the agent must never run with --insecure -")
    print("without server verification a fake server receives the token and all tunnel traffic.")

    ok = all(r[4] == "OK" for r in rows)
    print(f"\nRESULT: authentication: {'PROTECTED' if ok else 'CHECK THE TABLE'}")
    return 0 if ok else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Demonstrate tunnel authentication layers")
    p.add_argument("--url", default="wss://127.0.0.1:8443/ws-tunnel", help="Tunnel URL behind Nginx")
    p.add_argument("--certs", default="certs", help="Directory with ca.crt, agent.crt, agent.key")
    p.add_argument("--token", default=os.environ.get("TUNNEL_TOKEN"))
    sys.exit(asyncio.run(main(p.parse_args())))

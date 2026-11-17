"""Eavesdropping demo: what an attacker on the network sees in the tunnel traffic.

Records the agent <-> broker traffic with tshark (Wireshark) in two scenarios and
searches the captured bytes for secrets:
  A) ws://  - plain WebSocket straight to vps.py (no TLS)       -> started by this script
  B) wss:// - through Nginx with TLS + mTLS (Docker replica or the real VPS)

In each scenario the script starts its own gallery service and agent, opens a page and
a photo through the tunnel, then analyses the capture. Captures are saved to
demo/captures/*.pcapng - open them in Wireshark: the GET request carries the token,
filter "websocket" shows the JSON messages (WebSocket -> Payload -> Text).

Stop your own agent first: the agent started here replaces it while the demo runs.

Usage (local Docker replica, see demo/README.md):
  python security_tests/demo_eavesdrop.py --tls-url wss://127.0.0.1:8443/ws-tunnel --certs demo/certs
Real VPS (capture on the Wi-Fi interface, run `tshark -D` to list interfaces):
  python security_tests/demo_eavesdrop.py --tls-url wss://<VPS_IP>/ws-tunnel --certs certs --interface Wi-Fi
The token is taken from --token or the TUNNEL_TOKEN environment variable.
"""
import argparse
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES = os.path.join(ROOT, "demo", "captures")
GALLERY_PORT = 13300
PLAIN_HTTP, PLAIN_WS = 18080, 18765
PHOTO = "/photos/gory_tatry.jpg"


def find_tshark():
    found = shutil.which("tshark")
    default = r"C:\Program Files\Wireshark\tshark.exe"
    return found or (default if os.path.isfile(default) else None)


def start(*args, env=None):
    return subprocess.Popen([sys.executable, "-u", *args], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fetch(url, ctx=None):
    try:
        with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
            return r.status, r.read()
    except Exception as e:
        return None, repr(e).encode()


def wait_for_tunnel(url, ctx=None, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fetch(url, ctx)[0] == 200:
            return True
        time.sleep(0.5)
    return False


def capture(tshark, interface, bfilter, out, traffic):
    """Run tshark around the traffic() callback and return the capture file path."""
    proc = subprocess.Popen([tshark, "-i", interface, "-f", bfilter, "-w", out],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for line in proc.stderr:           # wait until tshark really captures
        if "Capturing on" in line:
            break
    try:
        ok = traffic()
        time.sleep(1)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    return ok


def payload_bytes(tshark, pcap, port):
    """Raw TCP bytes plus WebSocket messages as Wireshark shows them (unmasked + decompressed).

    Masking and permessage-deflate are not encryption - Wireshark undoes both automatically.
    """
    raw = subprocess.run([tshark, "-r", pcap, "-T", "fields", "-e", "tcp.payload"],
                         capture_output=True, text=True).stdout
    data = b"".join(bytes.fromhex(h.replace(":", "")) for h in raw.split() if h)
    ws = subprocess.run([tshark, "-r", pcap, "-d", f"tcp.port=={port},http", "-T", "fields",
                         "-e", "websocket.payload.text"], capture_output=True, text=True, encoding="utf-8").stdout
    return data + ws.encode()


def tls_info(tshark, pcap):
    out = subprocess.run([tshark, "-r", pcap, "-Y", "tls.handshake.type==2", "-T", "fields",
                          "-e", "tls.handshake.extensions.supported_version", "-e", "tls.handshake.ciphersuite"],
                         capture_output=True, text=True).stdout.split()
    versions = {"0x0304": "TLS 1.3", "0x0303": "TLS 1.2"}
    suites = {"0x1301": "TLS_AES_128_GCM_SHA256", "0x1302": "TLS_AES_256_GCM_SHA384",
              "0x1303": "TLS_CHACHA20_POLY1305_SHA256"}
    if len(out) >= 2:
        return f"{versions.get(out[0], out[0])}, {suites.get(out[1], out[1])}"
    return "TLS (version not decoded)" if out else "none - plaintext"


def analyse(data, token):
    return {
        "Bearer token": token.encode() in data,
        "request paths (/photos/...)": f'"path": "{PHOTO}"'.encode() in data,
        "photo content (JPEG, base64)": b'"body": "/9j/' in data,
        "HTML of the private page": b"<!DOCTYPE html>" in data,
    }


def scenario_plain(tshark, token, env):
    broker = start("vps.py", "--host", "127.0.0.1", "--http-port", str(PLAIN_HTTP), "--ws-port", str(PLAIN_WS), env=env)
    time.sleep(1.5)
    agent = None

    def traffic():
        nonlocal agent
        agent = start("agent.py", "--vps-url", f"ws://127.0.0.1:{PLAIN_WS}",
                      "--target-url", f"http://127.0.0.1:{GALLERY_PORT}", env=env)
        base = f"http://127.0.0.1:{PLAIN_HTTP}"
        ok = wait_for_tunnel(base + "/")
        fetch(base + PHOTO)
        return ok

    pcap = os.path.join(CAPTURES, "A_plain_ws.pcapng")
    try:
        ok = capture(tshark, r"\Device\NPF_Loopback", f"tcp port {PLAIN_WS}", pcap, traffic)
    finally:
        for p in (agent, broker):
            if p:
                p.terminate()
    return ok, pcap


def scenario_tls(tshark, token, env, tls_url, certs, interface):
    u = urllib.parse.urlsplit(tls_url)
    port = u.port or 443
    public = f"https://{u.hostname}:{port}"
    ctx = ssl.create_default_context(cafile=os.path.join(certs, "ca.crt"))
    ctx.load_cert_chain(os.path.join(certs, "client.crt"), os.path.join(certs, "client.key"))
    agent = None

    def traffic():
        nonlocal agent
        agent = start("agent.py", "--vps-url", tls_url, "--target-url", f"http://127.0.0.1:{GALLERY_PORT}",
                      "--ca-cert", os.path.join(certs, "ca.crt"),
                      "--agent-cert", os.path.join(certs, "agent.crt"),
                      "--agent-key", os.path.join(certs, "agent.key"), env=env)
        ok = wait_for_tunnel(public + "/", ctx)
        fetch(public + PHOTO, ctx)
        return ok

    iface = interface or r"\Device\NPF_Loopback"
    bfilter = f"host {u.hostname} and tcp port {port}" if interface else f"tcp port {port}"
    pcap = os.path.join(CAPTURES, "B_tls_wss.pcapng")
    try:
        ok = capture(tshark, iface, bfilter, pcap, traffic)
    finally:
        if agent:
            agent.terminate()
    return ok, pcap


def main(args):
    tshark = find_tshark()
    if not tshark:
        print("[X] tshark not found - install Wireshark (with Npcap).")
        return 2
    if not args.token:
        print("[X] No token - set TUNNEL_TOKEN or pass --token.")
        return 2
    os.makedirs(CAPTURES, exist_ok=True)
    env = dict(os.environ, TUNNEL_TOKEN=args.token)
    gallery = start("gallery_service.py", "--port", str(GALLERY_PORT))
    time.sleep(1)
    try:
        print("[*] Scenario A: ws:// without TLS - capturing...")
        ok_a, pcap_a = scenario_plain(tshark, args.token, env)
        print(f"[*] Scenario B: {args.tls_url} (TLS + mTLS) - capturing...")
        ok_b, pcap_b = scenario_tls(tshark, args.token, env, args.tls_url, args.certs, args.interface)
    finally:
        gallery.terminate()

    if not (ok_a and ok_b):
        print(f"[X] Setup error - tunnel did not work (A: {ok_a}, B: {ok_b}). Is Nginx/broker running and the token right?")
        return 2

    data_a = payload_bytes(tshark, pcap_a, PLAIN_WS)
    data_b = payload_bytes(tshark, pcap_b, urllib.parse.urlsplit(args.tls_url).port or 443)
    res_a, res_b = analyse(data_a, args.token), analyse(data_b, args.token)

    rows = [(k, "VISIBLE" if res_a[k] else "-", "VISIBLE" if res_b[k] else "not visible") for k in res_a]
    rows.append(("protocol on the wire", "plain HTTP/WebSocket", tls_info(tshark, pcap_b)))
    header = ("What the eavesdropper looks for", "A) ws://", "B) wss:// + mTLS")
    widths = [max(len(r[i]) for r in rows + [header]) for i in range(3)]
    line = "+".join("-" * (w + 2) for w in widths)
    print("\n" + line)
    print("|".join(f" {h:<{w}} " for h, w in zip(header, widths)))
    print(line)
    for r in rows:
        print("|".join(f" {c:<{w}} " for c, w in zip(r, widths)))
    print(line)

    idx = data_a.find(b"Authorization: Bearer")
    if idx >= 0:
        snippet = data_a[idx:idx + 60].split(b"\r\n")[0].decode(errors="replace")
        print(f"\nIn scenario A the attacker reads directly: {snippet[:28]}{'*' * 10} (token masked here)")
    print(f"\nCaptures saved: {pcap_a}\n                {pcap_b}")
    print("Open them in Wireshark: the GET / packet shows the token, filter \"websocket\" shows the JSON.")

    leaked = any(res_b.values())
    print(f"\nRESULT: eavesdropping (ws://): {'VULNERABLE' if any(res_a.values()) else 'PROTECTED'}")
    print(f"RESULT: eavesdropping (wss:// + mTLS): {'VULNERABLE' if leaked else 'PROTECTED'}")
    return 1 if leaked else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Show what an eavesdropper sees with ws:// vs wss://")
    p.add_argument("--tls-url", default="wss://127.0.0.1:8443/ws-tunnel", help="Tunnel URL behind Nginx")
    p.add_argument("--certs", default="certs", help="Directory with ca.crt, agent.*, client.*")
    p.add_argument("--interface", default=None, help="Capture interface for the TLS scenario (default: loopback)")
    p.add_argument("--token", default=os.environ.get("TUNNEL_TOKEN"))
    sys.exit(main(p.parse_args()))

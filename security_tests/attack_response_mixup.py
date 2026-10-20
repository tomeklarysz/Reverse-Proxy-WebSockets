"""Attack: head-of-line blocking (DoS) and responses delivered to the wrong user.

Starts a "slow" home service on 127.0.0.1:13000:
  /slow  - answers after 12 s (longer than the broker's 10 s timeout)
  other  - answers immediately with "response to <path>"

The agent must target this service:
  python agent.py --vps-url ws://127.0.0.1:8765 --target-url http://127.0.0.1:13000

Vulnerable (single lock + recv in the broker):
  - user B (fast request) waits ~9 s because A holds the lock      -> DoS
  - after A times out, C gets A's response, D gets C's response...  -> data leak
Protected (request ids): B is served immediately, everyone gets their own response.

Usage: python attack_response_mixup.py [--http-url http://127.0.0.1:8080] [--service-port 13000]
Exit code: 0 = protected, 1 = vulnerable, 2 = setup error.
"""
import argparse
import http.server
import sys
import threading
import time
import urllib.request


class SlowHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(12)
        body = f"response to {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def fetch(url):
    try:
        return urllib.request.urlopen(url, timeout=30).read().decode()
    except Exception as e:
        return f"ERROR {e}"


def main(http_url, service_port):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", service_port), SlowHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # Setup check: the agent must forward traffic to the test service.
    probe = fetch(f"{http_url}/probe")
    if probe != "response to /probe":
        srv.shutdown()
        print(f"[X] Setup error - test NOT executed (broker returned: {probe!r}).")
        print(f"    Start the agent with: --target-url http://127.0.0.1:{service_port}")
        print("RESULT: blocking (DoS) / response mix-up: SETUP_ERROR")
        return 2

    t0 = time.time()
    leaks = []

    def get(user, path):
        body = fetch(f"{http_url}{path}")
        ok = body == f"response to {path}"
        if not ok and not body.startswith("ERROR"):
            leaks.append(user)
        print(f"[t={time.time() - t0:4.1f}s] {user} asked for {path:6} -> got: {body}"
              + ("" if ok or body.startswith("ERROR") else "   <-- SOMEONE ELSE'S DATA!"))

    print("A asks for /slow, 1 s later B asks for /fast ...")
    a = threading.Thread(target=get, args=("A", "/slow"))
    a.start()
    time.sleep(1)
    tb = time.time()
    get("B", "/fast")
    b_wait = time.time() - tb
    a.join()
    time.sleep(3)
    print("A moment later more users arrive:")
    get("C", "/C")
    get("D", "/D")
    srv.shutdown()

    print()
    blocked = b_wait > 5
    print(f"[!] DoS: fast request B waited {b_wait:.1f} s, blocked by A." if blocked
          else f"[+] B was served immediately ({b_wait:.1f} s).")
    print(f"[!] LEAK: users {', '.join(leaks)} received someone else's responses." if leaks
          else "[+] Everyone received their own response.")
    print(f"RESULT: blocking (DoS): {'VULNERABLE' if blocked else 'PROTECTED'}")
    print(f"RESULT: response mix-up (data leak): {'VULNERABLE' if leaks else 'PROTECTED'}")
    return 1 if blocked or leaks else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--http-url", default="http://127.0.0.1:8080")
    p.add_argument("--service-port", type=int, default=13000)
    a = p.parse_args()
    sys.exit(main(a.http_url.rstrip("/"), a.service_port))

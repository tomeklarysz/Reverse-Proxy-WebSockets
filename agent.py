import argparse
import asyncio
import base64
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional

try:
    from websockets.asyncio.client import connect
except ImportError:
    from websockets import connect

MAX_BODY = 10 * 1024 * 1024         # max response body read from the local service
MAX_WS_MESSAGE = 16 * 1024 * 1024   # must not exceed the broker's max_size
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
SAFE_PATH = re.compile(r"/[\x21-\x7e]{0,2047}")


class ForwardError(Exception):
    pass


def build_local_request(target_base: str, method: str, path: str, data: Optional[bytes]) -> urllib.request.Request:
    """Build the request and make sure it really goes to target_base (SSRF protection)."""
    if not SAFE_PATH.fullmatch(path):
        raise ForwardError("path must start with '/'")
    target = urllib.request.Request(target_base)
    req = urllib.request.Request(url=f"{target_base.rstrip('/')}{path}", data=data, method=method)
    if (req.type, req.host) != (target.type, target.host):
        raise ForwardError(f"request would leave the target ({req.host!r})")
    return req


def read_limited(resp) -> bytes:
    data = resp.read(MAX_BODY + 1)
    if len(data) > MAX_BODY:
        raise ForwardError(f"response body larger than {MAX_BODY} bytes")
    return data


def forward_to_local(target_base: str, method: str, path: str, headers: Optional[dict] = None, body: Optional[str] = None) -> tuple[int, dict, str, bool]:
    data = body.encode("utf-8") if body else None
    try:
        req = build_local_request(target_base, method, path, data)
    except ForwardError as e:
        print(f"[security] Rejected request {method} {path[:80]!r}: {e}")
        return 400, {}, "<h1>400 Bad Request</h1>", False

    if headers:
        for k, v in headers.items():
            if k.lower() not in ("host", "content-length"):
                req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status_code = resp.status
            resp_headers = dict(resp.getheaders())
            raw_data = read_limited(resp)
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), read_limited(e).decode("utf-8", errors="replace"), False
        except ForwardError:
            return 502, {}, "<h1>502 Bad Gateway</h1><p>Response too large.</p>", False
    except urllib.error.URLError as e:
        print(f"[-] Cannot reach target: {e.reason}")
        return 502, {}, "<h1>502 Bad Gateway</h1><p>Agent cannot reach target.</p>", False
    except ForwardError as e:
        print(f"[-] {e}")
        return 502, {}, "<h1>502 Bad Gateway</h1><p>Response too large.</p>", False
    except Exception as e:
        print(f"[-] Local request failed: {e!r}")
        return 500, {}, "<h1>500 Internal Error</h1>", False

    content_type = resp_headers.get("Content-Type", "").lower()
    is_binary = any(content_type.startswith(prefix) for prefix in ("image/", "video/", "audio/", "application/octet-stream"))

    if not is_binary:
        try:
            return status_code, resp_headers, raw_data.decode("utf-8"), False
        except UnicodeDecodeError:
            pass

    return status_code, resp_headers, base64.b64encode(raw_data).decode("ascii"), True


async def handle_request(ws, raw_msg: str, target_base: str):
    try:
        data = json.loads(raw_msg)
        if not isinstance(data, dict):
            raise ValueError("message is not a JSON object")
    except Exception:
        await ws.send(json.dumps({"body": "<h1>400 Bad Request</h1>", "status_code": 400}))
        return

    req_id = data.get("id")
    method = str(data.get("method", "GET")).upper()
    path = str(data.get("path", "/"))
    headers = data.get("headers", {})
    body = data.get("body")

    start_t = time.perf_counter()
    if method not in ALLOWED_METHODS:
        print(f"[security] Rejected method {method[:16]!r}")
        status_code, resp_headers, resp_body, is_base64 = 405, {}, "<h1>405 Method Not Allowed</h1>", False
    else:
        status_code, resp_headers, resp_body, is_base64 = await asyncio.to_thread(
            forward_to_local, target_base, method, path, headers, body
        )
    elapsed_ms = (time.perf_counter() - start_t) * 1000
    print(f"[{method}] {path} -> {status_code} ({elapsed_ms:.1f}ms, base64={is_base64})")

    response_payload = {
        "status_code": status_code,
        "headers": resp_headers,
        "body": resp_body,
        "is_base64": is_base64
    }
    if req_id is not None:
        response_payload["id"] = req_id

    message = json.dumps(response_payload)
    if len(message) > MAX_WS_MESSAGE:
        print(f"[-] Response for {path} too large for the tunnel ({len(message)} bytes)")
        response_payload.update(status_code=502, headers={}, body="<h1>502 Bad Gateway</h1><p>Response too large.</p>", is_base64=False)
        message = json.dumps(response_payload)
    await ws.send(message)


async def run_agent(vps_url: str, target_base: str, token: Optional[str] = None, insecure: bool = False):
    ssl_context = None
    if vps_url.startswith("wss://"):
        ssl_context = ssl.create_default_context()
        if insecure:
            print("[security] WARNING: TLS certificate verification is disabled (--insecure), use only for testing")
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
    elif token:
        print("[security] WARNING: unencrypted ws:// - the token is sent in plain text, use wss:// outside local tests")

    connect_kwargs = {"max_size": MAX_WS_MESSAGE}
    if ssl_context:
        connect_kwargs["ssl"] = ssl_context
    if token:
        connect_kwargs["additional_headers"] = {"Authorization": f"Bearer {token}"}

    retry_delay = 2
    while True:
        try:
            print(f"[*] Connecting to: {vps_url}...")
            async with connect(vps_url, **connect_kwargs) as ws:
                print(f"[+] Connected to {vps_url}")
                retry_delay = 2

                async for message in ws:
                    asyncio.create_task(handle_request(ws, message, target_base))

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[-] Connection error: {e}. Retrying in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 30)


def parse_args():
    parser = argparse.ArgumentParser(description="Local Agent (Reverse Proxy over WS)")
    parser.add_argument("--vps-url", "--broker-url", dest="vps_url", default="ws://127.0.0.1:8765", help="VPS WebSocket URL")
    parser.add_argument("--target-url", default="http://127.0.0.1:3000", help="Local HTTP service URL")
    parser.add_argument("--token", default=os.environ.get("TUNNEL_TOKEN"),
                        help="Authentication Bearer token (default: TUNNEL_TOKEN env variable, preferred - CLI args are visible in the process list)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(run_agent(args.vps_url, args.target_url, args.token, args.insecure))
    except KeyboardInterrupt:
        pass

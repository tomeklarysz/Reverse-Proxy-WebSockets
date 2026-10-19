import argparse
import asyncio
import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional

try:
    from websockets.asyncio.client import connect
except ImportError:
    from websockets import connect


def forward_to_local(target_base: str, method: str, path: str, headers: Optional[dict] = None, body: Optional[str] = None) -> tuple[int, dict, str, bool]:
    url = f"{target_base.rstrip('/')}{path}"
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url=url, data=data, method=method)

    if headers:
        for k, v in headers.items():
            if k.lower() not in ("host", "content-length"):
                req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status_code = resp.status
            resp_headers = dict(resp.getheaders())
            raw_data = resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace"), False
    except urllib.error.URLError as e:
        return 502, {}, f"<h1>502 Bad Gateway</h1><p>Agent cannot reach target: {e.reason}</p>", False
    except Exception as e:
        return 500, {}, f"<h1>500 Internal Error</h1><p>{str(e)}</p>", False

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
    except Exception as e:
        await ws.send(json.dumps({"body": f"<h1>400 Bad Request</h1><p>{e}</p>", "status_code": 400}))
        return

    req_id = data.get("id")
    method = data.get("method", "GET").upper()
    path = data.get("path", "/")
    headers = data.get("headers", {})
    body = data.get("body")

    start_t = time.perf_counter()
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

    await ws.send(json.dumps(response_payload))


async def run_agent(vps_url: str, target_base: str, token: Optional[str] = None, insecure: bool = False):
    ssl_context = None
    if vps_url.startswith("wss://"):
        ssl_context = ssl.create_default_context()
        if insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

    connect_kwargs = {}
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
    parser.add_argument("--token", default=None, help="Authentication Bearer token")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(run_agent(args.vps_url, args.target_url, args.token, args.insecure))
    except KeyboardInterrupt:
        pass

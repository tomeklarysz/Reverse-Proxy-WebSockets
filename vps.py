import argparse
import asyncio
import base64
import hmac
import itertools
import json
import os
import re
import secrets
from http import HTTPStatus

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

MAX_WS_MESSAGE = 16 * 1024 * 1024   # max tunnel message (base64 photo + JSON), default in websockets is 1 MiB
REQUEST_TIMEOUT = 10                # seconds to wait for the home agent's response
HEADER_TIMEOUT = 10                 # seconds a client gets to send the request line + headers (slowloris)
MAX_LINE = 8 * 1024                 # max length of a single request/header line
MAX_HEADER_LINES = 100
MAX_CONNECTIONS = 100               # max concurrent public HTTP connections
MAX_PATH = 2048
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
SAFE_PATH = re.compile(r"/[\x21-\x7e]*")
SAFE_CONTENT_TYPE = re.compile(r"[\x20-\x7e]{1,200}")

TOKEN = None

tunnel = None
pending = {}
request_ids = itertools.count(1)
active_connections = 0


def is_safe_path(path):
    """Reject anything that is not an origin-form path, e.g. '0/' or '@host/' (SSRF in the agent)."""
    return len(path) <= MAX_PATH and SAFE_PATH.fullmatch(path) is not None


def check_token(connection, request):
    auth = request.headers.get("Authorization", "")
    if not hmac.compare_digest(auth.encode(), f"Bearer {TOKEN}".encode()):
        print(f"[security] Rejected tunnel connection from {connection.remote_address[0]}: invalid token")
        return connection.respond(HTTPStatus.UNAUTHORIZED, "Unauthorized\n")
    return None


async def tunnel_handler(ws):
    global tunnel
    old = tunnel
    tunnel = ws
    print(f"Home tunnel connected from {ws.remote_address[0]}")
    if old is not None:
        print("[security] Previous tunnel replaced by a new authenticated connection")
        await old.close(code=1008, reason="replaced by a new connection")

    try:
        async for message in ws:
            try:
                res = json.loads(message)
                entry = pending.get(res.get("id"))
            except (ValueError, AttributeError, TypeError):
                print("[security] Dropping malformed message from tunnel")
                continue
            if entry is None or entry[0] is not ws or entry[1].done():
                print(f"Dropping response with unknown/expired id {res.get('id')!r}")
                continue
            entry[1].set_result(res)
    except ConnectionClosed:
        pass
    finally:
        if tunnel is ws:
            tunnel = None
        for req_id, (owner, fut) in list(pending.items()):
            if owner is ws and not fut.done():
                fut.set_exception(ConnectionError("tunnel closed"))
        print("Tunnel disconnected")


async def forward(method, path):
    ws = tunnel
    if ws is None:
        return 502, b"<h1>502 Bad Gateway</h1><p>Home server is offline.</p>", "text/html; charset=utf-8"

    req_id = next(request_ids)
    fut = asyncio.get_running_loop().create_future()
    pending[req_id] = (ws, fut)
    try:
        await ws.send(json.dumps({"id": req_id, "method": method, "path": path}))
        res = await asyncio.wait_for(fut, timeout=REQUEST_TIMEOUT)
    except asyncio.TimeoutError:
        return 504, b"<h1>504 Gateway Timeout</h1><p>Home server did not respond in time.</p>", "text/html; charset=utf-8"
    except Exception as e:
        print(f"Tunnel error for request {req_id}: {e!r}")
        return 502, b"<h1>502 Bad Gateway</h1><p>Tunnel error.</p>", "text/html; charset=utf-8"
    finally:
        pending.pop(req_id, None)

    try:
        status = res.get("status_code", 200)
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise ValueError(f"invalid status {status!r}")
        content_type = res.get("headers", {}).get("Content-Type", "text/html; charset=utf-8")
        if not isinstance(content_type, str) or not SAFE_CONTENT_TYPE.fullmatch(content_type):
            content_type = "application/octet-stream"
        if res.get("is_base64"):
            data = base64.b64decode(res["body"], validate=True)
        else:
            data = res["body"].encode("utf-8")
    except Exception as e:
        print(f"Invalid response from agent for request {req_id}: {e!r}")
        return 502, b"<h1>502 Bad Gateway</h1><p>Invalid response from home server.</p>", "text/html; charset=utf-8"
    return status, data, content_type


async def read_request_head(reader):
    line = await reader.readline()
    if not line:
        return None
    parts = line.decode("latin-1").split(" ", 2)
    if len(parts) < 2:
        raise ValueError("malformed request line")
    for _ in range(MAX_HEADER_LINES):
        if not (await reader.readline()).strip():
            break
    else:
        raise ValueError("too many header lines")
    return parts[0], parts[1]


def send_response(writer, status, data, content_type="text/html; charset=utf-8"):
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = "Unknown"
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(data)}\r\n"
        f"X-Content-Type-Options: nosniff\r\n"
        f"Connection: close\r\n\r\n".encode() + data
    )


async def http_handler(reader, writer):
    global active_connections
    peer = (writer.get_extra_info("peername") or ("?",))[0]
    if active_connections >= MAX_CONNECTIONS:
        print(f"[security] Connection limit reached, rejecting {peer}")
        send_response(writer, 503, b"<h1>503 Service Unavailable</h1>")
        writer.close()
        return

    active_connections += 1
    try:
        try:
            head = await asyncio.wait_for(read_request_head(reader), timeout=HEADER_TIMEOUT)
        except asyncio.TimeoutError:
            print(f"[security] Header timeout from {peer}")
            return
        except (ValueError, ConnectionError):
            print(f"[security] Malformed request from {peer}")
            send_response(writer, 400, b"<h1>400 Bad Request</h1>")
            return
        if head is None:
            return
        method, path = head

        if method not in ALLOWED_METHODS or not is_safe_path(path):
            print(f"[security] Rejected request from {peer}: {method[:16]!r} {path[:80]!r}")
            send_response(writer, 400, b"<h1>400 Bad Request</h1>")
            return

        print(f"HTTP {method} {path}")
        status, data, content_type = await forward(method, path)
        send_response(writer, status, data, content_type)
        await writer.drain()
    except Exception as e:
        print(f"HTTP handler error for {peer}: {e!r}")
    finally:
        active_connections -= 1
        writer.close()


def load_token():
    token = os.environ.get("TUNNEL_TOKEN")
    if not token:
        token = secrets.token_urlsafe(32)
        print("[security] TUNNEL_TOKEN is not set - generated a one-time token for this run:")
        print(f"           {token}")
    elif len(token) < 16:
        print("[security] WARNING: TUNNEL_TOKEN is shorter than 16 characters")
    return token


def parse_args():
    parser = argparse.ArgumentParser(description="VPS broker (Reverse Proxy over WS)")
    parser.add_argument("--host", default="0.0.0.0", help="Address to bind both servers to")
    parser.add_argument("--http-port", type=int, default=8080, help="Public HTTP port")
    parser.add_argument("--ws-port", type=int, default=8765, help="WebSocket tunnel port")
    return parser.parse_args()


async def main():
    global TOKEN
    args = parse_args()
    TOKEN = load_token()
    http_server = await asyncio.start_server(http_handler, args.host, args.http_port, limit=MAX_LINE)
    async with serve(
        tunnel_handler, args.host, args.ws_port,
        process_request=check_token,
        origins=[None],
        max_size=MAX_WS_MESSAGE,
    ):
        print(f"HTTP on :{args.http_port}, WebSocket tunnel on :{args.ws_port}")
        await http_server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())

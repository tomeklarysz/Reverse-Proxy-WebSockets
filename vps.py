import asyncio
import base64
import json

from websockets.asyncio.server import serve

tunnel = None
lock = asyncio.Lock()

async def tunnel_handler(ws):
    global tunnel
    tunnel = ws
    print("Home tunnel connected")
    await ws.wait_closed()
    tunnel = None
    print("Tunnel disconnected")

async def http_handler(reader, writer):
    try:
        line = await reader.readline()
        if not line:
            writer.close()
            return
        parts = line.decode().split(" ", 2)
        if len(parts) < 2:
            writer.close()
            return
        method, path = parts[0], parts[1]
        while (await reader.readline()).strip():
            pass
    except Exception:
        writer.close()
        return

    print(f"HTTP {method} {path}")

    content_type = "text/html; charset=utf-8"
    if tunnel is None:
        status, data = 502, b"<h1>502 Bad Gateway</h1><p>Home server is offline.</p>"
    else:
        async with lock:
            try:
                await tunnel.send(json.dumps({"method": method, "path": path}))
                response = await asyncio.wait_for(tunnel.recv(), timeout=10)
                res = json.loads(response)
                status = res.get("status_code", 200)
                content_type = res.get("headers", {}).get("Content-Type", "text/html; charset=utf-8")

                if res.get("is_base64"):
                    data = base64.b64decode(res["body"])
                else:
                    data = res["body"].encode("utf-8")
            except Exception as e:
                status, data = 504, f"<h1>504 Gateway Timeout</h1><p>{e}</p>".encode("utf-8")

    writer.write(
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(data)}\r\n"
        f"Connection: close\r\n\r\n".encode() + data
    )
    await writer.drain()
    writer.close()

async def main():
    http_server = await asyncio.start_server(http_handler, "0.0.0.0", 8080)
    async with serve(tunnel_handler, "0.0.0.0", 8765):
        print("HTTP on :8080, WebSocket tunnel on :8765")
        await http_server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
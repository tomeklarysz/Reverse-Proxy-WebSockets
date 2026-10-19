import asyncio
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
    method, path, _ = (await reader.readline()).decode().split(" ", 2)
    while (await reader.readline()).strip():
        pass
    print(f"HTTP {method} {path}")

    if tunnel is None:
        status, body = 502, "<h1>502</h1><p>Home server is offline.</p>"
    else:
        async with lock:
            try:
                await tunnel.send(json.dumps({"method": method, "path": path}))
                response = await asyncio.wait_for(tunnel.recv(), timeout=10)
                status, body = 200, json.loads(response)["body"]
            except Exception:
                status, body = 504, "<h1>504</h1><p>No response from home server.</p>"

    data = body.encode()
    writer.write(
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
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

asyncio.run(main())
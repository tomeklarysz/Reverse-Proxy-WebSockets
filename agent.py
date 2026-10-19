import argparse
import asyncio
import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional

try:
    # websockets 13.0+ API
    from websockets.asyncio.client import connect
except ImportError:
    # websockets <13.0 fallback
    from websockets import connect


def forward_to_local(target_base: str, method: str, path: str, headers: Optional[dict] = None, body: Optional[str] = None) -> tuple[int, dict, str]:
    """Forwarduje zapytanie HTTP do lokalnej usługi za pomocą standardowej biblioteki urllib."""
    url = f"{target_base.rstrip('/')}{path}"
    data = body.encode("utf-8") if body else None

    req = urllib.request.Request(url=url, data=data, method=method)
    
    # Przekaż nagłówki, jeśli istnieją (pomijamy Host, by nie psuć routingu lokalnego)
    if headers:
        for k, v in headers.items():
            if k.lower() not in ("host", "content-length"):
                req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status_code = resp.status
            resp_headers = dict(resp.getheaders())
            resp_body = resp.read().decode("utf-8", errors="replace")
            return status_code, resp_headers, resp_body
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return e.code, dict(e.headers), err_body
    except urllib.error.URLError as e:
        return 502, {}, f"<h1>502 Bad Gateway</h1><p>Agent cannot reach local service at {target_base}: {e.reason}</p>"
    except Exception as e:
        return 500, {}, f"<h1>500 Internal Error</h1><p>Agent error forwarding request: {str(e)}</p>"


async def process_message(raw_msg: str, target_base: str) -> str:
    """Przetwarza ramkę z brokera, wykonuje żądanie lokalne i tworzy ramkę odpowiedzi."""
    try:
        data = json.loads(raw_msg)
    except Exception as e:
        return json.dumps({"body": f"<h1>400 Bad Request</h1><p>Invalid JSON frame: {e}</p>"})

    req_id = data.get("id")
    method = data.get("method", "GET").upper()
    path = data.get("path", "/")
    headers = data.get("headers", {})
    body = data.get("body", None)

    start_t = time.perf_counter()
    print(f"--> [{method}] {path} (ID: {req_id or 'none'})")

    # Wywołanie lokalnej usługi w osobnym wątku (by nie blokować pętli asyncio)
    status_code, resp_headers, resp_body = await asyncio.to_thread(
        forward_to_local, target_base, method, path, headers, body
    )

    elapsed_ms = (time.perf_counter() - start_t) * 1000
    print(f"<-- [{status_code}] {path} ({elapsed_ms:.1f}ms)")

    # Odpowiedź zgodna z obecnym vps.py (klucz 'body'), ale rozszerzona o przyszłe pola
    response_payload = {
        "body": resp_body,
        "status_code": status_code,
        "headers": resp_headers,
    }
    if req_id is not None:
        response_payload["id"] = req_id

    return json.dumps(response_payload)


async def run_agent(vps_url: str, target_base: str, insecure: bool = False):
    ssl_context = None
    if vps_url.startswith("wss://"):
        ssl_context = ssl.create_default_context()
        if insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            print("[WARN] Weryfikacja certyfikatu TLS wyłączona (--insecure)")

    retry_delay = 2
    max_delay = 30

    while True:
        try:
            print(f"connecting to: {vps_url}...")
            connect_kwargs = {}
            if ssl_context:
                connect_kwargs["ssl"] = ssl_context

            async with connect(vps_url, **connect_kwargs) as ws:
                print(f"[+] successfully connected to {vps_url}!")
                retry_delay = 2  # Reset licznika po udanym połączeniu

                async for message in ws:
                    resp_json = await process_message(message, target_base)
                    await ws.send(resp_json)

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[-] connection error: {e}")
            print(f"[*] retry in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_delay)


def parse_args():
    parser = argparse.ArgumentParser(description="Local Agent do zwrotnego tunelu WebSocket (Reverse Proxy over WS)")
    parser.add_argument(
        "--vps-url",
        default="ws://127.0.0.1:8765",
        help="Adres WebSocket brokera (np. ws://127.0.0.1:8765 lub wss://twoj-vps.ip:8765)"
    )
    parser.add_argument(
        "--target-url",
        default="http://127.0.0.1:3000",
        help="Lokalna usługa HTTP, do której przekazujemy ruch (np. http://localhost:3000)"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Ignoruj błędy weryfikacji certyfikatu TLS (dla wss:// z self-signed cert)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(run_agent(args.vps_url, args.target_url, args.insecure))
    except KeyboardInterrupt:
        print("\n[*] Agent zatrzymany.")

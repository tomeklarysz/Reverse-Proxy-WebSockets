# Demo: authentication and protection against eavesdropping and attacks

Project requirement: *Demonstrate authentication, protection against WebSocket eavesdropping and attacks.*

| Requirement | What we show | Script |
|---|---|---|
| Authentication | 3 independent layers: mTLS (Nginx), token (broker), server verification (agent) + browser blocking (Origin) | `security_tests/demo_auth.py` |
| Eavesdropping | Wireshark: on `ws://` the token, paths and photos are readable, on `wss://` only TLS 1.3 | `security_tests/demo_eavesdrop.py` |
| Attacks | Tunnel hijack, SSRF, DoS, response mix-up – how each attack works and how we block it | `security_tests/attack_*.py` |

The demo runs **locally** (a Docker replica of the VPS: the same `nginx/default.conf` with mTLS + `vps.py`)
or against the **real VPS**. The scripts are the same, only the address and the certificate folder change.

---

## Local setup

Requirements: Docker Desktop (running), Wireshark (with Npcap), OpenSSL, `.venv` with `requirements.txt`.
Run every command from the project root, in a terminal with the virtual environment activated:

```powershell
.venv\Scripts\Activate.ps1
```

1. Demo-only certificates (a separate CA in `demo/certs/`):
   ```powershell
   python demo/setup_local_certs.py
   ```
2. Token (the same value in every terminal where you run something):
   ```powershell
   $env:TUNNEL_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
3. VPS replica (Nginx with mTLS on `https://127.0.0.1:8443` + broker):
   ```powershell
   docker compose -f demo/docker-compose.yml up -d --force-recreate
   ```
   `--force-recreate` makes sure the broker picks up the token from step 2.

Parts 1 and 2 need nothing else – the scripts start their own agent and gallery service.

---

## Part 1: Authentication

```powershell
python security_tests/demo_auth.py --url wss://127.0.0.1:8443/ws-tunnel --certs demo/certs
```

Expected result (every row `OK`):

| # | Who connects | Result | What it shows |
|---|---|---|---|
| 1 | stolen token, no client certificate | 400 (Nginx) | a token alone is not enough – mTLS stops the attacker first |
| 2 | stolen token, certificate from a foreign CA | 400 (Nginx) | the certificate must be signed by **our** CA |
| 3 | valid certificate, no token | 401 | second, independent layer (defense in depth) |
| 4 | valid certificate, wrong token | 401 | same – a stolen certificate is not enough either |
| 5 | everything valid, but from a browser (`Origin`) | 403 | protection against CSWSH |
| 6 | valid certificate + token | 101 – connected | the real agent gets in |
| 7 | agent connects to a **fake server** (MITM) | rejected by the agent | the agent verifies the server certificate |
| 8 | same with `--insecure` | connected, token captured | this is why `--insecure` must never be used outside tests |

Broker logs (rejections with the client IP address):
```powershell
docker compose -f demo/docker-compose.yml logs broker
```

---

## Part 2: Eavesdropping (Wireshark)

Stop your own agent if it is running (the script starts its own). Then:

```powershell
python security_tests/demo_eavesdrop.py --tls-url wss://127.0.0.1:8443/ws-tunnel --certs demo/certs
```

The script captures the tunnel traffic twice (A: `ws://` without TLS, B: `wss://` through Nginx),
searches it for the token, paths, photos and HTML, and prints a table: in A everything is `VISIBLE`,
in B nothing is.

For the presentation it is best to show it in Wireshark:
1. Open `demo/captures/A_plain_ws.pcapng`:
   - the `GET / HTTP/1.1` packet is the tunnel opening – expand *Hypertext Transfer Protocol*:
     `Authorization: Bearer <token>` is in plain text;
   - type the filter `websocket` → click a *WebSocket Text* packet → expand *WebSocket → Payload → Text*:
     JSON with requests (`"path": "/photos/gory_tatry.jpg"`) and responses (HTML, photo in Base64).
   (*Follow → TCP Stream* shows only the token – the JSON frames are compressed, so they look like
   garbage there; the readable content comes from the WebSocket decoding in the packet details pane.)
2. Open `demo/captures/B_tls_wss.pcapng`: only *Client Hello / Server Hello* and
   *Application Data* (TLS 1.3, `TLS_AES_256_GCM_SHA384`) – the content is unreadable,
   and the `websocket` filter finds nothing.

Note for questions: WebSocket frame masking and compression (permessage-deflate) are **not**
encryption – Wireshark reverses both automatically. Only TLS protects the content.

---

## Part 3: Attacks

These scripts attack the broker and the agent directly (`ws://`, without Nginx), so you start
the components manually. You need **4 terminals**, each with the venv activated and the same token:

```powershell
.venv\Scripts\Activate.ps1
$env:TUNNEL_TOKEN = "<THE SAME TOKEN EVERYWHERE>"
```

| Terminal | Command |
|---|---|
| 1 – gallery (port 3000) | `python gallery_service.py` |
| 2 – broker (HTTP 8080, tunnel 8765) | `python vps.py` |
| 3 – agent | `python agent.py --vps-url ws://127.0.0.1:8765 --target-url http://127.0.0.1:3000` |
| 4 – attacks | see below |

```powershell
python security_tests/attack_tunnel_hijack.py
python security_tests/attack_ssrf.py
```

`attack_response_mixup.py` starts its own service on port 13000, so restart the agent in terminal 3 with
`--target-url http://127.0.0.1:13000` first, then:

```powershell
python security_tests/attack_response_mixup.py
```

On the current code every script prints `RESULT: ... PROTECTED`.

### The attacks and how we defend against them

#### 1. Tunnel hijack – `attack_tunnel_hijack.py`

**Attack:** the original broker accepted any WebSocket connection on the tunnel port and treated
the newest one as "the home agent". An attacker could connect, take over the tunnel and answer
every user request with their own page (phishing, stealing form data). The real agent was left
disconnected from users – the service stayed down even after the attacker left.

**Defense:**
- the agent must send `Authorization: Bearer <token>`; the broker checks it during the handshake
  and rejects the connection with **401** before the tunnel is opened;
- the token is compared in constant time (`hmac.compare_digest`), so it cannot be guessed
  character by character from response times;
- connections with an `Origin` header (from a browser) are rejected with **403** (CSWSH);
- behind Nginx the attacker also needs a client certificate signed by our CA (mTLS) –
  without it they do not even reach the broker (rows 1 and 2 in part 1);
- rejected attempts are logged with the real client IP (`X-Real-IP` from Nginx).

#### 2. SSRF through the agent – `attack_ssrf.py`

**Attack:** the agent built the local URL by plain string concatenation: `target_url + path`.
With the target `http://127.0.0.1:3000` and the path `0/` (no leading `/`) the result is
`http://127.0.0.1:30000/` – a **different port**. Through the tunnel an outsider could reach
services in the home network that were never meant to be exposed (e.g. an admin panel).

**Defense:**
- the path must start with `/` and may contain only printable ASCII characters, max 2048
  (checked in the broker and again in the agent);
- after building the request the agent checks that its scheme and host are **exactly** the same
  as in `--target-url` – otherwise it refuses with 400;
- only standard HTTP methods are forwarded (unknown ones get 405).

#### 3. DoS and response mix-up – `attack_response_mixup.py`

**Attack:** the original broker handled the tunnel with a single lock: one request at a time,
and the response was "whatever comes next" from the WebSocket.
- **DoS:** one slow request (e.g. 12 s) blocked all other users – they waited in a queue.
- **Data leak:** after a timeout the late response was still in the tunnel, so the *next* user
  received the previous user's response – users saw each other's data.

**Defense:**
- every request gets a unique `id`; the agent returns it in the response and the broker delivers
  the response only to the request with that `id`;
- requests are handled concurrently – a slow request no longer blocks the others;
- after a timeout (10 s → **504**) the request is removed, so a late response is dropped instead of
  being delivered to someone else.

#### Additional hardening (no separate script)

| Threat | Defense |
|---|---|
| Slowloris – a client sends headers very slowly to hold connections | 10 s limit for the request line and headers |
| Huge headers or too many of them | max 8 KiB per line, max 100 header lines (400) |
| Connection flooding | max 100 concurrent public HTTP connections (503) |
| Oversized messages / responses | max 16 MiB per tunnel message, max 10 MiB response body in the agent |

With Nginx in front, mTLS is the first line of defense. These fixes in the broker and the agent
are a **second line of defense** – they still work if someone gets past Nginx,
e.g. with a stolen certificate.

---

## Variant: the real VPS

When the VPS is running and you have the team's certificates in `certs/`:

```powershell
python security_tests/demo_auth.py --url wss://<VPS_IP>/ws-tunnel --certs certs
python security_tests/demo_eavesdrop.py --tls-url wss://<VPS_IP>/ws-tunnel --certs certs --interface Wi-Fi
```

`--interface` is the name of the network adapter the traffic to the VPS goes through
(list them with `& "C:\Program Files\Wireshark\tshark.exe" -D`). The token must be the same as on the VPS.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'websockets'` | the venv is not active – run `.venv\Scripts\Activate.ps1` (the prompt should start with `(.venv)`) |
| `openssl req` fails with `Can't open ".../openssl.cnf"` (e.g. openssl from Strawberry Perl) | the demo scripts handle it with a minimal config; for `scripts/generate_ca_and_clients.py` run from Git Bash or set `$env:OPENSSL_CONF = "$PWD\demo\certs\openssl-minimal.cnf"` |
| `demo_auth.py` row 6 gets 401 | the broker runs with a different token – re-run step 3 with `--force-recreate` in the terminal where `TUNNEL_TOKEN` is set |

---

## Cleanup

```powershell
docker compose -f demo/docker-compose.yml down
```

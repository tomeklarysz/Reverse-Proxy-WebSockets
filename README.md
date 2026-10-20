# Reverse-Proxy-WebSockets

## Setup

Create and activate a virtual environment, then install the Python dependency:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Running locally

The broker only accepts tunnel connections with a shared token. Set the same
`TUNNEL_TOKEN` in every terminal that runs `vps.py` or `agent.py`
(if it is not set, `vps.py` generates a one-time token and prints it):

```powershell
$env:TUNNEL_TOKEN = "change-me-to-a-long-random-string"
python gallery_service.py                                   # terminal 1
python vps.py                                               # terminal 2
python agent.py --vps-url ws://127.0.0.1:8765 --target-url http://127.0.0.1:3000   # terminal 3
```

Open http://localhost:8080. Security tests are described in [security_tests/README.md](security_tests/README.md).
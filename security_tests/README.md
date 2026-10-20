# Security tests

Scripts that reproduce attacks against the broker (`vps.py`) and the agent (`agent.py`).
They only talk to `127.0.0.1` and are meant for local testing of this project.

Each script prints `RESULT: <name>: PROTECTED | VULNERABLE` and exits with
`0` (protected), `1` (vulnerable) or `2` (setup error).

| Script | Attack | Agent `--target-url` |
|---|---|---|
| `attack_tunnel_hijack.py` | Connects to the tunnel without a token and serves a fake page to users; checks if the real agent gets orphaned | any working service, e.g. `http://127.0.0.1:3000` (gallery) |
| `attack_ssrf.py` | Path `0/` makes the original agent request `127.0.0.1:30000` instead of `:3000` | `http://127.0.0.1:3000` |
| `attack_response_mixup.py` | A slow request blocks everyone (DoS) and, after a timeout, users receive each other's responses | `http://127.0.0.1:13000` (the script starts this service itself) |

## How to run

Start `vps.py` and `agent.py` as described in the main README (with `TUNNEL_TOKEN` set),
point the agent at the service from the table, then run e.g.:

```powershell
python security_tests\attack_tunnel_hijack.py
python security_tests\attack_ssrf.py
python security_tests\attack_response_mixup.py
```

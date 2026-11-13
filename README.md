# Reverse-Proxy over WebSockets with mTLS

Bezpieczny zwrotny tunel dostępowy (architektura w stylu Cloudflare Tunnel / ngrok) z pełnym wzajemnym uwierzytelnianiem TLS (**mTLS**), terminacją TLS na Nginxie oraz asynchronicznym brokerem i agentem WebSocket napisanym w Pythonie.

Projekt zrealizowany w ramach przedmiotu **Secure Communication Systems (Proof of Concept)**.

---

## Architektura systemu

```text
[ Przeglądarka WWW ] --(HTTPS / mTLS TLS 1.3 :443)--> [ Nginx Reverse Proxy (VPS) ]
                                                               |
               +-----------------------------------------------+
               |
               +--> (HTTP :8080) -------> [ vps.py (Broker HTTP) ]
               |                                   ^
               |                                   |  (Wewnętrzny tunel WS)
               +--> (/ws-tunnel :8765) -> [ vps.py (Broker WS) ]
                                                   ^
                                                   | (Wychodzący tunel WSS z mTLS)
                                        [ agent.py (Local Agent) ]
                                                   |
                                                   v (Lokalny HTTP :3000)
                                        [ gallery_service.py ]
```

* **Nginx (port 443):** Jedyny proces wystawiony publicznie na świat. Wymaga TLS 1.2/1.3 oraz weryfikacji certyfikatów klienckich (`ssl_verify_client on;`).
* **Broker (`vps.py`):** Nasłuchuje wyłącznie na pętli zwrotnej (`127.0.0.1`), multipleksuje zapytania asynchronicznie za pomocą identyfikatorów zapytań i weryfikuje token autoryzacyjny (*Defense-in-Depth*).
* **Local Agent (`agent.py`):** Utrzymuje stałe, wychodzące połączenie WSS do `/ws-tunnel`, weryfikuje certyfikat serwera, uwierzytelnia się własnym certyfikatem (`agent.crt`), zabezpiecza przed atakami SSRF i przekazuje ruch na lokalną usługę.
* **Local Service (`gallery_service.py`):** Prywatna aplikacja HTTP za firewallem serwująca zdjęcia w formatach binarnych (Base64 over WebSocket).

---

## Wymagania wstępne

1. Python 3.10+ oraz OpenSSL zainstalowane lokalnie.
2. Wirtualne środowisko Pythona i zainstalowane zależności:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```
3. **Klucz SSH na serwerze (Wymóg krytyczny):**
   Twój lokalny klucz publiczny SSH (z pliku `~/.ssh/id_ed25519.pub` lub `~/.ssh/id_rsa.pub`) **musi być dodany** do pliku `~/.ssh/authorized_keys` użytkownika `ubuntu` na instancji VPS. Jest to niezbędne, aby skrypt podpisywania mógł przesłać certyfikaty przez SCP i przeładować Nginxa przez SSH.

---

## Wdrożenie produkcyjne z mTLS (Krok po kroku)

### Krok 1: Wygenerowanie lokalnego Root CA i tożsamości klientów

Wykonaj jednorazowo w głównym katalogu projektu:

```powershell
python scripts/generate_ca_and_clients.py
```

Skrypt utworzy w katalogu `certs/`:
* `ca.crt` / `ca.key` — Twój prywatny Root Certificate Authority.
* `agent.crt` / `agent.key` — certyfikat mTLS dla Agenta tunelu.
* `client.crt` / `client.key` / `client.p12` — certyfikat mTLS dla przeglądarki użytkownika (hasło eksportu: `client123`).

> [!NOTE]
> Klucze prywatne (`*.key`, `*.p12`) są automatycznie ignorowane przez `.gitignore` i nigdy nie trafiają do repozytorium.

---

### Krok 2: Instalacja certyfikatu klienckiego w przeglądarce

Aby wejść na stronę przez HTTPS, Twoja przeglądarka musi przedstawić certyfikat `client.p12`:

* **Windows (Chrome / Edge / system):**
  Kliknij dwukrotnie plik `certs/client.p12` $\rightarrow$ wybierz *Bieżący użytkownik* $\rightarrow$ wpisz hasło `client123` $\rightarrow$ wybierz automatyczny magazyn certyfikatów (*Osobisty*).
* **Firefox:**
  Ustawienia $\rightarrow$ Prywatność i bezpieczeństwo $\rightarrow$ Certyfikaty $\rightarrow$ *Wyświetl certyfikaty* $\rightarrow$ zakładka *Twoje certyfikaty* $\rightarrow$ *Importuj* $\rightarrow$ wskaż `certs/client.p12` i wpisz hasło `client123`.
* **macOS (Safari / Chrome):**
  Kliknij dwukrotnie `client.p12` i dodaj go do pęku kluczy *logowanie*.

---

### Krok 3: Podpisanie certyfikatu serwera i przesłanie na VPS

Gdy znasz publiczny adres IP swojego serwera VPS, uruchom skrypt wdrażający, podając IP oraz ścieżkę do swojego klucza prywatnego SSH:

* **W PowerShellu:**
  ```powershell
  .\sign-server.ps1 <VPS_PUBLIC_IP> "$HOME\.ssh\twoj_klucz_prywatny"
  ```
* **W Bashu:**
  ```bash
  ./sign-server.sh <VPS_PUBLIC_IP> ~/.ssh/twoj_klucz_prywatny
  ```

**Co wykonuje ten skrypt:**
1. Generuje `server.key` i plik żądania `server.csr` dla wskazanego adresu IP.
2. Podpisuje certyfikat lokalnym kluczem Root CA, dodając rozszerzenie `subjectAltName = IP:<VPS_PUBLIC_IP>`.
3. Przesyła `server.crt`, `server.key` oraz `ca.crt` przez `scp` na serwer.
4. Przenosi pliki do `/etc/nginx/certs/` z odpowiednimi uprawnieniami (`chmod 600` dla klucza) i przeładowuje Nginxa (`sudo systemctl reload nginx`).

---

### Krok 4: Ustawienie stałego tokenu autoryzacji na serwerze

Broker na VPS oprócz mTLS weryfikuje nagłówek `Authorization: Bearer <TOKEN>`. Aby ustawić stały token w usłudze systemd na serwerze, wykonaj jedną komendę przez SSH:

```powershell
ssh -i "$HOME\.ssh\twoj_klucz_prywatny" ubuntu@<VPS_PUBLIC_IP> 'sudo sed -i "/\[Service\]/a Environment=\"TUNNEL_TOKEN=tajny_token_projektu_123\"" /etc/systemd/system/tunnel-broker.service && sudo systemctl daemon-reload && sudo systemctl restart tunnel-broker'
```

---

### Krok 5: Uruchomienie serwisu lokalnego i Agenta

1. **Terminal 1 — Uruchom lokalną usługę testową (galerię zdjęć):**
   ```powershell
   python gallery_service.py
   ```
   *(Usługa nasłuchuje na `http://127.0.0.1:3000`)*.

2. **Terminal 2 — Uruchom Agenta łączącego się przez tunel mTLS:**
   ```powershell
   python agent.py --vps-url wss://<VPS_PUBLIC_IP>:443/ws-tunnel --target-url http://127.0.0.1:3000 --token tajny_token_projektu_123
   ```
   *Agent automatycznie załaduje `certs/ca.crt` do weryfikacji serwera oraz `certs/agent.crt` i `certs/agent.key` do uwierzytelnienia przed Nginxem.*

3. **Otwórz w przeglądarce:**
   ```text
   https://<VPS_PUBLIC_IP>/
   ```
   Przeglądarka wyświetli monit o wybór certyfikatu klienta (`ReverseProxy Browser Client`). Po zatwierdzeniu wyświetli się galeria serwowana z Twojego komputera za NAT-em!

---

## Uruchomienie lokalne (Development bez mTLS)

Do szybkiego testowania zmian w kodzie bez konieczności stawiania Nginxa i certyfikatów:

```powershell
$env:TUNNEL_TOKEN = "local-secret"
python gallery_service.py                                                              # Terminal 1
python vps.py --host 127.0.0.1 --http-port 8080 --ws-port 8765                         # Terminal 2
python agent.py --vps-url ws://127.0.0.1:8765 --target-url http://127.0.0.1:3000      # Terminal 3
```

Otwórz w przeglądarce: `http://localhost:8080`.

---

## Testy bezpieczeństwa

Zestaw skryptów symulujących wektory ataków (SSRF, Tunnel Hijacking, Response Mixup/DoS) znajduje się w katalogu [security_tests/](security_tests/). Szczegółowy opis procedury testowej znajdziesz w [security_tests/README.md](security_tests/README.md).

# Test Environment — Vulnerable IoT Device Simulator

This Docker Compose environment simulates a deliberately insecure IoT gateway device.
It is used to validate the IoT Security Tester scanner against known vulnerabilities.

> **Warning:** This environment contains intentional security vulnerabilities.
> Run it only on an isolated network or localhost. Never expose it to the internet.

## Services & Port Mapping

| Service            | Host Port | Container Port | Vulnerabilities Tested |
|--------------------|-----------|----------------|------------------------|
| Vulnerable API     | 8888      | 8888           | I1, I3, I4, I5, I7, I9 |
| Vulnerable SSH     | 2222      | 22             | I1, I2                 |
| Vulnerable MQTT    | 1883      | 1883           | I1, I2, I7             |

## Start the Test Environment

```bash
cd test-environment
docker compose up --build -d
```

Verify all containers are running:

```bash
docker compose ps
```

## Run the Scanner Against It

```bash
cd ..
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
python app.py
```

Open http://localhost:8080, enter `127.0.0.1` as the device IP, and run the scan.

**Expected results — all 7 implemented checks should FAIL:**

| Check | Expected Result | Reason |
|-------|-----------------|--------|
| I1 — Credentials    | FAIL | SSH accepts `admin/admin`; MQTT allows anonymous access |
| I2 — Services       | FAIL | SSH (2222), MQTT (1883), HTTP (8888) all open |
| I3 — Interfaces     | FAIL | No security headers; `/admin`, `/api/config` unauthenticated; CORS wildcard |
| I4 — Updates        | FAIL | `/firmware`, `/firmware/update`, `/api/firmware`, `/ota` all unauthenticated over HTTP |
| I5 — Components     | FAIL | Server header: `lighttpd/1.4.35` (CVE-2022-22707) |
| I7 — Data Transfer  | FAIL | HTTP-only API (no HTTPS); MQTT cleartext (no MQTTS) |
| I9 — Defaults       | FAIL | Factory default device identity (ESP32) in HTTP headers |

## Stop the Test Environment

```bash
cd test-environment
docker compose down
```

To remove all images and volumes (full cleanup):

```bash
docker compose down --rmi all --volumes
```

> **Security Note:** Do not leave the test environment running unattended. These containers
> expose deliberately vulnerable services (unauthenticated SSH, open MQTT, cleartext HTTP
> with default credentials) on localhost ports. Any device on the same network could
> potentially access these services. Always stop the containers when testing is complete.

## Intentional Vulnerabilities Reference

### vulnerable-api (port 8888)

**I1 — Default Credentials:**
- `POST /api/login` — accepts `admin/admin`, `root/toor`, `pi/raspberry`, etc.

**I3 — Insecure Interfaces:**
- `GET /admin` — returns HTTP 200 with no authentication
- `GET /api/config` — returns credentials in plaintext JSON
- `GET /api/debug` — exposes environment variables and secrets
- `GET /api/users` — returns user list with password hashes
- `GET /setup` — setup wizard accessible post-deployment
- All responses: missing all 7 HTTP security headers
- `Access-Control-Allow-Origin: *` on all responses

**I4 — Insecure Update Channel:**
- `GET /firmware` — exposes firmware version and cleartext download URL without auth
- `GET /firmware/update` — firmware upload endpoint accessible without auth
- `POST /firmware/update` — accepts firmware upload without auth
- `GET /api/firmware` — exposes OTA server URL (HTTP, not HTTPS)
- `GET /api/update` — update check with `"signature": "none"`
- `GET /ota` — OTA config with cleartext server URL

**I5 — Outdated Components:**
- `Server: lighttpd/1.4.35` header — known vulnerable (CVE-2022-22707, use-after-free)

**I9 — Insecure Default Settings:**
- `X-Powered-By: ESP32-DevKit-v1` header — factory default device identity disclosed

**I7 — Insecure Data Transfer:**
- All endpoints served over HTTP only (no HTTPS)
- Login endpoint transmits credentials in cleartext

### vulnerable-ssh (port 2222)

**I1 — Default Credentials:**
- Accepts `admin` / `admin`
- Accepts `root` / `toor`
- Accepts `pi` / `raspberry`
- `PermitRootLogin yes`
- Password authentication enabled (no key enforcement)

**I2 — Insecure Network Services:**
- SSH on non-standard port with weak configuration

### vulnerable-mqtt (port 1883)

**I1 — Default Credentials:**
- `allow_anonymous true` — any client connects without credentials

**I2 — Insecure Network Services:**
- MQTT broker open on standard port

**I7 — Insecure Data Transfer:**
- No TLS (cleartext only, port 8883 not available)
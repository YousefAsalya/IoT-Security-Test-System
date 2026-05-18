# Test Environment — Vulnerable IoT Device Simulator

This Docker Compose environment simulates a deliberately insecure IoT gateway device.
It is used to validate the IoT Security Tester scanner against known vulnerabilities.

> **Warning:** This environment contains intentional security vulnerabilities.
> Run it only on an isolated network or localhost. Never expose it to the internet.

## Services & Port Mapping

| Service            | Host Port | Container Port | Vulnerabilities |
|--------------------|-----------|----------------|-----------------|
| Vulnerable API     | 8888      | 8888           | I1, I3, I7      |
| Vulnerable SSH     | 2222      | 22             | I1, I2          |
| Vulnerable MQTT    | 1883      | 1883           | I1, I2, I7      |

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
python app.py
```

Open http://localhost:8080, enter `127.0.0.1` as the device IP, and run the scan.

**Expected results — all 4 implemented checks should FAIL:**

| Check | Expected Result | Reason |
|-------|-----------------|--------|
| I1 — Credentials | FAIL | SSH accepts `admin/admin`; MQTT allows anonymous access |
| I2 — Services    | FAIL | SSH (2222), MQTT (1883), HTTP (8888) all open |
| I3 — Interfaces  | FAIL | No security headers; `/admin`, `/api/config` unauthenticated; CORS wildcard |
| I7 — Data Transfer | FAIL | HTTP-only API (no HTTPS); MQTT cleartext (no MQTTS) |

## Stop the Test Environment

```bash
cd test-environment
docker compose down
```

## Intentional Vulnerabilities Reference

### vulnerable-api (port 8888)
- `GET /admin` — returns HTTP 200 with no authentication
- `GET /api/config` — returns credentials in plaintext JSON
- `GET /api/debug` — exposes environment variables and secrets
- `GET /api/users` — returns user list with password hashes
- `GET /setup` — setup wizard accessible post-deployment
- `POST /api/login` — accepts `admin/admin`, `root/toor`, `pi/raspberry`, etc.
- All responses: missing all 7 HTTP security headers
- `Access-Control-Allow-Origin: *` on all responses
- `Server: IoT-Gateway/1.0.2 Python/3.11` discloses technology stack

### vulnerable-ssh (port 2222)
- Accepts `admin` / `admin`
- Accepts `root` / `toor`
- Accepts `pi` / `raspberry`
- `PermitRootLogin yes`
- Password authentication enabled (no key enforcement)

### vulnerable-mqtt (port 1883)
- `allow_anonymous true` — any client connects without credentials
- No TLS (cleartext only)

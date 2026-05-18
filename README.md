# IoT Security Tester

Automated IoT device security assessment tool aligned with the **OWASP IoT Top 10 (2018)**.
Built as a Master's-level security engineering project.

See **[REQUIREMENTS.md](REQUIREMENTS.md)** for the full requirements analysis — including the
OWASP IoT Top 10 assessment, selection rationale, and test environment design.

## Implemented Checks

| Check | OWASP Item | Method |
|-------|-----------|--------|
| I1 | Weak, Guessable, or Hardcoded Passwords | SSH brute-force (Paramiko), HTTP login POST, MQTT anonymous/default credential test |
| I2 | Insecure Network Services | TCP port scan (20 IoT ports), active banner grabbing, service fingerprinting |
| I3 | Insecure Ecosystem Interfaces | HTTP security headers (7), auth bypass on 12 API paths, CORS, server disclosure |
| I7 | Insecure Data Transfer and Storage | TLS version & certificate analysis, HTTP vs HTTPS, MQTT cleartext vs MQTTS |

Items I4, I5, I6, I8, I9, I10 are analysed but excluded — see REQUIREMENTS.md §2.

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:8080.

## Test Environment (Docker)

A deliberately vulnerable IoT device simulator is provided to validate the scanner:

```bash
cd test-environment
docker compose up --build -d
```

Then scan `127.0.0.1` in the dashboard — all 4 checks should produce FAIL results.

| Host Port | Service        | Vulnerabilities |
|-----------|----------------|-----------------|
| 8888      | HTTP API       | No headers, exposed credentials, unauthenticated /admin |
| 2222      | SSH            | admin/admin, root/toor, pi/raspberry |
| 1883      | MQTT           | Anonymous access, no TLS |

Stop: `docker compose down` (from test-environment/).

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`
- Docker + Docker Compose (for the test environment only)
- nmap optional (not required — port scanning uses raw sockets)

## Legal Notice

Only scan devices you own or have explicit written authorisation to test.
Unauthorised scanning may be illegal. The test environment is for local use only.

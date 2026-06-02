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
| I4 | Lack of Secure Update Mechanism | Firmware/update endpoint probing, cleartext update channel detection, HTTPS availability |
| I5 | Use of Insecure or Outdated Components | Banner version extraction, static CVE matching against known-vulnerable IoT components |
| I7 | Insecure Data Transfer and Storage | TLS version & certificate analysis, HTTP vs HTTPS, MQTT cleartext vs MQTTS |
| I9 | Insecure Default Settings | UPnP/SSDP exposure, ADB detection, SNMP default community, mDNS, factory hostname detection, setup wizard access |

Items I6, I8, I10 are analysed but excluded — see REQUIREMENTS.md §2.

## Features

- **Network Discovery** — scan a subnet (`/api/discover?cidr=192.168.1.0/24`) to find IoT devices before scanning
- **7 OWASP checks** running in parallel via ThreadPoolExecutor
- **Detailed findings** with CVSS scores, risk explanations, and remediation steps
- **Scan history** stored in SQLite with full result retrieval
- **Docker test environment** with deliberately vulnerable services for validation

## Quick Start

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# Install dependencies and run
pip install -r requirements.txt
python app.py
```

Open http://localhost:8080.

On Windows, double-click `autostart.bat` for one-click startup.

## Test Environment (Docker)

A deliberately vulnerable IoT device simulator is provided to validate the scanner:

```bash
cd test-environment
docker compose up --build -d
```

Then scan `127.0.0.1` in the dashboard — all 7 checks should produce FAIL results.

| Host Port | Service        | Vulnerabilities Tested |
|-----------|----------------|------------------------|
| 8888      | HTTP API       | I1, I3, I4, I5, I7, I9 — default creds, no headers, firmware endpoints, outdated server, cleartext, default identity |
| 2222      | SSH            | I1, I2 — admin/admin, root/toor, pi/raspberry |
| 1883      | MQTT           | I1, I2, I7 — anonymous access, no TLS |

See [test-environment/README.md](test-environment/README.md) for the full vulnerability reference.

Stop: `docker compose down` (from test-environment/). Full cleanup: `docker compose down --rmi all --volumes`.

> **Warning:** Do not leave the test environment running unattended — it exposes deliberately vulnerable services on localhost.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/discover?cidr=...` | Discover devices on a subnet |
| POST | `/api/scan` | Start a scan (`{"ip": "...", "device_name": "..."}`) |
| GET | `/api/scans` | List all scan history |
| GET | `/api/scan/<id>` | Get detailed scan results |
| DELETE | `/api/scan/<id>` | Delete a scan record |

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`
- Docker + Docker Compose (for the test environment only)
- nmap optional (not required — port scanning uses raw sockets)

## Legal Notice

Only scan devices you own or have explicit written authorisation to test.
Unauthorised scanning may be illegal. The test environment is for local use only.
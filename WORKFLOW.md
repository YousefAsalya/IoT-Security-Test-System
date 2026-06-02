# WORKFLOW.md — Development Log

This document records the changes made to the IoT Security Tester project, step by step.
It covers the evolution from v1 (initial codebase) through v2 (scanner implementation) to the
current version with expanded OWASP coverage, test environment enhancements, and documentation updates.

---

## Phase 0 — Project Analysis

### 0.1 — v1 Codebase Review (hozefaabbadi2-a11y/iot-security-tester)

Reviewed the original repository structure and quality:

- **Strengths:** Modular `scanner_core/` package with orchestrator pattern, `.github/` team workflow
  (PR templates, issue templates, CODEOWNERS), `CONTRIBUTING.md` with branch naming strategy,
  `docs/` with repository structure and development workflow documentation, network discovery
  via `scanner_core/discovery.py`, backward-compatible `scanner.py` shim.
- **Weaknesses:** All 10 OWASP checks were stubs (no real implementation), CORS wildcard open,
  no IP validation, no CI/CD pipeline, no type hints, JS-heavy (70%) for report generation,
  `database.py` had module-level `init_db()` side effect.
- **Score: 6.8/10** — strong skeleton, weak depth.

### 0.2 — v2 Codebase Review (YousefAsalya/IoT-Security-Test-System)

Reviewed the second repository and compared with v1:

- **Strengths:** 4 OWASP checks deeply implemented (I1, I2, I3, I7), `REQUIREMENTS.md` with
  academic-grade analysis (222 lines, IEEE/NIST references), Docker test environment with
  deliberately vulnerable services, `get_json(silent=True)` for safer error handling,
  `delete_scan()` added, `init_db()` side effect fixed.
- **Weaknesses:** Team workflow infrastructure lost (no `.github/`, no CODEOWNERS, no CONTRIBUTING.md),
  network discovery removed, JS report system dropped without replacement, parallel development
  (not a fork of v1).
- **Score: 8.1/10** — deep implementation, strong academic foundation.

### 0.3 — Gap Analysis

Identified that the two repositories were **parallel implementations**, not sequential.
Key items from v1 that were lost in v2 and needed restoration:

1. Network discovery (`/api/discover` endpoint)
2. `autostart.bat` for Windows one-click startup
3. Team workflow documentation (`docs/`)

Items from v1 intentionally NOT carried forward (v2's decisions were correct):

- JS report system (`make-report.js`, `make-pptx.js`) — replaced by browser-based PDF generation
- `scanner_core/` package structure — v2's `scanner/` structure is cleaner
- 10 OWASP stubs — v2's 4 real implementations are far more valuable

---

## Phase 1 — Restore Lost v1 Features

### 1.1 — autostart.bat

- Created `autostart.bat` with virtual environment support
- Auto-creates `venv/` on first run, installs dependencies, starts server
- Windows users can double-click to launch

### 1.2 — Network Discovery

- Created `scanner/discovery.py`:
  - Auto-detects local `/24` subnet via UDP socket trick
  - Accepts custom CIDR via query parameter
  - Probes 10 IoT-relevant ports per host in parallel (ThreadPoolExecutor)
  - Device type estimation based on open port combinations (MQTT broker, IoT gateway, router, etc.)
  - Safety cap at `/16` to prevent accidental wide scans
- Updated `app.py`:
  - Added `from scanner.discovery import discover_devices`
  - Added `GET /api/discover?cidr=...` endpoint with error handling

---

## Phase 2 — Implement I4 (Lack of Secure Update Mechanism)

### 2.1 — Scanner Module

- Created `scanner/i4_updates.py`:
  - **Scope:** Update *channel* security only — firmware signature verification is explicitly
    documented as out of scope (requires firmware binary access)
  - Probes 23 firmware/update/OTA endpoint paths across all active HTTP ports
  - Checks: unauthenticated access, cleartext (HTTP) vs encrypted (HTTPS) delivery,
    firmware version metadata exposure
  - Detects device-level "no HTTPS available" condition for update channel
  - CVSS scoring: Critical for cleartext + update content, High for cleartext + unknown content
  - VPNFilter malware reference in risk explanation

### 2.2 — Engine Integration

- Added `from .i4_updates import run_check as check_i4` to `engine.py`
- Added `check_i4` to `IMPLEMENTED_CHECKS`
- Removed I4 from `NOT_IMPLEMENTED` list

### 2.3 — Test Environment

- Updated `test-environment/vulnerable-api/app.py`:
  - Added `GET /firmware` — unauthenticated firmware info with cleartext download URL
  - Added `GET/POST /firmware/update` — unauthenticated firmware upload endpoint
  - Added `GET /api/firmware` — OTA server URL over HTTP
  - Added `GET /api/update` — update check with `"signature": "none"`
  - Added `GET /ota` — OTA configuration with cleartext server URL

---

## Phase 3 — Implement I5 (Use of Insecure or Outdated Components)

### 3.1 — Scanner Module

- Created `scanner/i5_components.py`:
  - Curated `VULNERABLE_VERSIONS` database covering 11 IoT-common components:
    OpenSSH, Dropbear, vsftpd, ProFTPD, Apache, nginx, lighttpd, OpenSSL,
    BusyBox, Mosquitto, MiniUPnP
  - 13 regex patterns for version extraction from service banners
  - Independent banner collection (not dependent on I2 data) for check isolation
  - Conservative matching — ambiguous/suppressed banners noted but don't produce findings
  - TLS banner grabbing for HTTPS ports via Python `ssl` module
  - Static CVE list with CVSS scores instead of live NVD API (more reliable for frozen IoT firmware)

### 3.2 — Engine Integration

- Added `from .i5_components import run_check as check_i5` to `engine.py`
- Added `check_i5` to `IMPLEMENTED_CHECKS`
- Removed I5 from `NOT_IMPLEMENTED` list
- Updated `max_workers` from 4 to 6

### 3.3 — Test Environment

- Changed `Server` header in `test-environment/vulnerable-api/app.py`:
  - From: `IoT-Gateway/1.0.2 Python/3.11 Flask/2.3`
  - To: `lighttpd/1.4.35` (CVE-2022-22707, use-after-free vulnerability)

---

## Phase 4 — Implement I9 (Insecure Default Settings)

### 4.1 — Scanner Module

- Created `scanner/i9_defaults.py`:
  - **6 check categories** targeting default-setting indicators NOT covered by I1/I2/I7:
    1. **UPnP/SSDP** (port 1900/UDP) — SSDP M-SEARCH probe, server info extraction
    2. **ADB over TCP** (port 5555) — Android Debug Bridge, unauthenticated root shell
    3. **SNMP default community** (port 161/UDP) — SNMPv1 GET with "public" community string
    4. **mDNS/Bonjour** (port 5353/UDP) — service discovery query
    5. **Factory default hostnames** — regex matching against 18 known IoT device name patterns
       in HTTP response body AND headers (OpenWrt, DD-WRT, ESP32, Raspberry Pi, etc.)
    6. **Setup wizard pages** — 11 common wizard paths with keyword confirmation (≥2 keywords)

### 4.2 — Engine Integration

- Added `from .i9_defaults import run_check as check_i9` to `engine.py`
- Added `check_i9` to `IMPLEMENTED_CHECKS`
- Removed I9 from `NOT_IMPLEMENTED` list
- Updated `max_workers` from 6 to 7

---

## Phase 5 — Scoring Fixes

### 5.1 — I5 Status Logic

- **Before:** `FAIL` only when Critical/High findings exist, or ≥2 Medium findings
- **After:** `FAIL` when any vulnerability is found
- **Reason:** Finding a known-vulnerable component should always be FAIL regardless of severity

### 5.2 — I2 Scoring Logic

- **Before:** Medium findings (open HTTP ports) didn't affect score or status
- **After:** `medium_count * 5` added to score formula; ≥2 Medium findings trigger FAIL
- **Reason:** Open ports with Medium risk are legitimate findings that should reduce the score

---

## Phase 6 — Report Template Fix

### 6.1 — Dynamic Scope and Header

- **Before:** Hardcoded `"4 of 10"`, `"I1, I2, I3, I7"`, `"Items I4, I5, I6, I8, I9, I10 were excluded"`
- **After:** Dynamically generated from `checks` data:
  - Header: `impl.length + ' implemented (' + impl.map(c => c.check_id).join(', ') + ')'`
  - Scope: `impl.length + ' of 10'` with auto-generated check names and exclusion list
  - Added `var notImpl` for excluded items list
- **Benefit:** Adding or removing checks in the future requires zero template changes

---

## Phase 7 — Documentation Updates

### 7.1 — README.md

- Implemented Checks table: 4 → 7 rows (added I4, I5, I9)
- Excluded items: `I4, I5, I6, I8, I9, I10` → `I6, I8, I10`
- Features section added (discovery, parallel checks, scan history)
- API Endpoints table added
- Test environment table updated with I4, I5, I9 vulnerability coverage
- Quick Start section: added virtual environment instructions
- `autostart.bat` reference added

### 7.2 — REQUIREMENTS.md

- **I4:** `EXCLUDE` → `IMPLEMENT (limited scope — update channel security only)`
- **I5:** `EXCLUDE` → `IMPLEMENT (static CVE matching against curated version database)`
- **I9:** `EXCLUDE` → `IMPLEMENT (network-observable default indicators not covered by I1/I2/I7)`
- **I6, I8, I10:** Remain `EXCLUDE` with original rationale preserved
- Section 3 (Selected Implementation Subset): added I4, I5, I9 rows
- Section 4.1 (Vulnerable API): added 5 new vulnerability rows for I4, I5, I9
- Section 4.4 (Expected Results): updated from 4 → 7 expected FAIL results
- Section 5 (Scope): added UDP probing, update channel security, static CVE matching,
  default configuration detection to "In scope"

### 7.3 — test-environment/README.md

- Service table: added I4, I5, I9 to vulnerable-api coverage
- Expected results: 6 → 7 checks, added I9 row
- Vulnerability reference: added I4 (5 firmware endpoints), I5 (lighttpd version),
  I9 (ESP32 factory identity) sections
- Scanner run instructions: added virtual environment setup

### 7.4 — Virtual Environment Setup

- All README files updated with `python3 -m venv venv` instructions
- `autostart.bat` updated to auto-create and activate venv
- `.gitignore` already includes `venv/`; `.deps_installed` should be added

---

## Exclusion Rationale Summary

Three OWASP IoT Top 10 items remain excluded. The rationale is documented in both
`REQUIREMENTS.md` (detailed analysis) and `engine.py` (`NOT_IMPLEMENTED` list with
`exclusion_reason` field included in scan output):

| Item | Reason | Where Covered Instead |
|------|--------|-----------------------|
| **I6** — Insufficient Privacy Protection | Requires device-specific threat modelling and regulatory context. Keyword-based scanning produces unacceptable false-positive rates. | API data exposure partially covered by I3 (auth bypass) |
| **I8** — Lack of Device Management | Network-observable aspects overlap ~80% with I1 (credentials) and I3 (interfaces). Remaining aspects (audit logging, remote wipe, credential rotation) are not network-observable. | I1 + I3 provide deeper coverage of the overlapping surface |
| **I10** — Lack of Physical Hardening | JTAG, UART, tamper-evident seals, secure boot — none assessable over TCP/IP. Requires physical hardware access and specialised tools. | Out of scope for any network-based scanner |

---

## Final State

| Metric | v2 (before) | Current |
|--------|-------------|---------|
| Implemented checks | 4 (I1, I2, I3, I7) | 7 (I1, I2, I3, I4, I5, I7, I9) |
| Excluded checks | 6 (I4–I6, I8–I10) | 3 (I6, I8, I10) |
| Scanner files | 6 | 10 (+discovery, i4, i5, i9) |
| Test env vulnerabilities | 12 | 18 (+firmware endpoints, version header, factory identity) |
| Report template | Hardcoded 4-check scope | Dynamic scope from scan data |
| Virtual environment | Not documented | Documented + autostart.bat support |

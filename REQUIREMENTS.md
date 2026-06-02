# Requirements Analysis — IoT Security Tester

**Course Project | Master's Level**
**Framework: OWASP IoT Top 10 (2018)**

---

## 1. Introduction

This document presents the requirements analysis for an automated IoT security assessment tool. The analysis examines the OWASP IoT Top 10 (2018) — the industry-standard enumeration of the most critical security risks facing IoT devices — and determines which items are feasible to implement as automated, network-based security checks.

The guiding principle of this selection is **testability over a standard TCP/IP network without physical device access**. IoT security assessments in practice are conducted remotely (e.g., by a security team on the same LAN as the device fleet), making network-observable vulnerabilities the most relevant attack surface.

---

## 2. OWASP IoT Top 10 — Full Analysis

### I1 — Weak, Guessable, or Hardcoded Passwords

**Description:** Devices ship with predictable default credentials (admin/admin, root/root, etc.) that users rarely change. Hardcoded credentials are compiled into firmware and cannot be changed at all.

**Testability Assessment:** High. Default credential attacks are fully executable over SSH (port 22), Telnet (port 23), HTTP login endpoints (port 80/8080), and MQTT brokers (port 1883) using standard protocol libraries. Success is unambiguous: either the connection is authenticated or it is not.

**Decision: IMPLEMENT.**
Rationale: This is the #1 real-world IoT attack vector. The Mirai botnet (2016), which compromised over 600,000 IoT devices, relied entirely on default credentials. Deep implementation includes protocol-specific brute-force with curated IoT credential lists, CVSS scoring of discovered credentials, and detection of rate-limiting mechanisms.

---

### I2 — Insecure Network Services

**Description:** Devices expose unnecessary or dangerous network services — legacy protocols (Telnet, FTP, rsh), unauthenticated databases, industrial protocols (Modbus, BACnet) — that expand the attack surface far beyond what the device's function requires.

**Testability Assessment:** High. TCP port scanning with service banner grabbing is fully executable over a network. Banner responses reveal service names and versions, enabling risk classification and CVE cross-referencing.

**Decision: IMPLEMENT.**
Rationale: Network service enumeration is the foundation of any security assessment. Deep implementation includes active banner grabbing for each discovered port (not just port state), service fingerprinting, IoT-specific protocol detection (MQTT, Modbus/502, BACnet/47808, RTSP/554, OPC-UA/4840), and per-service risk classification against a known-dangerous service registry.

---

### I3 — Insecure Ecosystem Interfaces

**Description:** Web interfaces, APIs, and cloud connectors lack authentication, expose sensitive information, or omit browser security controls (HTTP security headers), enabling XSS, clickjacking, CSRF, and unauthenticated access.

**Testability Assessment:** High. HTTP security header analysis, unauthenticated endpoint probing, server information disclosure detection, and CORS misconfiguration checks are all executable via standard HTTP requests. Results are deterministic.

**Decision: IMPLEMENT.**
Rationale: The majority of consumer IoT devices expose a web management interface. Missing security headers and unauthenticated API endpoints are among the most commonly found vulnerabilities in real-world IoT assessments. Deep implementation includes scoring against OWASP Secure Headers Project criteria, authentication bypass testing against common IoT API paths, CORS analysis, and server information disclosure quantification.

---

### I4 — Lack of Secure Update Mechanism

**Description:** Firmware updates are transmitted without encryption or cryptographic signature verification, allowing man-in-the-middle attacks to install malicious firmware.

**Testability Assessment:** Low for full assessment, Medium for update channel security. Verifying firmware signature verification requires firmware binary access (binwalk, Ghidra) and is outside the scope of a black-box network scanner. However, update *channel* security is network-observable: unauthenticated firmware endpoints, cleartext (HTTP) update URLs, and absence of HTTPS for update delivery can all be detected through endpoint probing.

**Decision: IMPLEMENT (limited scope — update channel security only).**
Rationale: While firmware signature verification cannot be confirmed over a network, the update channel itself can be assessed. The implementation probes 23 common firmware/update/OTA endpoint paths across all active HTTP ports, checking: (a) whether firmware management endpoints are accessible without authentication, (b) whether the update channel uses HTTPS or cleartext HTTP, and (c) whether the device exposes firmware version metadata to unauthenticated clients. This captures the network-observable dimension of I4 while clearly documenting the out-of-scope aspects (signature verification, secure boot chain) in both the check output and scan report. The 2018 VPNFilter malware, which exploited insecure update channels on 500,000+ routers, demonstrates the practical impact of this vulnerability class.

---

### I5 — Use of Insecure or Outdated Components

**Description:** Device firmware includes outdated OS kernels, libraries (OpenSSL, uClibc), or application software with known CVEs that have not been patched.

**Testability Assessment:** Medium. Service banners frequently reveal version strings (SSH, HTTP Server, FTP, MQTT) that can be matched against known-vulnerable releases. While version detection alone does not confirm exploitability, IoT firmware versions are largely frozen at the time of compilation and rarely updated, making static version matching a practical indicator of risk.

**Decision: IMPLEMENT (static CVE matching against curated version database).**
Rationale: Rather than integrating a live NVD API (rate-limited, requires continuous maintenance), the implementation uses a curated database of known-vulnerable versions for components commonly found on IoT devices: OpenSSH, Dropbear, vsftpd, ProFTPD, Apache, nginx, lighttpd, OpenSSL, BusyBox, Mosquitto, and MiniUPnP. Version strings are extracted from service banners via regex, then matched against version-range patterns with associated CVE references and CVSS scores. Conservative matching reduces false positives — ambiguous or suppressed banners are noted in the scan summary but do not produce findings (version suppression is actually a security best practice). The I2 banner data provides complementary input but I5 performs its own independent banner collection to maintain check isolation. Banner data from I2 remains available for manual CVE lookup of components not covered by the static database.

---

### I6 — Insufficient Privacy Protection

**Description:** Devices collect and transmit personal data (location, usage patterns, credentials) without adequate protection — no encryption in transit, no access controls on stored data, no data minimization.

**Testability Assessment:** Medium. Detecting sensitive data in API responses (credentials in JSON, PII in status endpoints) is achievable. However, comprehensive privacy assessment requires: (a) understanding of what data the device should and should not collect, (b) analysis of all communication channels including cloud APIs, and (c) knowledge of applicable privacy regulations (GDPR, CCPA) for classification.

**Decision: EXCLUDE.**
Rationale: Privacy assessment cannot be reduced to keyword matching in HTTP responses without generating high false-positive rates. A rigorous privacy analysis requires threat modeling specific to the device type and its data flows. The authentication bypass findings in I3 partially cover the API data exposure dimension of this item. Full privacy assessment is a separate compliance-oriented activity.

---

### I7 — Insecure Data Transfer and Storage

**Description:** Device communications use unencrypted protocols (HTTP instead of HTTPS, MQTT instead of MQTTS) or weak TLS configurations (outdated protocol versions, expired certificates, weak cipher suites), exposing data to network eavesdropping.

**Testability Assessment:** High. Encryption presence/absence is directly observable: port 80 vs 443 for HTTP, port 1883 vs 8883 for MQTT, port 21 vs 22 for file transfer. TLS quality is analyzable using Python's ssl module to retrieve negotiated versions and certificate metadata.

**Decision: IMPLEMENT.**
Rationale: Unencrypted IoT communications are an extremely common finding. Smart home devices, industrial sensors, and IP cameras frequently communicate over plaintext protocols. Deep implementation includes TLS version negotiation testing, certificate validity analysis (expiry, self-signed status, hostname mismatch), MQTT encryption detection, and FTP/cleartext protocol identification. The combination with I3 (HTTP interface) provides a complete view of the device's encryption posture.

---

### I8 — Lack of Device Management

**Description:** Devices lack secure management capabilities: no ability to update credentials, no audit logging, no remote wipe, no access controls on management interfaces.

**Testability Assessment:** Low-Medium. While detecting unauthenticated management endpoints (HTTP 200 on /admin) is achievable, this is a subset of I3 (Insecure Ecosystem Interfaces). The broader management security issues (audit logging, credential rotation, remote wipe) are not network-observable.

**Decision: EXCLUDE.**
Rationale: The network-observable aspects of I8 (unauthenticated management endpoints, Telnet for management) are already covered with greater depth by I1 (credential testing) and I3 (interface security). Including I8 as a separate check would produce a significant overlap and dilute the depth of both checks. The OWASP guidance itself acknowledges substantial overlap between I3 and I8.

---

### I9 — Insecure Default Settings

**Description:** Devices ship with insecure default configurations: unnecessary services enabled, unrestricted firewall rules, debug interfaces active, default admin accounts enabled.

**Testability Assessment:** Medium. While I1, I2, and I7 cover the highest-impact default settings (credentials, dangerous services, missing encryption), several network-observable default-setting indicators remain uncovered: UPnP/SSDP enabled by default, Android Debug Bridge (ADB) over TCP, SNMP with default community strings, mDNS service advertisement, factory-default device hostnames, and setup wizard pages accessible post-deployment.

**Decision: IMPLEMENT (network-observable default indicators not covered by I1/I2/I7).**
Rationale: The implementation checks 6 categories of default-setting indicators via both TCP and UDP probes: UPnP/SSDP (port 1900/UDP) which allows automatic firewall port-opening and was exploited in the CallStranger vulnerability (CVE-2020-12695); ADB over TCP (port 5555) which provides unauthenticated root shell access on Android-based IoT devices; SNMP with the default "public" community string (port 161/UDP) exposing full system inventory; mDNS/Bonjour (port 5353/UDP) leaking device metadata; factory-default hostnames and device identifiers in HTTP responses and headers; and setup wizard pages still accessible after deployment indicating incomplete hardening. These indicators are distinct from I1 (credentials), I2 (service inventory), and I7 (transport encryption) and specifically target the "device was never hardened" signal.

---

### I10 — Lack of Physical Hardening

**Description:** Debug interfaces (JTAG, UART) are physically accessible on production hardware, enabling firmware extraction, privilege escalation, and bypass of all software security controls via hardware-level access.

**Testability Assessment:** None. Physical hardening is definitionally not assessable over a TCP/IP network. While debug port enumeration (ADB on port 5555, Metasploit on 4444) is network-observable, these are specific service checks already covered by I2's port scan. Physical interface assessment requires hardware access, specialized tools (JTAG debugger, logic analyzer, SPI flash reader), and firmware analysis.

**Decision: EXCLUDE.**
Rationale: This item is fundamentally outside the scope of a network-based scanner. A "remote clue" check (looking for "uart" in HTTP responses) provides negligible security value and produces false positives on legitimate documentation pages. Physical hardening assessment belongs to hardware security audits, not network-based automated tools.

---

## 3. Selected Implementation Subset

| OWASP Item | Check Name | Implementation Depth |
|------------|------------|----------------------|
| **I1** | Weak, Guessable, or Hardcoded Passwords | SSH brute-force (Paramiko), HTTP login brute-force (POST to common endpoints), MQTT anonymous + default credential test, CVSS 9.8 scoring for found credentials |
| **I2** | Insecure Network Services | TCP port scan across 20 IoT-relevant ports, active banner grabbing via raw socket, service fingerprinting, per-service risk classification, IoT protocol detection (MQTT, Modbus, BACnet, RTSP, OPC-UA) |
| **I3** | Insecure Ecosystem Interfaces | HTTP security header scoring (7 headers), CORS misconfiguration detection, server information disclosure analysis, authentication bypass testing on 12 common IoT API paths, HTTP method enumeration |
| **I4** | Lack of Secure Update Mechanism | Probes 23 firmware/update/OTA endpoint paths for unauthenticated access, detects cleartext (HTTP) update channels, checks HTTPS availability for update delivery. Limited scope: update channel security only — firmware signature verification is out of scope |
| **I5** | Use of Insecure or Outdated Components | Banner version extraction from SSH, HTTP, FTP, MQTT services via regex; static matching against curated database of 11 known-vulnerable IoT components (OpenSSH, Dropbear, lighttpd, BusyBox, Mosquitto, etc.) with CVE references and CVSS scores |
| **I7** | Insecure Data Transfer and Storage | HTTP vs HTTPS detection, TLS version negotiation (TLS 1.0/1.1/1.2/1.3), X.509 certificate analysis (expiry, self-signed, CN mismatch), MQTT cleartext vs TLS, FTP detection, login over cleartext HTTP |
| **I9** | Insecure Default Settings | UPnP/SSDP exposure (1900/UDP), ADB over TCP (5555), SNMP default community (161/UDP), mDNS (5353/UDP), factory-default hostname detection in HTTP responses/headers, setup wizard accessibility post-deployment |

---

## 4. Test Environment Design

To validate the implemented checks against known vulnerabilities, a **deliberate vulnerability test environment** is provided as a Docker Compose application. This environment simulates a vulnerable IoT gateway device with the following services:

### 4.1 Vulnerable IoT API (`vulnerable-api`, port 8888)

A Flask web application simulating a poorly-secured IoT device management interface:

| Vulnerability | Location | OWASP Item |
|---------------|----------|------------|
| No HTTP security headers | All responses | I3 |
| Server version disclosure | `Server: lighttpd/1.4.35` header | I3, I5 |
| Unauthenticated admin panel | `GET /admin` | I3 |
| Credentials exposed in API | `GET /api/config` | I3, I7 |
| Default credential accepted | `POST /api/login` | I1 |
| HTTP-only (no TLS) | All endpoints | I7 |
| CORS misconfiguration | `Access-Control-Allow-Origin: *` | I3 |
| Sensitive debug endpoint | `GET /api/debug` | I3 |
| Unauthenticated firmware info | `GET /firmware` | I4 |
| Unauthenticated firmware upload | `GET/POST /firmware/update` | I4 |
| Cleartext OTA server URL | `GET /api/firmware`, `GET /ota` | I4 |
| Update with no signature | `GET /api/update` (`"signature": "none"`) | I4 |
| Outdated server component | `lighttpd/1.4.35` (CVE-2022-22707) | I5 |

### 4.2 Vulnerable SSH Server (`vulnerable-ssh`, port 2222)

An Alpine Linux container running OpenSSH with:
- Default credentials: `admin:admin`, `root:toor`
- Password authentication enabled (no key enforcement)
- Banner disclosing version information

| Vulnerability | OWASP Item |
|---------------|------------|
| Default SSH credential `admin/admin` | I1 |
| Default SSH credential `root/toor` | I1 |
| SSH version exposed in banner | I2 |

### 4.3 Vulnerable MQTT Broker (`vulnerable-mqtt`, port 1883)

Eclipse Mosquitto MQTT broker configured with:
- Anonymous connections allowed (no authentication)
- No TLS (cleartext on port 1883 only)
- Sensor data published to discoverable topics

| Vulnerability | OWASP Item |
|---------------|------------|
| Anonymous MQTT connection accepted | I1, I2 |
| MQTT data transmitted in cleartext | I7 |

### 4.4 Expected Scan Results Against Test Environment

When the scanner targets `127.0.0.1`, all seven implemented checks should produce FAIL results, confirming correct detection:

- **I1**: Default credentials found on SSH (admin/admin) and MQTT (anonymous)
- **I2**: Dangerous open services: SSH (2222), MQTT (1883), HTTP API (8888)
- **I3**: All 7 security headers missing; `/admin` accessible without auth; credentials exposed at `/api/config`; CORS misconfigured
- **I4**: Firmware endpoints (`/firmware`, `/firmware/update`, `/api/firmware`, `/ota`) accessible without authentication over cleartext HTTP
- **I5**: Outdated component detected via Server header: `lighttpd/1.4.35` (CVE-2022-22707)
- **I7**: HTTP-only API on port 8888 (no HTTPS); MQTT on port 1883 (no MQTTS)
- **I9**: Factory default device identity (ESP32) detected in HTTP response headers

---

## 5. Scope and Limitations

**In scope:**
- Black-box network-based security assessment
- TCP/IP and UDP reachable services
- Protocol-level vulnerability detection
- Update channel security (endpoint authentication, transport encryption)
- Static version-to-CVE matching for common IoT components
- Default configuration detection (UPnP, ADB, SNMP, mDNS, factory hostnames)

**Out of scope:**
- Firmware binary analysis (signature verification, secure boot)
- Physical interface assessment (JTAG, UART)
- Cloud backend security testing
- Privacy compliance assessment
- Live CVE database integration (NVD API) — static curated list used instead

**Limitations:**
- Credential brute-force stops after first successful hit to avoid account lockout
- TLS analysis limited to what Python's ssl module exposes (no cipher suite enumeration without OpenSSL bindings)
- Banner grabbing may not succeed against services with non-standard banners
- MQTT data capture is limited to a brief window (5 seconds) to avoid blocking

---

## 6. References

- OWASP IoT Project. (2018). *OWASP IoT Top 10*. https://owasp.org/www-project-internet-of-things/
- Antonakakis, M., et al. (2017). Understanding the Mirai Botnet. *USENIX Security Symposium*.
- NIST. (2020). *Foundational Cybersecurity Activities for IoT Device Manufacturers* (NISTIR 8259).
- Alrawi, O., et al. (2019). SoK: Security Evaluation of Home-Based IoT Deployments. *IEEE S&P*.
- OWASP Secure Headers Project. https://owasp.org/www-project-secure-headers/